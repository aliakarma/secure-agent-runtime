import json
import os
import pytesseract
from PIL import Image
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from logging_config import get_logger
from dotenv import load_dotenv

load_dotenv()

logger = get_logger(__name__)

class SanitizerResult(BaseModel):
    is_malicious: bool = Field(description="True if the content contains a prompt injection, PII, hidden instructions, jailbreak, or policy violation. False otherwise.")
    reason: str = Field(description="Explanation for why the content was flagged or marked safe.")
    confidence: float = Field(default=1.0, description="Confidence score between 0.0 and 1.0 representing how confident you are in this classification.")

# Confidence threshold: only flag as malicious when the classifier is at
# least this confident.  Benign travel queries often land at 0.55-0.75
# confidence for LABEL_1 — well below a genuine injection (>0.95).
CONFIDENCE_THRESHOLD = 0.85

class TextSanitizer:
    def __init__(self):
        self.local_classifier = None
        self.init_error = None
        self.llm = None
        self.prompt = None
        
        # 1. Attempt to load the local fine-tuned classifier
        if os.getenv("SECURED_SYSTEM_MODE", "full-research").lower() != "fast":
            try:
                from transformers import pipeline
                logger.info("Initializing local prompt injection classifier...")
                from transformers import AutoTokenizer
                tokenizer = AutoTokenizer.from_pretrained(
                    "./models/local_prompt_detector"
                )
                tokenizer.model_input_names = [
                    n for n in tokenizer.model_input_names
                    if n != "token_type_ids"
                ]
                self.local_classifier = pipeline(
                    "text-classification",
                    model="./models/local_prompt_detector",
                    tokenizer=tokenizer,
                    device=-1,  # Run on CPU. Set to 0 if CUDA is available.
                )
                logger.info("Local prompt injection classifier successfully loaded.")
            except Exception as e:
                self.init_error = str(e)
                if os.getenv("STRICT_SECURITY", "0") == "1":
                    raise RuntimeError(
                        "STRICT_SECURITY=1: local prompt injection classifier is required "
                        f"but failed to load: {e}. Train it via scripts/train_local_classifier.py."
                    ) from e
                logger.warning(f"Failed to load local prompt injection classifier: {e}. Falling back to local heuristics.")

    def _fast_heuristic_filter(self, text: str) -> bool:
        """Latency fast-path check. Returns True if suspicious keywords found.

        NOTE: This is a coarse pre-filter, not the detector. It deliberately
        contains only generic injection vocabulary — benchmark-specific canary
        tokens (e.g. location names used in the attack dataset) must never be
        added here, or evaluation becomes circular.
        """
        suspicious_keywords = [
            "ignore", "disregard", "override", "bypass", "system", "jailbreak",
            "admin", "you are now", "new instructions", "previous instructions",
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in suspicious_keywords)

    def sanitize(self, text: str) -> SanitizerResult:
        if not text or not str(text).strip():
            return SanitizerResult(is_malicious=False, reason="Empty input", confidence=1.0)

        system_mode = os.getenv("SECURED_SYSTEM_MODE", "full-research").lower()

        # Fast Mode: Keyword screening only, skip classifier and LLM calls
        if system_mode == "fast":
            is_malicious = self._fast_heuristic_filter(text)
            return SanitizerResult(
                is_malicious=is_malicious,
                reason="Fast heuristic check.",
                confidence=0.7
            )

        # Secure Mode: Local classifier only, skip OpenAI LLM fallback
        if system_mode == "secure":
            if self.local_classifier is not None:
                try:
                    res = self.local_classifier(str(text))[0]
                    label = res["label"]
                    score = res["score"]
                    is_injection_label = (label in ["INJECTION", "LABEL_1"])
                    is_malicious = is_injection_label and score >= CONFIDENCE_THRESHOLD
                    reason = f"Local classifier: {label} (confidence={score:.3f}, threshold={CONFIDENCE_THRESHOLD})"
                    if is_injection_label and not is_malicious:
                        reason += " — below threshold, treating as benign"
                    return SanitizerResult(is_malicious=is_malicious, reason=reason, confidence=score)
                except Exception:
                    pass
            is_malicious = self._fast_heuristic_filter(text)
            return SanitizerResult(is_malicious=is_malicious, reason="Secure mode fallback to heuristics", confidence=0.7)

        # Full-research mode: classifier-first.
        # A previous revision short-circuited to "benign, confidence 1.0" when
        # no keyword matched, so paraphrased (keyword-free) injections never
        # reached the classifier at all. The classifier now sees every input;
        # keywords are only the emergency fallback when no classifier exists.
        if self.local_classifier is not None:
            try:
                res = self.local_classifier(str(text))[0]
                label = res["label"]
                score = res["score"]
                is_injection_label = (label in ["INJECTION", "LABEL_1"])
                is_malicious = is_injection_label and score >= CONFIDENCE_THRESHOLD
                reason = f"Local classifier verdict: {label} (confidence={score:.3f}, threshold={CONFIDENCE_THRESHOLD})."
                if is_injection_label and not is_malicious:
                    reason += " Below threshold — treating as benign."
                return SanitizerResult(is_malicious=is_malicious, reason=reason, confidence=score)
            except Exception as e:
                logger.error(f"Local classifier execution failed: {e}. Falling back to local heuristics.")
                if os.getenv("STRICT_SECURITY", "0") == "1":
                    raise RuntimeError(
                        f"STRICT_SECURITY=1: classifier execution failed: {e}"
                    ) from e

        # Hard fallback on keywords (classifier unavailable)
        if os.getenv("STRICT_SECURITY", "0") == "1":
            raise RuntimeError(
                "STRICT_SECURITY=1: refusing keyword-only fallback in full-research mode. "
                f"Classifier init error: {self.init_error}"
            )
        is_malicious = self._fast_heuristic_filter(text)
        return SanitizerResult(
            is_malicious=is_malicious,
            reason=f"Hard fallback based on heuristic keywords. Local error: {self.init_error}",
            confidence=0.5
        )

class VisualSanitizer:
    def __init__(self):
        self.text_sanitizer = TextSanitizer()
        
    def sanitize(self, image_path: str) -> SanitizerResult:
        if not os.path.exists(image_path):
            return SanitizerResult(is_malicious=False, reason="File not found, treating as safe/ignorable.")
            
        try:
            img = Image.open(image_path)
            
            # Phase C: Deep Image Inspection (Metadata & Steganography)
            metadata_text = []
            if hasattr(img, '_getexif') and img._getexif() is not None:
                from PIL import ExifTags
                exif_data = img._getexif()
                for tag, value in exif_data.items():
                    if tag in ExifTags.TAGS:
                        tag_name = ExifTags.TAGS[tag]
                        if isinstance(value, str):
                            metadata_text.append(f"{tag_name}: {value}")
                            
            # Basic Steganography Heuristic
            stegano_flag = False
            file_size = os.path.getsize(image_path)
            if file_size > 5 * 1024 * 1024:  # Suspiciously large
                stegano_flag = True

            text = pytesseract.image_to_string(img)
            
            full_context = text
            if metadata_text:
                full_context += "\n[HIDDEN METADATA]: " + " | ".join(metadata_text)
                
            if not full_context.strip() and not stegano_flag:
                return SanitizerResult(is_malicious=False, reason="No text or suspicious metadata found in image.")
                
            if stegano_flag:
                logger.warning("VisualSanitizer: Possible steganographic payload detected.")
                
            logger.info(f"VisualSanitizer extracted content: {full_context}")
            return self.text_sanitizer.sanitize(full_context)
        except Exception as e:
            logger.error(f"VisualSanitizer error: {e}")
            return SanitizerResult(is_malicious=True, reason=f"Image processing failed: {e}")

class AudioSanitizer:
    """
    Phase 5: Audio Sanitizer Agent (Aa).
    Converts audio to text using OpenAI Whisper, then checks the 
    transcript for hidden phonetic commands or injection payloads.
    """
    def __init__(self):
        self.text_sanitizer = TextSanitizer()
        self.local_model = None
        
    def sanitize(self, audio_path: str) -> SanitizerResult:
        if not os.path.exists(audio_path):
            return SanitizerResult(is_malicious=False, reason="Audio file not found, treating as safe/ignorable.")
        
        try:
            # Use local Whisper package for transcription
            import whisper
            if self.local_model is None:
                logger.info("Loading local Whisper model ('tiny') on CPU...")
                self.local_model = whisper.load_model("tiny", device="cpu")
                
            result = self.local_model.transcribe(audio_path)
            transcript = result.get("text", "")
            
            if not transcript.strip():
                return SanitizerResult(is_malicious=False, reason="No speech detected in audio.")
                
            logger.info(f"AudioSanitizer transcribed: {transcript[:100]}...")
            return self.text_sanitizer.sanitize(transcript)
        except ImportError:
            if os.getenv("STRICT_SECURITY", "0") == "1":
                return SanitizerResult(is_malicious=True, reason="STRICT_SECURITY: whisper unavailable, failing closed on audio input.")
            logger.warning("Local whisper package not available, skipping audio sanitization.")
            return SanitizerResult(is_malicious=False, reason="Whisper unavailable, skipping audio sanitization.")
        except Exception as e:
            logger.error(f"AudioSanitizer error: {e}")
            # Fail-closed: if we can't process audio, treat as suspicious
            return SanitizerResult(is_malicious=True, reason=f"Audio processing failed: {e}")

class VideoSanitizer:
    """
    Phase 5: Video Sanitizer Agent (Avid).
    Extracts keyframes from video using OpenCV, runs OCR on each frame
    to detect temporal injection — instructions that appear for only
    a fraction of a second and are invisible to human viewers.
    """
    def __init__(self):
        self.text_sanitizer = TextSanitizer()
        self.keyframe_interval = 30  # Extract every 30th frame (~1 per second at 30fps)
        
    def sanitize(self, video_path: str) -> SanitizerResult:
        if not os.path.exists(video_path):
            return SanitizerResult(is_malicious=False, reason="Video file not found, treating as safe/ignorable.")
        
        try:
            import cv2
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return SanitizerResult(is_malicious=True, reason="Failed to open video file.")
            
            frame_count = 0
            extracted_texts = []
            
            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                    
                # Extract keyframes at interval
                if frame_count % self.keyframe_interval == 0:
                    try:
                        # Convert frame to PIL Image for OCR
                        from PIL import Image as PILImage
                        import numpy as np
                        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        pil_image = PILImage.fromarray(rgb_frame)
                        text = pytesseract.image_to_string(pil_image)
                        if text.strip():
                            extracted_texts.append(text.strip())
                    except Exception as e:
                        logger.warning(f"Frame {frame_count} OCR failed: {e}")
                        
                frame_count += 1
            
            cap.release()
            
            if not extracted_texts:
                return SanitizerResult(is_malicious=False, reason=f"No text found in {frame_count} video frames.")
            
            # Concatenate all extracted text and run through text sanitizer
            combined_text = " ".join(extracted_texts)
            logger.info(f"VideoSanitizer extracted text from {len(extracted_texts)} frames: {combined_text[:100]}...")
            return self.text_sanitizer.sanitize(combined_text)
            
        except ImportError:
            if os.getenv("STRICT_SECURITY", "0") == "1":
                return SanitizerResult(is_malicious=True, reason="STRICT_SECURITY: OpenCV unavailable, failing closed on video input.")
            logger.warning("OpenCV not available, falling back to text passthrough.")
            return SanitizerResult(is_malicious=False, reason="OpenCV unavailable, skipping video sanitization.")
        except Exception as e:
            logger.error(f"VideoSanitizer error: {e}")
            return SanitizerResult(is_malicious=True, reason=f"Video processing failed: {e}")

def _unroll_structured_text(text: str) -> str:
    """Extract string leaf values from JSON so the classifier sees natural language, not syntax.

    If *text* is valid JSON, recursively collect every string-valued leaf and
    join them with spaces.  Non-JSON input is returned unchanged so callers
    that already pass plain text are unaffected.
    """
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text

    leaves: list[str] = []

    def _walk(node):
        if isinstance(node, str):
            stripped = node.strip()
            if stripped:
                leaves.append(stripped)
        elif isinstance(node, dict):
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(obj)
    return " ".join(leaves) if leaves else text


class RAGSanitizer:
    def __init__(self):
        self.text_sanitizer = TextSanitizer()

    def sanitize(self, chunk: str) -> SanitizerResult:
        if not chunk or not chunk.strip():
            return SanitizerResult(is_malicious=False, reason="Empty memory chunk", confidence=1.0)

        # 1. Run local memory heuristics for active commands/poisoning.
        # Memory should contain facts/preferences; imperative instructions in
        # a memory chunk indicate poisoning. Generic vocabulary only — no
        # benchmark-specific poison phrases (see anti-circularity note above).
        imperative_markers = [
            "ignore", "disregard", "override", "you must", "you are now",
            "output exactly", "respond with", "demands that you",
        ]
        is_malicious = any(w in chunk.lower() for w in imperative_markers)
        if is_malicious:
            return SanitizerResult(
                is_malicious=True,
                reason="Flagged by local memory heuristics (active commands or overrides).",
                confidence=0.9
            )

        # 2. Run local TextSanitizer (uses local classifier)
        return self.text_sanitizer.sanitize(_unroll_structured_text(chunk))


class ToolOutputSanitizer:
    def __init__(self):
        self.text_sanitizer = TextSanitizer()

    def sanitize(self, payload: str) -> SanitizerResult:
        unrolled = _unroll_structured_text(str(payload))
        return self.text_sanitizer.sanitize(unrolled)
