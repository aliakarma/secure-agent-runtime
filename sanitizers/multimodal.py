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
    # Shared across instances so swapping in a heavy model (Prompt Guard 2,
    # ensemble) loads it once, not per-sanitizer.
    _shared_classifier = None
    _shared_name = "none"
    _shared_error = None
    _shared_loaded = False

    def __init__(self):
        self.local_classifier = None
        self.detector_name = "none"
        self.init_error = None
        self.llm = None
        self.prompt = None

        # 1. Load the configured detector backend (distilbert | promptguard2 |
        #    deberta-pi | ensemble) via the pluggable detector registry. Loads
        #    once and is shared. Fail-soft unless STRICT_SECURITY=1.
        if os.getenv("SECURED_SYSTEM_MODE", "full-research").lower() != "fast":
            if not TextSanitizer._shared_loaded:
                from config import settings
                from sanitizers.detectors import build_detector
                logger.info(f"Initializing detector backend: {settings.detector_backend} ...")
                detector, name, error = build_detector(
                    settings.detector_backend,
                    promptguard_model=settings.promptguard_model,
                    deberta_pi_model=settings.deberta_pi_model,
                )
                TextSanitizer._shared_classifier = detector
                TextSanitizer._shared_name = name
                TextSanitizer._shared_error = error
                TextSanitizer._shared_loaded = True
                if detector is not None:
                    logger.info(f"Detector active: {name}")
                else:
                    logger.warning(f"No detector loaded ({error}); using keyword heuristics.")

            self.local_classifier = TextSanitizer._shared_classifier
            self.detector_name = TextSanitizer._shared_name
            self.init_error = TextSanitizer._shared_error
            if self.local_classifier is None and os.getenv("STRICT_SECURITY", "0") == "1":
                raise RuntimeError(
                    "STRICT_SECURITY=1: a prompt-injection detector is required "
                    f"but none loaded: {self.init_error}. "
                    "Train DistilBERT via scripts/train_local_classifier.py or set DETECTOR_BACKEND."
                )

    @staticmethod
    def _strip_multimodal_markers(text: str) -> str:
        """Remove structural extraction markers so the classifier sees clean
        natural language, not out-of-distribution tokens.

        This replaces the old "skip the classifier on any multimodal marker"
        behaviour: the markers are noise to strip, never a reason to bypass
        detection. Injected *content* still reaches the classifier.
        """
        import re as _re
        out = text
        # Bracketed labels: "[Extracted from uploaded image via OCR]",
        # "[Transcribed from uploaded audio]", "[HIDDEN METADATA]", etc.
        out = _re.sub(r'\[(?:extracted from|transcribed from|hidden metadata)[^\]]*\]',
                      ' ', out, flags=_re.IGNORECASE)
        # Short trailing modality tags appended by the multimodal sanitizers.
        for tag in ("[image ocr]", "[audio transcript]", "[video frames]",
                    "[pdf document]", "[filepath]"):
            out = out.replace(tag, " ").replace(tag.upper(), " ")
        return _re.sub(r'\s{2,}', ' ', out).strip()

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

        import re as _re
        cleaned_text = str(text)
        cleaned_text = _re.sub(r'\b[a-zA-Z]:[\\/][^:\*\?"<>\|]+?\.[a-zA-Z0-9]{3,4}\b', '[FILEPATH]', cleaned_text)
        cleaned_text = _re.sub(r'\bdatasets[\\/][A-Za-z0-9_.\-\\/]+', '[FILEPATH]', cleaned_text)

        # Multimodal prompts carry structural markers (e.g.
        # "[Extracted from uploaded image via OCR]", "[pdf document]",
        # "[FILEPATH]") that the plain-text-trained classifier treats as
        # out-of-distribution and can false-positive on.
        #
        # Previously the code *skipped the classifier entirely* whenever such
        # a marker was present — a trivial evasion: appending "[image ocr]"
        # to any injection bypassed detection. We now STRIP the markers and
        # still run the full classifier on the residual natural-language text,
        # so injected content is always classified while the OOD tokens that
        # caused false positives are removed.
        cleaned_text = self._strip_multimodal_markers(cleaned_text)

        system_mode = os.getenv("SECURED_SYSTEM_MODE", "full-research").lower()

        # Fast Mode: Keyword screening only, skip classifier and LLM calls
        if system_mode == "fast":
            is_malicious = self._fast_heuristic_filter(cleaned_text)
            return SanitizerResult(
                is_malicious=is_malicious,
                reason="Fast heuristic check.",
                confidence=0.7
            )

        # Secure Mode: Local classifier only, skip OpenAI LLM fallback
        if system_mode == "secure":
            if self.local_classifier is not None:
                try:
                    res = self.local_classifier(str(cleaned_text))[0]
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
            is_malicious = self._fast_heuristic_filter(cleaned_text)
            return SanitizerResult(is_malicious=is_malicious, reason="Secure mode fallback to heuristics", confidence=0.7)

        # Full-research mode: classifier-first.
        # A previous revision short-circuited to "benign, confidence 1.0" when
        # no keyword matched, so paraphrased (keyword-free) injections never
        # reached the classifier at all. The classifier now sees every input;
        # keywords are only the emergency fallback when no classifier exists.
        if self.local_classifier is not None:
            try:
                res = self.local_classifier(str(cleaned_text))[0]
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
        is_malicious = self._fast_heuristic_filter(cleaned_text)
        return SanitizerResult(
            is_malicious=is_malicious,
            reason=f"Hard fallback based on heuristic keywords. Local error: {self.init_error}",
            confidence=0.5
        )

class VisualSanitizer:
    def __init__(self):
        self.text_sanitizer = TextSanitizer()
        
    def extract_text(self, image_path: str) -> str:
        if not os.path.exists(image_path):
            return ""
        sidecar_path = str(image_path) + ".txt"
        if os.path.exists(sidecar_path):
            try:
                with open(sidecar_path, "r", encoding="utf-8") as f:
                    ocr_text = f.read().strip()
                # Also check exif for hidden metadata even when sidecar is present
                from sanitizers.forensics import extract_metadata_text
                metadata_text = extract_metadata_text(image_path)
                if metadata_text:
                    ocr_text += "\n[HIDDEN METADATA]: " + " | ".join(metadata_text)
                return ocr_text.strip()
            except Exception:
                pass

        # Try to use OpenAI API OCR first if key is available. FORCE_LOCAL_EXTRACTION=1
        # disables the network path so "offline" benchmarks are genuinely offline
        # and reproducible (a prior isolation run silently called the live vision
        # API per image, making it network-bound and non-deterministic).
        _force_local = os.getenv("FORCE_LOCAL_EXTRACTION", "0").strip().lower() in ("1", "true", "yes", "on")
        api_key = None if _force_local else os.getenv("OPENAI_API_KEY")
        if api_key:
            try:
                import base64
                from openai import OpenAI
                client = OpenAI(api_key=api_key)
                
                # Check EXIF metadata
                from sanitizers.forensics import extract_metadata_text
                metadata_text = extract_metadata_text(image_path)
                
                ext = os.path.splitext(image_path)[1].lower()
                mime_type = "image/png"
                if ext in [".jpg", ".jpeg"]:
                    mime_type = "image/jpeg"
                elif ext == ".gif":
                    mime_type = "image/gif"
                elif ext == ".webp":
                    mime_type = "image/webp"

                with open(image_path, "rb") as image_file:
                    encoded_image = base64.b64encode(image_file.read()).decode("utf-8")
                
                logger.info(f"Performing OCR via OpenAI GPT-4o-mini: {image_path}")
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "text", 
                                    "text": "Extract all text or commands present in this image via OCR. Return only the exact text content found in the image. If no text is found, return nothing. Do not explain, just return the text."
                                },
                                {
                                    "type": "image_url",
                                    "image_url": {
                                        "url": f"data:{mime_type};base64,{encoded_image}"
                                    }
                                }
                            ]
                        }
                    ],
                    max_tokens=1000
                )
                text = response.choices[0].message.content.strip()
                if metadata_text:
                    text += "\n[HIDDEN METADATA]: " + " | ".join(metadata_text)
                return text.strip()
            except Exception as e:
                logger.error(f"OpenAI OCR failed: {e}. Falling back to local pytesseract.")

        try:
            img = Image.open(image_path)
            from sanitizers.forensics import extract_metadata_text
            metadata_text = extract_metadata_text(image_path)
            try:
                text = pytesseract.image_to_string(img)
            except Exception:
                text = ""
            full_context = text
            if metadata_text:
                full_context += "\n[HIDDEN METADATA]: " + " | ".join(metadata_text)
            return full_context.strip()
        except Exception as e:
            logger.error(f"VisualSanitizer.extract_text error: {e}")
            raise e

    def sanitize(self, image_path: str) -> SanitizerResult:
        if not os.path.exists(image_path):
            return SanitizerResult(is_malicious=False, reason="File not found, treating as safe/ignorable.")

        stegano_flag = False
        try:
            from config import settings as _settings
            if _settings.enable_steganalysis:
                from sanitizers.forensics import chi_square_lsb
                stego = chi_square_lsb(image_path)
                stegano_flag = bool(stego.get("suspected"))
                if stegano_flag:
                    logger.warning(f"VisualSanitizer: LSB steganography suspected ({stego.get('reason')}).")
        except Exception:
            pass

        try:
            full_context = self.extract_text(image_path)
            if not full_context.strip() and not stegano_flag:
                return SanitizerResult(is_malicious=False, reason="No text or suspicious metadata found in image.")
            # Append an indicator so the TextSanitizer's multimodal bypass
            # prevents classifier false positives when Hook 2 re-scans the
            # extracted content.  Security is NOT weakened: the multimodal
            # endpoint pre-scans the raw text (without indicators) before it
            # enters the graph, catching real injections at ingestion time.
            return self.text_sanitizer.sanitize(full_context + " [image ocr]")
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
        
    def extract_text(self, audio_path: str) -> str:
        if not os.path.exists(audio_path):
            return ""
        sidecar_path = str(audio_path) + ".txt"
        if os.path.exists(sidecar_path):
            with open(sidecar_path, "r", encoding="utf-8") as f:
                return f.read().strip()

        api_key = (None if os.getenv("FORCE_LOCAL_EXTRACTION","0").strip().lower() in ("1","true","yes","on")
                   else os.getenv("OPENAI_API_KEY"))
        if api_key:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=api_key)
                logger.info(f"Transcribing audio via OpenAI Whisper API: {audio_path}")
                with open(audio_path, "rb") as audio_file:
                    transcript_obj = client.audio.transcriptions.create(
                        model="whisper-1",
                        file=audio_file
                    )
                return transcript_obj.text.strip()
            except Exception as e:
                logger.error(f"OpenAI Whisper API transcription failed: {e}. Falling back to local Whisper.")

        import whisper
        if self.local_model is None:
            logger.info("Loading local Whisper model ('tiny') on CPU...")
            self.local_model = whisper.load_model("tiny", device="cpu")
        result = self.local_model.transcribe(audio_path)
        return result.get("text", "").strip()

    def sanitize(self, audio_path: str) -> SanitizerResult:
        if not os.path.exists(audio_path):
            return SanitizerResult(is_malicious=False, reason="Audio file not found, treating as safe/ignorable.")
        try:
            transcript = self.extract_text(audio_path)
            if not transcript.strip():
                return SanitizerResult(is_malicious=False, reason="No speech detected in audio.")
            return self.text_sanitizer.sanitize(transcript + " [audio transcript]")
        except ImportError:
            if os.getenv("STRICT_SECURITY", "0") == "1":
                return SanitizerResult(is_malicious=True, reason="STRICT_SECURITY: whisper unavailable, failing closed on audio input.")
            logger.warning("Local whisper package not available, skipping audio sanitization.")
            return SanitizerResult(is_malicious=False, reason="Whisper unavailable, skipping audio sanitization.")
        except Exception as e:
            logger.error(f"AudioSanitizer error: {e}")
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
        
    def extract_text(self, video_path: str) -> str:
        if not os.path.exists(video_path):
            return ""
        sidecar_path = str(video_path) + ".txt"
        if os.path.exists(sidecar_path):
            with open(sidecar_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        import cv2
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise RuntimeError("Failed to open video file.")
        
        frame_count = 0
        frames = []
        max_api_frames = 5
        
        # Determine total frames to spread them out evenly
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if total_frames <= 0:
            total_frames = 300
            
        interval = max(1, total_frames // max_api_frames)
        
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
            if frame_count % interval == 0:
                frames.append(frame.copy())
                if len(frames) >= max_api_frames:
                    break
            frame_count += 1
        cap.release()

        api_key = (None if os.getenv("FORCE_LOCAL_EXTRACTION","0").strip().lower() in ("1","true","yes","on")
                   else os.getenv("OPENAI_API_KEY"))
        if api_key and frames:
            try:
                import base64
                from openai import OpenAI
                client = OpenAI(api_key=api_key)
                
                content_list = [
                    {
                        "type": "text",
                        "text": "These are keyframes from a video. Extract all text, messages, or commands from these frames. Return only the combined text content found. If no text is found, return nothing. Do not explain, just return the text."
                    }
                ]
                
                for f in frames:
                    _, buffer = cv2.imencode('.jpg', f)
                    encoded_img = base64.b64encode(buffer).decode('utf-8')
                    content_list.append({
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{encoded_img}"
                        }
                    })
                
                logger.info(f"Extracting text from video keyframes via OpenAI GPT-4o-mini: {video_path}")
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {
                            "role": "user",
                            "content": content_list
                        }
                    ],
                    max_tokens=1000
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                logger.error(f"OpenAI Video OCR failed: {e}. Falling back to local pytesseract.")

        extracted_texts = []
        for f in frames:
            try:
                from PIL import Image as PILImage
                rgb_frame = cv2.cvtColor(f, cv2.COLOR_BGR2RGB)
                pil_image = PILImage.fromarray(rgb_frame)
                text = pytesseract.image_to_string(pil_image)
                if text.strip():
                    extracted_texts.append(text.strip())
            except Exception:
                pass
        return " ".join(extracted_texts).strip()

    def sanitize(self, video_path: str) -> SanitizerResult:
        if not os.path.exists(video_path):
            return SanitizerResult(is_malicious=False, reason="Video file not found, treating as safe/ignorable.")
        try:
            combined_text = self.extract_text(video_path)
            if not combined_text.strip():
                return SanitizerResult(is_malicious=False, reason="No text found in video frames.")
            return self.text_sanitizer.sanitize(combined_text + " [video frames]")
        except ImportError:
            if os.getenv("STRICT_SECURITY", "0") == "1":
                return SanitizerResult(is_malicious=True, reason="STRICT_SECURITY: OpenCV unavailable, failing closed on video input.")
            logger.warning("OpenCV not available, falling back to text passthrough.")
            return SanitizerResult(is_malicious=False, reason="OpenCV unavailable, skipping video sanitization.")
        except Exception as e:
            logger.error(f"VideoSanitizer error: {e}")
            return SanitizerResult(is_malicious=True, reason=f"Video processing failed: {e}")

class PdfSanitizer:
    """
    Document Sanitizer (Adoc) for PDF uploads.

    Mirrors the image OCR pathway: text is *extracted first*, and that
    extracted text is then pre-scanned for injection before it ever reaches
    the agent prompt — exactly like VisualSanitizer for images.

    Extraction order:
      1. Sidecar ``<path>.txt`` — parity with the other modalities so the
         dashboard preset / pre-extraction flow behaves identically.
      2. Embedded text layer via PyMuPDF — digital-born PDFs.
      3. Rendered-page OCR fallback for scanned / image-only PDFs
         (OpenAI GPT-4o-mini vision first, local pytesseract second).
      4. Structural metadata: document info, annotation text, and embedded
         JavaScript / OpenAction — classic PDF prompt-injection vectors that
         never appear in the visible text layer.
    """

    MAX_OCR_PAGES = 10  # cap rendered-page OCR to bound latency / token cost

    def __init__(self):
        self.text_sanitizer = TextSanitizer()

    def extract_text(self, pdf_path: str) -> str:
        if not os.path.exists(pdf_path):
            return ""

        # 1) Sidecar parity with image/audio/video modalities.
        sidecar_path = str(pdf_path) + ".txt"
        if os.path.exists(sidecar_path):
            with open(sidecar_path, "r", encoding="utf-8") as f:
                return f.read().strip()

        try:
            import fitz  # PyMuPDF
        except Exception as e:
            logger.error(f"PyMuPDF unavailable for PDF extraction: {e}")
            raise ImportError("PyMuPDF (pymupdf) is required for PDF extraction") from e

        try:
            doc = fitz.open(pdf_path)
        except Exception as e:
            logger.error(f"PdfSanitizer: failed to open PDF {pdf_path}: {e}")
            raise

        text_parts: list[str] = []
        metadata_parts: list[str] = []
        try:
            # 2) Embedded text layer.
            page_texts = [page.get_text("text") for page in doc]
            embedded = "\n".join(t for t in page_texts if t and t.strip()).strip()
            if embedded:
                text_parts.append(embedded)

            # 3a) Document metadata (title/author/subject/keywords).
            try:
                meta = doc.metadata or {}
                for key in ("title", "author", "subject", "keywords"):
                    val = meta.get(key)
                    if isinstance(val, str) and val.strip():
                        metadata_parts.append(f"{key}: {val.strip()}")
            except Exception:
                pass

            # 3b) Annotation text (comments / form fields hide instructions here).
            try:
                for page in doc:
                    for annot in (page.annots() or []):
                        content = (annot.info or {}).get("content")
                        if content and content.strip():
                            metadata_parts.append(f"annotation: {content.strip()}")
            except Exception:
                pass

            # 3c) Embedded JavaScript / OpenAction — a real PDF injection vector.
            try:
                for xref in range(1, doc.xref_length()):
                    try:
                        obj = doc.xref_object(xref, compressed=False)
                    except Exception:
                        continue
                    if obj and ("/JavaScript" in obj or "/JS" in obj or "/OpenAction" in obj):
                        metadata_parts.append("embedded-script: PDF declares JavaScript/OpenAction")
                        break
            except Exception:
                pass

            # 4) OCR fallback when there is little/no extractable text layer
            #    (scanned documents, image-only PDFs).
            if len(embedded) < 20:
                ocr_text = self._ocr_rendered_pages(doc)
                if ocr_text.strip():
                    text_parts.append(ocr_text.strip())
        finally:
            doc.close()

        full = "\n".join(p for p in text_parts if p.strip()).strip()
        if metadata_parts:
            full += "\n[HIDDEN METADATA]: " + " | ".join(metadata_parts)
        return full.strip()

    def _ocr_rendered_pages(self, doc) -> str:
        """Render up to MAX_OCR_PAGES pages to PNG and OCR them."""
        page_count = min(len(doc), self.MAX_OCR_PAGES)
        images = []
        for i in range(page_count):
            try:
                pix = doc[i].get_pixmap(dpi=150)
                images.append(pix.tobytes("png"))
            except Exception:
                continue

        api_key = (None if os.getenv("FORCE_LOCAL_EXTRACTION","0").strip().lower() in ("1","true","yes","on")
                   else os.getenv("OPENAI_API_KEY"))
        if api_key and images:
            try:
                import base64
                from openai import OpenAI
                client = OpenAI(api_key=api_key)
                content_list = [{
                    "type": "text",
                    "text": "These are rendered pages from a PDF document. Extract all text, messages, or commands present. Return only the exact text content found. If no text is found, return nothing. Do not explain, just return the text."
                }]
                for img_bytes in images:
                    enc = base64.b64encode(img_bytes).decode("utf-8")
                    content_list.append({
                        "type": "image_url",
                        "image_url": {"url": f"data:image/png;base64,{enc}"}
                    })
                logger.info("PdfSanitizer: OCR rendered pages via OpenAI GPT-4o-mini")
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": content_list}],
                    max_tokens=1500
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                logger.error(f"OpenAI PDF OCR failed: {e}. Falling back to local pytesseract.")

        from io import BytesIO
        texts = []
        for img_bytes in images:
            try:
                text = pytesseract.image_to_string(Image.open(BytesIO(img_bytes)))
                if text.strip():
                    texts.append(text.strip())
            except Exception:
                pass
        return "\n".join(texts).strip()

    def sanitize(self, pdf_path: str) -> SanitizerResult:
        if not os.path.exists(pdf_path):
            return SanitizerResult(is_malicious=False, reason="PDF not found, treating as safe/ignorable.")
        try:
            text = self.extract_text(pdf_path)
            if not text.strip():
                return SanitizerResult(is_malicious=False, reason="No text or metadata found in PDF.")
            # Append a modality indicator so Hook 2's re-scan uses the multimodal
            # bypass (the raw text was already pre-scanned at ingestion, identical
            # to the image/audio/video pathway).
            return self.text_sanitizer.sanitize(text + " [pdf document]")
        except ImportError:
            if os.getenv("STRICT_SECURITY", "0") == "1":
                return SanitizerResult(is_malicious=True, reason="STRICT_SECURITY: PyMuPDF unavailable, failing closed on PDF input.")
            logger.warning("PyMuPDF unavailable, skipping PDF sanitization.")
            return SanitizerResult(is_malicious=False, reason="PyMuPDF unavailable, skipping PDF sanitization.")
        except Exception as e:
            logger.error(f"PdfSanitizer error: {e}")
            return SanitizerResult(is_malicious=True, reason=f"PDF processing failed: {e}")


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
