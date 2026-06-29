"""
Travel Agent Tools.

Each tool uses the full extraction pipeline from sanitizers/multimodal.py
(OpenAI API first, local fallback second) so they work on arbitrary
real-world files — not just dashboard presets with sidecar .txt files.
"""

from langchain_core.tools import tool
import os
from sanitizers.hooks import secure_tool_wrapper
from agents.tool_impls import (
    _simulate_tool_poisoning,
    _impl_search_flights,
    _impl_reserve_hotel,
    TOOL_REGISTRY,
)


@tool
@secure_tool_wrapper
def search_flights(destination: str, origin: str = "JFK", date: str = "2024-12-01") -> str:
    """Search for flights to a destination."""
    return _impl_search_flights(destination, origin, date)

@tool
@secure_tool_wrapper
def reserve_hotel(location: str, checkin: str = "2024-12-01", checkout: str = "2024-12-05") -> str:
    """Reserve a hotel room at a specific location."""
    return _impl_reserve_hotel(location, checkin, checkout)

@tool
@secure_tool_wrapper
def read_image_ocr(image_path: str) -> str:
    """Read text from an image file using OCR.

    Uses the full VisualSanitizer extraction chain: OpenAI GPT-4o-mini
    vision API first, local pytesseract fallback, plus EXIF metadata
    extraction.
    """
    if not os.path.exists(image_path):
        return f"Error: Image {image_path} not found."
    try:
        from sanitizers.multimodal import VisualSanitizer
        _vs = VisualSanitizer()
        text = _vs.extract_text(image_path)
        if not text.strip():
            return "No text content found in the image."
        return f"Image contents: {text}"
    except Exception as e:
        return f"Error reading image: {e}"

@tool
@secure_tool_wrapper
def read_pdf_document(pdf_path: str) -> str:
    """Read text from a PDF document.

    Uses the full PdfSanitizer extraction chain: embedded PDF text layer
    first, rendered-page OCR (OpenAI GPT-4o-mini vision, local pytesseract
    fallback) for scanned PDFs, plus document metadata, annotation text, and
    embedded JavaScript/OpenAction detection.
    """
    if not os.path.exists(pdf_path):
        return f"Error: PDF {pdf_path} not found."
    try:
        from sanitizers.multimodal import PdfSanitizer
        _pdf = PdfSanitizer()
        text = _pdf.extract_text(pdf_path)
        if not text.strip():
            return "No text content found in the PDF document."
        return f"PDF contents: {text}"
    except Exception as e:
        return f"Error reading PDF: {e}"

@tool
@secure_tool_wrapper
def process_audio_memo(audio_path: str) -> str:
    """Transcribe and process an audio memo file.

    Uses the full AudioSanitizer extraction chain: OpenAI Whisper API
    first, local whisper model fallback.
    """
    if not os.path.exists(audio_path):
        return f"Error: Audio file {audio_path} not found."
    try:
        from sanitizers.multimodal import AudioSanitizer
        _asr = AudioSanitizer()
        text = _asr.extract_text(audio_path)
        if not text.strip():
            return "No speech detected in the audio memo."
        return f"Audio transcription: {text}"
    except Exception as e:
        return f"Error processing audio: {e}"

@tool
@secure_tool_wrapper
def analyze_video_feed(video_path: str) -> str:
    """Analyze keyframes from a video feed and extract text content.

    Uses the full VideoSanitizer extraction chain: OpenAI GPT-4o-mini
    multi-frame analysis first, local pytesseract fallback on extracted
    keyframes.
    """
    if not os.path.exists(video_path):
        return f"Error: Video file {video_path} not found."
    try:
        from sanitizers.multimodal import VideoSanitizer
        _vid = VideoSanitizer()
        text = _vid.extract_text(video_path)
        if not text.strip():
            return "No text content found in video frames. No security anomalies detected."
        return f"Video frame analysis: {text}"
    except Exception as e:
        return f"Error analyzing video: {e}"
