import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

print("Python version:", sys.version)

try:
    import PIL
    print("PIL version:", PIL.__version__)
except ImportError as e:
    print("PIL failed to import:", e)

try:
    import cv2
    print("OpenCV (cv2) version:", cv2.__version__)
except ImportError as e:
    print("cv2 failed to import:", e)

try:
    import pytesseract
    print("pytesseract version:", pytesseract.__version__)
    try:
        tess_ver = pytesseract.get_tesseract_version()
        print("Tesseract system version:", tess_ver)
    except Exception as e:
        print("Tesseract binary check failed:", e)
except ImportError as e:
    print("pytesseract failed to import:", e)

try:
    import whisper
    print("Whisper version: imported successfully")
except ImportError as e:
    print("whisper failed to import:", e)
