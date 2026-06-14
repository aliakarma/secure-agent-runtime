import os
import pytesseract

paths = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
]

found = False
for p in paths:
    if os.path.exists(p):
        print("Found Tesseract at:", p)
        pytesseract.pytesseract.tesseract_cmd = p
        try:
            ver = pytesseract.get_tesseract_version()
            print("Successfully checked version:", ver)
            found = True
            break
        except Exception as e:
            print("Failed version check for", p, ":", e)

if not found:
    print("Tesseract was not found in common Windows paths.")
