import os
import sys

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_generate_presets():
    presets = [
        "benign_image",
        "ocr_injection",
        "exif_injection",
        "benign_audio",
        "audio_injection",
        "benign_video",
        "video_injection"
    ]
    for preset in presets:
        response = client.post(f"/api/generate-preset?preset_type={preset}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert os.path.exists(data["file_path"])
        assert os.path.exists(data["file_path"] + ".txt")

def test_run_image_benign():
    preset_resp = client.post("/api/generate-preset?preset_type=benign_image")
    assert preset_resp.status_code == 200
    preset_data = preset_resp.json()
    
    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "image",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "sidecar_text": preset_data["sidecar_text"],
            "session_id": "test_session_img_benign"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["security_blocked"] is False

def test_run_image_ocr_injection():
    preset_resp = client.post("/api/generate-preset?preset_type=ocr_injection")
    assert preset_resp.status_code == 200
    preset_data = preset_resp.json()
    
    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "image",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "sidecar_text": preset_data["sidecar_text"],
            "session_id": "test_session_img_ocr_inject"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["security_blocked"] is True or data["trust_score"] < 0.6

def test_run_image_exif_injection():
    preset_resp = client.post("/api/generate-preset?preset_type=exif_injection")
    assert preset_resp.status_code == 200
    preset_data = preset_resp.json()
    
    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "image",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "sidecar_text": preset_data["sidecar_text"],
            "session_id": "test_session_img_exif_inject"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    # EXIF metadata sanitization is handled by visual sanitizer
    assert data["security_blocked"] is True or data["trust_score"] < 0.6

def test_run_audio_benign():
    preset_resp = client.post("/api/generate-preset?preset_type=benign_audio")
    assert preset_resp.status_code == 200
    preset_data = preset_resp.json()
    
    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "audio",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "sidecar_text": preset_data["sidecar_text"],
            "session_id": "test_session_audio_benign"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["security_blocked"] is False

def test_run_audio_injection():
    preset_resp = client.post("/api/generate-preset?preset_type=audio_injection")
    assert preset_resp.status_code == 200
    preset_data = preset_resp.json()
    
    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "audio",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "sidecar_text": preset_data["sidecar_text"],
            "session_id": "test_session_audio_inject"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["security_blocked"] is True or data["trust_score"] < 0.6

def test_run_video_benign():
    preset_resp = client.post("/api/generate-preset?preset_type=benign_video")
    assert preset_resp.status_code == 200
    preset_data = preset_resp.json()
    
    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "video",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "sidecar_text": preset_data["sidecar_text"],
            "session_id": "test_session_video_benign"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["security_blocked"] is False

def test_run_video_injection():
    preset_resp = client.post("/api/generate-preset?preset_type=video_injection")
    assert preset_resp.status_code == 200
    preset_data = preset_resp.json()

    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "video",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "sidecar_text": preset_data["sidecar_text"],
            "session_id": "test_session_video_inject"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["security_blocked"] is True or data["trust_score"] < 0.6


# ── PDF modality ─────────────────────────────────────────────────────
# PDF presets generate a REAL PDF with an embedded text layer (no sidecar
# .txt), so these exercise genuine PyMuPDF extraction, not a mock file.

def test_generate_pdf_presets():
    for preset in ("benign_pdf", "pdf_injection"):
        response = client.post(f"/api/generate-preset?preset_type={preset}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["file_path"].endswith(".pdf")
        assert os.path.exists(data["file_path"])
        # PDF presets rely on the real text layer, not a sidecar .txt.
        assert not os.path.exists(data["file_path"] + ".txt")


def test_extract_pdf_text():
    preset_data = client.post("/api/generate-preset?preset_type=benign_pdf").json()
    response = client.post(
        "/api/extract-text",
        data={"modality": "pdf", "file_path": preset_data["file_path"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "Tokyo" in data["text"]


def test_run_pdf_benign():
    preset_data = client.post("/api/generate-preset?preset_type=benign_pdf").json()
    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "pdf",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "session_id": "test_session_pdf_benign",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["security_blocked"] is False


def test_run_pdf_injection():
    preset_data = client.post("/api/generate-preset?preset_type=pdf_injection").json()
    response = client.post(
        "/run-travel-multimodal",
        data={
            "modality": "pdf",
            "user_input": preset_data["prompt"],
            "file_path": preset_data["file_path"],
            "session_id": "test_session_pdf_inject",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    # Injection text embedded in the PDF must degrade trust or be blocked.
    assert data["security_blocked"] is True or data["trust_score"] < 0.6
