from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from utils.qr_utils import extract_qr_link
import os
import requests
import base64
from urllib.parse import urlparse

app = FastAPI()

# .env yerine doğrudan burada tanımlıyoruz
VT_API_KEY = "a7a3b876563f84d2a52a7c75e76da9430a2f20bfc1b22c37e3148f9d1753c710"
ALLOWED_DOMAINS = ["guvenli-site.com", "example.com"]

@app.post("/scan-qr")
async def scan_qr(file: UploadFile = File(...)):
    if file.content_type not in ["image/png", "image/jpeg", "image/jpg"]:
        raise HTTPException(status_code=400, detail="Sadece PNG veya JPG dosyası kabul edilir.")

    image_bytes = await file.read()
    qr_url = extract_qr_link(image_bytes)

    if not qr_url:
        raise HTTPException(status_code=400, detail="QR kod çözülemedi.")

    # Domain güvenliyse VT kontrolünü atla
    domain_result = check_domain(qr_url)
    if domain_result == "passed":
        return JSONResponse(content={
            "decoded_url": qr_url,
            "domain_check": "passed",
            "security_status": "trusted (vt skipped)"
        })

    result = {
        "decoded_url": qr_url,
        "domain_check": "failed",
        "security_status": check_virustotal(qr_url)
    }

    return JSONResponse(content=result)

def check_domain(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc
    return "passed" if netloc in ALLOWED_DOMAINS else "failed"

def check_virustotal(url: str) -> str:
    if not VT_API_KEY:
        return "not_configured"

    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    response = requests.get(vt_url, headers=headers)
    if response.status_code != 200:
        return f"error (status_code: {response.status_code})"

    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    if stats.get("malicious", 0) > 0:
        return "malicious"
    elif stats.get("suspicious", 0) > 0:
        return "suspicious"
    else:
        return "clean"
