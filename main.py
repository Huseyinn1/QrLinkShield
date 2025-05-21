from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import JSONResponse
from utils.qr_utils import extract_qr_link
from utils.security_checks import check_ssl, check_whois, check_phishing, check_ip
from utils.security_apis import check_abuseipdb, check_google_safe_browsing, check_phishtank, check_urlscan
from utils.abuse_ch_apis import check_urlhaus, check_threatfox
from utils.network_security_apis import check_spamhaus, check_cisco_talos
import os
import requests
import base64
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Body
from pydantic import BaseModel
from typing import Dict, List, Any
from sqlalchemy.orm import Session
from datetime import datetime
from models import MaliciousURL
from database import get_db, engine
from models import Base

class URLRequest(BaseModel):
    url: str

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Güvenlik açısından sadece frontend domainini yazman daha iyidir
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# .env yerine doğrudan burada tanımlıyoruz
VT_API_KEY = "a7a3b876563f84d2a52a7c75e76da9430a2f20bfc1b22c37e3148f9d1753c710"
ALLOWED_DOMAINS = ["guvenli-site.com", "example.com"]

def get_risk_level(abuse_score: int) -> str:
    if abuse_score >= 75:
        return "yüksek"
    elif abuse_score >= 50:
        return "orta"
    elif abuse_score >= 25:
        return "düşük"
    return "çok düşük"

def get_virustotal_details(status: str) -> Dict[str, Any]:
    """VirusTotal detaylarını döndür"""
    return {
        "status": status,
        "description": "Zararlı yazılım veya şüpheli aktivite tespit edildi" if status in ["malicious", "suspicious"] else "Temiz"
    }

def get_google_safe_browsing_details(result: Dict[str, Any]) -> Dict[str, Any]:
    """Google Safe Browsing detaylarını döndür"""
    return {
        "status": "zararlı" if not result.get("is_safe", True) else "güvenli",
        "threats": result.get("threats", []),
        "description": "Google tarafından zararlı site olarak işaretlendi" if not result.get("is_safe", True) else "Google tarafından güvenli olarak işaretlendi"
    }

def get_phishtank_details(result: Dict[str, Any]) -> Dict[str, Any]:
    """PhishTank detaylarını döndür"""
    return {
        "status": "phishing" if result.get("is_phishing", False) else "güvenli",
        "verification_time": result.get("verification_time"),
        "description": "Phishing sitesi olarak tespit edildi" if result.get("is_phishing", False) else "Phishing sitesi olarak tespit edilmedi"
    }

def get_abuseipdb_details(result: Dict[str, Any]) -> Dict[str, Any]:
    """AbuseIPDB detaylarını döndür"""
    return {
        "abuse_score": result.get("abuse_score", 0),
        "risk_level": get_risk_level(result.get("abuse_score", 0)),
        "total_reports": result.get("total_reports", 0),
        "description": f"IP adresi {result.get('abuse_score', 0)}% kötüye kullanım skoruna sahip"
    }

def get_urlscan_details(result: Dict[str, Any]) -> Dict[str, Any]:
    """URLScan detaylarını döndür"""
    verdicts = result.get("verdicts", {})
    overall = verdicts.get("overall", {})
    return {
        "score": overall.get("score", 0),
        "categories": overall.get("categories", []),
        "description": "Şüpheli aktivite tespit edildi" if overall.get("score", 0) > 0 else "Şüpheli aktivite tespit edilmedi"
    }

def check_all_security_services(url: str) -> Dict[str, Any]:
    """
    Tüm güvenlik servislerini kontrol et ve sonuçları birleştir
    """
    results = {
        "virustotal": check_virustotal(url),
        "google_safe_browsing": check_google_safe_browsing(url),
        "phishtank": check_phishtank(url),
        "abuseipdb": check_abuseipdb(url),
        "urlscan": check_urlscan(url),
        "urlhaus": check_urlhaus(url),
        "threatfox": check_threatfox(url),
        "spamhaus": check_spamhaus(url),
        "cisco_talos": check_cisco_talos(url)
    }
    
    malicious_services = []
    risk_factors = []
    service_findings = {}
    important_details = {}
    
    # VirusTotal kontrolü
    is_vt_malicious = results["virustotal"] in ["malicious", "suspicious"]
    service_findings["virustotal"] = is_vt_malicious
    if is_vt_malicious:
        malicious_services.append("VirusTotal")
        risk_factors.append("Zararlı yazılım tespit edildi")
        important_details["virustotal"] = get_virustotal_details(results["virustotal"])
    
    # Google Safe Browsing kontrolü
    is_gsb_safe = results["google_safe_browsing"].get("is_safe", True)
    service_findings["google_safe_browsing"] = not is_gsb_safe
    if not is_gsb_safe:
        malicious_services.append("Google Safe Browsing")
        risk_factors.append("Google tarafından zararlı site olarak işaretlendi")
        important_details["google_safe_browsing"] = get_google_safe_browsing_details(results["google_safe_browsing"])
    
    # PhishTank kontrolü
    is_phishing = results["phishtank"].get("is_phishing", False)
    service_findings["phishtank"] = is_phishing
    if is_phishing:
        malicious_services.append("PhishTank")
        risk_factors.append("Phishing sitesi olarak tespit edildi")
        important_details["phishtank"] = get_phishtank_details(results["phishtank"])
    
    # AbuseIPDB kontrolü
    abuse_score = results["abuseipdb"].get("abuse_score", 0)
    is_abuse_safe = abuse_score <= 25
    service_findings["abuseipdb"] = not is_abuse_safe
    if not is_abuse_safe:
        malicious_services.append("AbuseIPDB")
        risk_factors.append(f"IP adresi kötüye kullanım skoru: {get_risk_level(abuse_score)}")
        important_details["abuseipdb"] = get_abuseipdb_details(results["abuseipdb"])
    
    # URLScan kontrolü
    urlscan_score = results["urlscan"].get("verdicts", {}).get("overall", {}).get("score", 0)
    is_urlscan_safe = urlscan_score == 0
    service_findings["urlscan"] = not is_urlscan_safe
    if not is_urlscan_safe:
        malicious_services.append("URLScan")
        risk_factors.append("Şüpheli aktivite tespit edildi")
        important_details["urlscan"] = get_urlscan_details(results["urlscan"])
    
    # URLhaus kontrolü
    is_urlhaus_malicious = results["urlhaus"].get("is_malicious", False)
    service_findings["urlhaus"] = is_urlhaus_malicious
    if is_urlhaus_malicious:
        malicious_services.append("URLhaus")
        risk_factors.append(f"URLhaus: {results['urlhaus'].get('threat_type', 'Bilinmeyen')} tehdidi")
        important_details["urlhaus"] = results["urlhaus"]
    
    # ThreatFox kontrolü
    is_threatfox_malicious = results["threatfox"].get("is_malicious", False)
    service_findings["threatfox"] = is_threatfox_malicious
    if is_threatfox_malicious:
        malicious_services.append("ThreatFox")
        risk_factors.append(f"ThreatFox: {results['threatfox'].get('threat_type', 'Bilinmeyen')} tehdidi")
        important_details["threatfox"] = results["threatfox"]
    
    # Spamhaus kontrolü
    is_spamhaus_malicious = results["spamhaus"].get("is_malicious", False)
    service_findings["spamhaus"] = is_spamhaus_malicious
    if is_spamhaus_malicious:
        malicious_services.append("Spamhaus")
        risk_factors.append(f"Spamhaus: {', '.join(results['spamhaus'].get('blacklists', []))} listelerinde")
        important_details["spamhaus"] = results["spamhaus"]
    
    # Cisco Talos kontrolü
    is_talos_malicious = results["cisco_talos"].get("is_malicious", False)
    service_findings["cisco_talos"] = is_talos_malicious
    if is_talos_malicious:
        malicious_services.append("Cisco Talos")
        risk_factors.append(f"Cisco Talos: Düşük reputation skoru ({results['cisco_talos'].get('reputation_score', 0)})")
        important_details["cisco_talos"] = results["cisco_talos"]
    
    # Güvenlik durumunu belirle
    security_status = "zararlı" if malicious_services else "şüpheli" if any("düşük" in factor for factor in risk_factors) else "güvenli"
    
    response = {
        "url": url,
        "security_status": security_status,
        "risk_factors": risk_factors,
        "malicious_services": malicious_services,
        "bulgu_durumlari": service_findings,
        "servis_detaylari": important_details
    }
    
    return response

# Veritabanı tablolarını oluştur
Base.metadata.create_all(bind=engine)

def save_malicious_url(db: Session, security_result: dict):
    """Zararlı URL'yi veritabanına kaydet"""
    if any(security_result["bulgu_durumlari"].values()):
        db_url = MaliciousURL(
            url=security_result["url"],
            malicious_services=security_result["malicious_services"],
            risk_factors=security_result["risk_factors"],
            security_status=security_result["security_status"],
            service_details=security_result["servis_detaylari"]
        )
        db.add(db_url)
        db.commit()
        db.refresh(db_url)
        return db_url
    return None

@app.post("/scan-qr")
async def scan_qr(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if file.content_type not in ["image/png", "image/jpeg", "image/jpg"]:
        raise HTTPException(status_code=400, detail="Sadece PNG veya JPG dosyası kabul edilir.")

    image_bytes = await file.read()
    qr_url = extract_qr_link(image_bytes)

    if not qr_url:
        raise HTTPException(status_code=400, detail="QR kod çözülemedi.")

    # Domain güvenliyse kontrolleri atla
    domain_result = check_domain(qr_url)
    if domain_result == "passed":
        return JSONResponse(content={
            "url": qr_url,
            "security_status": "güvenli",
            "risk_factors": [],
            "malicious_services": [],
            "bulgu_durumlari": {},
            "servis_detaylari": {}
        })

    # Tüm güvenlik servislerini kontrol et
    security_result = check_all_security_services(qr_url)
    
    # Eğer zararlı bulgu varsa kaydet
    save_malicious_url(db, security_result)
    
    return JSONResponse(content=security_result)

@app.post("/scan-url")
async def scan_url(request: URLRequest, db: Session = Depends(get_db)):
    url = request.url

    # Domain güvenliyse kontrolleri atla
    domain_result = check_domain(url)
    if domain_result == "passed":
        return {
            "url": url,
            "security_status": "güvenli",
            "risk_factors": [],
            "malicious_services": [],
            "bulgu_durumlari": {},
            "servis_detaylari": {}
        }

    # Tüm güvenlik servislerini kontrol et
    security_result = check_all_security_services(url)
    
    # Eğer zararlı bulgu varsa kaydet
    save_malicious_url(db, security_result)
    
    return security_result

@app.post("/security-check")
async def security_check(request: URLRequest):
    """
    Detaylı güvenlik kontrolü endpoint'i
    """
    url = request.url
    
    return {
        "url": url,
        "security_checks": {
            "ssl": check_ssl(url),
            "whois": check_whois(url),
            "phishing": check_phishing(url),
            "ip": check_ip(url)
        },
        "security_apis": {
            "abuseipdb": check_abuseipdb(url),
            "google_safe_browsing": check_google_safe_browsing(url),
            "phishtank": check_phishtank(url),
            "urlscan": check_urlscan(url)
        }
    }

@app.post("/fast-check")
async def fast_check(request: URLRequest):
    """
    Hızlı güvenlik kontrolü endpoint'i - Sadece kritik ve hızlı servisleri kontrol eder
    """
    url = request.url
    
    # Domain güvenliyse kontrolleri atla
    domain_result = check_domain(url)
    if domain_result == "passed":
        return {
            "url": url,
            "security_status": "güvenli",
            "risk_factors": [],
            "malicious_services": [],
            "bulgu_durumlari": {},
            "servis_detaylari": {}
        }

    # Sadece hızlı servisleri kontrol et
    results = {
        "virustotal": check_virustotal(url),
        "google_safe_browsing": check_google_safe_browsing(url),
        "phishtank": check_phishtank(url),
        "urlhaus": check_urlhaus(url)
    }
    
    malicious_services = []
    risk_factors = []
    service_findings = {}
    important_details = {}
    
    # VirusTotal kontrolü
    is_vt_malicious = results["virustotal"] in ["malicious", "suspicious"]
    service_findings["virustotal"] = is_vt_malicious
    if is_vt_malicious:
        malicious_services.append("VirusTotal")
        risk_factors.append("Zararlı yazılım tespit edildi")
        important_details["virustotal"] = get_virustotal_details(results["virustotal"])
    
    # Google Safe Browsing kontrolü
    is_gsb_safe = results["google_safe_browsing"].get("is_safe", True)
    service_findings["google_safe_browsing"] = not is_gsb_safe
    if not is_gsb_safe:
        malicious_services.append("Google Safe Browsing")
        risk_factors.append("Google tarafından zararlı site olarak işaretlendi")
        important_details["google_safe_browsing"] = get_google_safe_browsing_details(results["google_safe_browsing"])
    
    # PhishTank kontrolü
    is_phishing = results["phishtank"].get("is_phishing", False)
    service_findings["phishtank"] = is_phishing
    if is_phishing:
        malicious_services.append("PhishTank")
        risk_factors.append("Phishing sitesi olarak tespit edildi")
        important_details["phishtank"] = get_phishtank_details(results["phishtank"])
    
    # URLhaus kontrolü
    is_urlhaus_malicious = results["urlhaus"].get("is_malicious", False)
    service_findings["urlhaus"] = is_urlhaus_malicious
    if is_urlhaus_malicious:
        malicious_services.append("URLhaus")
        risk_factors.append(f"URLhaus: {results['urlhaus'].get('threat_type', 'Bilinmeyen')} tehdidi")
        important_details["urlhaus"] = results["urlhaus"]
    
    # Güvenlik durumunu belirle
    security_status = "zararlı" if malicious_services else "güvenli"
    
    response = {
        "url": url,
        "security_status": security_status,
        "risk_factors": risk_factors,
        "malicious_services": malicious_services,
        "bulgu_durumlari": service_findings,
        "servis_detaylari": important_details
    }
    
    return response

@app.get("/malicious-urls", response_model=List[dict])
async def get_malicious_urls(db: Session = Depends(get_db)):
    """Tüm zararlı URL'leri getir"""
    urls = db.query(MaliciousURL).all()
    return [
        {
            "id": url.id,
            "url": url.url,
            "detection_time": url.detection_time,
            "malicious_services": url.malicious_services,
            "risk_factors": url.risk_factors,
            "security_status": url.security_status,
            "service_details": url.service_details
        }
        for url in urls
    ]

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