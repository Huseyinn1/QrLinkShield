import requests
from typing import Dict, Any
import json
from urllib.parse import urlparse



def check_abuseipdb(url: str) -> Dict[str, Any]:
    """
    AbuseIPDB API ile IP kontrolü
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Domain'i IP'ye çevir
        ip = requests.get(f"https://dns.google/resolve?name={domain}").json()["Answer"][0]["data"]
        
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json',
        }
        
        response = requests.get(
            f'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params={'ipAddress': ip}
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "abuse_score": data["data"]["abuseConfidenceScore"],
                "total_reports": data["data"]["totalReports"],
                "last_reported": data["data"]["lastReportedAt"],
                "is_whitelisted": data["data"]["isWhitelisted"]
            }
        return {"error": f"API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """
    Google Safe Browsing API kontrolü
    """
    try:
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {
                "clientId": "qrlinkshield",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(
            f"{api_url}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "is_safe": len(data) == 0,
                "threats": data.get("matches", [])
            }
        return {"error": f"API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_phishtank(url: str) -> Dict[str, Any]:
    """
    PhishTank API kontrolü
    """
    try:
        # URL'yi hash'le
        import hashlib
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        response = requests.get(
            f"https://checkurl.phishtank.com/checkurl/",
            params={"url": url}
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "is_phishing": data.get("in_database", False),
                "verified": data.get("verified", False),
                "verified_at": data.get("verified_at")
            }
        return {"error": f"API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_urlscan(url: str) -> Dict[str, Any]:
    """
    URLScan.io API kontrolü
    """
    try:
        headers = {
            'API-Key': URLSCAN_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Önce arama yap
        search_response = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{urlparse(url).netloc}",
            headers=headers
        )
        
        if search_response.status_code == 200:
            search_data = search_response.json()
            results = search_data.get("results", [])
            
            if results:
                # En son sonucu al
                latest_result = results[0]
                return {
                    "has_results": True,
                    "last_scan": latest_result.get("task", {}).get("time"),
                    "verdicts": latest_result.get("verdicts", {}),
                    "stats": latest_result.get("stats", {})
                }
            
        return {"has_results": False}
    except Exception as e:
        return {"error": str(e)} 