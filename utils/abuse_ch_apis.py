import requests
import hashlib
import json
from typing import Dict, Any
from datetime import datetime

def check_urlhaus(url: str) -> Dict[str, Any]:
    """
    Abuse.ch URLhaus API ile URL kontrolü yapar
    """
    try:
        # URL'yi hash'le
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        # API endpoint
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        
        # API isteği için veri hazırlama
        data = {
            "url": url
        }
        
        # API isteği gönderme
        response = requests.post(api_url, data=data)
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get("query_status") == "ok":
                if result.get("blacklists", {}).get("urlhaus"):
                    return {
                        "is_malicious": True,
                        "threat_type": result.get("threat", "unknown"),
                        "tags": result.get("tags", []),
                        "description": f"URLhaus: {result.get('threat', 'Bilinmeyen')} tehdidi tespit edildi"
                    }
        
        return {
            "is_malicious": False,
            "description": "URLhaus: Temiz"
        }
        
    except Exception as e:
        return {
            "is_malicious": False,
            "description": f"URLhaus API hatası: {str(e)}"
        }

def check_threatfox(url: str) -> Dict[str, Any]:
    """
    Abuse.ch ThreatFox API ile URL kontrolü yapar
    """
    try:
        # API endpoint
        api_url = "https://threatfox-api.abuse.ch/api/v1/"
        
        # API isteği için veri hazırlama
        data = {
            "query": "search_ioc",
            "search_term": url
        }
        
        # API isteği gönderme
        response = requests.post(api_url, json=data)
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get("query_status") == "ok":
                iocs = result.get("data", [])
                if iocs:
                    return {
                        "is_malicious": True,
                        "threat_type": iocs[0].get("threat_type", "unknown"),
                        "malware_type": iocs[0].get("malware_type", "unknown"),
                        "description": f"ThreatFox: {iocs[0].get('threat_type', 'Bilinmeyen')} tehdidi tespit edildi"
                    }
        
        return {
            "is_malicious": False,
            "description": "ThreatFox: Temiz"
        }
        
    except Exception as e:
        return {
            "is_malicious": False,
            "description": f"ThreatFox API hatası: {str(e)}"
        } 