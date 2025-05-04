import requests
import socket
from typing import Dict, Any
from datetime import datetime

def check_spamhaus(url: str) -> Dict[str, Any]:
    """
    Spamhaus API ile domain ve IP kontrolü yapar
    """
    try:
        # URL'den domain veya IP çıkar
        domain = url.split("//")[-1].split("/")[0]
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = domain

        # Spamhaus SBL, XBL, PBL ve DBL listelerini kontrol et
        lists = {
            "SBL": f"zen.spamhaus.org",
            "XBL": f"zen.spamhaus.org",
            "PBL": f"zen.spamhaus.org",
            "DBL": f"dbl.spamhaus.org"
        }
        
        findings = []
        for list_name, dns in lists.items():
            try:
                socket.gethostbyname(f"{ip}.{dns}")
                findings.append(list_name)
            except:
                continue

        if findings:
            return {
                "is_malicious": True,
                "blacklists": findings,
                "description": f"Spamhaus: {', '.join(findings)} listelerinde bulundu"
            }
        
        return {
            "is_malicious": False,
            "blacklists": [],
            "description": "Spamhaus: Temiz"
        }
        
    except Exception as e:
        return {
            "is_malicious": False,
            "description": f"Spamhaus kontrol hatası: {str(e)}"
        }

def check_cisco_talos(url: str) -> Dict[str, Any]:
    """
    Cisco Talos API ile domain ve IP kontrolü yapar
    """
    try:
        # URL'den domain veya IP çıkar
        domain = url.split("//")[-1].split("/")[0]
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = domain

        # Talos API endpoint
        api_url = f"https://talosintelligence.com/sb_api/query_lookup"
        
        # API isteği için veri hazırlama
        params = {
            "query": f"/api/v2/details/ip/{ip}",
            "query_type": "ip"
        }
        
        # API isteği gönderme
        response = requests.get(api_url, params=params)
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get("status") == "success":
                data = result.get("data", {})
                return {
                    "is_malicious": data.get("reputation", 0) < 0,
                    "reputation_score": data.get("reputation", 0),
                    "category": data.get("category", "unknown"),
                    "description": f"Cisco Talos: Reputation skoru {data.get('reputation', 0)}"
                }
        
        return {
            "is_malicious": False,
            "reputation_score": 0,
            "description": "Cisco Talos: Temiz"
        }
        
    except Exception as e:
        return {
            "is_malicious": False,
            "description": f"Cisco Talos API hatası: {str(e)}"
        } 