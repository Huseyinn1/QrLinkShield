import ssl
import socket
import whois
import requests
from urllib.parse import urlparse
from typing import Dict, Any
import re
import dns.resolver

def check_ssl(url: str) -> Dict[str, Any]:
    """
    SSL sertifika kontrolü
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                return {
                    "is_valid": True,
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "expires": cert['notAfter']
                }
    except Exception as e:
        return {
            "is_valid": False,
            "error": str(e)
        }

def check_whois(url: str) -> Dict[str, Any]:
    """
    WHOIS bilgileri kontrolü
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        w = whois.whois(domain)
        
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
    except Exception as e:
        return {
            "error": str(e)
        }

def check_phishing(url: str) -> Dict[str, Any]:
    """
    Phishing kontrolü
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Yaygın phishing domainlerini kontrol et
        suspicious_keywords = ['login', 'signin', 'account', 'secure', 'bank', 'paypal']
        domain_parts = domain.split('.')
        
        # Domain içinde şüpheli kelimeler var mı?
        has_suspicious_keywords = any(keyword in domain.lower() for keyword in suspicious_keywords)
        
        # Subdomain sayısı kontrolü (çok fazla subdomain şüpheli olabilir)
        subdomain_count = len(domain_parts) - 2  # -2 for TLD and domain
        
        return {
            "has_suspicious_keywords": has_suspicious_keywords,
            "subdomain_count": subdomain_count,
            "risk_level": "high" if has_suspicious_keywords or subdomain_count > 3 else "low"
        }
    except Exception as e:
        return {
            "error": str(e)
        }

def check_ip(url: str) -> Dict[str, Any]:
    """
    IP adresi kontrolü
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # DNS kayıtlarını kontrol et
        a_records = dns.resolver.resolve(domain, 'A')
        ip_addresses = [str(record) for record in a_records]
        
        # IP adreslerinin güvenlik durumunu kontrol et
        ip_checks = []
        for ip in ip_addresses:
            # IP'nin private range'de olup olmadığını kontrol et
            is_private = any([
                ip.startswith('10.'),
                ip.startswith('172.16.'),
                ip.startswith('192.168.')
            ])
            
            ip_checks.append({
                "ip": ip,
                "is_private": is_private
            })
        
        return {
            "ip_addresses": ip_checks
        }
    except Exception as e:
        return {
            "error": str(e)
        } 