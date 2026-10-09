"""
IOC Defanging and Refanging utility.
Prevents accidental clicks or execution of malicious indicators in UI/logs.
"""
import re

def defang_url(url: str) -> str:
    """Replace http/https with hxxp/hxxps and brackets around dots."""
    if not url:
        return ""
    val = re.sub(r'^http://', 'hxxp://', url, flags=re.IGNORECASE)
    val = re.sub(r'^https://', 'hxxps://', val, flags=re.IGNORECASE)
    return val.replace('.', '[.]')

def defang_ip(ip: str) -> str:
    """Defangs an IP address by wrapping dots in brackets."""
    if not ip:
        return ""
    return ip.replace('.', '[.]')

def defang_domain(domain: str) -> str:
    """Defangs a domain name."""
    if not domain:
        return ""
    return domain.replace('.', '[.]')

def defang_email(email: str) -> str:
    """Defangs an email address by escaping @ and dots."""
    if not email:
        return ""
    val = email.replace('@', '[@]')
    return val.replace('.', '[.]')
