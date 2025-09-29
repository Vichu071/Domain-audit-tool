from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import dns.resolver
import whois
import builtwith
import requests
from bs4 import BeautifulSoup
import re
import logging
from urllib.parse import urljoin
import os

# ----------------- CONFIG -----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("competitor_audit")

app = FastAPI(title="Competitor Analysis Tool", version="1.7")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

# ----------------- HELPERS -----------------
def safe_fetch(url: str, timeout: int = 10) -> str:
    headers = {"User-Agent": "Mozilla/5.0 (CompetitorAuditBot/1.0)"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=False)
        r.raise_for_status()
        return r.text
    except requests.exceptions.RequestException:
        return ""

# ----------------- WHOIS -----------------
def get_whois_info(domain: str):
    try:
        w = whois.whois(domain)
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        return {
            "Registrar": w.registrar or "N/A",
            "Created On": str(creation) if creation else "N/A",
            "Expires On": str(expiration) if expiration else "N/A"
        }
    except Exception:
        return {"Registrar": "N/A", "Created On": "N/A", "Expires On": "N/A"}

# ----------------- EMAIL PROVIDER LOOKUP -----------------
def get_email_provider_api(domain: str):
    try:
        email = f"contact@{domain}"
        url = f"https://api.emailproviderlookup.com/v1/lookup?email={email}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "Provider": data.get("providerName", "Unknown"),
                "Details": data
            }
        return {"Provider": "Unknown", "Error": resp.text}
    except Exception as e:
        return {"Provider": "Unknown", "Error": str(e)}

# ----------------- EMAIL -----------------
def get_mx(domain: str):
    try:
        return [str(r.exchange).rstrip('.') for r in resolver.resolve(domain, "MX")]
    except Exception:
        return []

def get_txt(domain: str):
    try:
        return ["".join(s.decode() if isinstance(s, bytes) else s for s in r.strings) for r in resolver.resolve(domain, "TXT")]
    except Exception:
        return []

def detect_email_provider(mx_records, txt_records):
    providers = {
        "google": "Google Workspace",
        "outlook": "Microsoft 365",
        "office365": "Microsoft 365",
        "zoho": "Zoho Mail",
        "yahoo": "Yahoo Mail",
        "yandex": "Yandex Mail",
        "proton": "ProtonMail",
        "icloud": "iCloud Mail",
        "secureserver": "GoDaddy Email",
        "bluehost": "Bluehost Mail"
    }
    found = []
    for mx in mx_records:
        for k, v in providers.items():
            if k in mx.lower():
                found.append(v)
    for txt in txt_records:
        if "v=spf1" in txt.lower():
            for k, v in providers.items():
                if k in txt.lower():
                    found.append(v)
    return list(set(found)) or ["Custom / Unknown"]

def extract_emails(domain: str):
    html = safe_fetch(f"https://{domain}") or safe_fetch(f"http://{domain}")
    if not html:
        return ["Not found"]
    soup = BeautifulSoup(html, "html.parser")
    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}", html))
    for a in soup.find_all("a", href=True):
        if a["href"].startswith("mailto:"):
            emails.add(a["href"].replace("mailto:", ""))
    for a in soup.find_all("a", href=True):
        if any(k in a["href"].lower() for k in ["contact", "about", "team"]):
            url = urljoin(f"https://{domain}", a["href"])
            sub_html = safe_fetch(url)
            emails.update(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}", sub_html))
    return list(emails) or ["Not found"]

# ----------------- TECH STACK -----------------
def detect_tech(domain: str):
    try:
        tech = builtwith.parse(f"https://{domain}") or builtwith.parse(f"http://{domain}") or {}
        if not tech:
            return {}
        grouped = {}
        for category, technologies in tech.items():
            grouped[category] = list(set(technologies))
        return grouped
    except Exception as e:
        logger.error(f"Tech detection failed: {e}")
        return {}

# ----------------- WORDPRESS -----------------
def detect_wordpress(domain: str):
    wp_info = {"is_wordpress": False, "version": "N/A", "theme": "N/A"}
    html = safe_fetch(f"https://{domain}") or safe_fetch(f"http://{domain}")
    if not html:
        return wp_info
    if "wp-content" in html.lower() or "wp-includes" in html.lower():
        wp_info["is_wordpress"] = True
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", attrs={"name": "generator"})
    if meta and "wordpress" in meta.get("content", "").lower():
        wp_info["version"] = meta.get("content")
    theme_match = re.search(r"/wp-content/themes/([^/]+)/", html.lower())
    if theme_match:
        wp_info["theme"] = theme_match.group(1)
    return wp_info

# ----------------- ADS -----------------
AD_PATTERNS = {
    "Google Ads": r"pagead2\.googlesyndication\.com|doubleclick\.net",
    "Facebook Pixel": r"connect\.facebook\.net|fbq\(",
    "Google Analytics": r"gtag\(",
    "Criteo": r"static\.criteo\.net",
    "Taboola": r"cdn\.taboola\.com",
    "Outbrain": r"widgets\.outbrain\.com"
}

def detect_ads(domain: str):
    html = safe_fetch(f"https://{domain}") or safe_fetch(f"http://{domain}")
    if not html:
        return ["Not available"]
    found = set()
    for name, pattern in AD_PATTERNS.items():
        if re.search(pattern, html.lower()):
            found.add(name)
    return list(found) or ["No common ad networks detected"]

# ----------------- SECURITY -----------------
def audit_security(domain: str):
    security_report = {}
    try:
        r = requests.get(f"http://{domain}", timeout=5)
    except:
        try:
            r = requests.get(f"https://{domain}", timeout=5)
        except:
            return {
                "Content Security Policy": "Not Found",
                "Clickjacking Protection": "Not Found",
                "MIME Sniffing Protection": "Not Found"
            }
    headers = r.headers
    security_report["Content Security Policy"] = "Present" if headers.get("Content-Security-Policy") else "Not Found"
    security_report["Clickjacking Protection"] = "Present" if headers.get("X-Frame-Options") else "Not Found"
    security_report["MIME Sniffing Protection"] = "Present" if headers.get("X-Content-Type-Options") else "Not Found"
    return security_report

# ----------------- PERFORMANCE -----------------
def detect_performance(domain: str):
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        return f"Page loaded in {round(r.elapsed.total_seconds(), 2)} seconds, size {round(len(r.content)/1024,2)} KB"
    except:
        return "Performance data not available"

# ----------------- ROUTES -----------------
@app.get("/")
def home():
    if os.path.exists("templates/index.html"):
        return FileResponse("templates/index.html")
    return {"message": "Place 'index.html' in a 'templates' folder."}

@app.get("/audit/{domain}")
def audit(domain: str):
    domain = domain.strip()
    if not domain:
        return JSONResponse({"error": "Domain cannot be empty"}, status_code=400)
    logger.info(f"Auditing: {domain}")

    whois_info = get_whois_info(domain)
    mx_records = get_mx(domain)
    txt_records = get_txt(domain)
    email_provider = detect_email_provider(mx_records, txt_records)
    email_api_provider = get_email_provider_api(domain)  # API-based provider lookup
    extracted_emails = extract_emails(domain)
    wp_info = detect_wordpress(domain)
    tech_list = detect_tech(domain)
    ads_list = detect_ads(domain)
    security_info = audit_security(domain)
    performance_info = detect_performance(domain)

    results = {
        "Domain": domain,
        "Domain Info": whois_info,
        "Email Setup": {
            "Provider": email_provider[0] if email_provider else "Custom / Unknown",
            "Contact Emails": extracted_emails,
            "API Email Provider": email_api_provider
        },
        "Website Tech": tech_list,
        "WordPress": {
            "Is WordPress": "Yes" if wp_info["is_wordpress"] else "No",
            "Theme": wp_info["theme"],
            "Version": wp_info["version"]
        },
        "Ads Running": ads_list,
        "Security": security_info,
        "Performance": performance_info
    }
    return JSONResponse(results)

# ----------------- RUN -----------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))  # Render compatibility
    uvicorn.run(app, host="0.0.0.0", port=port)
