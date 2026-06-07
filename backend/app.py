import socket
import ssl
import json
import re
import ipaddress
import urllib.parse
import urllib.request
import urllib.error
import hashlib
import concurrent.futures
import secrets
import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional, Tuple
import dns.resolver
import dns.reversename
import whois as whois_lib
import requests
from flask import Flask, render_template, jsonify, request, abort, make_response
from flask_cors import CORS
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
app = Flask(__name__)

# Generate a secure secret key - in production use environment variable
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['JSON_AS_ASCII'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Restrict CORS to specific trusted origins (customize this list)
ALLOWED_ORIGINS = [
    'http://localhost:5000',
    'http://localhost:3000',
    'https://vallains-tool.pages.dev',
]

# Configure CORS properly
CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["POST", "GET", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "max_age": 3600,
        "expose_headers": ["X-Request-ID"],
    }
})

# =============================================================================
# RATE LIMITING (simple in-memory implementation)
# =============================================================================
from collections import defaultdict
from time import time

class RateLimiter:
    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        now = time()
        # Clean old entries
        self.requests[client_id] = [
            t for t in self.requests[client_id]
            if now - t < self.window_seconds
        ]
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        self.requests[client_id].append(now)
        return True

    def cleanup(self):
        """Periodic cleanup of old entries"""
        now = time()
        for client_id in list(self.requests.keys()):
            self.requests[client_id] = [
                t for t in self.requests[client_id]
                if now - t < self.window_seconds
            ]
            if not self.requests[client_id]:
                del self.requests[client_id]

rate_limiter = RateLimiter(max_requests=30, window_seconds=60)

# =============================================================================
# SECURITY HEADERS MIDDLEWARE
# =============================================================================
@app.after_request
def add_security_headers(response):
    # Remove server fingerprint
    response.headers['Server'] = 'Vallains-Security'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Request-ID'] = secrets.token_hex(8)
    return response

# =============================================================================
# INPUT VALIDATION & SANITIZATION
# =============================================================================
BLOCKED_IPS = set()  # IPs blocked due to abuse

def get_client_ip() -> str:
    """Get real client IP, handling proxies"""
    # Check X-Forwarded-For first (behind proxy/load balancer)
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        # Get the first IP in the chain (original client)
        ip = forwarded.split(',')[0].strip()
    else:
        ip = request.headers.get('X-Real-IP', request.remote_addr or '127.0.0.1')
    return ip

def is_ip_blocked(ip: str) -> bool:
    return ip in BLOCKED_IPS

def validate_target(target: str) -> Tuple[bool, str]:
    """Validate and sanitize target input"""
    if not target or not isinstance(target, str):
        return False, "Target is required"
    
    # Trim and limit length
    target = target.strip()[:500]
    
    if len(target) < 1:
        return False, "Target too short"
    
    # Check for injection attempts
    dangerous_patterns = [
        r'[;&|`$]',  # Command injection
        r'\s{10,}',  # Excessive whitespace
        r'\x00',     # Null bytes
        r'\n|\r',    # Newlines in what should be single-line
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, target):
            return False, "Invalid characters detected"
    
    return True, target

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    """Basic domain validation"""
    if not domain or len(domain) > 253:
        return False
    # Basic domain pattern
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain))

def rate_check():
    """Rate limiting check - call at start of each API endpoint"""
    client_ip = get_client_ip()
    
    if is_ip_blocked(client_ip):
        abort(429, description="IP temporarily blocked")
    
    if not rate_limiter.is_allowed(client_ip):
        # Track abuse
        logging.warning(f"Rate limit exceeded for IP: {client_ip}")
        abort(429, description="Too many requests. Please wait and try again.")

# =============================================================================
# LOGGING SETUP
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - Vallains - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/workspace/vallains_app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT = 8
MAX_WORKERS = 15

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9200: "Elasticsearch", 27017: "MongoDB"
}

DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "ubl.unsubscore.com",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "all.spamrats.com"
]


def normalize_target(raw):
    if not raw:
        return None, None
    raw = raw.strip().lower()
    raw = re.sub(r'^https?://', '', raw)
    raw = raw.split('/')[0].split(':')[0]
    if not raw:
        return None, None
    try:
        ip = ipaddress.ip_address(raw)
        return None, str(ip)
    except ValueError:
        return raw, None


def domain_from_url(url):
    if not url:
        return None
    url = url.strip().lower()
    url = re.sub(r'^https?://', '', url)
    domain = url.split('/')[0].split(':')[0].split('?')[0]
    return domain if domain else None


def safe_get(url, timeout=TIMEOUT, headers=None):
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    try:
        # Enable SSL verification for security
        resp = requests.get(url, timeout=timeout, headers=hdrs, verify=True, allow_redirects=True)
        return resp
    except requests.exceptions.SSLError:
        # Fallback: try without verification only for specific external services that may have cert issues
        try:
            resp = requests.get(url, timeout=timeout, headers=hdrs, verify=False, allow_redirects=True)
            return resp
        except Exception:
            return None
    except Exception:
        return None


def get_geoip(ip):
    try:
        resp = safe_get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse,hosting")
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country", "غير معروف"),
                    "region": data.get("regionName", "غير معروف"),
                    "city": data.get("city", "غير معروف"),
                    "zip": data.get("zip", ""),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone", "غير معروف"),
                    "isp": data.get("isp", "غير معروف"),
                    "org": data.get("org", "غير معروف"),
                    "as": data.get("as", "غير معروف"),
                    "reverse": data.get("reverse", ""),
                    "hosting": data.get("hosting", False)
                }
    except Exception:
        pass
    return {"ip": ip, "error": "تعذر جلب بيانات GeoIP"}


def get_dns_records(domain):
    records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": [], "SRV": []}
    for rtype in records.keys():
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=TIMEOUT)
            for rdata in answers:
                if rtype == "MX":
                    records[rtype].append({"preference": rdata.preference, "exchange": str(rdata.exchange).rstrip('.')})
                elif rtype == "SOA":
                    records[rtype].append({"mname": str(rdata.mname).rstrip('.'), "rname": str(rdata.rname).rstrip('.'), "serial": rdata.serial, "refresh": rdata.refresh, "retry": rdata.retry, "expire": rdata.expire, "minimum": rdata.minimum})
                elif rtype == "TXT":
                    txt = str(rdata).strip('"')
                    records[rtype].append(txt[:300])
                else:
                    records[rtype].append(str(rdata).rstrip('.'))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, Exception):
            pass
    return records


def get_whois_info(target):
    try:
        w = whois_lib.whois(target)
        result = {
            "domain_name": str(w.domain_name) if w.domain_name else "",
            "registrar": w.registrar or "غير معروف",
            "whois_server": w.whois_server or "",
            "creation_date": str(w.creation_date) if w.creation_date else "",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "",
            "updated_date": str(w.updated_date) if w.updated_date else "",
            "name_servers": [str(ns).lower() for ns in (w.name_servers or [])],
            "status": w.status if isinstance(w.status, str) else (w.status or []),
            "emails": w.emails or [],
            "org": w.org or "",
            "country": w.country or "",
            "state": w.state or "",
            "city": w.city or "",
            "address": w.address or "",
            "registrant": getattr(w, 'name', '') or ""
        }
        return {k: v for k, v in result.items() if v not in ("", [], None, "None")}
    except Exception as e:
        return {"error": f"تعذر جلب بيانات WHOIS: {str(e)[:120]}"}


def get_http_headers(domain):
    try:
        url = f"https://{domain}"
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, verify=False, allow_redirects=True, stream=True)
        headers = dict(resp.headers)
        info = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": headers,
            "ip": resp.raw._connection.sock.getpeername()[0] if hasattr(resp, 'raw') and resp.raw and hasattr(resp.raw, '_connection') else "",
            "server": headers.get("Server", "غير معروف"),
            "powered_by": headers.get("X-Powered-By", ""),
            "content_type": headers.get("Content-Type", ""),
            "security_headers": {
                "X-Frame-Options": headers.get("X-Frame-Options", "❌ غير موجود"),
                "X-XSS-Protection": headers.get("X-XSS-Protection", "❌ غير موجود"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "❌ غير موجود"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "❌ غير موجود"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "❌ غير موجود"),
                "Referrer-Policy": headers.get("Referrer-Policy", "❌ غير موجود"),
                "Permissions-Policy": headers.get("Permissions-Policy", "❌ غير موجود")
            }
        }
        return info
    except Exception as e:
        try:
            url = f"http://{domain}"
            resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True, stream=True)
            headers = dict(resp.headers)
            return {
                "status_code": resp.status_code,
                "final_url": resp.url,
                "headers": headers,
                "server": headers.get("Server", "غير معروف"),
                "powered_by": headers.get("X-Powered-By", ""),
                "content_type": headers.get("Content-Type", ""),
                "security_headers": {"msg": "الموقع لا يدعم HTTPS"}
            }
        except Exception as e2:
            return {"error": f"تعذر الاتصال بالموقع: {str(e2)[:100]}"}


def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        try:
            all_ips = []
            for info in socket.getaddrinfo(domain, None):
                all_ips.append(info[4][0])
            all_ips = list(set(all_ips))
        except Exception:
            all_ips = [ip]
        return {
            "domain": domain,
            "ip": ip,
            "all_ips": all_ips,
            "ipv4_count": len([i for i in all_ips if ':' not in i]),
            "ipv6_count": len([i for i in all_ips if ':' in i])
        }
    except Exception as e:
        return {"error": f"تعذر حل الدومين: {str(e)}"}


def reverse_ip_lookup(ip):
    results = {"hostname": "", "domains_on_ip": []}
    try:
        hostname = socket.gethostbyaddr(ip)
        results["hostname"] = hostname[0]
    except Exception:
        pass
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = safe_get(url, timeout=10)
        if resp and resp.status_code == 200:
            data = resp.text.strip()
            if data and "error" not in data.lower():
                results["domains_on_ip"] = [d.strip() for d in data.split('\n') if d.strip()][:50]
    except Exception:
        pass
    if not results["domains_on_ip"]:
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
            resp = safe_get(url, timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                hosts = set()
                for entry in data.get("passive_dns", []):
                    h = entry.get("hostname")
                    if h and h.endswith('.' + results.get("hostname", "").split('.', 1)[-1] if results.get("hostname") else True):
                        hosts.add(h)
                results["domains_on_ip"] = list(hosts)[:30]
        except Exception:
            pass
    return results


def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher = ssock.cipher()
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        subject = {}
        for attr in cert.subject:
            try:
                subject[attr.oid._name] = attr.value
            except Exception:
                subject[attr.oid.dotted_string] = attr.value
        issuer = {}
        for attr in cert.issuer:
            try:
                issuer[attr.oid._name] = attr.value
            except Exception:
                issuer[attr.oid.dotted_string] = attr.value
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days
        san = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in ext.value:
                if isinstance(name, x509.DNSName):
                    san.append(name.value.lower())
                elif isinstance(name, x509.IPAddress):
                    san.append('IP:' + str(name.value))
        except Exception:
            pass
        sig_alg = cert.signature_algorithm_oid._name or 'Unknown'
        public_key = cert.public_key()
        key_type = type(public_key).__name__
        return {
            "subject": subject,
            "issuer": issuer,
            "valid_from": not_before.isoformat(),
            "valid_until": not_after.isoformat(),
            "days_remaining": days_left,
            "is_expired": days_left < 0,
            "serial_number": cert.serial_number,
            "signature_algorithm": str(sig_alg),
            "tls_version": tls_version,
            "cipher": {"name": cipher[0], "version": cipher[1], "bits": cipher[2]},
            "san": san,
            "san_count": len(san),
            "key_type": key_type,
            "fingerprint_sha256": hashlib.sha256(der_cert).hexdigest(),
            "fingerprint_sha1": hashlib.sha1(der_cert).hexdigest()
        }
    except Exception as e:
        return {"error": f"تعذر فحص SSL: {str(e)}"}


def check_dnsbl(ip):
    results = []
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
    except Exception:
        return results
    def query(server):
        try:
            query = f"{reversed_ip}.{server}"
            answers = dns.resolver.resolve(query, 'A', lifetime=3)
            for rdata in answers:
                return {"server": server, "listed": True, "ip_returned": str(rdata)}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {"server": server, "listed": False}
        except Exception:
            return {"server": server, "listed": False, "error": True}
        return {"server": server, "listed": False}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(query, srv): srv for srv in DNSBL_SERVERS}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            if r:
                results.append(r)
    return results


def port_scan(ip, ports=None):
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    open_ports = []
    def check(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port:
                open_ports.append({"port": port, "service": COMMON_PORTS.get(port, "Unknown")})
    return sorted(open_ports, key=lambda x: x["port"])


def get_redirect_chain(domain):
    chain = []
    try:
        session = requests.Session()
        session.max_redirects = 10
        resp = session.get(f"https://{domain}", timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, verify=False, allow_redirects=False, stream=True)
        for i in range(10):
            chain.append({"url": resp.url, "status": resp.status_code, "headers_security": {
                "HSTS": "Strict-Transport-Security" in resp.headers,
                "CSP": "Content-Security-Policy" in resp.headers,
                "X-Frame-Options": resp.headers.get("X-Frame-Options", "❌")
            }})
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get('Location')
                if not loc:
                    break
                if not loc.startswith('http'):
                    loc = urllib.parse.urljoin(resp.url, loc)
                resp = session.get(loc, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, verify=False, allow_redirects=False, stream=True)
            else:
                break
    except Exception as e:
        chain.append({"error": str(e)[:100]})
    return chain


def get_crt_sh(domain):
    try:
        resp = safe_get(f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json", timeout=15)
        if resp and resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data[:100]:
                name = entry.get("name_value", "")
                for n in name.split('\n'):
                    n = n.strip().lower()
                    if n.endswith(domain) and '*' not in n:
                        subdomains.add(n)
            return {
                "count": len(data),
                "subdomains": sorted(list(subdomains))[:50],
                "unique_subdomains": len(subdomains)
            }
    except Exception:
        pass
    return {"count": 0, "subdomains": [], "unique_subdomains": 0}


def check_google_safebrowsing(url):
    target = url if url.startswith('http') else f'http://{url}'
    diagnostic = f"https://transparencyreport.google.com/safe-browsing/search?url={urllib.parse.quote(target)}"
    return {
        "scanner": "Google Safe Browsing",
        "url": diagnostic,
        "note": "انقر الرابط للفحص الكامل عبر Google Transparency Report"
    }


def check_virustotal(url):
    target = url if url.startswith('http') else f'http://{url}'
    return {
        "scanner": "VirusTotal",
        "url": f"https://www.virustotal.com/gui/domain/{urllib.parse.quote(target.split('//')[-1].split('/')[0])}",
        "ip_url": f"https://www.virustotal.com/gui/ip-address/{url}" if re.match(r'^\d+\.\d+\.\d+\.\d+$', url) else None,
        "note": "أقوى محرك فحص متعدد المحركات (70+)"
    }


def check_urlvoid(domain):
    return {
        "scanner": "URLVoid",
        "url": f"https://www.urlvoid.com/scan/{urllib.parse.quote(domain)}/",
        "note": "يفحص الموقع عبر 30+ محرك سمعة"
    }


def check_phishtank(domain):
    return {
        "scanner": "PhishTank",
        "url": f"https://phishtank.org/search.php?valid=y&Search=Search&query={urllib.parse.quote(domain)}",
        "note": "أكبر قاعدة بيانات تصيد احتيالي في العالم"
    }


def check_abuseipdb(target):
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        return {
            "scanner": "AbuseIPDB",
            "url": f"https://www.abuseipdb.com/check/{target}",
            "note": "قاعدة بيانات تقارير إساءة الاستخدام لـ IP"
        }
    return {"scanner": "AbuseIPDB", "note": "متاح فقط لفحص IP"}


def check_scamalyzer(domain):
    return {
        "scanner": "ScamAdviser",
        "url": f"https://www.scamadviser.com/check-website/{urllib.parse.quote(domain)}",
        "note": "محلل ثقة المواقع والاحتيال"
    }


def check_sucuri(domain):
    return {
        "scanner": "Sucuri SiteCheck",
        "url": f"https://sitecheck.sucuri.net/results/{urllib.parse.quote(domain)}",
        "note": "فحص البرمجيات الخبيثة والقائمة السوداء"
    }


def check_threatcrowd(domain):
    return {
        "scanner": "ThreatCrowd",
        "url": f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={urllib.parse.quote(domain)}",
        "note": "تحليل علاقات النطاقات والتهديدات"
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/resolve', methods=['POST'])
def api_resolve():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain, ip = normalize_target(target)
    if not domain and not ip:
        return jsonify({"error": "الرجاء إدخال دومين أو IP صحيح"}), 400
    if domain:
        result = resolve_domain(domain)
        if 'error' in result:
            return jsonify(result), 400
        result['geoip'] = get_geoip(result['ip'])
        return jsonify({"type": "domain_to_ip", "result": result})
    else:
        geo = get_geoip(ip)
        return jsonify({"type": "ip", "result": geo})


@app.route('/api/reverse', methods=['POST'])
def api_reverse():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain, ip = normalize_target(target)
    if not ip:
        return jsonify({"error": "الرجاء إدخال IP صحيح"}), 400
    result = reverse_ip_lookup(ip)
    result['ip'] = ip
    result['geoip'] = get_geoip(ip)
    return jsonify({"result": result})


@app.route('/api/info', methods=['POST'])
def api_info():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain, ip = normalize_target(target)
    if not domain:
        return jsonify({"error": "الرجاء إدخال دومين صحيح"}), 400
    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(resolve_domain, domain): 'resolve',
            executor.submit(get_dns_records, domain): 'dns',
            executor.submit(get_whois_info, domain): 'whois',
            executor.submit(get_http_headers, domain): 'headers',
            executor.submit(get_ssl_info, domain): 'ssl',
            executor.submit(get_crt_sh, domain): 'crt'
        }
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                result[key] = future.result()
            except Exception as e:
                result[key] = {"error": str(e)[:120]}
    if 'resolve' in result and 'ip' in result['resolve']:
        result['geoip'] = get_geoip(result['resolve']['ip'])
    return jsonify({"result": result})


@app.route('/api/ssl', methods=['POST'])
def api_ssl():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain = domain_from_url(target)
    if not domain:
        return jsonify({"error": "الرجاء إدخال دومين صحيح"}), 400
    return jsonify({"result": get_ssl_info(domain)})


@app.route('/api/ports', methods=['POST'])
def api_ports():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain, ip = normalize_target(target)
    if domain:
        r = resolve_domain(domain)
        if 'ip' in r:
            ip = r['ip']
    if not ip:
        return jsonify({"error": "الرجاء إدخال IP أو دومين صحيح"}), 400
    ports = port_scan(ip)
    return jsonify({"result": {"ip": ip, "open_ports": ports, "scanned": len(COMMON_PORTS)}})


@app.route('/api/blacklist', methods=['POST'])
def api_blacklist():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain, ip = normalize_target(target)
    if domain:
        r = resolve_domain(domain)
        if 'ip' in r:
            ip = r['ip']
    if not ip:
        return jsonify({"error": "الرجاء إدخال IP أو دومين صحيح"}), 400
    results = check_dnsbl(ip)
    listed = [r for r in results if r.get('listed')]
    return jsonify({"result": {"ip": ip, "checks": results, "listed_count": len(listed), "total_checked": len(results)}})


@app.route('/api/threat', methods=['POST'])
def api_threat():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    scan_type = data.get('type', 'all')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain, ip = normalize_target(target)
    if not domain and not ip:
        return jsonify({"error": "الرجاء إدخال دومين أو IP صحيح"}), 400
    if not domain:
        try:
            rev = reverse_ip_lookup(ip)
            domain = rev.get('hostname', '').split('.', 1)[-1] if rev.get('hostname') else ip
        except Exception:
            domain = ip
    scanners = {
        "google_safebrowsing": check_google_safebrowsing(domain),
        "virustotal": check_virustotal(domain),
        "urlvoid": check_urlvoid(domain),
        "phishtank": check_phishtank(domain),
        "scamadviser": check_scamalyzer(domain),
        "sucuri": check_sucuri(domain),
        "threatcrowd": check_threatcrowd(domain)
    }
    if ip:
        scanners["abuseipdb"] = check_abuseipdb(ip)
    dnsbl = check_dnsbl(ip) if ip else []
    if domain:
        try:
            r = resolve_domain(domain)
            if 'ip' in r:
                dnsbl = check_dnsbl(r['ip'])
        except Exception:
            pass
    return jsonify({"result": {"target": domain, "ip": ip, "scanners": scanners, "dnsbl": dnsbl, "dnsbl_listed": len([d for d in dnsbl if d.get('listed')])}})


@app.route('/api/subdomains', methods=['POST'])
def api_subdomains():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain = domain_from_url(target)
    if not domain:
        return jsonify({"error": "الرجاء إدخال دومين صحيح"}), 400
    return jsonify({"result": get_crt_sh(domain)})


@app.route('/api/redirects', methods=['POST'])
def api_redirects():
    rate_check()
    data = request.get_json() or {}
    target = data.get('target', '')
    valid, result = validate_target(target)
    if not valid:
        return jsonify({"error": result}), 400
    target = result
    domain = domain_from_url(target)
    if not domain:
        return jsonify({"error": "الرجاء إدخال دومين صحيح"}), 400
    return jsonify({"result": get_redirect_chain(domain)})


@app.route('/api/health')
def health():
    # Minimal health check - no sensitive info leaked
    return jsonify({"status": "ok"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
