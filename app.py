import ipaddress
import os
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()  # يقرأ GOOGLE_API_KEY من ملف .env

app = Flask(__name__)
# خلف بروكسي الاستضافة: ناخذ IP الزائر الحقيقي حتى الـ rate limit يشتغل لكل زائر لوحده
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://",
)

API_KEY = os.getenv("GOOGLE_API_KEY", "")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# ---------- تخزين مؤقت بسيط (ساعة واحدة، أقصى 500 نتيجة) ----------
CACHE_TTL = 3600
CACHE_MAX = 500
_cache = {}


def cache_get(key):
    item = _cache.get(key)
    if item and time.time() - item[0] < CACHE_TTL:
        return item[1]
    _cache.pop(key, None)
    return None


def cache_set(key, value):
    if len(_cache) >= CACHE_MAX:
        _cache.pop(next(iter(_cache)))
    _cache[key] = (time.time(), value)


# ---------- تجهيز الرابط والحماية ----------
def normalize(raw):
    """يرجّع (الرابط الكامل، اسم الدومين) أو None إذا الرابط غير صالح."""
    raw = raw.strip()
    if not raw or len(raw) > 2048:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
        host = parsed.hostname
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not host:
        return None
    return raw, host.lower()


def resolve_public(host):
    """يحوّل الدومين إلى IP ويرفض العناوين الداخلية (حماية من SSRF)."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            return None
        ips.append(str(ip))
    return ips or None


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------- الفحوصات ----------
def check_safe_browsing(url):
    if not API_KEY:
        return {"checked": False, "safe": None, "threats": []}
    hit = cache_get(("sb", url))
    if hit:
        return hit
    body = {
        "client": {"clientId": "url-scanner-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(SAFE_BROWSING_URL, params={"key": API_KEY}, json=body, timeout=5)
        r.raise_for_status()
        matches = r.json().get("matches", [])
    except (requests.RequestException, ValueError):
        # فشل الاتصال لا يعني أن الرابط آمن، فنرجّعه "غير مفحوص"
        return {"checked": False, "safe": None, "threats": []}
    result = {
        "checked": True,
        "safe": not matches,
        "threats": sorted({m["threatType"] for m in matches}),
    }
    cache_set(("sb", url), result)
    return result


def check_ssl(host, ip):
    ctx = ssl.create_default_context()
    try:
        # نتصل بالـ IP اللي تحققنا منه، حتى ما يتغير الدومين بين الفحص والاتصال
        with socket.create_connection((ip, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        return {"has_ssl": True, "valid": True, "expires": expires.date().isoformat()}
    except ssl.SSLCertVerificationError:
        return {"has_ssl": True, "valid": False, "expires": None}
    except (OSError, ssl.SSLError):
        return {"has_ssl": False, "valid": False, "expires": None}


def check_whois(host):
    empty = {"registrar": None, "created": None, "age_days": None}
    if is_ip(host):
        return empty
    hit = cache_get(("whois", host))
    if hit:
        return hit
    try:
        w = whois.whois(host)
    except Exception:
        return empty
    created = w.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    result = dict(empty)
    if isinstance(w.registrar, str):
        result["registrar"] = w.registrar
    if isinstance(created, datetime):
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        result["created"] = created.date().isoformat()
        result["age_days"] = (datetime.now(timezone.utc) - created).days
    cache_set(("whois", host), result)
    return result


def verdict(sb, ssl_info, who):
    if sb["checked"] and not sb["safe"]:
        return "danger", "خطير: الرابط مُبلَّغ عنه كموقع خبيث أو تصيّد"
    reasons = []
    if not ssl_info["has_ssl"]:
        reasons.append("لا توجد شهادة SSL")
    elif not ssl_info["valid"]:
        reasons.append("شهادة SSL غير صالحة")
    if who["age_days"] is not None and who["age_days"] < 30:
        reasons.append("الدومين جديد (أقل من 30 يوم)")
    if reasons:
        return "warning", "مشكوك فيه: " + "، ".join(reasons)
    if not sb["checked"]:
        return "unknown", "ما تم فحص Google Safe Browsing (المفتاح غير مضبوط أو الخدمة ما استجابت)"
    return "safe", "ما لقينا أي تهديد معروف لهذا الرابط"


# ---------- المسارات ----------
@app.get("/")
def home():
    return render_template("index.html")


@app.post("/scan")
@limiter.limit("5 per minute")
def scan():
    data = request.get_json(silent=True) or {}
    parsed = normalize(str(data.get("url", "")))
    if not parsed:
        return jsonify(error="الرجاء إدخال رابط صحيح"), 400
    url, host = parsed

    ips = resolve_public(host)
    if not ips:
        return jsonify(error="تعذّر الوصول للدومين، أو أنه عنوان داخلي غير مسموح بفحصه"), 400

    # الفحوصات الثلاثة تشتغل بالتوازي حتى النتيجة تطلع أسرع
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_sb = pool.submit(check_safe_browsing, url)
        f_ssl = pool.submit(check_ssl, host, ips[0])
        f_who = pool.submit(check_whois, host)
        sb, ssl_info, who = f_sb.result(), f_ssl.result(), f_who.result()

    level, message = verdict(sb, ssl_info, who)
    return jsonify(
        url=url,
        domain=host,
        level=level,
        message=message,
        safe_browsing=sb,
        ssl=ssl_info,
        whois=who,
    )


@app.errorhandler(429)
def too_many(_):
    return jsonify(error="طلبات كثيرة، انتظر دقيقة وحاول مرة ثانية"), 429


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
