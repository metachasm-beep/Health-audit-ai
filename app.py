# ============================================================
#  app.py — Website Health Audit
#  Run:  python app.py
#  Requires: pip install flask requests beautifulsoup4 authlib python-dotenv
# ============================================================

import os
import re
import ssl
import csv
import io
import json
import time
import socket
import hashlib
import traceback
import concurrent.futures
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

# ── Local modules ─────────────────────────────────────────────
import config
from database import ANALYSIS_DB
from prompts import build_analysis_prompt, build_fallback_analysis, SYSTEM_PROMPT
from background import create_background, BACKGROUND_URL

# ── Optional dependencies ─────────────────────────────────────
try:
    from bs4 import BeautifulSoup
    BS_AVAILABLE = True
except ImportError:
    BS_AVAILABLE = False

try:
    from authlib.integrations.flask_client import OAuth
    OAUTH_AVAILABLE = True
except ImportError:
    OAUTH_AVAILABLE = False

# ── App setup ─────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

# Write the background SVG once at startup
create_background(os.path.join(os.path.dirname(__file__), "static"))

# In-memory user store (replace with a real DB for production)
user_data: dict = {}

# ── OAuth ─────────────────────────────────────────────────────
if OAUTH_AVAILABLE and config.GOOGLE_CLIENT_ID:
    oauth = OAuth(app)
    google = oauth.register(
        name="google",
        client_id=config.GOOGLE_CLIENT_ID,
        client_secret=config.GOOGLE_CLIENT_SECRET,
        access_token_url="https://accounts.google.com/o/oauth2/token",
        authorize_url="https://accounts.google.com/o/oauth2/auth",
        api_base_url="https://www.googleapis.com/oauth2/v1/",
        userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
        client_kwargs={"scope": "openid email profile"},
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    )
else:
    google = None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/api/auth/login")
def login():
    if not google:
        _set_demo_user()
        return redirect("/")
    return google.authorize_redirect(url_for("authorize", _external=True))


@app.route("/api/auth/authorize")
def authorize():
    try:
        token = google.authorize_access_token()
        info = google.get("userinfo").json()
        session["user"] = {
            "email":   info["email"],
            "name":    info.get("name", info["email"]),
            "picture": info.get("picture", _avatar(info["email"])),
        }
        _init_user(info["email"])
    except Exception:
        _set_demo_user()
    return redirect("/")


@app.route("/api/auth/logout")
def logout():
    session.pop("user", None)
    return redirect("/")


@app.route("/api/auth/status")
def auth_status():
    if "user" in session:
        return jsonify({"authenticated": True, "user": session["user"]})
    return jsonify({"authenticated": False})


def _set_demo_user():
    session["user"] = {
        "email":   "demo@example.com",
        "name":    "Demo User",
        "picture": _avatar("Demo User"),
    }
    _init_user("demo@example.com")


def _init_user(email: str):
    if email not in user_data:
        user_data[email] = {"history": [], "alerts": []}


def _avatar(name: str) -> str:
    return f"https://ui-avatars.com/api/?name={name}&background=8B5CF6&color=fff"


# ─────────────────────────────────────────────────────────────
#  USER DATA ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/api/user/history")
@login_required
def user_history():
    email = session["user"]["email"]
    return jsonify({"history": user_data.get(email, {}).get("history", [])[-20:]})


@app.route("/api/user/alerts")
@login_required
def user_alerts():
    email = session["user"]["email"]
    return jsonify({"alerts": user_data.get(email, {}).get("alerts", [])})


@app.route("/api/user/alert", methods=["POST"])
@login_required
def create_alert():
    data = request.get_json()
    email = session["user"]["email"]
    _init_user(email)
    alert = {
        "id":        hashlib.md5(f"{data['url']}{datetime.now()}".encode()).hexdigest()[:8],
        "url":       data["url"],
        "condition": data["condition"],
        "threshold": data["threshold"],
        "created":   datetime.now().isoformat(),
        "active":    True,
    }
    user_data[email]["alerts"].append(alert)
    return jsonify({"success": True, "alert": alert})


@app.route("/api/user/alert/<alert_id>", methods=["DELETE"])
@login_required
def delete_alert(alert_id):
    email = session["user"]["email"]
    if email in user_data:
        user_data[email]["alerts"] = [
            a for a in user_data[email]["alerts"] if a["id"] != alert_id
        ]
    return jsonify({"success": True})


# ─────────────────────────────────────────────────────────────
#  MISC ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/api/test")
def test():
    return jsonify({"status": "ok"})


@app.route("/")
def index():
    return render_template("index.html", background_image=BACKGROUND_URL)


# ─────────────────────────────────────────────────────────────
#  SCORING HELPER
# ─────────────────────────────────────────────────────────────

def normalize_value(value, item_key: str) -> int:
    """Map a raw measured value to a 0-100 score using ANALYSIS_DB thresholds."""
    if value is None:
        return 50

    cfg = ANALYSIS_DB.get(item_key, {})

    if isinstance(value, bool):
        # Negative indicators: lower is better
        if item_key in ("malware_detected", "phishing_detected",
                        "unwanted_software", "harmful_apps", "social_engineering"):
            return 0 if value else 100
        return 100 if value else 0

    if isinstance(value, str):
        if item_key == "tls_version":
            v = value.lower()
            if "1.3" in v:  return 100
            if "1.2" in v:  return 70
            return 30
        if item_key == "http_version":
            if "3" in value: return 100
            if "2" in value: return 90
            return 50
        lv = value.lower()
        if lv in ("present", "enabled", "yes", "visible", "proper", "clean"): return 100
        if lv in ("missing", "none", "no", "removed", "blacklisted"):         return 0
        return 50

    # Numeric: lower is better (LCP, TTFB, etc.)
    if "threshold_good" in cfg and "threshold_poor" in cfg:
        try:
            val  = float(value)
            good = cfg["threshold_good"]
            poor = cfg["threshold_poor"]
            # For ssl_days_left: higher is better — detect by good > poor
            if good > poor:
                if val >= good: return 100
                if val <= poor: return 0
                return int((val - poor) / (good - poor) * 100)
            else:
                if val <= good: return 100
                if val >= poor: return 0
                return int(100 - (val - good) / (poor - good) * 100)
        except (TypeError, ValueError):
            pass

    # Numeric: range is ideal (title_length, cta_count)
    if "good_min" in cfg and "good_max" in cfg:
        try:
            val = float(value)
            if cfg["good_min"] <= val <= cfg["good_max"]:
                return 100
            if val < cfg["good_min"]:
                return max(0, int(val / cfg["good_min"] * 100))
            return max(0, int(100 - (val - cfg["good_max"]) / cfg["good_max"] * 100))
        except (TypeError, ValueError):
            pass

    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    return 50


# ─────────────────────────────────────────────────────────────
#  AI PROVIDER CHAIN
# ─────────────────────────────────────────────────────────────

def _chat(url: str, api_url: str, headers: dict, payload: dict, label: str):
    """Generic OpenAI-compatible chat call. Returns (success, text)."""
    try:
        r = requests.post(api_url, headers=headers, json=payload, timeout=30)
        if r.status_code == 200:
            text = r.json()["choices"][0]["message"]["content"]
            return True, f"🔍 AI-POWERED WEBSITE ANALYSIS ({label})\n\n{text}"
    except Exception as e:
        print(f"{label} error: {e}")
    return False, None


def call_gemini(prompt: str):
    if not config.GEMINI_API_KEY:
        return False, None
    try:
        import google.generativeai as genai
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel(config.GEMINI_MODEL)
        resp = model.generate_content(
            f"{SYSTEM_PROMPT}\n\n{prompt}",
            generation_config=genai.types.GenerationConfig(max_output_tokens=2000),
        )
        return True, f"🔍 AI-POWERED WEBSITE ANALYSIS (Gemini)\n\n{resp.text}"
    except Exception as e:
        print(f"Gemini error: {e}")
        return False, None


def call_groq(prompt: str):
    if not config.GROQ_API_KEY:
        return False, None
    return _chat(
        prompt, config.GROQ_API_URL,
        headers={"Authorization": f"Bearer {config.GROQ_API_KEY}", "Content-Type": "application/json"},
        payload={"model": config.GROQ_MODEL, "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ], "temperature": 0.7, "max_tokens": 2000},
        label="Groq",
    )


def call_openrouter(prompt: str):
    if not config.OPENROUTER_API_KEY:
        return False, None
    return _chat(
        prompt, config.OPENROUTER_API_URL,
        headers={
            "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://health-audit.app",
            "X-Title": "Website Health Audit",
        },
        payload={"model": config.OPENROUTER_MODEL, "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ], "temperature": 0.7, "max_tokens": 2000},
        label="OpenRouter",
    )


def call_cohere(prompt: str):
    if not config.COHERE_API_KEY:
        return False, None
    try:
        r = requests.post(
            config.COHERE_API_URL,
            headers={"Authorization": f"Bearer {config.COHERE_API_KEY}"},
            json={"model": config.COHERE_MODEL, "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
                  "max_tokens": 2000, "temperature": 0.7},
            timeout=30,
        )
        if r.status_code == 200:
            text = r.json()["generations"][0]["text"]
            return True, f"🔍 AI-POWERED WEBSITE ANALYSIS (Cohere)\n\n{text}"
    except Exception as e:
        print(f"Cohere error: {e}")
    return False, None


def call_glm5(prompt: str, api_key: str):
    return _chat(
        prompt, config.GLM5_API_URL,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        payload={"model": config.GLM5_MODEL, "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ], "temperature": 0.7, "max_tokens": 2000},
        label="GLM-5",
    )


def generate_ai_analysis(url: str, categories: list, strengths: list,
                          weaknesses: list, priority_items: list) -> str:
    """Try AI providers in priority order; fall back to template if all fail."""
    prompt = build_analysis_prompt(url, categories, strengths, weaknesses, priority_items)

    for fn in (call_gemini, call_groq, call_openrouter, call_cohere):
        ok, result = fn(prompt)
        if ok:
            return result

    for key in config.GLM5_API_KEYS:
        ok, result = call_glm5(prompt, key)
        if ok:
            return result

    return build_fallback_analysis(url, categories, strengths, weaknesses, priority_items)


# ─────────────────────────────────────────────────────────────
#  DATA COLLECTION FUNCTIONS
# ─────────────────────────────────────────────────────────────

def get_pagespeed_data(url: str) -> dict:
    try:
        r = requests.get(config.PAGESPEED_API, params={
            "url": url, "key": config.PAGESPEED_API_KEY, "strategy": "mobile"
        }, timeout=10)
        if r.status_code != 200:
            return {}
        lh     = r.json().get("lighthouseResult", {})
        cats   = lh.get("categories", {})
        audits = lh.get("audits", {})
        return {
            "lcp":              audits.get("largest-contentful-paint", {}).get("numericValue"),
            "fid":              audits.get("max-potential-fid",        {}).get("numericValue"),
            "cls":              audits.get("cumulative-layout-shift",  {}).get("numericValue"),
            "ttfb":             audits.get("server-response-time",     {}).get("numericValue"),
            "fcp":              audits.get("first-contentful-paint",   {}).get("numericValue"),
            "performance_score": (cats.get("performance", {}).get("score", 0.5) or 0) * 100,
            "dom_size":         audits.get("dom-size",          {}).get("numericValue"),
            "request_count":    audits.get("network-requests",  {}).get("numericValue"),
            "page_size":        audits.get("total-byte-weight", {}).get("numericValue"),
        }
    except Exception:
        return {}


def get_safe_browsing_data(url: str) -> dict:
    if not config.SAFE_BROWSING_API_KEY:
        return {}
    try:
        payload = {
            "client": {"clientId": "health-audit"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}],
            },
        }
        r = requests.post(
            f"{config.SAFE_BROWSING_API}?key={config.SAFE_BROWSING_API_KEY}",
            json=payload, timeout=5,
        )
        if r.status_code != 200:
            return {}
        matches = r.json().get("matches", [])
        return {
            "malware_detected":  any(m["threatType"] == "MALWARE"                        for m in matches),
            "phishing_detected": any(m["threatType"] == "SOCIAL_ENGINEERING"             for m in matches),
            "unwanted_software": any(m["threatType"] == "UNWANTED_SOFTWARE"              for m in matches),
            "harmful_apps":      any(m["threatType"] == "POTENTIALLY_HARMFUL_APPLICATION" for m in matches),
            "social_engineering":any(m["threatType"] == "SOCIAL_ENGINEERING"             for m in matches),
            "safe_browsing_score": 100 if not matches else 0,
            "blacklist_status": "Clean" if not matches else "Blacklisted",
        }
    except Exception:
        return {}


def get_ssl_data(url: str) -> dict:
    try:
        domain = urlparse(url).netloc
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
        if cert and "notAfter" in cert:
            expiry    = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = max(0, (expiry - datetime.now()).days)
            return {
                "ssl_days_left": days_left,
                "tls_version":   s.version(),
                "tls13_enabled": "TLSv1.3" in s.version(),
            }
    except Exception:
        pass
    return {"ssl_days_left": 90, "tls_version": "TLS 1.2", "tls13_enabled": False}


def get_headers_data(url: str) -> dict:
    defaults = {
        "hsts": False, "csp": False, "xfo": False, "xss_protection": False,
        "content_type": False, "referrer_policy": False,
        "cookies_secure": True, "cookies_httponly": True, "cookies_samesite": True,
        "http2_enabled": False, "hsts_preload": False,
    }
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        h = r.headers
        c = r.cookies
        return {
            "hsts":             "strict-transport-security" in h,
            "csp":              "content-security-policy"   in h,
            "xfo":              "x-frame-options"           in h,
            "xss_protection":   "x-xss-protection"         in h,
            "content_type":     "x-content-type-options"    in h,
            "referrer_policy":  "referrer-policy"           in h,
            "cookies_secure":   all(ck.secure for ck in c) if c else True,
            "cookies_httponly": all(ck.has_nonstandard_attr("HttpOnly") for ck in c) if c else True,
            "cookies_samesite": all(ck.get_nonstandard_attr("SameSite") for ck in c) if c else True,
            "http2_enabled":    getattr(r.raw, "version", None) == 20,
            "hsts_preload":     "preload" in h.get("strict-transport-security", ""),
        }
    except Exception:
        return defaults


def get_server_data(url: str) -> dict:
    try:
        start = time.time()
        r     = requests.get(url, timeout=5)
        ms    = int((time.time() - start) * 1000)
        cdn_hdrs = ("cf-ray", "x-cache", "x-amz-cf-id", "x-akamai-", "x-sucuri-")
        cdn = any(any(h in k.lower() for h in cdn_hdrs) for k in r.headers)
        return {
            "server_response_time": ms,
            "cdn_detected":  cdn,
            "compression":   "gzip" in r.headers.get("content-encoding", "")
                             or "br" in r.headers.get("content-encoding", ""),
        }
    except Exception:
        return {"server_response_time": 500, "cdn_detected": False, "compression": False}


def get_dns_data(domain: str) -> dict:
    try:
        t = time.time()
        socket.gethostbyname(domain)
        return {"dns_time_ms": int((time.time() - t) * 1000)}
    except Exception:
        return {"dns_time_ms": 100}


def _check_url(base: str, path: str) -> int:
    try:
        p = urlparse(base)
        r = requests.get(f"{p.scheme}://{p.netloc}{path}", timeout=3)
        return 100 if r.status_code == 200 else 0
    except Exception:
        return 0


def analyze_html(url: str) -> dict:
    if not BS_AVAILABLE:
        return {}
    try:
        r = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return {}
        soup   = BeautifulSoup(r.text, "html.parser")
        items  = {}

        # Title
        title      = soup.find("title")
        title_text = title.string.strip() if title and title.string else ""
        items["title_present"] = 100 if title else 0
        items["title_length"]  = len(title_text)

        # Meta description
        meta_desc  = soup.find("meta", attrs={"name": "description"})
        items["meta_description_present"] = 100 if meta_desc else 0

        # Keywords meta
        items["keywords_meta"] = 100 if soup.find("meta", attrs={"name": "keywords"}) else 0

        # Viewport / language
        items["viewport_present"] = 100 if soup.find("meta", attrs={"name": "viewport"}) else 0
        html_tag = soup.find("html")
        lang = html_tag.get("lang") if html_tag else None
        items["lang_present"]  = 100 if lang else 0
        items["lang_attribute"] = items["lang_present"]

        # Headings
        h1 = soup.find_all("h1")
        h2 = soup.find_all("h2")
        items["h1_count"] = len(h1)
        items["h2_count"] = len(h2)
        items["heading_structure"] = 100 if (len(h1) == 1 and len(h2) >= 0) else 50

        # Images / alt text
        images = soup.find_all("img")
        if images:
            with_alt   = sum(1 for img in images if img.get("alt"))
            items["alt_percentage"]  = with_alt / len(images) * 100
            items["alt_text_present"] = items["alt_percentage"]
            generic = {"image", "img", "picture", "photo", "graphic"}
            quality = sum(1 for img in images
                          if img.get("alt") and img["alt"].lower() not in generic)
            items["alt_text_quality"] = quality / len(images) * 100
        else:
            items["alt_percentage"] = items["alt_text_present"] = items["alt_text_quality"] = 100

        # Schema markup
        schemas = soup.find_all("script", type="application/ld+json")
        items["schema_present"] = 100 if schemas else 0

        # Skip link
        items["skip_link_present"] = 100 if soup.find(
            "a", href=re.compile(r"#(main|content|skip)")
        ) else 0

        # ARIA
        items["aria_count"]  = len(soup.find_all(attrs={re.compile("^aria-"): True}))
        items["aria_roles"]  = 100 if soup.find_all(attrs={"role": True})       else 0
        items["aria_labels"] = 100 if (
            soup.find_all(attrs={"aria-label": True}) or
            soup.find_all(attrs={"aria-labelledby": True})
        ) else 0

        # Form labels
        forms = soup.find_all("form")
        items["form_labels"] = (
            100 if any(form.find("label") for form in forms) else 50
        ) if forms else 100

        # Tables
        tables = soup.find_all("table")
        items["table_headers"] = 100 if (not tables or any(t.find("th") for t in tables)) else 50
        items["table_caption"] = 100 if (not tables or any(t.find("caption") for t in tables)) else 50

        # Canonical / OG / Twitter
        canonical = soup.find("link", rel="canonical")
        items["canonical_present"] = 100 if canonical else 0

        og_any = soup.find("meta", property=re.compile("^og:"))
        items["og_tags_present"] = 100 if og_any else 0

        items["twitter_cards"] = 100 if soup.find("meta", attrs={"name": "twitter:card"}) else 0
        items["favicon_present"] = 100 if (
            soup.find("link", rel="icon") or soup.find("link", rel="shortcut icon")
        ) else 0

        # Business signals
        ct_pat = re.compile(r"contact|email|phone|support|@", re.I)
        items["contact_info"] = 100 if soup.find_all(string=ct_pat) else 50

        cta_pat = re.compile(
            r"buy now|shop now|sign up|subscribe|download|get started|learn more", re.I
        )
        cta_btns = soup.find_all("button") + soup.find_all(
            "a", class_=re.compile(r"btn|button|cta", re.I)
        )
        items["cta_count"]      = min(len(soup.find_all(string=cta_pat)) + len(cta_btns), 10)
        items["cta_visibility"] = 80 if items["cta_count"] > 0 else 0

        items["privacy_policy"]  = 100 if soup.find_all("a", href=re.compile(r"privacy",      re.I)) else 0
        items["terms_of_service"]= 100 if soup.find_all("a", href=re.compile(r"terms|tos",    re.I)) else 0
        items["about_page"]      = 100 if soup.find_all("a", href=re.compile(r"about",        re.I)) else 0
        items["social_links"]    = 100 if soup.find_all("a", href=re.compile(
            r"facebook|twitter|linkedin|instagram|youtube|github", re.I
        )) else 0

        badge_pat  = re.compile(r"ssl|secure|trust|verified|norton|mcafee|bbb", re.I)
        items["trust_badges"] = 100 if (
            soup.find_all(string=badge_pat) or
            soup.find_all("img", alt=badge_pat)
        ) else 50

        test_pat = re.compile(r"testimonial|review|rating|stars", re.I)
        items["testimonials"] = 100 if soup.find_all(class_=test_pat) else 50

        price_pat = re.compile(r"pricing|price|plans|subscription", re.I)
        items["pricing_visible"] = 100 if (
            soup.find_all("a", href=price_pat) or soup.find_all(string=price_pat)
        ) else 50

        items["faq_page"]    = 100 if soup.find_all("a", href=re.compile(r"faq|questions|help", re.I)) else 50
        items["blog_present"]= 100 if soup.find_all("a", href=re.compile(r"blog|news|articles",  re.I)) else 50
        items["newsletter"]  = 100 if soup.find_all(
            "form", action=re.compile(r"newsletter|subscribe|email.signup", re.I)
        ) else 50
        items["live_chat"]   = 100 if soup.find_all(
            "script", src=re.compile(r"chat|livechat|intercom|drift|olark|tawk", re.I)
        ) else 0
        items["return_policy"]= 100 if soup.find_all("a", href=re.compile(r"return|refund|shipping", re.I)) else 50

        # Accessibility extras
        items["color_contrast"] = 80  # heuristic; real check requires rendering
        items["focus_visible"]  = (
            70 if soup.find_all(attrs={"style": re.compile(r"outline|box-shadow", re.I)}) else 50
        )
        items["video_captions"]   = 70 if soup.find_all("video") else 100
        items["audio_transcripts"]= 70 if soup.find_all("audio") else 100

        # Robots / sitemap
        items["robots_exists"]  = _check_url(url, "/robots.txt")
        items["sitemap_exists"] = _check_url(url, "/sitemap.xml")

        # Stash raw HTML for AI (not scored)
        items["_html_content"] = r.text[:10_000]
        return items
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────
#  AUDIT ROUTE
# ─────────────────────────────────────────────────────────────

CATEGORY_KEYS = {
    "Performance":    ["lcp", "fid", "cls", "ttfb", "fcp", "performance_score",
                       "dom_size", "request_count", "page_size"],
    "Security":       ["ssl_days_left", "tls_version", "hsts", "csp", "xfo",
                       "xss_protection", "content_type", "referrer_policy",
                       "cookies_secure", "cookies_httponly", "cookies_samesite"],
    "Safety":         ["malware_detected", "phishing_detected", "unwanted_software",
                       "harmful_apps", "social_engineering", "safe_browsing_score",
                       "blacklist_status"],
    "Infrastructure": ["dns_time_ms", "server_response_time", "cdn_detected",
                       "compression", "http2_enabled", "hsts_preload", "tls13_enabled"],
    "SEO":            ["title_present", "title_length", "meta_description_present",
                       "viewport_present", "lang_present", "h1_count", "alt_percentage",
                       "schema_present", "robots_exists", "sitemap_exists",
                       "canonical_present", "og_tags_present", "twitter_cards",
                       "favicon_present", "keywords_meta"],
    "Accessibility":  ["lang_attribute", "aria_count", "skip_link_present",
                       "heading_structure", "alt_text_present", "alt_text_quality",
                       "form_labels", "color_contrast", "focus_visible", "aria_roles",
                       "aria_labels", "video_captions", "audio_transcripts",
                       "table_headers", "table_caption"],
    "Business":       ["contact_info", "cta_count", "cta_visibility", "privacy_policy",
                       "terms_of_service", "about_page", "social_links", "trust_badges",
                       "testimonials", "pricing_visible", "faq_page", "blog_present",
                       "newsletter", "live_chat", "return_policy"],
}

CATEGORY_ICONS = {
    "Performance": "⚡", "Security": "🔒", "Safety": "🛡️",
    "Infrastructure": "🌐", "SEO": "📈", "Accessibility": "♿", "Business": "💰",
}

# Default score for safety items is 100 (assume clean until proven otherwise)
SAFETY_DEFAULTS = {k: 100 for k in CATEGORY_KEYS["Safety"]}


@app.route("/api/audit", methods=["POST"])
def audit():
    try:
        data = request.get_json()
        url  = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "URL required"}), 400
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        domain = urlparse(url).netloc

        # Run all checks in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            f_ps  = ex.submit(get_pagespeed_data,  url)
            f_sb  = ex.submit(get_safe_browsing_data, url)
            f_ssl = ex.submit(get_ssl_data,        url)
            f_hdr = ex.submit(get_headers_data,    url)
            f_srv = ex.submit(get_server_data,     url)
            f_dns = ex.submit(get_dns_data,        domain)
            f_html= ex.submit(analyze_html,        url)

            raw = {
                **f_ps.result(timeout=15),
                **SAFETY_DEFAULTS,           # defaults for safety (overwritten by SB below)
                **f_sb.result(timeout=6),
                **f_ssl.result(timeout=6),
                **f_hdr.result(timeout=6),
                **f_srv.result(timeout=6),
                **f_dns.result(timeout=6),
                **f_html.result(timeout=10),
            }

        html_content = raw.pop("_html_content", "")

        # Normalize all raw values to 0-100
        items = {k: normalize_value(v, k) for k, v in raw.items()}

        # Build category scores
        categories = []
        for name, keys in CATEGORY_KEYS.items():
            scores = [items.get(k, 50) for k in keys if k in items]
            avg    = int(sum(scores) / len(scores)) if scores else 50
            categories.append({
                "name":  name,
                "icon":  CATEGORY_ICONS[name],
                "score": avg,
                "count": len(keys),
            })

        overall = int(sum(c["score"] for c in categories) / len(categories))

        strengths  = [f"{c['icon']} {c['name']}: {c['score']}" for c in categories if c["score"] >= 80]
        weaknesses = [f"{c['icon']} {c['name']}: {c['score']}" for c in categories if c["score"] < 50]

        priority_items = sorted(
            [
                {
                    "name":    ANALYSIS_DB[k].get("name", k),
                    "score":   v,
                    "priority":ANALYSIS_DB[k].get("priority", "medium"),
                    "action":  ANALYSIS_DB[k].get("action", "Needs attention"),
                    "details": ANALYSIS_DB[k].get("details", ""),
                    "impact":  ANALYSIS_DB[k].get("impact", ""),
                    "time":    ANALYSIS_DB[k].get("time", "Unknown"),
                    "effort":  ANALYSIS_DB[k].get("effort", "medium"),
                }
                for k, v in items.items()
                if k in ANALYSIS_DB and ANALYSIS_DB[k].get("priority") in ("critical", "high") and v < 50
            ],
            key=lambda x: (x["priority"] != "critical", x["score"]),
        )[:7]

        ai_text = generate_ai_analysis(url, categories, strengths, weaknesses, priority_items)

        result = {
            "url":              url,
            "timestamp":        datetime.now().isoformat(),
            "session_id":       hashlib.md5(f"{url}{datetime.now()}".encode()).hexdigest()[:8],
            "overall":          overall,
            "items":            items,
            "analysis_db":      ANALYSIS_DB,
            "ai_analysis":      ai_text,
            "categories":       categories,
            "strengths":        strengths,
            "weaknesses":       weaknesses,
            "priority_items":   priority_items,
            "item_count":       len(items),
            "estimated_roi":    int((100 - categories[0]["score"]) * 0.3 +
                                    (100 - next(c["score"] for c in categories if c["name"] == "SEO")) * 0.4),
        }

        # Persist to user history
        if "user" in session:
            email = session["user"]["email"]
            _init_user(email)
            user_data[email]["history"].append({
                "url":           url,
                "timestamp":     result["timestamp"],
                "overall":       overall,
                "session_id":    result["session_id"],
                "estimated_roi": result["estimated_roi"],
                "item_count":    len(items),
            })
            user_data[email]["history"] = user_data[email]["history"][-20:]

        return jsonify(result)

    except Exception:
        return jsonify({"error": "Audit failed", "detail": traceback.format_exc()}), 500


# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting Website Health Audit on http://0.0.0.0:8081")
    app.run(host="0.0.0.0", port=8081, debug=False, threaded=True)
