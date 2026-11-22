import io
import re
import ast
import difflib
import random
import unicodedata
import base64
import html as htmllib
import fitz  # PyMuPDF
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from rapidfuzz import fuzz

import streamlit_authenticator as stauth


# ==============================================================================
# 0. LOGIN SYSTEM  (নতুন অ্যাকাউন্টে অ্যাডমিন অনুমতি + যেকোনো সময় ব্লক)
# ==============================================================================
import json
import os
import secrets
import smtplib
import threading
import hashlib
import hmac
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import bcrypt

_ICON = "assets/icon/ficon.png"
st.set_page_config(
    page_title="BMS IT BD - D-CODE Memo Print",
    page_icon=_ICON if os.path.exists(_ICON) else "🔒",
    layout="wide",
)


def cfg(key, default=""):
    """Streamlit Secrets থেকে মান পড়ে; না থাকলে ডিফল্ট।"""
    try:
        return st.secrets[key]
    except Exception:
        return os.environ.get(key, default)


ADMIN_USERNAME = cfg("ADMIN_USERNAME", "kishor")
ADMIN_PASSWORD = cfg("ADMIN_PASSWORD", "test@123")
ADMIN_NAME = cfg("ADMIN_NAME", "Kishor Kumar")
ADMIN_EMAIL = cfg("ADMIN_EMAIL", "kishor3das@gmail.com")   # নোটিফিকেশন এই জিমেইলে যাবে
GMAIL_ADDRESS = cfg("GMAIL_ADDRESS", "kishor3das@gmail.com")           # যে জিমেইল থেকে মেইল পাঠানো হবে
GMAIL_APP_PASSWORD = cfg("GMAIL_APP_PASSWORD", "")          # Gmail App Password (Secrets-এ দিন)
APP_URL = cfg("APP_URL", "https://kishor01852792728.streamlit.app").rstrip("/")
COOKIE_KEY = cfg("COOKIE_KEY", "pdf-fix-secret-cookie-key-change-me")
LOGIN_TITLE = "D-CODE Memo Print"

# ----------------------------- ডাটাবেস (JSON) -----------------------------
DB_FILE = "users_db.json"
_db_lock = threading.Lock()


def load_db():
    with _db_lock:
        if not os.path.exists(DB_FILE):
            return {"users": {}}
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"users": {}}


def save_db(db):
    with _db_lock:
        tmp = DB_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
        os.replace(tmp, DB_FILE)


def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


@st.cache_data(show_spinner=False)
def _admin_hash(pw: str) -> str:
    return hash_pw(pw)


# ----------------------------- "মনে রাখুন" টোকেন (রিফ্রেশেও লগইন থাকবে) -----------------------------
TOKEN_DAYS = 365


def _tok_hash(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def token_user(tok):
    """টোকেন বৈধ হলে ইউজারনেম ফেরত দেয়।"""
    rec = load_db().get("tokens", {}).get(_tok_hash(tok))
    if not rec or rec["exp"] < time.time():
        return None
    return rec["username"]


def issue_token(username):
    tok = secrets.token_urlsafe(32)
    db = load_db()
    now = time.time()
    toks = {h: r for h, r in db.get("tokens", {}).items() if r["exp"] > now}
    toks[_tok_hash(tok)] = {"username": username, "exp": now + TOKEN_DAYS * 86400}
    db["tokens"] = toks
    save_db(db)
    return tok


def revoke_token(tok):
    db = load_db()
    db.get("tokens", {}).pop(_tok_hash(tok), None)
    save_db(db)


# ----------------------------- স্থায়ী লগইন কুকি (সই করা; ব্রাউজার মনে রাখবে) -----------------------------
# লগইনের পর ব্রাউজারে একটি সই-করা কুকি বসে। পরে রিফ্রেশ করলে বা কয়েকদিন পর লিংকে ঢুকলে
# সার্ভার ওই কুকি যাচাই করে সরাসরি লগইন করিয়ে দেয় (st.context.cookies — কোনো অপেক্ষা লাগে না)।
# প্রতিবার অ্যাপ খুললে কুকির মেয়াদ নতুন করে বাড়ে, তাই নিয়মিত ব্যবহারে কখনো শেষ হয় না।
AUTH_COOKIE = "dcode_auth"
COOKIE_MAX_AGE = 400 * 86400   # ব্রাউজারগুলো সর্বোচ্চ ~৪০০ দিন মানে; প্রতি ভিজিটে নবায়ন হয়


def _cookie_secret(username):
    """ইউজারের পাসওয়ার্ড বদলালে/ডিলিট হলে পুরনো কুকি আপনাআপনি অচল হয়ে যায়।"""
    if username == ADMIN_USERNAME:
        return hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    u = load_db()["users"].get(username)
    return u["password"] if u else None


def _cookie_sig(msg, sec):
    return hmac.new((COOKIE_KEY + sec).encode(), msg.encode(), hashlib.sha256).hexdigest()


def make_auth_cookie(username):
    sec = _cookie_secret(username)
    if sec is None:
        return None
    msg = f"{username}.{int(time.time()) + COOKIE_MAX_AGE}"
    return f"{msg}.{_cookie_sig(msg, sec)}"


def verify_auth_cookie(val):
    """কুকি বৈধ হলে ইউজারনেম ফেরত দেয়, নইলে None।"""
    try:
        username, exp, sig = val.rsplit(".", 2)
        sec = _cookie_secret(username)
        if sec is None or int(exp) < time.time():
            return None
        if not hmac.compare_digest(sig, _cookie_sig(f"{username}.{exp}", sec)):
            return None
        return username
    except Exception:
        return None


def read_auth_cookie():
    try:
        return st.context.cookies.get(AUTH_COOKIE)
    except Exception:
        return None


def write_auth_cookie(value, max_age=COOKIE_MAX_AGE):
    """ব্রাউজারে লগইন কুকি + localStorage ব্যাকআপ বসায় (max_age=0 হলে দুটোই মুছে দেয়)।
    নতুন Streamlit-এ st.html(unsafe_allow_javascript=True) মূল পেজে চলে;
    পুরনো ভার্সনের জন্য components.html (iframe) ফ্যালব্যাক আছে।"""
    def _js(win):
        ls = (f"{win}localStorage.removeItem('{AUTH_COOKIE}');" if max_age == 0
              else f"{win}localStorage.setItem('{AUTH_COOKIE}',{json.dumps(value)});"
                   f"{win}sessionStorage.removeItem('dcode_restore');")
        return (
            "(function(){try{"
            f"var secure=({win}location.protocol==='https:')?'; Secure':'';"
            f"{win}document.cookie='{AUTH_COOKIE}='+{json.dumps(value)}"
            f"+'; max-age={max_age}; path=/; SameSite=Lax'+secure;"
            f"{ls}"
            "}catch(e){}})();"
        )

    try:
        st.html(f"<script>{_js('')}</script>", unsafe_allow_javascript=True)
        return
    except Exception:
        pass
    try:
        components.html(f"<script>{_js('window.parent.')}</script>", height=0)
    except Exception:
        pass


_RESTORE_JS = (
    "var t=localStorage.getItem('%s');"
    "if(!t)return false;"
    "var u=new URL(window.location.href);"
    "u.searchParams.set('dtk',t);"
    "window.location.replace(u.toString());"
    "return true;"
) % AUTH_COOKIE


def restore_cookie_from_backup():
    """লগইন পেজে: সার্ভার কুকি না পেলেও ব্রাউজারের localStorage-এ টোকেন থাকলে
    সেটা ?dtk= দিয়ে সার্ভারকে পাঠিয়ে পেজ রিলোড করে (একবারই চেষ্টা করে, লুপ হয় না)।"""
    if st.query_params.get("debug") == "1":
        return   # ডিবাগ মোডে অটো-রিডাইরেক্ট বন্ধ, নিচের বাটন দিয়ে হাতে চেষ্টা করুন
    try:
        st.html(
            "<script>(function(){try{"
            "if(sessionStorage.getItem('dcode_restore'))return;"
            "sessionStorage.setItem('dcode_restore','1');"
            + _RESTORE_JS +
            "}catch(e){}})();</script>",
            unsafe_allow_javascript=True,
        )
    except Exception:
        pass


def login_debug_panel():
    """?debug=1 দিয়ে অ্যাপ খুললে লগইন কুকির অবস্থা দেখায় (সমস্যা ধরার জন্য)।"""
    if st.query_params.get("debug") != "1":
        return
    with st.expander("🔧 লগইন ডায়াগনস্টিক", expanded=True):
        try:
            names = list(st.context.cookies.keys())
        except Exception as e:
            names = f"st.context.cookies পড়া যায়নি: {e}"
        raw = read_auth_cookie()
        st.write({
            "streamlit_version": st.__version__,
            "st.context আছে?": hasattr(st, "context"),
            "ব্রাউজার থেকে আসা কুকির নাম": names,
            f"{AUTH_COOKIE} কুকি এসেছে?": bool(raw),
            "কুকি যাচাই ফল (ইউজারনেম)": verify_auth_cookie(raw or ""),
            "authentication_status": st.session_state.get("authentication_status"),
            "_user_logged_out": st.session_state.get("_user_logged_out"),
            "_cookie_set": st.session_state.get("_cookie_set"),
        })
        try:
            st.html(
                '<div id="dcode_dbg" style="font:13px monospace;white-space:pre-wrap">JS চলেনি ❌</div>'
                '<button id="dcode_try" style="margin-top:6px">টোকেন দিয়ে লগইন চেষ্টা করুন</button>'
                "<script>setTimeout(function(){try{"
                "var el=document.getElementById('dcode_dbg');"
                "var names=document.cookie.split('; ').map(function(c){return c.split('=')[0]}).filter(Boolean);"
                "el.textContent='JS চলছে ✅\\nব্রাউজারের কুকি: '+(names.join(', ')||'(কিছু নেই)')"
                f"+'\\nlocalStorage {AUTH_COOKIE}: '+(localStorage.getItem('{AUTH_COOKIE}')?'আছে ✅':'নেই ❌')"
                "+'\\nsessionStorage guard: '+sessionStorage.getItem('dcode_restore');"
                "document.getElementById('dcode_try').onclick=function(){(function(){"
                + _RESTORE_JS +
                "})();};"
                "}catch(e){document.getElementById('dcode_dbg').textContent='JS ত্রুটি: '+e;}},300);</script>",
                unsafe_allow_javascript=True,
            )
        except Exception as e:
            st.write(f"st.html JS চালানো যায়নি: {e}")


# ----------------------------- ইমেইল -----------------------------
def send_mail(to_addr, subject, html):
    if not (GMAIL_ADDRESS and GMAIL_APP_PASSWORD and to_addr):
        return False, "GMAIL_APP_PASSWORD সেট করা নেই"
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = GMAIL_ADDRESS
        msg["To"] = to_addr
        msg.attach(MIMEText(html, "html", "utf-8"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as server:
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, to_addr, msg.as_string())
        return True, ""
    except Exception as e:
        return False, str(e)


def notify_admin_new_signup(username, user):
    approve = f"{APP_URL}/?action=approve&token={user['token']}"
    reject = f"{APP_URL}/?action=reject&token={user['token']}"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;
                border-radius:16px;background:#fffbea;border:1px solid #f3e2a9">
      <h2 style="margin-top:0;color:#b77d00">🔔 নতুন অ্যাকাউন্টের অনুরোধ</h2>
      <p><b>নাম:</b> {user['name']}<br><b>ইউজারনেম:</b> {username}<br>
         <b>ইমেইল:</b> {user['email']}<br><b>সময়:</b> {user['created_at']}</p>
      <p style="margin-top:24px">
        <a href="{approve}" style="background:#16a34a;color:#fff;padding:12px 22px;
           border-radius:10px;text-decoration:none;font-weight:bold">✅ অনুমতি দিন</a>
        &nbsp;
        <a href="{reject}" style="background:#dc2626;color:#fff;padding:12px 22px;
           border-radius:10px;text-decoration:none;font-weight:bold">❌ বাতিল করুন</a>
      </p>
    </div>"""
    return send_mail(ADMIN_EMAIL, f"নতুন সাইনআপ অনুরোধ: {username}", html)


def notify_user_approved(user):
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;
                border-radius:16px;background:#f0fdf4;border:1px solid #bbf7d0">
      <h2 style="margin-top:0;color:#16a34a">✅ আপনার অ্যাকাউন্ট অনুমোদিত হয়েছে</h2>
      <p>হ্যালো {user['name']}, এখন আপনি লগইন করতে পারবেন।</p>
      <p><a href="{APP_URL}" style="background:#f2a900;color:#3b2800;padding:12px 22px;
         border-radius:10px;text-decoration:none;font-weight:bold">অ্যাপ খুলুন</a></p>
    </div>"""
    send_mail(user["email"], f"{LOGIN_TITLE} - অ্যাকাউন্ট অনুমোদিত", html)


# ----------------------------- লগইন পেজের স্টাইল -----------------------------
AUTH_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+Bengali:wght@400;600;700;800&display=swap');
#MainMenu, footer, header {visibility:hidden;}
.stApp, .stApp button, .stApp input, .stApp label, .stApp p{font-family:'Noto Sans Bengali',Arial,sans-serif;}
.stApp{background:linear-gradient(135deg,#fffdf4 0%,#fff3c9 45%,#ffe4ef 100%);background-attachment:fixed;}
.block-container{position:relative;z-index:1;padding-top:2rem !important;}

/* ভাসমান রঙিন ব্লব */
.stApp::before,.stApp::after{content:"";position:fixed;border-radius:50%;filter:blur(55px);
  pointer-events:none;z-index:0;opacity:.75;}
.stApp::before{width:520px;height:520px;top:-160px;left:-140px;
  background:radial-gradient(circle,#ffc933,transparent 68%);animation:au-float 14s ease-in-out infinite;}
.stApp::after{width:560px;height:560px;bottom:-200px;right:-160px;
  background:radial-gradient(circle,#ff8fb8,transparent 68%);animation:au-float 18s ease-in-out infinite reverse;}
@keyframes au-float{0%,100%{transform:translate(0,0) scale(1);}50%{transform:translate(50px,40px) scale(1.12);}}
@keyframes au-up{from{opacity:0;transform:translateY(26px);}to{opacity:1;transform:none;}}
@keyframes au-pulse{0%{box-shadow:0 0 0 0 rgba(242,169,0,.55);}70%{box-shadow:0 0 0 22px rgba(242,169,0,0);}100%{box-shadow:0 0 0 0 rgba(242,169,0,0);}}
@keyframes au-shine{0%{background-position:0% 50%;}100%{background-position:200% 50%;}}

/* হিরো */
.au-hero{text-align:center;margin:1.4rem 0 1.1rem;animation:au-up .6s ease both;}
.au-logo{width:84px;height:84px;margin:0 auto 16px;border-radius:28px;display:flex;align-items:center;
  justify-content:center;font-size:40px;background:linear-gradient(135deg,#ffe07a,#f2a900 60%,#e08a00);
  box-shadow:0 16px 36px rgba(242,169,0,.45), inset 0 2px 0 rgba(255,255,255,.55);
  animation:au-pulse 2.6s infinite;transform:rotate(-6deg);}
.au-hero h1{font-size:2rem;margin:0;font-weight:800;letter-spacing:-.3px;
  background:linear-gradient(90deg,#3b2f10,#b77d00 55%,#3b2f10);-webkit-background-clip:text;
  background-clip:text;-webkit-text-fill-color:transparent;}
.au-hero p{color:#8a7440;margin:.45rem 0 0;font-size:.98rem;}
.au-chips{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:14px;}
.au-chip{font-size:.78rem;font-weight:700;color:#7a5a00;background:rgba(255,255,255,.7);
  border:1px solid rgba(243,226,169,.9);padding:5px 12px;border-radius:99px;backdrop-filter:blur(6px);}

/* গ্লাস কার্ড */
.st-key-auth_card{background:rgba(255,255,255,.74);backdrop-filter:blur(20px) saturate(170%);
  -webkit-backdrop-filter:blur(20px) saturate(170%);border:1px solid rgba(255,255,255,.9);
  border-radius:28px;padding:20px 24px 12px;
  box-shadow:0 30px 70px rgba(184,134,11,.22),0 2px 0 rgba(255,255,255,.9) inset;
  animation:au-up .8s cubic-bezier(.2,.8,.2,1) both;}

/* ট্যাব: সেগমেন্টেড কন্ট্রোল */
.stTabs [data-baseweb="tab-list"]{background:rgba(243,226,169,.4);padding:5px;border-radius:16px;gap:4px;border:0;}
.stTabs [data-baseweb="tab"]{flex:1;justify-content:center;height:42px;border-radius:12px;
  font-weight:700;color:#8a7440;transition:all .2s ease;}
.stTabs [aria-selected="true"]{background:#fff;color:#3b2800;box-shadow:0 6px 16px rgba(212,160,23,.28);}
.stTabs [data-baseweb="tab-highlight"],.stTabs [data-baseweb="tab-border"]{display:none;}

/* ফর্ম ও ইনপুট */
[data-testid="stForm"]{border:0 !important;padding:6px 0 0 !important;background:transparent;}
.stTextInput label p{font-weight:700;color:#5a4410;font-size:.88rem;}
.stTextInput div[data-baseweb="input"]{border-radius:14px;background:rgba(255,255,255,.9);
  border:1.5px solid #f0dc9c;transition:all .2s ease;}
.stTextInput div[data-baseweb="input"]:focus-within{border-color:#f2a900;
  box-shadow:0 0 0 4px rgba(242,169,0,.18);transform:translateY(-1px);}
.stTextInput input{padding:.7rem .9rem;}

/* বাটন */
.stButton>button,.stFormSubmitButton>button{width:100%;border:0;border-radius:14px;padding:.75rem 1rem;
  font-weight:800;font-size:1rem;color:#3b2800;
  background:linear-gradient(110deg,#ffd34d,#f2a900,#ffd34d,#f2a900);background-size:200% 100%;
  animation:au-shine 4s linear infinite;box-shadow:0 10px 22px rgba(242,169,0,.4);
  transition:transform .15s ease,box-shadow .15s ease;}
.stButton>button:hover,.stFormSubmitButton>button:hover{transform:translateY(-2px);
  box-shadow:0 14px 30px rgba(242,169,0,.55);color:#3b2800;}
.stButton>button:active,.stFormSubmitButton>button:active{transform:scale(.98);}

/* অ্যালার্ট */
[data-testid="stAlert"]{border-radius:14px;}

/* ইউজার কার্ড (অ্যাডমিন প্যানেল) */
.au-user{background:rgba(255,255,255,.9);border:1px solid #f3e2a9;border-radius:18px;padding:14px 18px;
  margin-bottom:10px;box-shadow:0 6px 18px rgba(212,160,23,.12);transition:transform .15s ease;}
.au-user:hover{transform:translateY(-2px);}
.au-foot{text-align:center;color:#a8924f;font-size:.78rem;margin-top:1.2rem;}
</style>
"""


def au_hero(title, subtitle, icon="🔐", chips=False):
    chip_html = ""
    if chips:
        chip_html = (
            '<div class="au-chips"><span class="au-chip">🔒 সুরক্ষিত লগইন</span>'
            '<span class="au-chip">✅ অ্যাডমিন অনুমোদিত</span>'
            '<span class="au-chip">⚡ দ্রুত ও সহজ</span></div>'
        )
    st.markdown(
        f'<div class="au-hero"><div class="au-logo">{icon}</div>'
        f"<h1>{title}</h1><p>{subtitle}</p>{chip_html}</div>",
        unsafe_allow_html=True,
    )


# ----------------------------- ইমেইলের লিংক থেকে অনুমতি/বাতিল -----------------------------
def handle_email_action():
    action = st.query_params.get("action")
    token = st.query_params.get("token")
    if not action or not token:
        return
    st.markdown(AUTH_CSS, unsafe_allow_html=True)
    db = load_db()
    target = next(
        (u for u, v in db["users"].items() if v.get("token") == token and v["status"] == "pending"),
        None,
    )
    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        au_hero("সাইনআপ অনুরোধ", "অ্যাডমিন কনফার্মেশন", "📩")
        if not target:
            st.warning("এই লিংকটি আর বৈধ নয় (আগেই অনুমোদন/বাতিল করা হয়েছে)।")
        else:
            u = db["users"][target]
            st.markdown(
                f'<div class="au-user"><b>{u["name"]}</b><br>👤 {target}<br>✉️ {u["email"]}</div>',
                unsafe_allow_html=True,
            )
            if action == "approve" and st.button("✅ হ্যাঁ, অনুমতি দিন"):
                db["users"][target]["status"] = "approved"
                db["users"][target]["token"] = ""
                save_db(db)
                notify_user_approved(u)
                st.success("অনুমোদন সম্পন্ন! ব্যবহারকারীকে ইমেইলে জানানো হয়েছে।")
            elif action == "reject" and st.button("❌ হ্যাঁ, বাতিল করুন"):
                del db["users"][target]
                save_db(db)
                st.success("অনুরোধ বাতিল করা হয়েছে।")
        if st.button("⬅️ অ্যাপে ফিরে যান", key="back_home"):
            st.query_params.clear()
            st.rerun()
    st.stop()


handle_email_action()

# ----------------------------- Authenticator -----------------------------
def build_credentials():
    creds = {
        "usernames": {
            ADMIN_USERNAME: {
                "name": ADMIN_NAME,
                "email": ADMIN_EMAIL,
                "password": _admin_hash(ADMIN_PASSWORD),
            }
        }
    }
    for uname, u in load_db()["users"].items():
        if u["status"] == "approved":   # শুধু অনুমোদিতরাই লগইন করতে পারবে
            creds["usernames"][uname] = {
                "name": u["name"],
                "email": u["email"],
                "password": u["password"],
            }
    return creds


authenticator = stauth.Authenticate(
    build_credentials(),
    cookie_name="pdf_fix_auth",
    cookie_key=COOKIE_KEY,
    cookie_expiry_days=3650,
    auto_hash=False,
)

# আগের ভুল/পুরনো ?t=... লিংক থাকলে সরিয়ে দিই (লিংক শেয়ার করলে অন্যের লগইন ফাঁস হতো)
if "t" in st.query_params:
    del st.query_params["t"]

# ব্রাউজারের স্থায়ী কুকি থেকে অটো-লগইন (রিফ্রেশ বা কয়েকদিন পরে লিংকে ঢুকলেও)
_dtk = st.query_params.get("dtk")        # ব্রাউজারের localStorage থেকে JS যে টোকেন পাঠায়
if "dtk" in st.query_params:
    del st.query_params["dtk"]            # সাথে সাথে URL থেকে সরিয়ে দিই
if not st.session_state.get("authentication_status") and not st.session_state.get("_user_logged_out"):
    _cu = verify_auth_cookie(_dtk or "") or verify_auth_cookie(read_auth_cookie() or "")
    _cinfo = None
    if _cu == ADMIN_USERNAME:
        _cinfo = (ADMIN_NAME, ADMIN_EMAIL)
    elif _cu:
        _crec = load_db()["users"].get(_cu)
        if _crec and _crec["status"] == "approved":   # ব্লক করা হলে অটো-লগইন হবে না
            _cinfo = (_crec["name"], _crec["email"])
    if _cinfo:
        st.session_state["authentication_status"] = True
        st.session_state["username"] = _cu
        st.session_state["name"] = _cinfo[0]
        st.session_state["email"] = _cinfo[1]
        st.session_state["roles"] = None
        st.session_state["logout"] = False

authenticator.login(location="unrendered")   # কুকি থেকে আগের লগইন চেক

# ব্রাউজারের কুকি পড়তে প্রথমবার একটু সময় লাগে; সেই সময়টুকু অপেক্ষা করে নিই
# (নইলে রিফ্রেশ দিলে মুহূর্তের জন্য লগইন ফর্ম ঝলকে ওঠে)
if st.session_state.get("authentication_status") is None and not st.session_state.get("_cookie_wait"):
    import time as _time
    st.session_state["_cookie_wait"] = True
    st.markdown(AUTH_CSS, unsafe_allow_html=True)
    au_hero(LOGIN_TITLE, "লোড হচ্ছে…", "⏳")
    _time.sleep(1.2)
    st.rerun()


# ----------------------------- সাইনআপ ফর্ম -----------------------------
def signup_form():
    with st.form("signup_form", clear_on_submit=False):
        name = st.text_input("পুরো নাম")
        email = st.text_input("ইমেইল")
        username = st.text_input("ইউজারনেম (ইংরেজি অক্ষর/সংখ্যা)")
        pw1 = st.text_input("পাসওয়ার্ড", type="password")
        pw2 = st.text_input("পাসওয়ার্ড আবার দিন", type="password")
        submit = st.form_submit_button("📩 অনুরোধ পাঠান")
    if not submit:
        return
    username, email, name = username.strip().lower(), email.strip().lower(), name.strip()

    if not (name and email and username and pw1):
        st.error("সবগুলো ঘর পূরণ করুন।")
        return
    if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
        st.error("ইউজারনেম ৩-২০ অক্ষরের হতে হবে (a-z, 0-9, _)।")
        return
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        st.error("সঠিক ইমেইল দিন।")
        return
    if len(pw1) < 6:
        st.error("পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে।")
        return
    if pw1 != pw2:
        st.error("দুইটি পাসওয়ার্ড মিলছে না।")
        return

    db = load_db()
    if username == ADMIN_USERNAME.lower() or username in db["users"]:
        st.error("এই ইউজারনেম আগে থেকেই আছে।")
        return
    if any(v["email"] == email for v in db["users"].values()):
        st.error("এই ইমেইল দিয়ে আগেই অনুরোধ/অ্যাকাউন্ট আছে।")
        return

    user = {
        "name": name,
        "email": email,
        "password": hash_pw(pw1),
        "status": "pending",
        "token": secrets.token_urlsafe(24),
        "created_at": datetime.now().strftime("%d-%m-%Y %I:%M %p"),
    }
    db["users"][username] = user
    save_db(db)
    ok, err = notify_admin_new_signup(username, user)
    st.success("✅ অনুরোধ পাঠানো হয়েছে! অ্যাডমিন অনুমতি দিলে আপনি লগইন করতে পারবেন।")
    if not ok:
        st.warning(f"অ্যাডমিনকে ইমেইল পাঠানো যায়নি: {err}")


# ----------------------------- লগইন পেজ -----------------------------
def auth_page():
    st.markdown(AUTH_CSS, unsafe_allow_html=True)
    if not hasattr(st, "context"):
        st.warning("⚠️ স্থায়ী লগইনের জন্য Streamlit ১.৩৭ বা তার বেশি লাগবে। requirements.txt-এ `streamlit>=1.50` দিন।")
    restore_cookie_from_backup()
    login_debug_panel()
    au_hero(LOGIN_TITLE, "আপনার অ্যাকাউন্টে প্রবেশ করুন", "🔐", chips=True)
    _, mid, _ = st.columns([1, 1.25, 1])
    with mid:
        with st.container(key="auth_card"):
            tab_login, tab_signup = st.tabs(["🔑 লগইন", "✨ নতুন অ্যাকাউন্ট"])
            with tab_login:
                authenticator.login(
                    location="main",
                    fields={
                        "Form name": "স্বাগতম 👋",
                        "Username": "ইউজারনেম",
                        "Password": "পাসওয়ার্ড",
                        "Login": "লগইন করুন",
                    },
                )
                if st.session_state.get("authentication_status") is False:
                    st.caption("অনুমোদনের অপেক্ষায় থাকলে অথবা ব্লক হলে লগইন কাজ করবে না।")
            with tab_signup:
                st.caption("অনুরোধ পাঠানোর পর অ্যাডমিন অনুমতি দিলে তবেই লগইন করা যাবে।")
                signup_form()
        st.markdown('<div class="au-foot">✨ Developed with kishor</div>', unsafe_allow_html=True)


# ----------------------------- অ্যাডমিন প্যানেল -----------------------------
def _user_row(uname, u, buttons):
    c1, *cols = st.columns([3] + [1.4] * len(buttons))
    with c1:
        st.markdown(
            f'<div class="au-user"><b>{u["name"]}</b> '
            f'<span style="color:#8a7440">@{uname}</span><br>✉️ {u["email"]}<br>'
            f'<small>🕒 {u.get("created_at", "")}</small></div>',
            unsafe_allow_html=True,
        )
    for col, (label, prefix, fn) in zip(cols, buttons):
        with col:
            st.write("")
            if st.button(label, key=f"{prefix}_{uname}"):
                fn(uname)
                st.rerun()


def admin_panel():
    st.markdown(AUTH_CSS, unsafe_allow_html=True)
    au_hero("অ্যাডমিন প্যানেল", "ব্যবহারকারী অনুমতি ও নিয়ন্ত্রণ", "🛡️")
    users = load_db()["users"]
    pending = {k: v for k, v in users.items() if v["status"] == "pending"}
    active = {k: v for k, v in users.items() if v["status"] == "approved"}
    blocked = {k: v for k, v in users.items() if v["status"] == "blocked"}

    def set_status(status):
        def _f(uname):
            d = load_db()
            d["users"][uname]["status"] = status
            d["users"][uname]["token"] = ""
            save_db(d)
            if status == "approved":
                notify_user_approved(d["users"][uname])
        return _f

    def delete(uname):
        d = load_db()
        d["users"].pop(uname, None)
        save_db(d)

    t1, t2, t3 = st.tabs([
        f"⏳ অপেক্ষমাণ ({len(pending)})",
        f"✅ সক্রিয় ({len(active)})",
        f"🚫 ব্লকড ({len(blocked)})",
    ])
    with t1:
        if not pending:
            st.info("কোনো অপেক্ষমাণ অনুরোধ নেই।")
        for k, v in pending.items():
            _user_row(k, v, [("✅ অনুমতি", "ap", set_status("approved")), ("❌ বাতিল", "rj", delete)])
    with t2:
        if not active:
            st.info("কোনো সক্রিয় ব্যবহারকারী নেই।")
        for k, v in active.items():
            _user_row(k, v, [("🚫 বের করে দিন", "bl", set_status("blocked")), ("🗑️ ডিলিট", "dl", delete)])
    with t3:
        if not blocked:
            st.info("কেউ ব্লকড নেই।")
        for k, v in blocked.items():
            _user_row(k, v, [("↩️ আবার অনুমতি", "ub", set_status("approved")), ("🗑️ ডিলিট", "dl2", delete)])


# ----------------------------- গেট: লগইন ছাড়া নিচের অ্যাপ চলবে না -----------------------------
if not st.session_state.get("authentication_status"):
    auth_page()
    if st.session_state.get("authentication_status"):
        # লগইনের কুকি ব্রাউজারে লেখা শেষ হতে একটু সময় লাগে; সাথে সাথে রিরান করলে কুকি সেভ হয় না
        import time as _t
        st.success("✅ লগইন সফল! অ্যাপ খুলছে…")
        _t.sleep(2)
        st.rerun()
    st.stop()

_me = st.session_state.get("username")
_is_admin = _me == ADMIN_USERNAME

# অ্যাডমিন ব্লক করলে চলমান সেশনও সাথে সাথে বন্ধ হবে
if not _is_admin:
    _rec = load_db()["users"].get(_me)
    if not _rec or _rec["status"] != "approved":
        authenticator.logout(location="unrendered")
        st.rerun()

# এই ব্রাউজারকে মনে রাখার জন্য কুকি বসাই/নবায়ন করি (প্রতি সেশনে একবার)
st.session_state["_user_logged_out"] = False
if not st.session_state.get("_cookie_set"):
    _ck = make_auth_cookie(_me)
    if _ck:
        write_auth_cookie(_ck)
        st.session_state["_cookie_set"] = True

login_debug_panel()

# উপরের ছোট বার: নাম + (অ্যাডমিনের জন্য প্যানেল বাটন) + লগআউট
_c1, _c2, _c3 = st.columns([5, 2, 2], gap="small")
_c1.markdown(
    f"<div style='padding-top:6px;font-weight:700;color:#3b2f10'>👤 {st.session_state.get('name')}"
    f"{' · অ্যাডমিন' if _is_admin else ''}</div>",
    unsafe_allow_html=True,
)
if _is_admin:
    _show_admin = st.session_state.get("show_admin", False)
    if _c2.button("🏠 অ্যাপে ফিরুন" if _show_admin else "🛡️ অ্যাডমিন প্যানেল", key="toggle_admin", use_container_width=True):
        st.session_state["show_admin"] = not _show_admin
        st.rerun()
with _c3:
    if st.button("🚪 লগআউট", key="logout_main", use_container_width=True):
        st.session_state["_user_logged_out"] = True
        st.session_state["_cookie_set"] = False
        write_auth_cookie("", max_age=0)   # স্থায়ী কুকি মুছি
        authenticator.logout(location="unrendered")
        time.sleep(1)   # কুকি মোছার সময় দিই
        st.rerun()

if _is_admin and st.session_state.get("show_admin", False):
    admin_panel()
    st.stop()
# ==============================================================================
# লগইন সিস্টেম শেষ — নিচে আপনার মূল অ্যাপ
# ==============================================================================


# ------------------------------------------------------------------------------
# 1. CONSTANTS & REGEX PATTERNS
# ------------------------------------------------------------------------------
BANGLA_DIGITS = "১২৩৪৫৬৭৮৯০"
ENGLISH_DIGITS = "1234567890"
TRANSLATION_TABLE = str.maketrans(BANGLA_DIGITS, ENGLISH_DIGITS)

MAT_PATTERN = re.compile(
    r"(মা\s*ট|মা\s*ট\s*মু\s*ল|মো\s*ট|মো\s*ট\s*মু\s*ল)[\s:-]*((?:[\d\.]+\s*)+)",
    re.IGNORECASE,
)
NUM_PATTERN = re.compile(r"\d+(?:\.\d+)?")
WHITESPACE_PATTERN = re.compile(r"\s+")

# ------------------------------------------------------------------------------
# 1B. CUSTOMER DATA (C Code -> C Name)
# ------------------------------------------------------------------------------
# কাস্টমারের তালিকা (CUSTOMER_MAP) আপনার আগের ফাইল থেকে পড়া হয়।
# আগের app.py ফাইলটার নাম বদলে  app_old.py  রাখুন (বা customer_data.py) — ব্যস, আর কিছু করতে হবে না।
CODE_PATTERN = re.compile(r"([A-Za-z]\d{2})\s*[-–—−]\s*(\d{4,7})")


CUSTOMER_MAP = {
"D30-0001": "রাশেদ স্টোর",
"D30-0002": "লক্ষি ভান্ডার",
"D30-0003": "আমির স্টোর",
"D30-0004": "মৌ স্টোর",
"D30-0005": "ইসমাইল স্টোর",
"D30-0007": "একরামুল স্টোর",
"D30-0011": "মা ভান্ডার ষ্টোর",
"D30-0012": "বৈশাখি বেকারি",
"D30-0013": "রানা স্টোর (পশ্চিম)",
"D30-0014": "শোপন স্টোর ১",
"D30-0025": "এস কে ব্রাদার্স",
"D30-0028": "আমদের বাজার",
"D30-0030": "সেতু এন্টারপ্রাইজ",
"D30-0032": "জাহান স্টোর",
"D30-0036": "সাঈদ স্টোর",
"D30-0037": "অনুসরণ",
"D30-0042": "এভরিথিং স্টোর",
"D30-0047": "আসলাম স্টোর",
"D30-0049": "সারোয়ার স্টোর",
"D30-0052": "মমিনুল স্টোর",
"D30-0057": "সিরাজুল স্টোর",
"D30-0058": "শহদি ষ্টোর",
"D30-0061": "নিমাই স্টোর",
"D30-0073": "আতাউর স্টোর",
"D30-0076": "আনন্দো স্টোর",
"D30-0082": "মোজিদ স্টোর",
"D30-0083": "রাজা স্টোর",
"D30-0085": "গনেশ ভ্যান্ডার",
"D30-0091": "দিনাজপুর বিগ বাজার",
"D30-0093": "মহনা ডি. স্টোর",
"D30-0094": "সিরাজ স্টোর",
"D30-0097": "রোজ কসমেটিক্স",
"D30-0099": "মৌবন কসমেটিক্স",
"D30-0101": "অনুসরণ",
"D30-0103": "তিয়াশ কসমেটিক্স",
"D30-0105": "সাজ ঘোর",
"D30-0106": "মালা ঘোর",
"D30-0107": "রবিন কসমেটিক্স",
"D30-0109": "টিপ কর্নার কসমেটিক্স",
"D30-0110": "মিঠু কসমেটিক্স",
"D30-0113": "অ্যাপোলো কসমেটিক্স",
"D30-0114": "সইবাল ডি. স্টোর",
"D30-0115": "ছায়া গিফট",
"D30-0116": "কোয়ালিটি কসমেটিক্স",
"D30-0117": "মুগধো কসমেটিক্স",
"D30-0119": "মুন গিফট অ্যান্ড কসমেটিক্স",
"D30-0121": "মুসকান কসমেটিক্স",
"D30-0122": "অভিনব কসমেটিক্স",
"D30-0123": "আরমান উপহার ও কসমেটিক্স",
"D30-0130": "সাব্বির স্টোর",
"D30-0131": "সাত্তার স্টোর",
"D30-0132": "মোল্লা ডি স্টোর।",
"D30-0136": "জয়দেব স্টোর",
"D30-0138": "হিরু স্টোর",
"D30-0166": "মনি স্টোর",
"D30-0169": "এম. এ. স্টোর",
"D30-0174": "শাহাজান স্টোর",
"D30-0176": "শুসান্ত স্টোর",
"D30-0181": "মিলন স্টোর",
"D30-0184": "শাকোয়াত স্টোর",
"D30-0186": "আনোয়ার স্টোর",
"D30-0193": "জব্বার টেলিকম ও বিভাগীয়",
"D30-0198": "খাজা স্টোর",
"D30-0199": "ইকবাল ও ব্রাদার্স",
"D30-0200": "মনোয়ার স্টোর",
"D30-0203": "টয়েল ভান্ডার",
"D30-0206": "আব্দুল লতিফ স্টোর",
"D30-0207": "রশিদুল স্টোর",
"D30-0212": "সামাদ স্টোর",
"D30-0215": "চাওয়া পাওয়া স্টোর",
"D30-0219": "সংকর ষ্টোর",
"D30-0223": "রুবেল স্টোর",
"D30-0224": "সঞ্জয় মোসলা",
"D30-0225": "মিলন সবজি ঘোর",
"D30-0229": "রতন স্টোর",
"D30-0233": "দাদা স্টোর",
"D30-0243": "সুমন স্টোর",
"D30-0247": "পুণভবা ষ্টোর",
"D30-0253": "মর্নিং সান কস্মেটিক্স",
"D30-0256": "বাবুল স্টোর",
"D30-0268": "ইয়ামান স্টোর",
"D30-0295": "তাপস স্টোর",
"D30-0325": "আনসার স্টোর",
"D30-0330": "নিউ হ্যাপ্পি কসমেটিক্স",
"D30-0336": "মোস্তফা স্টোর",
"D30-0340": "সাকিল স্টোর",
"D30-0344": "মা ডিপার্টমেন্ট স্টোর",
"D30-0346": "আবিদ স্টোর",
"D30-0352": "শ্রীথি স্টোর",
"D30-0355": "মুন্সি স্টোর",
"D30-0356": "মিন্টু স্টোর",
"D30-0359": "ভাই ভাই স্টোর",
"D30-0360": "সালাউদ্দিন স্টোর",
"D30-0361": "আব্দুল আজিজ স্টোর",
"D30-0364": "জুলফিকার ষ্টোর",
"D30-0371": "হামজা ভ্যারাইটি স্টোর",
"D30-0374": "খাইরুল স্টোর",
"D30-0377": "টু কন্না স্টোর",
"D30-0387": "জোমশেদ স্টোর",
"D30-0389": "সাজ্জাদ স্টোর",
"D30-0393": "মৌসুমী কসমেটিক্স",
"D30-0394": "ইব্রাহিম স্টোর",
"D30-0397": "ভাই ভাই স্টোর",
"D30-0416": "মোল্লা স্টোর",
"D30-0427": "আমির ভ্যারাইটি স্টোর",
"D30-0430": "স্টুডেন্ট স্টোর",
"D30-0431": "শরিফুল স্টোর",
"D30-0438": "পূর্ণিমা বেকারী",
"D30-0442": "জিয়া স্টোর",
"D30-0444": "রুহুল আমিন স্টোর",
"D30-0452": "জিয়া স্টোর",
"D30-0454": "আমেনা স্টোর",
"D30-0458": "খালেক স্টোর",
"D30-0460": "বিসমিল্লাহ স্টোর",
"D30-0466": "আব্দুল রশিদ স্টোর",
"D30-0469": "আল-আমিন ভ্যারাইটি স্টোর",
"D30-0480": "ইউওপোমা স্টোর",
"D30-0484": "মিজানুর ষ্টোর",
"D30-0489": "জুয়েল স্টোর",
"D30-04928": "রাজ স্টোর",
"D30-04929": "আমির ষ্টোর",
"D30-04930": "মাসুম স্টোর",
"D30-04934": "নূর কসমেটিক",
"D30-04938": "জুয়েলকোয়েল স্টোর",
"D30-04940": "সরকার স্টোর",
"D30-04943": "রংধনু কসমেটিক্স",
"D30-04944": "মৌ ডিপার্টমেন্টাল স্টোর",
"D30-04945": "প্রণব স্টোর",
"D30-04946": "ভুমি কসমেটিক্স",
"D30-04948": "আলতাফ স্টোর",
"D30-04949": "খোকন স্টোর",
"D30-04952": "গোবিন্দ ষ্টোর",
"D30-04968": "বিল্পব ভ্যারাইটিস",
"D30-04970": "হাবিব স্টোর",
"D30-04980": "মা স্টোর",
"D30-04981": "ইমরান স্টোর",
"D30-04992": "পারভেজ স্টোর",
"D30-04995": "আল আমিন ষ্টোর",
"D30-04998": "কারিক স্টোর",
"D30-0500": "পিঙ্কি স্টোর",
"D30-05004": "তায়েব স্টোর",
"D30-05006": "দুলু স্টোর",
"D30-05008": "সাজ্জাদ স্টোর",
"D30-05013": "পোরেন স্টোর",
"D30-0505": "আঁখি স্টোর",
"D30-05084": "সিরাজ স্টোর",
"D30-05089": "ফেয়ার ডিপারটমেন্ট ষ্টোর",
"D30-0509": "মোবারক স্টোর",
"D30-05121": "মেসার্স কাঞ্চন কসমেটিক্স",
"D30-05123": "সফিক কসমেটিক্স",
"D30-05124": "শাহিন স্টোর",
"D30-05127": "রেজা ষ্টোর",
"D30-05128": "জাবের স্টোর",
"D30-05132": "জি.এস ট্রেডার্স",
"D30-05133": "মা কসমেটিক্স",
"D30-05136": "মেয়ের দোয়া স্টোর",
"D30-05137": "ভাই ভাই স্টোর মোসলা",
"D30-05140": "দারুস সালাম ট্রেডার্স",
"D30-05141": "রঙ্গন স্টোর",
"D30-05142": "অনুপ স্টোর",
"D30-05145": "তুহিন ট্রেডার্স",
"D30-05148": "নীল আকাশ",
"D30-05149": "আশা স্টোর",
"D30-05150": "এভ্রিডে স্টেশনারি",
"D30-05152": "রাসেল ডিপার্টমেন্টাল স্টোর",
"D30-05154": "রুবেল ষ্টোর",
"D30-05155": "নয়ন স্টোর",
"D30-05160": "শেখ স্টোর",
"D30-05161": "অনন্ত স্টোর",
"D30-05162": "মামুন ডিপার্টমেন্টাল স্টোর (১)",
"D30-05167": "রিলেশন ডি স্টোর",
"D30-05168": "হট স্পট",
"D30-05181": "সানমুন স্টোর",
"D30-05183": "জুয়েল কসমেটিক্স",
"D30-05184": "হিমি ভ্যারাইটি স্টোর",
"D30-05185": "মানিক স্টোর",
"D30-05189": "কৃষ্ণ স্টোর",
"D30-0519": "মন্টু প্রসাদ স্টোর",
"D30-05191": "বাপ্পি স্টোর",
"D30-05192": "মাসুদ রানা স্টোর",
"D30-05194": "সাত্তার স্টোর",
"D30-05195": "রহিদুল ভ্যারাইটি স্টোর",
"D30-05196": "আইনুল ঁ ব্রাদার্স",
"D30-05197": "রংধনু স্টোর",
"D30-05198": "তসলিম স্টোর",
"D30-0520": "মান্নান স্টোর",
"D30-05201": "মেসার্স মান্নান অ্যান্ড সন্স",
"D30-05202": "জিয়া ষ্টোর",
"D30-05203": "মেসার্স ইসলাম ট্রেডার্স",
"D30-05205": "মনোয়ার স্টোর",
"D30-05208": "মেসার্স ওমেগা ট্রেডার্স",
"D30-05210": "ফারিকুল স্টোর",
"D30-05211": "রোহিম ভ্যারাইটি স্টোর",
"D30-05214": "মিজান ষ্টোর এন্ড ভ্যারাইটি",
"D30-05216": "সুইটি স্টোর",
"D30-05217": "গনেশ ভান্ডার",
"D30-05220": "ভাই ভাই স্টোর - ১",
"D30-05221": "তামান্না স্টোর",
"D30-05222": "আয়োজন ভ্যারাইটিজ স্টোর",
"D30-05223": "পাপ্পু স্টোর",
"D30-05224": "মা ভ্যারাইটি",
"D30-05226": "নাসির স্টোর",
"D30-05227": "মেজবা স্টোর",
"D30-05229": "শামীম ষ্টোর",
"D30-05231": "আব্দুর রাজ্জাক স্টোর",
"D30-05236": "আশরাফ স্টোর",
"D30-05237": "আরিফ স্টোর",
"D30-05238": "ফরহাদ স্টোর",
"D30-05241": "লিয়াকত স্টোর",
"D30-05242": "মেসার্স আতিক স্টোর",
"D30-05243": "বাবা ভ্যারাইটি",
"D30-05247": "আরমি স্টোর",
"D30-05248": "আজহার স্টোর",
"D30-05249": "ইসমাইল স্টোর",
"D30-0525": "জিয়া স্টোর",
"D30-05250": "মোতাহার স্টোর",
"D30-05251": "সিদ্দিকা স্টোর",
"D30-05252": "দেলওয়ার স্টোর",
"D30-05254": "রবিউল স্টোর",
"D30-05255": "নিউ মা কসমেটিক্স",
"D30-05257": "সুমন স্টোর",
"D30-05258": "মা বাবার দোয়া স্টোর",
"D30-05260": "ভাই ভাই স্টোর",
"D30-05262": "থ্রি স্টার স্টোর",
"D30-05265": "নাজিম স্টোর",
"D30-05268": "নিখিল স্টোর",
"D30-05272": "সরকার স্টোর",
"D30-05273": "সাকিল ভ্যারাইটি স্টোর",
"D30-05275": "বিপুল স্টোর",
"D30-05276": "মা দোয়ার স্টোর",
"D30-05279": "সন্দীপ স্টোর",
"D30-05283": "তানজিল স্টোর",
"D30-05284": "বাবু স্টোর",
"D30-05286": "উত্তম স্টোর",
"D30-05290": "নিত্য স্টোর",
"D30-05291": "সৌরব স্টোর",
"D30-05293": "মাহাবুর স্টোর",
"D30-05294": "মোয়াজ্জেম স্টোর",
"D30-05295": "৯৯ বাজার",
"D30-05303": "মেসার্স এস কে বি ট্রেডার্স",
"D30-05304": "বিসমিল্লাহ স্টোর",
"D30-05305": "বিসমিল্লাহ স্টোর",
"D30-05310": "মুসা স্টোর",
"D30-05316": "আনোয়ার পান সোপ",
"D30-05318": "মনোয়ার স্টোর",
"D30-05322": "চার ভাই স্টোর",
"D30-05326": "পল্লব স্টোর",
"D30-05327": "শুভ স্টোর",
"D30-05331": "জোরি হাউস",
"D30-05332": "মোস্তফা স্টোর",
"D30-05335": "বন্ধন স্টোর",
"D30-05339": "গনেশ স্টোর",
"D30-05340": "শাহিরুল স্টোর",
"D30-05345": "শাহাবুদ্দিন স্টোর",
"D30-05346": "বিষ্ণুনাথ স্টোর",
"D30-05349": "হুমাউন স্টোর",
"D30-05350": "ভাই ভাই স্টোর",
"D30-05352": "সাদেকুল স্টোর",
"D30-05353": "সাদিক স্টোর",
"D30-05355": "মানিক স্টোর",
"D30-05357": "দুই ভাই স্টোর",
"D30-05361": "রফিকুল স্টোর",
"D30-05362": "বাবুল স্টোর",
"D30-05363": "মা স্টোর",
"D30-05365": "ফারুক ষ্টোর",
"D30-05367": "রেজাউল ষ্টোর",
"D30-05369": "ইসরাত ট্রেডার্স",
"D30-05371": "রেবেকা স্টোর",
"D30-05375": "নাজমুল স্টোর",
"D30-05377": "মাহি স্টোর",
"D30-05379": "রায় স্টোর",
"D30-05382": "হিরা স্টোর",
"D30-05384": "ওবাদুর পান শপ",
"D30-05386": "মোঃ আলমগীর স্টোর",
"D30-05387": "প্রাপ্তি ষ্টোর",
"D30-05389": "রাসেল স্টোর",
"D30-05392": "চ্যান ডিপার্টমেন্টাল স্টোর",
"D30-05394": "লুকি কর্নার",
"D30-05397": "মৃদুল স্টোর",
"D30-05400": "সইনিক স্টোর",
"D30-05401": "বেবি স্টোর",
"D30-05403": "রেজাউল স্টোর",
"D30-05409": "মান্নান স্টোর",
"D30-05410": "লিটন ষ্টোর",
"D30-05414": "নজরুল স্টোর",
"D30-05419": "রংধনু ইলেকট্রনিক্স",
"D30-05420": "বাবলু স্টোর",
"D30-05421": "ইতি ষ্টোর",
"D30-05423": "সুমন ষ্টোর",
"D30-05424": "জামান ষ্টোর",
"D30-05426": "কুলসুম স্টোর",
"D30-05427": "মাসুদ স্টোর",
"D30-05428": "মুডু স্টোর",
"D30-05429": "আফসার নান্নু স্টোর",
"D30-05431": "অর্পি কসমেটিক্স",
"D30-05432": "রুবেল স্টোর",
"D30-05434": "বাপ্পী ষ্টোর",
"D30-05435": "বিবিধ ষ্টোর",
"D30-05439": "মা দুর্গা স্টোর",
"D30-05440": "ভাই ভাই স্টোর",
"D30-05441": "জিয়া ষ্টোর",
"D30-05443": "মেগলা কসমেটিক্স",
"D30-05444": "আরমান স্টোর",
"D30-05445": "উদয় ভ্যারাইটি স্টোর",
"D30-05447": "দিগন্ত স্টেশনারী",
"D30-05453": "আতিক স্টোর",
"D30-05456": "দুই বোন ভ্যারাইটিস স্টোর",
"D30-05457": "উত্তম স্টোর",
"D30-05458": "গৌতম স্টোর",
"D30-05459": "শহিদুল স্টোর",
"D30-05463": "ভাই ভাই স্টোর",
"D30-05466": "আর ইসলাম ব্রাদার্স",
"D30-05467": "ভুবন ও বাপন স্টোর",
"D30-05469": "সোহেল স্টোর",
"D30-05471": "আঁখি স্টোর",
"D30-05474": "দুই ভাই স্টোর",
"D30-05476": "রাজ্জাক ভ্যারাইটি স্টোর",
"D30-05477": "সাফিউল স্টোর",
"D30-05478": "পিন্টু ষ্টোর",
"D30-05479": "মানিক কসমেটিক্স",
"D30-0548": "কুন্ডু স্টোর",
"D30-05480": "রেজা কসমেটিক্স",
"D30-05481": "সুজন স্টোর",
"D30-05487": "আবুল স্টোর",
"D30-05498": "নূর জামান স্টোর",
"D30-05501": "আশা স্টোর",
"D30-05503": "খালেদ স্টোর",
"D30-05506": "আক্কাস ষ্টোর",
"D30-05507": "আলাহি স্টোর",
"D30-05510": "দুলাল ষ্টোর",
"D30-05511": "আরিফ আসিফ স্টোর",
"D30-05512": "আনিস স্টোর",
"D30-05513": "রোহান কসমটক্সিে",
"D30-05518": "আতাউর স্টোর",
"D30-05529": "আনসার স্টোর",
"D30-05531": "জিল্লুর ষ্টেশনারী",
"D30-05532": "মা ভ্যারাইটি স্টোর",
"D30-05536": "শ্যামল ষ্টোর",
"D30-05548": "আনিসুর স্টোর",
"D30-05550": "নাজমুল ষ্টোর",
"D30-05551": "জাহাঙ্গীর স্টোর",
"D30-05558": "আল আমিন স্টোর",
"D30-05559": "ভাই বন স্টোর",
"D30-05561": "কালার ষ্টেশনারী",
"D30-05562": "ফজলুল স্টোর",
"D30-05563": "মা স্টোর",
"D30-05564": "সামসুল ষ্টোর",
"D30-05565": "পাপ্পু স্টোর",
"D30-05566": "নুরুল চা স্টোর",
"D30-05569": "মইজুল স্টোর",
"D30-05573": "দিদা ষ্টোর",
"D30-05578": "আতাউর স্টোর",
"D30-05580": "আর কে ডিপার্টমেন্টাল স্টোর",
"D30-05582": "দবির স্টোর",
"D30-05583": "মাহিম স্টোর",
"D30-05586": "আয়েশা স্টোর",
"D30-05587": "মা বাবা ডপর্িাটমন্টোল ষ্টোর",
"D30-05588": "ভাই বোন ডিপার্টমেন্টাল স্টোর",
"D30-05589": "মাইসা মিষ্টান্ন",
"D30-0559": "লামিয়া ভ্যারাইটিস",
"D30-05592": "মা মনি স্টোর",
"D30-05596": "ওহাব স্টোর",
"D30-05597": "আল্লার দান",
"D30-05598": "সোহেল ট্রেডার্স",
"D30-05599": "দুই কন্যা ভ্যারাইটি স্টোর",
"D30-05606": "ফারুক স্টোর",
"D30-05607": "মোকাররম ষ্টোর",
"D30-05609": "মাইশা ট্রেডার্স",
"D30-05610": "সুমন ট্রেডার্স",
"D30-05611": "নিউ রোহিম কসমেটিক্স এবং কনফ্যাকশনারি",
"D30-05612": "মেসার্স মোহাম্মদ স্টোর",
"D30-05613": "ওভি ভ্যারাইটি স্টোর",
"D30-05614": "সৌরব কনফেকশনারি",
"D30-05615": "মুসা কসমেটিক্স",
"D30-05618": "বোধুয়া কসমেটিক্স",
"D30-05619": "রানা ডিপার্টমেন্টাল স্টোর",
"D30-0562": "সুশান্ত পান শপ",
"D30-05622": "ভাই ভাই স্টোর",
"D30-05625": "রুবেল স্টোর",
"D30-05626": "বাবুল স্টোর",
"D30-05629": "বাবু ১ স্টোর",
"D30-0563": "মেহেদী স্টোর",
"D30-05631": "পারভজে ভ্যারাইটিস ষ্টোর",
"D30-05632": "আমজাদ ষ্টোর",
"D30-05633": "তাসনিম স্টোর",
"D30-05636": "ভোবেশ স্টোর",
"D30-05640": "জাহিদ স্টোর",
"D30-05651": "ভাই বন স্টোর",
"D30-05655": "মা ভ্যারাইটি স্টোর টু",
"D30-05656": "বন্ধু কসমেটিক্স",
"D30-05661": "বাবুল স্টোর ০১",
"D30-05662": "ভাই ভাই স্টোর",
"D30-05663": "মান্নান স্টোর",
"D30-05665": "নেহা স্টোর",
"D30-05666": "হাসান স্টোর",
"D30-05667": "সুজাত স্টোর",
"D30-05669": "আলিফ মিম স্টোর",
"D30-05675": "আসাদ জর্দা স্টোর",
"D30-05677": "সাগর ষ্টোর",
"D30-05680": "রিংকু স্টোর",
"D30-05681": "আহাদ ডিপার্টমেন্টাল স্টোর",
"D30-05684": "তিন ভাই স্টোর",
"D30-05685": "জাহাঙ্গীর স্টোর",
"D30-05687": "মামুন স্টোর",
"D30-05688": "সংকর ডিপার্টমেন্টাল স্টোর",
"D30-05689": "সোর্নো স্টোর",
"D30-05690": "শামীম ডিপার্টমেন্টাল স্টোর",
"D30-05691": "মাহিন স্টোর",
"D30-05692": "মিথিলা ষ্টোর",
"D30-05693": "আদিত্য ষ্টোর",
"D30-05694": "শাহাবাজ স্টোর",
"D30-05695": "আবিদ স্টোর",
"D30-05696": "ডলার স্টোর",
"D30-05698": "হিমেল স্টোর",
"D30-05699": "নজরুল স্টোর",
"D30-05700": "ফারহানা স্টোর",
"D30-05701": "আইনুল স্টোর",
"D30-05702": "আফতাফ মুন্না স্টোর",
"D30-05704": "জেএস স্টোর",
"D30-05705": "মৌ ভ্যারাইটি স্টোর",
"D30-05709": "মিলন কনফেকশনারি",
"D30-05712": "টুটুল পান সাবান",
"D30-05713": "জালাল স্টোর",
"D30-05714": "মালেক স্টোর",
"D30-05715": "মোশরুফ স্টোর",
"D30-05716": "আবদুর রহমান স্টোর",
"D30-05724": "আশরাফুজ্জামান স্টোর",
"D30-0573": "হাফিজুল স্টোর",
"D30-05731": "গুলজার স্টোর",
"D30-05732": "আরিফ কসমেটিক্স",
"D30-05736": "রুমন স্টোর",
"D30-05738": "সনি ভ্যারাইটি স্টোর",
"D30-05742": "ওসমান স্টোর",
"D30-05746": "লাকি স্টোর",
"D30-05747": "নুর ভ্যারাইটি স্টোর",
"D30-0575": "বিসমিল্লাহ কসমেটিক্স",
"D30-05751": "কুদ্দুস স্টোর",
"D30-05752": "মালেক স্টোর",
"D30-05754": "রিমন স্টোর",
"D30-05755": "আপন স্টোর",
"D30-05756": "ডিনো বন্ধু স্টোর",
"D30-05757": "বৈদ্য স্টোর",
"D30-05758": "দিপু স্টোর",
"D30-0576": "অরণ্য কসমেটিক্স",
"D30-05760": "দিপু স্টোর",
"D30-05762": "ফ্যাশন এইড",
"D30-05764": "মা ভ্যারাইটিস ষ্টোর",
"D30-05766": "তাকসুর স্টোর",
"D30-05769": "ভাই ভাই স্টোর",
"D30-0577": "ওহিদুল স্টোর",
"D30-05774": "শাহিন স্টোর",
"D30-05776": "গৌতম স্টোর",
"D30-05777": "নন্দিনি স্টোর",
"D30-05778": "আরিফ স্টোর",
"D30-05779": "কৃষ্ণো স্টোর",
"D30-05780": "করিমুল স্টোর",
"D30-05782": "মামুন স্টোর",
"D30-05783": "বানেচা কসমেটিক্স",
"D30-05786": "দুলাল স্টোর",
"D30-05789": "মোমিন স্টোর",
"D30-05790": "মা জনোরলে ষ্টোর",
"D30-05791": "আজাদ স্টোর",
"D30-05792": "সাহিন স্টোর",
"D30-05793": "দুই ভাই স্টোর",
"D30-05797": "মেসার্স ভাই ভাই স্টোর",
"D30-05798": "হাসিনা এন্টারপ্রাইজ",
"D30-0580": "সুবধ স্টোর",
"D30-05802": "কামিনী স্টোর",
"D30-05803": "মা ষ্টোর",
"D30-05804": "মৌসুমী ভ্যারাইটি স্টোর",
"D30-05805": "আল মোমিন",
"D30-05806": "আনোয়ার ষ্টোর",
"D30-05808": "আমিনুল স্টোর",
"D30-05809": "আল মামুন ষ্টোর",
"D30-05810": "দুই ভাই স্টোর",
"D30-05814": "পুলক স্টোর",
"D30-05815": "মেসার্স সোনালী এন্টারপ্রাইজ",
"D30-05816": "ইসা স্টোর",
"D30-05817": "স্বপ্নপুরী ডিপার্টমেন্টাল স্টোর",
"D30-05819": "ফেয়ার ডিপার্টমেন্টাল স্টোর",
"D30-0607": "কাইয়ুম স্টোর",
"D30-0608": "সুচিত্র বসাক স্টোর",
"D30-0610": "ভি ভি বিতোরে",
"D30-0616": "প্যাসিফিক স্টোর",
"D30-0617": "বাবলু কসমেটিক্স",
"D30-0621": "পরিতোষ স্টোর",
"D30-0628": "পাবনা স্টোর",
"D30-0632": "বিক্রমপুর স্টোর",
"D30-0633": "এ হাই স্টোর",
"D30-0634": "বিক্রমপুর স্টোর ২",
"D30-0636": "খোকা স্টোর",
"D30-0643": "চন্দনা স্টোর",
"D30-0645": "বোশাক স্টোর",
"D30-0647": "বিপুল স্টোর",
"D30-0654": "বর্নি স্টোর",
"D30-0660": "মিজানুর স্টোর",
"D30-0661": "গনেশ স্টোর",
"D30-0663": "জোনোটা কসমেটিক্স",
"D30-0666": "মা ভ্যারাইটি ষ্টোর",
"D30-0668": "নূর কনফ্যাকশনারি",
"D30-0670": "মদিনা কসমেটিক্স",
"D30-06705": "শামীম প্রসাধনী",
"D30-06706": "মামা ভাগিনা কসমেটিক্স",
"D30-06707": "কেনা কাটা স্টোর",
"D30-06708": "রিহান কসমেটিক্স",
"D30-06709": "নূর হাসান স্টোর",
"D30-0671": "ভাই ভাই স্টোর (সাকি)",
"D30-06713": "এশিয়ান স্কাই সোপ",
"D30-06714": "কসমেটিক্স বাজার",
"D30-06716": "মেসার্স সুকদেব স্টোর",
"D30-06720": "লাবণ্য কসমটক্সেি",
"D30-06721": "মুস্তাকিম ভ্যারাইটিস স্টোর",
"D30-06724": "ফরহাদ ষ্টোর",
"D30-06726": "এম. এস টার্ডার্স",
"D30-06732": "দুলাল স্টোর",
"D30-06734": "তানিয়া কসমেটিক",
"D30-06737": "সুইটি স্টোর",
"D30-0674": "ভি. আই. পি কসমেটিকস টু",
"D30-06744": "মোতাহার স্টোর",
"D30-06745": "সানজদাি ষ্টোর",
"D30-06746": "জহুরুল স্টোর",
"D30-06747": "হামিদুল ষ্টোর",
"D30-06748": "মাসুদ স্টোর",
"D30-06750": "রশিদ স্টোর",
"D30-06751": "রাসেল স্টোর",
"D30-0676": "অনুসরণ",
"D30-06810": "মাসউদুর রহমান",
"D30-06816": "আফসানা স্টোর",
"D30-06819": "লিমন স্টোর",
"D30-0682": "আফজাল স্টোর",
"D30-06823": "জুয়েল ষ্টোর",
"D30-06826": "মাহাবুব স্টোর",
"D30-06839": "মিজান কসমেটিক্স",
"D30-06840": "মেসার্স আরবি অ্যান্ড আতিফ স্টোর",
"D30-06841": "মোমিন স্টোর",
"D30-06846": "অনুপ কুমার রায়",
"D30-0689": "মোস্তাফিজুর ষ্টোর",
"D30-0691": "উদয় ষ্টোর",
"D30-0700": "বিএলবি ষ্টোর",
"D30-0702": "ডলারের স্টোর",
"D30-0711": "তৈয়ব স্টোর",
"D30-0718": "মুনতাহা ট্রেডার্স",
"D30-0722": "আনারুল কসমেটিক্স",
"D30-0724": "বেলাল স্টোর",
"D30-0731": "মাহাবুব স্টোর",
"D30-0732": "আনসারুল স্টোর",
"D30-0738": "লুতফর স্টোর",
"D30-0740": "জাহাঙ্গির পান শপ",
"D30-0742": "জুয়েল স্টোর",
"D30-0746": "ভাই ভাই স্টোর",
"D30-0752": "সোহাগ কসমেটিক্স",
"D30-0762": "ভাই ভাই স্টোর",
"D30-0769": "সাগর স্টোর",
"D30-0774": "ভুপাল কসমেটিক্স",
"D30-0776": "মোজাহার স্টোর",
"D30-0781": "রবিউল স্টোর",
"D30-0782": "ড,ি এ ডপর্িামন্টোল",
"D30-0787": "আক্তারুজ্জামান স্টোর",
"D30-0793": "মানিক স্টোর",
"D30-0795": "মজুমদার স্টোর",
"D30-0810": "দোলন স্টোর",
"D30-0820": "আনারুল স্টোর",
"D30-0824": "মামুন স্টোর",
"D30-0826": "নাদিম তেল ঘোর",
"D30-0837": "মা ভ্যারাইটি ষ্টোর",
"D30-0842": "রউফ স্টোর (পশ্চিম)",
"D30-0843": "হাজি কসমেটিক্স",
"D30-0845": "সামিম স্টোর",
"D30-0848": "শোপন স্টোর",
"D30-0849": "মেসার্স রশিদ স্টোর",
"D30-0861": "তমাল স্টোর",
"D30-0865": "ব্রাদার্স লাইব্রেরী",
"D30-0872": "অর্কো ট্রেডার্স (ডব্লিউএস)",
"D30-0876": "সুমন স্টোর",
"D30-0877": "আসা কসমেটিক্স",
"D30-0894": "দাস স্টোর",
"D30-0903": "মনির স্টোর",
"D30-0909": "শাহা স্টোর",
"D30-0912": "রোজিদুল স্টোর",
"D30-0913": "রাহমান স্টোর",
"D30-0921": "নূর স্টোর অ্যান্ড কনফেকশনারি",
"D30-0922": "বর্ষা ব্রিস্টি কসমেটিক্স",
"D30-0945": "মোস্তফা স্টোর",
"D30-0952": "নূর স্টোর",
"D30-0955": "আরিফ ডি. স্টোর",
"D30-0956": "মা বিপনী কেন্দ্রো",
"D30-0960": "মিতু স্টোর",
"D30-0963": "নাহিদ স্টোর",
"D30-0965": "ইউসুফ বেকারি",
"D30-0966": "সালাম স্টোর (পশ্চিম)",
"D30-0969": "মোঃ মমিনুল স্টোর",
"D30-0976": "রুস্তম স্টোর",
"D30-0992": "রেসমা কসমেটিক্স",
"D30-1003": "মিজানুর স্টোর",
"D30-1008": "রেজাউল স্টোর",
"D30-1011": "জোহরুল স্টোর",
"D30-1018": "মা কসমেটিক্স ১০",
"D30-1034": "হাফিজ স্টোর",
"D30-1036": "মা কসমেটিক্স স্টোর",
"D30-1037": "রায়হান স্টোর",
"D30-1038": "হাফিজউদ্দিন স্টোর",
"D30-1042": "সালাম স্টোর",
"D30-1052": "জিন্নাহ স্টোর",
"D30-1069": "জনি স্টোর",
"D30-1075": "মিজান পান সপ",
"D30-1080": "শাহিন ষ্টোর",
"D30-1084": "আফজাল স্টোর",
"D30-1085": "মোকসেড স্টোর",
"D30-1086": "রবিউল স্টোর ১",
"D30-1089": "রানা স্টোর",
"D30-1100": "বাবু স্টোর",
"D30-1102": "ভাই ভাই স্টোর",
"D30-1112": "হীরার স্টোর",
"D30-1113": "জননি স্টোর",
"D30-1128": "ফারুক স্টোর",
"D30-1132": "নির্মল ষ্টোর",
"D30-1148": "ত্রিনা স্টোর",
"D30-1150": "সুসান্তো স্টোর",
"D30-1158": "এম আর স্টোর",
"D30-1160": "সময়ের কেনাকাটা",
"D30-1161": "হঠাৎ ব্রিস্টি",
"D30-1175": "রঞ্জন স্টোর",
"D30-1177": "কালীকেশ স্টোর",
"D30-1184": "সালাম স্টোর",
"D30-1187": "মুন্না পান সোপ",
"D30-1190": "বোলোরাম পান শপ",
"D30-1195": "রাজ্্জাক ষ্টোর",
"D30-1203": "আরমান স্টোর",
"D30-1204": "দেশ ডি. স্টোর",
"D30-1207": "খান ষ্টোর",
"D30-1212": "মা ষ্টোর",
"D30-1217": "মিল্লাথ স্টোর",
"D30-1222": "আব্বাস স্টোর",
"D30-1223": "জামাই স্টোর",
"D30-1234": "জোহির স্টোর",
"D30-1235": "রাজদুত এন্টারপ্রাইজ",
"D30-1236": "নিত্যপোন্নো স্টোর",
"D30-1237": "জেড. আর ভ্যারাইটি স্টোর",
"D30-1238": "আঞ্জুমান স্টোর",
"D30-1241": "সোহাগ এন্টারপ্রাইজ",
"D30-1246": "আমনি ষ্টোর",
"D30-1258": "রাশিদুল স্টোর",
"D30-1262": "নজমনি ষ্টোর",
"D30-1264": "নূর সোবজি গোর",
"D30-1274": "লালু স্টোর",
"D30-1277": "রাজ্জাক স্টোর",
"D30-1281": "প্রোভা ডি স্টোর",
"D30-1283": "দিলীপ স্টোর",
"D30-1291": "রাসেল স্টোর",
"D30-1317": "সৌরভ স্টোর",
"D30-1320": "মাসুদা কসমেটিক্স",
"D30-1321": "লিমা কসমেটিক্স",
"D30-1323": "লতিফ স্টোর",
"D30-1325": "মামা ভ্যাজাইনা স্টোর",
"D30-1326": "হামিদুর স্টোর",
"D30-1330": "মেসার্স আইবুর স্টোর",
"D30-1331": "রিফাত স্টোর",
"D30-1333": "নোয়াখালী স্টোর",
"D30-1335": "জান্নাত স্টোর",
"D30-1337": "সাব্বির কসমেটিক",
"D30-1340": "মেসার্স বাবুল স্টোর",
"D30-1341": "নুর কসমেটিক্স",
"D30-1347": "সাথী কসমেটিক্স",
"D30-1354": "মা ভ্যারাইটি স্টোর",
"D30-1355": "ফারুক অ্যান্ড ব্রাদার্স",
"D30-1357": "গনেশ ভ্যান্ডার",
"D30-1358": "লিমা ভ্যারাইটি স্টোর",
"D30-1360": "সিয়াম কসমেটিক্স",
"D30-1363": "নুরুল আমিন মোসলা স্টোর",
"D30-1364": "রফিকুল স্টোর",
"D30-1368": "মান্নান স্টোর",
"D30-1369": "মোস্তফা স্টোর",
"D30-1390": "ফয়জুল স্টোর",
"D30-1394": "নজরুল স্টোর",
"D30-1399": "ব্যাপ্পি ষ্টোর",
"D30-1401": "সুজন স্টোর",
"D30-1403": "মায়ের দোয়া স্টোর",
"D30-1404": "আজিজুর স্টোর",
"D30-1560": "মা কনফেকশনারী",
"D30-1561": "বাহার ষ্টোর",
"D30-1570620": "সিনহা কসমেটিক্স (পিএস)",
"D30-1570622": "ইত্যাদি স্টোর",
"D30-1570623": "মা ডিপার্টমেন্টাল স্টোর",
"D30-1570626": "মালিহা কসমেটিক্্র",
"D30-1570628": "বন্ধন ডিপার্টমেন্ট স্টোর",
"D30-1570630": "আল বাইক ফুড",
"D30-1570631": "কোনিকা স্টোর",
"D30-1570635": "আমজাদ স্টোর",
"D30-1570636": "মোতহার ষ্টোর",
"D30-1570637": "সাইফুল স্টোর",
"D30-1570638": "আসলাম ষ্টোর",
"D30-1570641": "ফয়জুর স্টোর",
"D30-1570642": "আরিফুল মাহফুজ স্টোর",
"D30-1570643": "আঙ্গুর স্টোর",
"D30-1570645": "নাহিদ স্টোর",
"D30-1570647": "মসিহুর স্টোর",
"D30-1570649": "ফাতাউর স্টোর",
"D30-1570650": "রউফ স্টোর",
"D30-1570652": "রাউসাল স্টোর",
"D30-1570653": "ইসমাইল হোসেন রেজওয়ান স্টোর",
"D30-1570654": "সানুওয়ারা তালিকম",
"D30-1570655": "দুই বন স্টোর",
"D30-1570658": "সায়েম ষ্টোর",
"D30-1570660": "মিনারুল স্টোর",
"D30-1570661": "নূর আলম স্টোর",
"D30-1570664": "উমর ফারুক স্টোর",
"D30-1570665": "মাইনুর ষ্ট্াের",
"D30-1570667": "শামির স্টোর",
"D30-1570670": "লুৎফর ষ্টোর",
"D30-1570671": "সাইদুল স্টোর",
"D30-1570674": "মোমিনুর স্টোর",
"D30-1570675": "মাইনুল স্টোর",
"D30-1570676": "রেজা স্টোর",
"D30-1570677": "মাজেদুর ষ্টোর",
"D30-1570679": "খাদেমুল স্টোর",
"D30-1570682": "বোর্না স্টোর",
"D30-1570683": "নেহা স্টোর",
"D30-1570684": "মিলন স্টোর",
"D30-1570687": "নিউ ভ্যারাইটি স্টোর",
"D30-1570688": "রনি স্টোর",
"D30-1570690": "মমোতাজ স্টোর",
"D30-1570693": "ফাহিম স্টোর",
"D30-1570694": "সুজন স্টোর",
"D30-1570697": "শাহিনুর স্টোর",
"D30-1570698": "ইকুব স্টোর",
"D30-1570699": "মা ভ্যারাইটি স্টোর",
"D30-1570701": "হাবিব স্টোর",
"D30-1570703": "ডন স্টোর",
"D30-1570704": "ফিরুজ স্টোর",
"D30-1570705": "খায়রুল লাইব্রেরি এবং কসমেটিক্স",
"D30-1570706": "কাজল সেন্ট",
"D30-1570708": "তোরিকুল স্টোর",
"D30-1570710": "লুৎফর স্টোর",
"D30-1570711": "রসিদুল স্টোর",
"D30-1570712": "সজিব স্টোর",
"D30-1570713": "রুবেল পান ষ্টোর",
"D30-1570714": "মোমোতা স্টোর",
"D30-1570718": "মহোশিন স্টোর",
"D30-1570719": "মেসার্স উৎস ট্রেডার্স",
"D30-1570723": "আশিকুল স্টোর",
"D30-1570726": "শাওদা ট্রেডারস",
"D30-1570730": "মায়রে দোয়া ষ্টোর",
"D30-1570734": "আবুল ষ্টোর",
"D30-1570735": "মিনারুল স্টোর",
"D30-1570740": "মোছা: মমিি",
"D30-1570742": "বাশার স্টোর",
"D30-1570747": "আনিকা স্টোর",
"D30-1570749": "মিঠু ষ্টোর",
"D30-1570752": "আসলাম স্টোর",
"D30-1570755": "রতন টেলিকম",
"D30-1570758": "আনামুল গোল্ড প্লেটিং স্টোর",
"D30-1570759": "মোকলেশ স্টোর",
"D30-1570760": "তানভীর কনফেকশনারি",
"D30-1570762": "হাবিব ডিপার্টমেন্ট স্টোর",
"D30-1570767": "রুপম ষ্টোর",
"D30-1570768": "হেনা স্টোর",
"D30-1570770": "লুলু ষ্টোর",
"D30-1570773": "আল নাইম ভ্যারাইটি স্টোর",
"D30-1570774": "সজিব চা বিপনি",
"D30-1570779": "কোবির স্টোর",
"D30-1570781": "বাবা পান স্টোর",
"D30-1570784": "মা বাবা স্টোর",
"D30-1570788": "বাবু স্টোর ২",
"D30-1570790": "রুমা ষ্টোর",
"D30-1570795": "স্নেহা ডিপার্টমেন্টাল স্টোর",
"D30-1570796": "দুই ভাই স্টোর",
"D30-1570800": "আনিকা ভ্যারাইটি স্টোর",
"D30-1570803": "লিয়াকোত স্টোর",
"D30-1570804": "জারিন স্টোর",
"D30-1570805": "বসিমল্লিাহ স্টাৈর",
"D30-1570806": "পুতুল স্টোর",
"D30-1570807": "বিশাল ষ্টোর",
"D30-1570808": "মেয়ের ডুয়া ভ্যারাইটি স্টোর",
"D30-1570809": "প্রচেষ্টা ভ্যারাইটি ষ্টোর",
"D30-1570811": "রাসেল ডিপার্টমেন্টাল স্টোর",
"D30-1570820": "মেসার্স রফিক স্টোর",
"D30-1570821": "মেরাজ স্টোর",
"D30-1570822": "সুজন স্টোর",
"D30-1570830": "মেসার্স মা ইলেকট্রনিক্স",
"D30-1570838": "সুমাইয়া স্টোর",
"D30-1570839": "ওহেদ স্টোর",
"D30-1570850": "বারি ভ্যারাইটি স্টোর",
"D30-1570857": "কনক স্টোর",
"D30-1570858": "নোসাদ স্টোর",
"D30-1570859": "আজিজুর স্টোর",
"D30-1570861": "ববি স্টোর",
"D30-1570865": "রহিম ষ্টোর",
"D30-1570869": "সোনার বাংলা ট্রেডার্স",
"D30-1570870": "আনোয়ার স্টোর",
"D30-1570871": "উর্ম্মি ষ্টোর",
"D30-1570872": "রাজ স্টোর",
"D30-1570873": "পিউয়াশ স্টোর",
"D30-1570874": "উৎসব স্টোর",
"D30-1570878": "জামান ষ্টোর",
"D30-1570879": "আরফি ষ্টোর",
"D30-1570882": "শাহিন স্টোর",
"D30-1570885": "হানিফ স্টোর",
"D30-1570886": "ফরিদ ষ্টোর",
"D30-1570888": "আসরাফুল স্টোর",
"D30-1570889": "বিশাল স্টোর",
"D30-1570891": "জগন্নাথ স্টোর",
"D30-1570892": "সরিফুল স্টোর",
"D30-1570896": "প্রিয়া স্টোর",
"D30-1570902": "রবিন ষ্টোর",
"D30-1570905": "ভাই ভ্ইা ষ্টোর",
"D30-1570908": "লিজা ডিপার্টমেন্টাল স্টোর",
"D30-1570909": "মকবুল স্টোর",
"D30-1570910": "আক্তারুল স্টোর",
"D30-1570911": "আমিনুল ভ্যারাইটি",
"D30-1570915": "মোস্তাকিম স্টোর",
"D30-1570917": "সিফাত ভ্যারাইটি",
"D30-1570921": "ফারুকের স্টোর",
"D30-1570922": "হাবিবা ষ্টোর",
"D30-1570923": "জামান ষ্টোর",
"D30-1570924": "শুভ স্টোর",
"D30-1570925": "নূর স্টোর",
"D30-1570926": "সাগর স্টোর",
"D30-1570927": "রানা স্টোর",
"D30-1570929": "জাহিদ স্টোর",
"D30-1570930": "নুসরাত স্টোর",
"D30-1570933": "মা স্টোর",
"D30-1570934": "মুসা স্টোর",
"D30-1570936": "তিন ভাই স্টোর",
"D30-1570937": "নূর স্টোর",
"D30-1570940": "জাহাঙ্গীর স্টোর",
"D30-1570942": "সুকুমার স্টোর",
"D30-1570943": "ইব্রাহিম সোর",
"D30-1570944": "রিপন কনফেকশনারি",
"D30-1570946": "বাবুল ষ্টোর",
"D30-1570947": "সেলিম স্টোর",
"D30-1570953": "রাজীব লাইব্রেরি এবং কসমেটিক্স",
"D30-1570955": "মা স্টোর",
"D30-1570959": "জাহাঙ্গির ষ্টোর",
"D30-1570960": "রায়হান স্টোর",
"D30-1570962": "মাসুদ কসমেটিক্স",
"D30-1570963": "মাহবুব স্টোর",
"D30-1570964": "সোয়েকার্নো স্টোর",
"D30-1570967": "আজিজুল স্টোর",
"D30-1570968": "বেলাল ষ্টোর",
"D30-1570970": "আনোয়ার স্টোর",
"D30-1570971": "মাহিন স্টোর",
"D30-1570972": "হাসান স্টোর",
"D30-1570973": "কার্তিক স্টোর",
"D30-1570976": "মালেক স্টোর",
"D30-1570977": "জিয়া স্টোর",
"D30-1570978": "হেলাল ষ্টোর",
"D30-1570982": "দিব্ব স্টোর",
"D30-1570983": "ভাই ভাই ষ্টোর",
"D30-1570985": "সাবিত্রী স্টোর",
"D30-1570989": "হিমালয় স্টোর",
"D30-1570990": "জাহিদ স্টোর",
"D30-1571003": "আনরাজুল স্টোর",
"D30-1571005": "মোকারম স্টোর",
"D30-1571006": "রুবেল স্টোর",
"D30-1571012": "সাহিন স্টোর",
"D30-1571014": "রাজু স্টোর",
"D30-1571016": "ফিরোজ টেলিকম",
"D30-1571018": "মোস্তফা স্টোর",
"D30-1571020": "মা ভ্যারাইটি স্টোর",
"D30-1571022": "দীপ্ত দিগন্ত ভারিটি স্টোর",
"D30-1571025": "আলিফ নূর স্টোর",
"D30-1571026": "মাহবুর স্টোর",
"D30-1571028": "ভাই ভাই স্টোর",
"D30-1571030": "জাহাঙ্গীর স্টোর",
"D30-1571034": "মনোসা ডস ভ্যান্ডার",
"D30-1571035": "বর্নি স্টোর",
"D30-1571037": "খুসি স্টোর",
"D30-1571044": "আরাফাত স্টোর",
"D30-1571045": "ভাই ভাই স্টোর",
"D30-1571046": "তুহিন কসমেটিক্স",
"D30-1571049": "সাইফুল স্টোর",
"D30-1571051": "নাহিদ কসমেটিক্স",
"D30-1571053": "মেসার্স রাজিব ট্রেডার্স",
"D30-1571054": "রাকিব ষ্টোর",
"D30-1571060": "রাজ্জাক ষ্টোর",
"D30-1571061": "ফিরোজ স্টোর",
"D30-1571066": "আইজুল স্টোর",
"D30-1571068": "মোদিনা স্টোর",
"D30-1571073": "সামিম স্টোর",
"D30-1571074": "জিল্লুর স্টোর",
"D30-1571075": "মন্ডল ষ্টোর",
"D30-1571081": "আলরাফসান জানি স্টোর",
"D30-1571085": "নন্দো স্টোর",
"D30-1571089": "মোস্তফা স্টোর",
"D30-1571094": "হাসনাত স্টোর",
"D30-1571100": "লিটন স্টোর",
"D30-1571107": "মিন্টু ষ্টোর",
"D30-1571110": "বরুন স্টোর",
"D30-1571120": "নতুন সাগর স্টোর",
"D30-1571121": "রুবেল ষ্টোর",
"D30-1571123": "রনি স্টোর",
"D30-1571126": "ইত্যাদি স্টোর",
"D30-1571127": "রাসিল ষ্টোর",
"D30-1571128": "জোনোনি ভ্যারাইটি স্টোর",
"D30-1571129": "মাইদুল স্টোর",
"D30-1571135": "আজিজুর ষ্টোর",
"D30-1571137": "কুরবান স্টোর",
"D30-1571138": "দুলাল স্টোর",
"D30-1571140": "মরিওম কনফেকশনারি",
"D30-1571142": "আলমগীর স্টোর-২",
"D30-1571143": "সাইফুল ফুড",
"D30-1571145": "শাহাজাহান স্টোর",
"D30-1571146": "আকবর স্টোর",
"D30-1571148": "মোহনা স্টোর",
"D30-1571149": "রফিকুল কসমেটিকেস",
"D30-1571153": "রবিউল স্টোর",
"D30-1571154": "জনি রনি স্টোর",
"D30-1571156": "সবুজ স্টোর",
"D30-1571158": "মেঘলা কনফেকশনারি",
"D30-1571160": "আবু সাইদ স্টোর",
"D30-1571161": "জাহিদুল স্টোর",
"D30-1571162": "লেবনি স্টোর",
"D30-1571164": "সুইটি ভ্যারাইটি স্টোর",
"D30-1571165": "লাইজু ষ্টোর",
"D30-1571170": "আতাউর স্টোর",
"D30-1571171": "আতাউর স্টোর",
"D30-1571172": "মোহসিন স্টোর",
"D30-1571176": "অ্যানোয়ার স্টোর",
"D30-1571179": "মামুন ষ্টোর",
"D30-1571184": "মেসার্স রাশেদ স্টোর",
"D30-1571185": "আকাশ স্টোর",
"D30-1571187": "ফিরোজ কনফেক্টনারি",
"D30-1571188": "আহমেদ আলী",
"D30-1571189": "মেসার্স আখিমুন ট্রেডার্স",
"D30-1571191": "ফুয়াদ স্টোর",
"D30-1571194": "সাদিয়া স্টোর",
"D30-1571196": "রিয়া স্টোর",
"D30-1571198": "সাহেব মিষ্টান্ন",
"D30-1571199": "মা ফাতেমা স্টোর",
"D30-1571202": "কুইন কস: স্টোর",
"D30-1571203": "উজ্জল ষ্টোর",
"D30-1571213": "রিয়া স্টোর",
"D30-1571216": "সাদিয়া স্টোর",
"D30-1571225": "শেমা কান্ত স্টোর",
"D30-1571227": "ফুল মিয়া",
"D30-1571228": "রবিউল স্টোর",
"D30-1571232": "রুবেল স্টোর",
"D30-1571234": "এফ বি স্টোর",
"D30-1571239": "মামুন ডিপার্টমেন্টাল স্টোর",
"D30-1571240": "আতাউর স্টোর",
"D30-1571242": "আঁখি স্টোর",
"D30-1571244": "রকিব ​​স্টোর",
"D30-1571246": "রানা স্টোর",
"D30-1571249": "সিদ্দিক স্টোর",
"D30-1571270": "শাজাহান স্টোর",
"D30-1571271": "সুধীর স্টোর",
"D30-1571272": "জয় কুমার স্টোর",
"D30-1571284": "হাসিনুর স্টোর",
"D30-1571285": "বেলাল স্টোর",
"D30-1571286": "বাবু স্টোর",
"D30-1571288": "কুরবান স্টোর",
"D30-1571291": "খাজা ষ্টোর",
"D30-1571293": "অমিত স্টোর",
"D30-1571295": "মা গিফ্ট কর্নার",
"D30-1571296": "বোনা স্টোর",
"D30-1571297": "আন্নিকা ষ্টোর",
"D30-1571298": "নবাব ষ্টোর",
"D30-1571299": "সোরিফুল স্টোর",
"D30-1571303": "মইনুল স্টোর",
"D30-1571305": "সালাম স্টোর",
"D30-1571307": "রাশিদুল স্টোর",
"D30-1571308": "মইনুল স্টোর",
"D30-1571309": "কুদ্দুস স্টোর",
"D30-1571311": "বকুল ষ্টোর",
"D30-1571312": "সবুর স্টোর",
"D30-1571313": "উজ্জ্বল স্টোর",
"D30-1571314": "রাসেল সেন্ট",
"D30-1571318": "ইসরাত কসমেটিক্স",
"D30-1571319": "আলম স্টোর",
"D30-1571322": "জামিউল স্টোর",
"D30-1571325": "আলী স্টোর",
"D30-1571327": "জামান স্টোর",
"D30-1571329": "রাজু স্টোর",
"D30-1571330": "মা ভ্যারাইটি",
"D30-1571334": "অরনি ষ্টোর",
"D30-1571336": "আমিনুল স্টোর",
"D30-1571337": "মা মুদি খানা",
"D30-1571339": "কুন্ডু স্টোর",
"D30-1571340": "ইকোনমি স্টোর",
"D30-1571341": "ইব্রাহিম স্টোর",
"D30-1571342": "ড,িকে ষ্টোর",
"D30-1571343": "ডট কম স্টোর",
"D30-1571345": "মুক্তি স্টোর",
"D30-1571346": "ওবায়দুল স্টোর",
"D30-1571353": "এ মান্নান স্টোর",
"D30-1571360": "আলী পান ষ্টোর",
"D30-1571361": "আমজাদ ষ্টোর",
"D30-1571364": "মা শাফিয়া চৌল ঘোর",
"D30-1571366": "হাসান ষ্টোর",
"D30-1571367": "শামীম স্টোর",
"D30-1571370": "ড্রমি কসমটেক্সি",
"D30-1571371": "নিহা কসমেটিক্স",
"D30-1571374": "আজগার ষ্টোর",
"D30-1571375": "মর্নিং সান স্টোর",
"D30-1571379": "মোস্তাফিজুর স্টোর",
"D30-1571380": "পারভিন স্টোর",
"D30-1571388": "রুবেল স্টোর",
"D30-1571389": "হাসান স্টোর",
"D30-1571390": "হুমায়ুন স্টোর",
"D30-1571392": "ফাতেমা ভ্যারাইটি স্টোর",
"D30-1571394": "মমতাজ ভ্যারাইটি স্টোর",
"D30-1571397": "জয় প্রসাধনি",
"D30-1571400": "নুরে জান্নাত ট্রেডার্স",
"D30-1571409": "নজরুল স্টোর",
"D30-1571410": "মন্টুি ষ্টোর",
"D30-1571413": "মিজান স্টোর",
"D30-1571414": "আবুল স্টোর",
"D30-1571418": "শাহ আলম পান সপ",
"D30-1571420": "আক্তার ষ্টোর",
"D30-1571421": "আ. মালেক ষ্টোর",
"D30-1571423": "সাদ্দাম ষ্টোর",
"D30-1571428": "পাল হোমিও চিকিৎসালয়",
"D30-1571429": "বাদশা পান ষ্টোর",
"D30-1571433": "মামুন স্টোর",
"D30-1571434": "কার্তিক স্টোর",
"D30-1571435": "আনুরুল ষ্টোর",
"D30-1571437": "সালাম ষ্টোর",
"D30-1571438": "মোস্তফা ষ্টোর",
"D30-1571440": "মাইকেল স্টোর",
"D30-1571441": "সুমি ষ্টোর",
"D30-1571444": "আমিনুল স্টোর",
"D30-1571445": "মানাফ কসমেটিক্স",
"D30-1571452": "ফাফিম ও ফারিয়া স্টোর",
"D30-1571453": "আয়েশা স্টোর",
"D30-1571454": "নুরনবী স্টোর",
"D30-1571455": "নুর আলম  চাউল",
"D30-1571456": "তামিম স্টোর",
"D30-1571458": "আল-মামুন স্টোর",
"D30-1571459": "আইয়ুব স্টোর",
"D30-1571463": "আলিফ স্টোর",
"D30-1571465": "সামসুল স্টোর",
"D30-1571468": "মেসার্স সোপন কসমেটিক্স",
"D30-1571470": "অ্যাপেল স্টোর",
"D30-1571471": "আজগর স্টোর",
"D30-1571475": "আনারুল পান শপ",
"D30-1571477": "রইসুদ্দিন স্টোর",
"D30-1571481": "আরাফাত ষ্টোর",
"D30-1571486": "মাহিন কনফেকশনারি",
"D30-1571487": "নুরে জান্নাত ভ্যারাইটি ষ্টোর",
"D30-1571488": "আল মামুন স্টোর",
"D30-1571489": "আল আমিন স্টোর",
"D30-1571490": "নূর আলম স্টোর",
"D30-1571491": "মোকলেশ স্টোর",
"D30-1571493": "আব্দুর রহমান ষ্টোর",
"D30-1571495": "মাইনুল স্টোর",
"D30-1571497": "মা স্কাই মিডিয়া",
"D30-1571501": "দুই ভাই স্টোর",
"D30-1571502": "শামীম স্টোর",
"D30-1571503": "মোজাফ্ফর ষ্টোর",
"D30-1571504": "ইসমাইল ষ্টোর",
"D30-1571508": "ওবাইদুর স্টোর",
"D30-1571509": "সুমন স্টোর",
"D30-1571511": "মা স্কাই মিডিয়া",
"D30-1571512": "মা কসমেটিক্স",
"D30-1571519": "ইমরান স্টোর",
"D30-1571520": "দিনাজপুর মোবাইল হাউস",
"D30-1571522": "নাহিয়ান ট্রেডার্স",
"D30-1571524": "জাহিদ ষ্টোর",
"D30-1571525": "তুসার স্টোর",
"D30-1571526": "হাফেজ স্টোর",
"D30-1571527": "নিশাত স্টোর",
"D30-1571530": "আসাদ স্টোর",
"D30-1571532": "তাওয়াক্কুল স্টোর",
"D30-1571535": "নিরব স্টোর",
"D30-1571538": "লিখন",
"D30-1571539": "রাহাত এন্টারপ্রাইজ",
"D30-1571540": "মালিহা স্টোর",
"D30-1571541": "জালাল স্টোর",
"D30-1571542": "খরসেদ স্টোর",
"D30-1571543": "মেসার্স তোফাজ্জল ট্রেডার",
"D30-1571544": "তানভীর স্টোর",
"D30-1571546": "বিসমিল্লাহ স্টোর",
"D30-1571550": "সাকিব স্টোর",
"D30-1571552": "আলম স্টোর",
"D30-1571555": "কেয়া লুবনা ডিপাটমেন্টাল ষ্টোর",
"D30-1571563": "ফরহাদ স্টোর",
"D30-1571564": "সুরজো স্টোর",
"D30-1571567": "অনিল স্টোর",
"D30-1571570": "নন্দি চৌলঘর",
"D30-1571572": "বিবেক স্টোর",
"D30-1571573": "পৃথিবি ভ্যারাইটি স্টোর",
"D30-1571576": "আবুল খায়ের ট্রেডার্স",
"D30-1571578": "ব্রাদার্স স্টোর",
"D30-1571580": "মাহির ভ্যারাইটি স্টোর",
"D30-1571582": "রিপন স্টোর",
"D30-1571583": "মিলন স্টোর",
"D30-1571585": "বাধন ষ্টোর",
"D30-1571586": "আশা ষ্টোর",
"D30-1571590": "আলী স্টোর",
"D30-1571595": "আরমান ষ্টোর",
"D30-1571597": "রাজু ষ্টোর",
"D30-1571598": "আমজাদ ষ্টোর",
"D30-1571603": "জাহাঙ্গীর স্টোর",
"D30-1571605": "ঘোষ স্টোর",
"D30-1571606": "অনুসরণ",
"D30-1571608": "হৃদয় তেল ঘোর",
"D30-1571612": "হাবিব স্টোর",
"D30-1571613": "মাহবুব ইসলাম",
"D30-1571615": "পলাশ স্টোর",
"D30-1571616": "আক্তার স্টোর",
"D30-1571620": "আলমগীর হোসেন",
"D30-1571623": "মায়ের দোয়া স্টোর",
"D30-1571626": "পলাশ স্টোর",
"D30-1571636": "সিরাজুল স্টোর",
"D30-1571637": "সোহাগ ষ্টোর",
"D30-1571638": "লিটন স্টোর",
"D30-1571643": "শরিফুল স্টোর",
"D30-1571645": "রমজান",
"D30-1571646": "ফাহিম স্টোর",
"D30-1571647": "সাজ্জাত স্টোর",
"D30-1571648": "ফারিয়া বেকারি",
"D30-1571652": "রবিউল স্টোর",
"D30-1571653": "মহাজ্জেম স্টোর",
"D30-1571658": "রবিউল স্টোর",
"D30-1571659": "সুমন ডিপার্টমেন্ট স্টোর",
"D30-1571660": "ওহাব ষ্টোর",
"D30-1571661": "মুসলিম স্টোর",
"D30-1571662": "জে, বি, এল স্টোর",
"D30-1571664": "ভাই ভাই স্টেশনারি",
"D30-1571666": "মা ডিপার্টমেন্ট স্টোর",
"D30-1571668": "সুমন স্টোর",
"D30-1571669": "ভাই ভাই ভ্যারাইটি স্টোর",
"D30-1571670": "আবু এন্টারপ্রাইজ",
"D30-1571672": "কল্লোল স্টোর",
"D30-1571673": "শেতু এন্টারপ্রাইজ ২",
"D30-1571674": "ইসলাম ব্রার্দৃসর্",
"D30-1571675": "আসাদ স্টোর",
"D30-1571677": "ইউসুফ স্টোর",
"D30-1571680": "এস এস বি ষ্টোর",
"D30-1571682": "রুমি ট্রেডার্স",
"D30-1571683": "ফ্রন্ডেস ভ্যারাইটি ষ্টোর",
"D30-1571684": "আলতাব ষ্টোর",
"D30-1571686": "ফরদিুল ষ্টোর",
"D30-1571688": "সোপন স্টোর",
"D30-1571691": "আরিফ স্টোর",
"D30-1571694": "নূর ইসলাম স্টোর",
"D30-1571695": "উজ্জল স্টোর",
"D30-1571697": "নুরুল স্টোর",
"D30-1571700": "আনোয়ার স্টোর",
"D30-1571702": "মিমি ষ্টোর",
"D30-1571703": "সৃাগর ষ্টোর",
"D30-1571708": "মজিবুল স্টোর",
"D30-1571712": "লিটন স্টোর",
"D30-1571731": "ভাই ভাই স্টোর",
"D30-1571732": "আকাশ ভ্যারাইটি স্টোর",
"D30-1571733": "মা কসমেটিক",
"D30-1571735": "জয় স্টোর",
"D30-1571736": "জেসিকাস স্টোর",
"D30-1571739": "মা ভ্যারাইটি ষ্টোর",
"D30-1571740": "আমিনুল ষ্টোর",
"D30-1571742": "মিঠু স্টোর",
"D30-1571746": "আক্তারুল স্টোর",
"D30-1571747": "তারিকুল স্টোর",
"D30-1571749": "কাগজঘর",
"D30-1571750": "আল-বাইক বেকারি",
"D30-1571752": "পর্না স্টোর",
"D30-1571753": "সুমন কসমেটিক্স",
"D30-1571754": "সানিহা কসমেটিক্স",
"D30-1571756": "শাগর স্টোর",
"D30-1571758": "নূর আলম স্টোর",
"D30-1571760": "মুন্নি ভ্যারাইটি ষ্টোর",
"D30-1571767": "ইমরান স্টোর",
"D30-1571771": "মান্নান স্টোর",
"D30-1571772": "বিসমিল্লা স্টোর",
"D30-1571776": "ভাই ভাই স্টোর",
"D30-1571778": "মুইন ষ্টোর",
"D30-1571783": "আউব স্টোর",
"D30-1571789": "মোহন  ডিপার্টমেন্টাল স্টোর",
"D30-1571790": "জয় ডিপার্টমেন্টাল স্টোর",
"D30-1571798": "সেতু ট্রের্ডাস",
"D30-1571801": "তুহিন স্টোর",
"D30-1571802": "হামজা স্টোর",
"D30-1571803": "নয়ন স্টোর",
"D30-1571804": "সাজু ডিপার্টমেন্টাল স্টোর",
"D30-1571806": "সাদিয়া টেলিকম",
"D30-1571808": "মা স্টোর",
"D30-1571810": "আহাত টেলিকম",
"D30-1571813": "আমিনুল স্টোর",
"D30-1571814": "সাইমুল স্টোর",
"D30-1571818": "লিমন স্টোর",
"D30-1571820": "রেজাউল স্টোর",
"D30-1571822": "মাহিন ভ্যারাইটি স্টোর",
"D30-1571823": "হিয়া স্টোর",
"D30-1571825": "জুলফিকার স্টোর",
"D30-1571828": "সাদেক স্টোর",
"D30-1571830": "রফিকুল স্টোর",
"D30-1571836": "অনু স্টোর",
"D30-1571837": "গোলাপ ষ্টোর",
"D30-1571844": "সঞ্জয় স্টোর",
"D30-1571845": "আরজন স্টোর",
"D30-1571846": "মনোজ স্টোর",
"D30-1571847": "নূর স্টোর",
"D30-1571848": "পূজা স্টোর",
"D30-1608": "নুরু ভ্যারাইটি ষ্টোর",
"D30-1627": "লুৎফর স্টোর",
"D30-1640407": "লোকনাথ ফার্মাসি",
"D30-1640410": "আর এম পি পল্লী",
"D30-1640413": "ইব্রাহিম মেডিকেল",
"D30-1640415": "উত্তরা ফার্মেসি",
"D30-1640416": "সবো র্ফামসেী",
"D30-1640418": "রয়েল মেডিসিন মার্ট",
"D30-1640419": "রুকু ফার্মেসী",
"D30-1640420": "মা, মেডিসিন মার্ট",
"D30-1640422": "আরসি স্টোর",
"D30-1640424": "রফিক মেডিসিন",
"D30-1640425": "আনিস ফার্মেসি",
"D30-1640427": "জিম ফার্মেসি",
"D30-1640428": "ঢাকা মেডিকেল স্টোর",
"D30-1640429": "পপুলাল মেডিকেল স্টোর",
"D30-1640430": "আনোয়ার মেডিকেল স্টোর",
"D30-1640449": "আফসনি র্ফামসেী",
"D30-1640450": "ঐশী ফার্মেসী",
"D30-1640452": "মাহমুদ মেডিকেল স্টোর",
"D30-1640455": "মৌমিতা ফারমেসি",
"D30-1640459": "মেঘলা ফার্মেসি",
"D30-1640460": "ভাই বোন ফার্মেসী",
"D30-1640461": "আরমান মেডিকেল স্টোর",
"D30-1640463": "মাসুদ মেডিকেল স্টোর",
"D30-1644": "রূপনকসা  কসমেটিক্স",
"D30-1646": "বাবুল কন",
"D30-1658": "খান স্টেশনারি",
"D30-1688": "ওভি কনফেকশনারি",
"D30-1726616": "আক্তারুল স্টোর",
"D30-1726617": "আজহারুল স্টোর",
"D30-1726621": "সাহিনুর স্টোর",
"D30-1726626": "আইনুল ষ্টোর",
"D30-1726627": "নোওয়ান স্টোর",
"D30-1726630": "অনিতা স্টোর",
"D30-1726639": "রেজা স্টোর",
"D30-1726640": "মোজাহারুল স্টোর",
"D30-1726646": "কালু স্টোর",
"D30-1726653": "আতাউর স্টোরেভ",
"D30-1726654": "লিটন স্টোর",
"D30-1726655": "মা বাবর দুয়া ভ্যারাইটি",
"D30-1726656": "জিউ স্টোর",
"D30-1726657": "ভি ভি ভ্যারাইটি স্টোর",
"D30-1726658": "মা ভ্যারাইটি",
"D30-1726663": "রিদয় স্টোর",
"D30-1726664": "হাবিব স্টোর",
"D30-1726669": "ফরহাদ ও ফয়সাল স্টোর",
"D30-1726705": "বিসমিল্লাহ কসমেটিক্স ও স্টেশনারি",
"D30-1726706": "মিজান ষ্টোর",
"D30-1726707": "জালাল ষ্টোর",
"D30-1726708": "ফারুকের স্টোর",
"D30-1726714": "ইমাম ভ্যারাইটি স্টোর।",
"D30-1726716": "জাকিরুল স্টোর",
"D30-1726717": "ইয়াকুব স্টোর।",
"D30-1726718": "উজ্জল স্টোর।",
"D30-1726719": "রবিউল স্টোর।",
"D30-1726722": "তৌহিদুল স্টোর।",
"D30-1726724": "হেলাল স্টোর",
"D30-1726726": "মাহাবুব ষ্টোর",
"D30-1726729": "মাসুদ ষ্টোর",
"D30-1726730": "সফিকুল স্টোর।",
"D30-1726733": "নুর নবি স্টোর",
"D30-1726734": "আমিনুল ষ্টোর",
"D30-1726738": "জালাল স্টোর।",
"D30-1726739": "ফারাজুল স্টোর।",
"D30-1726740": "লিটন স্টোর।",
"D30-1726741": "নোমিস স্টোর",
"D30-1726744": "মা ষ্টোর",
"D30-1726745": "হানিফ স্টোর।",
"D30-1726746": "গোপাসসর ষ্টোর",
"D30-1726747": "ফরহাদ স্টোর।",
"D30-1726749": "মনির স্টোর।",
"D30-1726753": "শাহিন স্টোর",
"D30-1726754": "শামিম ষ্টোর",
"D30-1726756": "আক্তার স্টোর",
"D30-1726757": "আবু তাহের ষ্টোর",
"D30-1726758": "দেলোওয়ার ষ্টোর",
"D30-1726759": "জিরুল ষ্টোর",
"D30-1726762": "শাহাবুদ্দীন ষ্টোর",
"D30-1726763": "রুহুল ষ্টোর",
"D30-1726765": "দেলওয়ার স্টোর",
"D30-1726769": "ইব্রাহীম ষ্টোর",
"D30-1726776": "বাবু স্টোর",
"D30-1726791": "রফিকুল স্টোর",
"D30-1726792": "জ্যাটিন স্টোর",
"D30-1726793": "গোপাল ষ্টোর",
"D30-1726795": "শিনান্দা স্টোর",
"D30-1726796": "রঞ্জিত স্টোর",
"D30-1726798": "স্ল্যাম পান স্টোর",
"D30-1726799": "হরিকৃষ্ণা পান ষ্টোর",
"D30-1726800": "মনসুর স্টোর",
"D30-1726801": "শরিফুল স্টোর",
"D30-1726802": "নবাব স্টোর",
"D30-1726803": "উপেন স্টোর",
"D30-1726806": "আনোয়ার স্টোর",
"D30-1726808": "সুধির স্টোর",
"D30-1726812": "বিসমিল্লাহ ষ্টোর",
"D30-1726815": "নাজমুল কসমেটিক্স",
"D30-1726816": "উজ্জ্বল স্টোর",
"D30-1726818": "অপু স্টোর",
"D30-1726823": "কামিনী স্টোর",
"D30-1726825": "পলাশ স্টোর",
"D30-1726826": "জননি মুদি স্টোর",
"D30-1726833": "আপন স্টোর",
"D30-1726838": "কিপ স্টোর",
"D30-1726840": "কুঞ্জুন ভ্যারাইটিস স্টোর",
"D30-1726844": "মা কসমেটিক্স",
"D30-1726846": "বিসমিল্লা স্টোর",
"D30-1726864": "সাফুন স্টোর",
"D30-1726868": "রফিকুল ষ্টোর",
"D30-1726872": "রঞ্জন স্টোর",
"D30-1726873": "বাবু ষ্টোর",
"D30-1726876": "খলিল স্টোর",
"D30-1726883": "আমিনুল স্টোর",
"D30-1726888": "টয়েলকো স্টোর",
"D30-1726891": "খুসি ভরাইটিস স্টোর এবং কসমেটিক্স",
"D30-1726895": "মাসুম স্টোর",
"D30-1726904": "আরমান স্টোর",
"D30-1726905": "রেজারুল স্টোর",
"D30-1726906": "খাদেমুল স্টোর",
"D30-1726907": "হানিফ স্টোর",
"D30-1726908": "রফিকুল স্টোর",
"D30-1726909": "মোতালেব স্টোর",
"D30-1726911": "আবুল কালাম স্টোর",
"D30-1726912": "মামুন স্টোর",
"D30-1726913": "মকসেদ স্টোর",
"D30-1726914": "মমিনুল স্টোর",
"D30-1726918": "হান্নান স্টোর",
"D30-1726920": "মামুন ষ্টোর",
"D30-1726921": "রহমান ষ্টোর",
"D30-1726923": "দবির স্টোর",
"D30-1726926": "বিনয় স্টোর",
"D30-1726929": "মিলন স্টোর",
"D30-1726930": "ফকরুল স্টোর",
"D30-1726933": "সুভাংকর স্টোর",
"D30-1726934": "নোবানু স্টোর",
"D30-1726937": "সাজাদ স্টোর",
"D30-1726940": "সোনাতল স্টোর",
"D30-1726941": "নাজমুল স্টোর",
"D30-1726943": "নূর স্টোর",
"D30-1726944": "আফসারুল স্টোর",
"D30-1726945": "ভাই ভাই স্টোর",
"D30-1726947": "জালাল স্টোর",
"D30-1726948": "মা স্টোর",
"D30-1726949": "নূর জামান স্টোর",
"D30-1726951": "অমল ষ্টোর",
"D30-1726953": "সাইফুল স্টোর",
"D30-1726958": "ফারুক স্টোর",
"D30-1726959": "রফিকুল ষ্টোর",
"D30-1726960": "লাল বাবু স্টোর",
"D30-1726961": "সাদাম স্টোর",
"D30-1726962": "হামাদুল স্টোর",
"D30-1726963": "মন্টাসিন স্টোর",
"D30-1726964": "জুয়েল স্টোর",
"D30-1726965": "রবিরুল স্টোর",
"D30-1726966": "রুমি স্টোর",
"D30-1726969": "নুরুল স্টোর",
"D30-1726972": "সমাজদ্দিন স্টোর",
"D30-1726976": "নোরোহোরি স্টোর",
"D30-1726977": "বৃষ্টি মেডিকেল ষ্টোর",
"D30-1726979": "মোদিনা",
"D30-1726982": "দুলাল স্টোর",
"D30-1726985": "হেমন্ত স্টোর",
"D30-1726988": "মিতু ভ্যারাইটি স্টোর",
"D30-1726992": "মহেশ স্টোর",
"D30-1726993": "বিষ্ণো স্টোর",
"D30-1726994": "গৌরাঙ্গ পান স্টোর",
"D30-1726996": "পরেশ স্টোর",
"D30-1726997": "শফিকুল স্টোর",
"D30-1726998": "রিয়াজুল স্টোর",
"D30-1726999": "সাহা আলম",
"D30-1727001": "রোহান স্টোর",
"D30-1727004": "লিমন স্টোর",
"D30-1727005": "লিয়াকোট স্টোর",
"D30-1727006": "জোবাইবুর স্টোর",
"D30-1727007": "আক্তার স্টোর",
"D30-1727009": "সোহিদুল স্টোর",
"D30-1727024": "মোকলেছুর স্টোর",
"D30-1727026": "মাসুদ ষ্টোর",
"D30-1727030": "হামিদুল ষ্টোর",
"D30-1727032": "মনি স্টোর",
"D30-1760": "মেসার্স মজুমদার ট্রেডার্স",
"D30-1799": "বাচ্চু স্টোর",
"D30-1800": "স্মৃতি কসমেটিক্স",
"D30-1813": "বাবু মশোলা স্টোর",
"D30-1838": "মিতালি ভ্যারাইটি স্টোর",
"D30-1839": "তাজ স্টোর",
"D30-1841": "রত্না কনফেকশনারি",
"D30-1847": "সততা কসমেটিক্স",
"D30-1848": "মোজিবর স্টোর",
"D30-1849": "হাফিজ স্টোর",
"D30-1849587": "পারভেজ স্টোর",
"D30-1849588": "আরিফ স্টোর",
"D30-1849589": "মোস্তাফিজুর স্টোর",
"D30-1849590": "সালাম ষ্টোর",
"D30-1849591": "আলমগীর স্টোর",
"D30-1849592": "রিপন স্টোর",
"D30-1849593": "মোমিন স্টোর",
"D30-1849594": "মদিনা ষ্টোর",
"D30-1849596": "মুন্না স্টোর",
"D30-1849600": "ইয়াকুব স্টোর",
"D30-1849601": "জেরিন স্টোর",
"D30-1849603": "আনোয়ার ষ্টোর",
"D30-1849604": "বাবুর পান স্টোর",
"D30-1849613": "শুভ ভ্যারাইটি ষ্টোর",
"D30-1849618": "খাদেমুল ফ্যাশন অ্যান্ড কসমেটিক্স",
"D30-1849620": "মতিউর এন্ড ষ্টোর",
"D30-1849623": "জামিরুল পান স্টোর",
"D30-1849624": "রফিকুল ভ্যারাইটি স্টোর",
"D30-1849625": "নজরুল ষ্টোর",
"D30-1849629": "আরমিন স্টোর",
"D30-1849632": "সোহাগ স্টোর",
"D30-1849634": "জুয়েল স্টোর",
"D30-1849639": "মা বাবর দোয়া",
"D30-1849640": "দিলীপ স্টোর",
"D30-1849647": "আমিনুল ষ্টোর",
"D30-1849649": "দুই ভাই স্টোর",
"D30-1849651": "মিজানুর স্টোর",
"D30-1849652": "মিনহাজ ষ্টোর",
"D30-1849653": "সোহেল স্টোর",
"D30-1849654": "বাবু স্টোর",
"D30-1849655": "রুবেল ষ্টোর",
"D30-1849656": "তোজাম্মেল স্টোর",
"D30-1849657": "আরিফ স্টোর",
"D30-1849659": "শাহিনুর স্টোর",
"D30-1849661": "তাজমুল স্টোর",
"D30-1849663": "মা টেলিকম",
"D30-1849664": "হাবিব স্টোর",
"D30-1849668": "জয়নাল স্টোর",
"D30-1849672": "শাহা আলম ষ্টোর",
"D30-1849673": "জুলফিকার ষ্টোর",
"D30-1849674": "গ্রাম ভান্ডার",
"D30-1849675": "বায়োজিদ স্টোর",
"D30-1849676": "জাহাঙ্গীর স্টোর",
"D30-1849677": "রিতুুু ফটোষ্ট্যাট",
"D30-1849679": "ওশোক স্টোর",
"D30-1849680": "কেনাকাটা স্টোর",
"D30-1849682": "সেলিম ফল স্টোর",
"D30-1849687": "কালিম স্টোর",
"D30-1849688": "মনোয়ার স্টোর",
"D30-1849689": "দুই কন্না স্টোর",
"D30-1849690": "শুভ স্টোর",
"D30-1849692": "পূর্ণিমা স্টোর",
"D30-1849693": "অ্যানোনা কসমেটিক্স",
"D30-1849694": "বিসমিল্লাহ স্টোর",
"D30-1849698": "আল বাইক ফুড",
"D30-1849699": "রংধনু কসমেটিক্স",
"D30-1849700": "শাবা কসমেটিক্স",
"D30-1849703": "শিহাব ডিপার্টমেন্টাল স্টোর",
"D30-1849705": "মর্সোস তাজমি রাইস এজন্সেি",
"D30-1849706": "মেসার্স অরনো ডিপার্টমেন্ট স্টোর",
"D30-1849707": "আরনি স্টোর",
"D30-1849712": "বন্ধু ট্রেডার্স",
"D30-1849714": "হাববিুর ষ্টোর",
"D30-1849716": "রত্না কসমেটিক্স",
"D30-1849717": "বাবু স্টোর",
"D30-1849721": "শাকিল স্টোর",
"D30-1849722": "রুবেল স্টোর",
"D30-1849725": "খান স্টোর",
"D30-1849726": "অ্যাডোরি কসমেটিক্স",
"D30-1849727": "চহিন স্টোর",
"D30-1849729": "রবি ষ্টোর",
"D30-1850": "মোজাম্মেল স্টোর",
"D30-1859": "বি.জি.বি ক্যান্টিন",
"D30-1866": "বাবুল স্টোর",
"D30-1879": "সিনিগথো কসমেটিক্স পিএস",
"D30-1881": "মাসুদ স্টোর",
"D30-1885": "মা ষ্টোর",
"D30-1887": "শেন্টু স্টোর",
"D30-1890": "সাজু ষ্টোর",
"D30-1906": "বাইতুসালাম স্টোর",
"D30-1910": "মৌ স্টোর",
"D30-1922": "সিরাজুল স্টোর",
"D30-1947": "মান্নান ভ্যারাইটি স্টোর",
"D30-1949": "রাজ্জাক টেলিকম",
"D30-1950947": "আল বাইক ফুড বেকারি",
"D30-1950949": "মা ভ্যারাইটি স্টোর",
"D30-1950953": "নুর জামান ষ্টোর",
"D30-1950955": "রানা স্টোর",
"D30-1950957": "মিলন স্টোর",
"D30-1950965": "বাবার স্টোর",
"D30-1950966": "নুর স্টোর",
"D30-1950971": "তাহমিদ ট্রেডাস",
"D30-1950972": "শরীফ পান স্টোর",
"D30-1950974": "নূর আলম ভ্যারাইটি স্টোর",
"D30-1950975": "রাজীব ষ্টোর",
"D30-1950976": "মোয়াজ্জেম পান স্টোর",
"D30-1950978": "আল-আমিন স্টোর",
"D30-1950979": "আইনুল হক স্টোর",
"D30-1950981": "সাজিদ সিনহা চাউল ঘর",
"D30-1950982": "ডিজিটাল গিফ্ট কর্ণার",
"D30-1950983": "শাহিন ষ্টোর",
"D30-1950984": "আব্দুল্লা স্টোর",
"D30-1950988": "ফরিদ স্টোর",
"D30-1950989": "রাফা ভ্যারাইটিস স্টোর",
"D30-1950990": "রাজ্জাক ট্রেডার্স",
"D30-1950991": "সংকর কনডু স্টোর",
"D30-1950992": "রুহানি ট্রেডস",
"D30-1953": "সাহিন স্টোর",
"D30-1959": "সাদিক স্টোর",
"D30-1960": "শোহানা স্টোর",
"D30-1989": "জাহাঙ্গীর ভ্যারাইটি স্টোর",
"D30-1995": "বিসমিল্লা স্টোর",
"D30-2001": "নিও ভ্যারাইটি স্টোর",
"D30-2003": "দেলোয়ার পেপারস",
"D30-2004": "আজিবুল স্টোর",
"D30-2010": "আব্দুর রশিদ স্টোর",
"D30-2015": "ফায়েজ কনফেকশনারি",
"D30-2016748": "মোহাম্মদ ওয়াইমার স্টোর",
"D30-2023": "জুয়েল ফোল",
"D30-2033": "হায়দার স্টোর",
"D30-2042": "আনামুল স্টোর",
"D30-2044": "গোপাল ষ্টোর",
"D30-2045": "সন্ধ্যা ষ্টোর",
"D30-2052": "সাইফুল স্টোর",
"D30-2053": "মোহন স্টোর",
"D30-2055708": "রফিকুল ষ্টোর",
"D30-2055709": "ইজে ইলেকট্রনিক",
"D30-2055710": "আইবে স্টোর",
"D30-2055712": "জান্নাতি স্টোর",
"D30-2055716": "সাজু স্টোর",
"D30-2055717": "হুমাইরা আরবি",
"D30-2055718": "ধর্মো স্টোর",
"D30-2055733": "সৈকত স্টোর",
"D30-2055734": "কালাম ষ্টোর",
"D30-2055736": "লিটন স্টোর",
"D30-2055741": "রাজ ভ্যারাইটিস স্টোর",
"D30-2055742": "মানিক পান স্টোর",
"D30-2055749": "পলাশ স্টোর",
"D30-2055750": "আসাদ স্টোর",
"D30-2055754": "ইউসুফ কম্পিউটার",
"D30-2055756": "মা ভ্যারাইটিজ স্টোর",
"D30-2055760": "সঞ্চয় স্টোর",
"D30-2055761": "রেজাউল স্টোর",
"D30-2055765": "রুবেল পান স্টোর",
"D30-2055767": "শুভ্র কনফেকশনারি",
"D30-2055770": "আবির স্টোর",
"D30-2055774": "আরপি স্টোর",
"D30-2055775": "তিথিরাজ স্টোর",
"D30-2055777": "আবায়েদ স্টোর",
"D30-2055779": "হাজি স্টোর",
"D30-2055780": "মুক্তার স্টোর",
"D30-2055782": "নূর আলম স্টোর",
"D30-2055785": "বিথি স্টোর",
"D30-2055786": "জাহিদুল স্টোর",
"D30-2055789": "আরজু কসমেটিক্স",
"D30-2055790": "হানিফ কসমেটিকস",
"D30-2055791": "ফারুক ভ্যারাইটিস ষ্টোর",
"D30-2055794": "জাহিদ স্টোর",
"D30-2055795": "ইউসুফ স্টোর",
"D30-2055796": "ইনউজ স্টোর",
"D30-2055797": "মোজাম্মেল স্টোর",
"D30-2055799": "মিজানুর স্টোর",
"D30-2055802": "হজরত স্টোর",
"D30-2055804": "রফিক স্টোর",
"D30-2055805": "মাসুম স্টোর",
"D30-2055806": "হানিফ স্টোর",
"D30-2055807": "জাহানারা স্টোর",
"D30-2055808": "নাইমুল স্টোর",
"D30-2055810": "বিসমিল্লাহ স্টোর",
"D30-2055811": "মানো স্টোর",
"D30-2055813": "বিসমিল্লা স্টোর",
"D30-2055817": "সাইফান ষ্টোর",
"D30-2055818": "নুর শফিক স্টোর",
"D30-2055819": "নিউ সুপার স্টোর",
"D30-2055821": "ফরিদুল স্টোর",
"D30-2055822": "হাফিজুর স্টোর",
"D30-2055823": "ইসহাক স্টোর",
"D30-2055825": "মা স্টোর",
"D30-2055827": "লাকি ভ্যারাইটিস স্টোর",
"D30-2055831": "জোতিশ স্টোর",
"D30-2055832": "সাদিয়া ভ্যারাইটিস স্টোর",
"D30-2055834": "বেলি স্টোর",
"D30-2055835": "রানি স্টোর",
"D30-2055836": "বিসমেলা স্টোর",
"D30-2055839": "রেজুল স্টোর",
"D30-2055840": "রাজিব স্টোর",
"D30-2055841": "জুলফিকার ষ্টোর",
"D30-2055842": "হোমিও হল স্টোর",
"D30-2055846": "ইব্রাহিম স্টোর",
"D30-2055851": "বেঙ্গল কসমেটিকস",
"D30-2055855": "তাপশ স্টোর",
"D30-2055856": "আজয় স্টোর",
"D30-2055857": "নুরজ্জামান ষ্টোর",
"D30-2055858": "মমিনুল স্টোর",
"D30-2055859": "সিরাজ স্টোর",
"D30-2055861": "রফিকুল স্টোর",
"D30-2055864": "রিয়াদ স্টোর",
"D30-2055870": "মোস্তফা স্টোর",
"D30-2055871": "সোবাহান ষ্টোর",
"D30-2055872": "সাদ্দাম স্টোর",
"D30-2055874": "টিঙ্কু স্টোর",
"D30-2055875": "স্বপন স্টোর",
"D30-2055876": "মামুন স্টোর",
"D30-2055878": "মা ষ্টোর",
"D30-2055879": "ইউনিক স্টোর",
"D30-2055880": "শিহাব ট্রেডার্স",
"D30-2055881": "জামাই স্টোর",
"D30-2055882": "আয়ান কসমেটিক্স",
"D30-2055885": "ফরহাদ কসমেটিকস",
"D30-2055886": "জনোটা লাইব্রেরি ও ডিপার্টমেন্টাল স্টোর",
"D30-2055887": "সোহেল স্টোর",
"D30-2055888": "নাইম স্টোর",
"D30-2055891": "আনিসুর স্টোর",
"D30-2055894": "প্রশান্ত স্টোর",
"D30-2055897": "মা বাবা ভ্যারাইটিসে স্টোর",
"D30-2055898": "ম্যাশলেম স্টোর",
"D30-2055899": "মহসেন স্টোর",
"D30-2055900": "রুবলে ষ্টোর",
"D30-2055901": "শুকচান ষ্টোর",
"D30-2055902": "কাজী অ্যান্টারপ্রাইজ স্টোর",
"D30-2055903": "নবাব স্টোর",
"D30-2055904": "রেজাউল স্টোর",
"D30-2055911": "মালিহা এন্টাপরপ্রাইজ ষ্টোর",
"D30-2055912": "রিয়া ষ্টোর",
"D30-2055915": "শাহালম ষ্টোর",
"D30-2055916": "রাবু ষ্টোর",
"D30-2055917": "দিন স্টোর",
"D30-2055918": "ভাই ভাই স্টোর ১",
"D30-2055919": "চন্দন স্টোর",
"D30-2055921": "আজাদ স্টোর",
"D30-2055923": "রেজোয়ান স্টোর",
"D30-2055924": "লিমন স্টোর",
"D30-2055925": "মতিউর স্টোর",
"D30-2055926": "জনি স্টোর",
"D30-2055927": "আলামিন ভ্যারাইটিস স্টোর",
"D30-2055928": "হাসি ষ্টোর",
"D30-2055930": "অনিকা স্টোর",
"D30-2055931": "বাবা ভ্যারাইটিস স্টোর",
"D30-2055932": "নূপুর কসমেটিক্স স্টোর",
"D30-2055933": "মজিদুল স্টোর",
"D30-2055934": "আব্দূও রহমান ষ্টোর",
"D30-2055935": "বাবা মায়ের দয়া কনফেকশনারি",
"D30-2055940": "খাদেমুল ষ্টোর",
"D30-2055941": "আজাদ স্টোর",
"D30-2055942": "নাজমুল স্টোর",
"D30-2055944": "মনি স্টোর",
"D30-2055946": "তুহিন স্টোর",
"D30-2055949": "বেলাল স্টোর",
"D30-2055951": "মুমু স্টোর",
"D30-2055956": "রুবি স্টোর",
"D30-2055957": "শাহাজান স্টোর",
"D30-2055959": "সাদ্দাম স্টোর",
"D30-2055961": "শফিকুল স্টোর",
"D30-2055964": "মা টেলিকম",
"D30-2055965": "ফাতেমা স্টোর",
"D30-2055967": "ফারুক স্টোর",
"D30-2055971": "সারা স্টোর",
"D30-2055976": "কামাল স্টোর",
"D30-2055977": "রানা স্টোর",
"D30-2055979": "আনোয়ার স্টোর",
"D30-2055987": "নয়ন স্টোর",
"D30-2055989": "নাসিম ষ্টোর",
"D30-2055990": "আফতাব ষ্টোর",
"D30-2055991": "বিশমিল্লাহ স্টোর",
"D30-2055992": "নুরু স্টোর",
"D30-2055994": "সাদেকুল স্টোর",
"D30-2055995": "অ্যানোয়ার স্টোর",
"D30-2055996": "জয় মা স্টোর",
"D30-2055997": "মিন্টু স্টোর",
"D30-2055998": "রবিউল ষ্টোর",
"D30-2056003": "আনাস ভ্যারাইটসি ষ্টোর",
"D30-2056006": "কুইন ভ্যারাইটিস স্টোর",
"D30-2056010": "শামীম স্টোর",
"D30-2056012": "ফারুক স্টোর",
"D30-2056013": "বিরেস স্টোর",
"D30-2056014": "অটিশ স্টোর",
"D30-2056017": "হাকিম ষ্টোর",
"D30-2056018": "মতিন স্টোর",
"D30-2056020": "নিশেকান্ত স্টোর",
"D30-2056021": "সিরাজুল স্টোর",
"D30-2056022": "সততা ষ্টোর",
"D30-2056023": "মেম্বার স্টোর",
"D30-2056024": "লিটন ষ্টোর",
"D30-2056029": "সেভেন সপ ষ্টোর",
"D30-2056030": "সফািট ষ্টোর",
"D30-2056031": "আশরাফুল স্টোর",
"D30-2056032": "মেসার্স রফিক স্টোর",
"D30-2056035": "সাব্বির স্টোর",
"D30-2056036": "আবু তোহা স্টোর",
"D30-2056038": "কাজল স্টোর",
"D30-2056044": "শীতল কসমেটিক্স",
"D30-2056046": "ফারুক কসমেটিক্স",
"D30-2056048": "ফাহিম ভ্যারাইটিস স্টোর",
"D30-2056049": "মা বাবা স্টোর",
"D30-2056051": "মেহেদী স্টোর",
"D30-2056053": "সাহা আলম পান দোকান",
"D30-2056056": "তানিয়া স্টোর",
"D30-2056058": "আলম ষ্টোর",
"D30-2056062": "মানিক ডিপার্টমেন্টাল স্টোর",
"D30-2056063": "মিশ্রা ডিপার্টমেন্টাল স্টোর",
"D30-2056064": "ইসমাইল স্টোর",
"D30-2056067": "নিতাই সেন্টার",
"D30-2056068": "নিতাই সেন্টার ২",
"D30-2056069": "বর্নি স্টোর",
"D30-2056072": "মামা ভাগিনা  স্টোর",
"D30-2056073": "ব্রিস্টি",
"D30-2056074": "প্রিন্স ষ্টোর",
"D30-2056075": "গোলাম রব্বানী স্টোর",
"D30-2056076": "শুভ স্টোর",
"D30-2056077": "জিহাদ স্টোর",
"D30-2056078": "ক্রিস্নো স্টোর",
"D30-2056080": "বিপুল স্টোর",
"D30-2056081": "মতিন ষ্টোর",
"D30-2056082": "জিয়া স্টোর",
"D30-2056083": "মাস্টার পান স্টোর",
"D30-2056085": "সেভেন এলিভেন স্টোর",
"D30-2056086": "সাহা স্টোর",
"D30-2056087": "এস.এন. ডিপারনেমতাল স্টোর",
"D30-2056088": "কানাই স্টোর",
"D30-2056089": "সুজা স্টোর",
"D30-2056091": "মৌসুমী ভেরাসিটি স্টোর",
"D30-2056093": "মোসলাম স্টোর",
"D30-2056095": "রিসাত মিডিয়া সেন্টার",
"D30-2056096": "সাইদুর স্টোর",
"D30-2056097": "আনোয়ার স্টোর",
"D30-2056098": "ডালোয়ার স্টোর",
"D30-2056099": "শাহিন ষ্টোর",
"D30-2056100": "দুই বোন স্টোর",
"D30-2056105": "মোকারম স্টোর",
"D30-2056107": "ভাই ভাই স্টোর",
"D30-2056109": "সিয়াম ডিপার্টমেন্টাল স্টোর",
"D30-2056110": "রিজভি স্টোর",
"D30-2056111": "নায়না ষ্টোর",
"D30-2056112": "মামুন স্টোর",
"D30-2056115": "মা কসমেটিক স্টোর ০১",
"D30-2056116": "সাজু স্টোর",
"D30-2056118": "নুপুর ষ্টোর",
"D30-2056120": "পারফেক্ট কসমেটিক্স",
"D30-2056121": "মিজানুর পান স্টোর",
"D30-2056122": "সিমা কনফেশনারী",
"D30-2056123": "সাদ্দাম ষ্টোর",
"D30-2056124": "ইমরান ষ্টোর -১",
"D30-2056125": "হাবিব স্টোর",
"D30-2056126": "বিকমপুর -৪ স্টোর",
"D30-2056130": "জ্যাকিকা স্টোর",
"D30-2056131": "জুয়েল স্টোর",
"D30-2056133": "সকল মামুন স্টোর",
"D30-2056138": "বিসমিল্লাহ স্টোর",
"D30-2056140": "মা ডিপারমেন্টাল স্টোর",
"D30-2056141": "সুমন স্টোর",
"D30-2056142": "হানি ডিপার্টমেন্টাল স্টোর",
"D30-2056143": "জামাল স্টোর",
"D30-2056146": "হাজরা স্টোর",
"D30-2064": "মা ষ্টোর",
"D30-2073": "মাহি কসমেটিক্স",
"D30-2076": "মোকসাদুর স্টোর",
"D30-2083": "প্রকাশ স্টোর",
"D30-2087": "বিকাশ স্টোর",
"D30-2093": "মনসুর স্টোর",
"D30-2094299": "দিনাজপুর_অফিস সেলস",
"D30-2095": "খালাদুর ষ্টোর",
"D30-2096": "রিফাত ভ্যারাইটি স্টোর",
"D30-2098": "ফারুক স্টোর",
"D30-2099": "বকুল স্টোর",
"D30-2167": "নিউ রাফি কসমেটিক্স",
"D30-2219848": "মেসার্স রোজ ট্রেডার্স",
"D30-2242": "কাফি স্টোর",
"D30-2245": "অতুল স্টোর",
"D30-2248": "আতা স্টোর",
"D30-2249": "ভাই ভাই স্টোর",
"D30-2250": "মজিবর স্টোর ১",
"D30-2255": "মোমোটাজ স্টোর",
"D30-2269": "মা ষ্টোর",
"D30-2270": "অনন্যা স্টুডিও এবং বিপনি",
"D30-2271": "কাজল ষ্টোর",
"D30-2276": "ইউসুফ স্টোর",
"D30-2279": "জননি ট্রেডার্স",
"D30-2284": "ফারুখ ষ্টোর",
"D30-2291": "খাজা ষ্টোর",
"D30-2292": "শামীম কসমেটিক্স",
"D30-2295": "সুমন কসমেটিক্স",
"D30-2298": "অরন্য প্রোসাধনি",
"D30-2299677": "মোঃ ওবাইদুল",
"D30-2299678": "শফিকুল  ষ্টোর",
"D30-2299679": "বাইরেন স্টোর",
"D30-2299680": "মা বাবা ভ্যারাইটি স্টোর",
"D30-2299682": "সাকিব স্টোর",
"D30-2299683": "রুবেল স্টোর",
"D30-2299685": "ভাই ভাই জনি",
"D30-2299688": "তিন ভাই বোন স্টোর",
"D30-2299692": "রুস্তম স্টোর",
"D30-2299694": "পিয়ার ষ্টোর",
"D30-2299697": "মাসুম",
"D30-2299698": "রিদয় স্টোর",
"D30-2299700": "ভাই বোন স্টোর",
"D30-2299701": "আর.এস স্টোর",
"D30-2299704": "সরকার স্টোর",
"D30-2299705": "হুমায়ুন স্টোর",
"D30-2299707": "গোপাল স্টোর",
"D30-2299708": "হিরম্ব ষ্টোর",
"D30-2299711": "ভাই বোন স্টোর",
"D30-2299712": "বাবা মা দোয়া স্টোর",
"D30-2299714": "জুবায়ের ষ্টোর",
"D30-2299715": "সততা স্টোর",
"D30-2299716": "সোহিদুল",
"D30-2299719": "আব্দুর জলিল স্টোর",
"D30-2299721": "নূপুর কসমেটিক্স ২",
"D30-2299722": "হালিমা স্টোর",
"D30-2299724": "ভাই বন স্টোর",
"D30-2299725": "তামিম স্টোর",
"D30-2299728": "রিয়াজুল স্টোর",
"D30-2299730": "বাবুল ষ্টোর",
"D30-2299731": "সুসিল স্টোর",
"D30-2299732": "মফিজ অ্যান্ড সন্স",
"D30-2299737": "নয়ন স্টোর",
"D30-2299740": "দুই ভাই ষ্টোর",
"D30-2299741": "আনোয়ার স্টোর",
"D30-2299742": "মা ভ্যারাইটি স্টোর",
"D30-2299743": "রেজাউল স্টোর",
"D30-2299744": "মা ডিপার্টমেন্টাল স্টোর",
"D30-2299745": "ডোননজয় স্টোর",
"D30-2299746": "সাওন ডিপাটমেন্টাল ষ্টোর",
"D30-2299747": "তিন ভাই",
"D30-2299749": "ভাই ভাই লাইব্রেরি এবং কসমেটিক্স",
"D30-2299750": "জোহা ট্রেডার্স",
"D30-2299753": "বিসমিল্লাহ বাজের",
"D30-2299754": "হারা ভ্যারাইটি স্টোর",
"D30-2299756": "হাসনাহেনা ষ্টোর",
"D30-2299758": "রবিউল স্টোর",
"D30-2299759": "ডয়েল স্টোর",
"D30-2299760": "মকবুল স্টোর",
"D30-2299761": "নিমি ষ্টোর",
"D30-2299762": "মুন্না স্টোর",
"D30-2299763": "বুলু স্টোর",
"D30-2299764": "কমলপুর ভ্যারাইটি স্টোর",
"D30-2299765": "সহোরা কসম্যাটিক",
"D30-2299767": "আসরাফুল",
"D30-2299768": "মায়ের দোয়া",
"D30-2299769": "রিপন স্টোর",
"D30-2299770": "আকাশ স্টোর",
"D30-2299771": "মা বেকারি",
"D30-2299772": "বিজয় স্টোর",
"D30-2299774": "আলফাল্লাহ স্টোর",
"D30-2299775": "এককালীন স্টোর",
"D30-2299778": "লিয়ানা ভ্যারাইটি",
"D30-2299779": "সারোয়ার স্টোর",
"D30-2299780": "ভাই বন স্টোর",
"D30-2299781": "আকরাম ষ্টোর",
"D30-2299783": "হালাল কসমেটিক্স",
"D30-2299785": "অর্কিড ইন্টার ফেশন",
"D30-2299786": "জনি কসমেটিক্স",
"D30-2299787": "শাহিনুর কসম্যাটিক",
"D30-2299788": "হাসান কনফেকসোনারি",
"D30-2299790": "রশিদুল স্টোর",
"D30-2299793": "ভাই বোন স্টোর",
"D30-2299794": "রাম ট্রেডার্স",
"D30-2299796": "জারিপ কসম্যাটিক",
"D30-2299797": "মেসার্স ইমরান এন্টারপ্রাইজ",
"D30-2299800": "নজরুজামান ষ্টোর",
"D30-2299802": "মানিক স্টোর",
"D30-2299803": "জামান স্টোর",
"D30-2299804": "জশিম স্টোর",
"D30-2299805": "খালেক স্টোর",
"D30-2299806": "জান্নাত স্টোর",
"D30-2299807": "অ্যানোয়ার স্টোর",
"D30-2299811": "অ্যাপেল স্টোর",
"D30-2299812": "মেসার্স এইচ অ্যান্ড এইচ কসমেটিক্স",
"D30-2299813": "পায়েরা ঘর",
"D30-2299814": "লিটন স্টোর",
"D30-2299817": "সোরিফুল স্টোর",
"D30-2299819": "হিমেল ভ্যারাইটি",
"D30-2299820": "শহিদুল ষ্টোর",
"D30-2299821": "মাহির স্টোর",
"D30-2299824": "হাবিবুর স্টোর",
"D30-2299825": "কোঠা ভ্যারিয়েটি স্টোর",
"D30-2299827": "সয়েল স্টোর",
"D30-2299829": "মনসুর ষ্টোর",
"D30-2299830": "মিনা কসমেটিকস",
"D30-2299833": "সান স্টোর",
"D30-2299834": "সাযিদা ষ্টোর",
"D30-2299835": "বেলায়েত ভেরাসিটিজ স্টোর",
"D30-2299839": "মা ভ্যারাইটিস স্টোর",
"D30-2299840": "আইনুল স্টোর",
"D30-2299841": "নাইম স্টোর",
"D30-2299842": "আরনিকা ষ্টোর",
"D30-2299843": "জারিন ষ্টোর",
"D30-2299851": "আরসাত স্টোর",
"D30-2299852": "মুন্নি স্টোর",
"D30-2299853": "তাসফিয়া স্টোর",
"D30-2299854": "জ্যাতি ষ্টোর",
"D30-2299856": "মুরাদ স্টোর",
"D30-2299857": "রবিউল ষ্টোর",
"D30-2299862": "খুরশিদ পান",
"D30-2299863": "জাহাঙ্গীর ষ্টোর",
"D30-2299864": "মা ভ্য: স্টোর",
"D30-2299865": "সাহেব বাকারে",
"D30-2299866": "সাহিল স্টোর",
"D30-2299867": "মায়ের স্টোর",
"D30-2299869": "তরিকুল",
"D30-2299872": "মা ডিপার্লমেন্টাল",
"D30-2299873": "আজহার ষ্টোর",
"D30-2299874": "আলম স্টোর",
"D30-2299875": "পরিবার পোনাগর",
"D30-2299876": "মাইশা কসমেটিক্স",
"D30-2299879": "লাবিব স্টোর",
"D30-2299881": "রিতু স্টোর",
"D30-2299884": "লোকনাথ স্টোর",
"D30-2299886": "মোঃ নূর স্টোর",
"D30-2299887": "বকুল স্টোর",
"D30-2299888": "ফজলুর স্টোর",
"D30-2299889": "তৌফিক ষ্টোর",
"D30-2299891": "সিদ্দিক স্টোর",
"D30-2299892": "নজরুল স্টোর",
"D30-2299893": "কায়সার ভ্যারাইটি স্টোর",
"D30-2299898": "মিতালি স্টোর",
"D30-2299900": "ভয় ভয় কসম্যাটিক",
"D30-2299901": "জগন্নাথ স্টোর",
"D30-2299902": "রহমত স্টোর",
"D30-2299903": "বিসমিল্লাহ স্টোর",
"D30-2299904": "বাবা ভ্যারাইটি স্টোর",
"D30-2299906": "আতিকুল কনফেকশনারী",
"D30-2299907": "হোসেন স্টোর",
"D30-2299908": "আক্কাস স্টোর",
"D30-2299909": "নজরুল ষ্টোর",
"D30-2299910": "আরবি স্টোর",
"D30-2299914": "জাকির স্টোর",
"D30-2299915": "আরিফুল ট্রেডার্স",
"D30-2299917": "লিটন স্টোর",
"D30-2299918": "মেহেদী স্টোর",
"D30-2299921": "মা স্টোর-১",
"D30-2299922": "ইত্তাদি ভ্যারাইটি স্টোর",
"D30-2299924": "মা কসমেটিক্স এবং ভ্যারাইটি স্টোর",
"D30-2299925": "জনি ষ্টোর",
"D30-2299926": "মা মনোসা স্টোর",
"D30-2299927": "মোনজুরুল ষ্টোর",
"D30-2299929": "আবু বক্কর স্টোর",
"D30-2299930": "সেনুর স্টোর",
"D30-2299931": "হায়দার ষ্টোর",
"D30-2299933": "বরকত স্টোর",
"D30-2299934": "হক ষ্টোর",
"D30-2299936": "রফিকুল ষ্টোর",
"D30-2299941": "সাদেকুল স্টোর",
"D30-2299943": "মোকসেদুল স্টোর",
"D30-2299944": "লাবু স্টোর",
"D30-2299945": "ইভা কসমেটিক্স",
"D30-2299947": "সোহেল কসমেটিক্স",
"D30-2299948": "বাপ্পি স্টোর",
"D30-2299949": "মমিনুল স্টোর",
"D30-2299951": "নেহা স্টোর",
"D30-2299952": "আনিসুর স্টোর",
"D30-2299954": "নান্টু স্টোর",
"D30-2299956": "আঙ্গুর স্টোর",
"D30-2299957": "ডাবলু স্টোর",
"D30-2299958": "হজরত স্টোর",
"D30-2299959": "শপিকুল স্টোর",
"D30-2299961": "হাসিনুর স্টোর",
"D30-2299962": "রাজু স্টোর",
"D30-2299964": "নূর মোহাম্মদ স্টোর",
"D30-2299969": "এম,পি স্টোর",
"D30-2299970": "মিলন স্টোর",
"D30-2299971": "ভাই ভাই ট্রেডার্স",
"D30-2299976": "আবিব স্টোর",
"D30-2299977": "নাজমুল স্টোর",
"D30-2299979": "শাখাওয়াত স্টোর",
"D30-2299981": "জুয়েল স্টোর",
"D30-2299982": "আকোতা কর্নার",
"D30-2299984": "লিপু স্টোর",
"D30-2299985": "রবিউল",
"D30-2299986": "জেরিন ষ্টোর",
"D30-2299987": "সাজিদুর স্টোর",
"D30-2299989": "ইমরান ষ্টোর",
"D30-2299992": "দুই ভাই স্টোর ১",
"D30-2299994": "দশ মাইল ডিপার্ট মেন্টাল স্টোর",
"D30-2299995": "সাদিয়া কসমেটিক্স",
"D30-2299996": "আনিছুর ষ্টোর",
"D30-2299997": "শফিক স্টোর",
"D30-2300000": "সেলিম স্টোর",
"D30-2300002": "আলী স্টোর",
"D30-2300003": "বিসমিল্লাহ স্টোর",
"D30-2300005": "সুমন স্টোর",
"D30-2300006": "বিপ্লব স্টোর",
"D30-2300007": "জাহিদ কসমেটিক্স",
"D30-2300009": "ভাই ভাই স্টোর",
"D30-2300010": "রাকিব স্টোর",
"D30-2300011": "লোকনাথ ভান্ডার",
"D30-2300013": "মাইকেল স্টোর",
"D30-2300016": "আঁখি স্টোর",
"D30-2300017": "আমিনুল স্টোর",
"D30-2300018": "বিক্রম স্টোর",
"D30-2300020": "রহমান স্টোর",
"D30-2300021": "আরভ স্টোর",
"D30-2300022": "দুই ভাই স্টোর",
"D30-2300023": "রোজা ষ্টোর",
"D30-2300024": "আমিল স্টোর",
"D30-2300026": "জিয়াউর ষ্টোর",
"D30-2300028": "মাহাবুর স্টোর",
"D30-2300030": "আরাফাতের স্টোর",
"D30-2300031": "সুবেল কসমেটিক্স",
"D30-2300033": "সুইটি স্টোর",
"D30-2300034": "ষরিফুল ষ্টোর",
"D30-2300036": "সাইদ স্টোর",
"D30-2300037": "মামুনি স্টেশনারি এবং কসমেটিক্স",
"D30-2300039": "নিমাই স্টোর",
"D30-2300040": "মাহামুদুল স্টোর",
"D30-2300041": "সিফাত স্টোর",
"D30-2300043": "নুরানী ভ্যঃ ষ্টোর",
"D30-2300044": "জয়দেব স্টোর",
"D30-2300045": "রফিকুল স্টোর",
"D30-2300046": "বিসমিল্লার স্টোর",
"D30-2300047": "নূর স্টোর",
"D30-2300048": "সেফাত স্টোর",
"D30-2300050": "নূর ইসলাম স্টোর",
"D30-2300051": "মোকলেসুর স্টোর",
"D30-2300052": "সাধন স্টোর",
"D30-2300053": "বেইজেদ স্টোর",
"D30-2300054": "সাকিব স্টোর",
"D30-2300055": "গোবিন্দ স্টোর",
"D30-2300056": "আল আমিন স্টোর",
"D30-2300057": "ফ্লোরেন্স ভ্যারাইটিস স্টোর",
"D30-2300058": "তিন বোন",
"D30-2300059": "আরস স্টোর",
"D30-2300063": "বিসমিল্লাহ ফেয়ার স্টোর",
"D30-2300064": "সুনীল স্টোর",
"D30-2300065": "রাজু ট্রেডার্স",
"D30-2300066": "ইদ্রিস স্টোর",
"D30-2300069": "সাথী ষ্টোর",
"D30-2300071": "মান্নান স্টোর",
"D30-2300072": "রুস্তম স্টোর",
"D30-2300073": "খাদিজা স্টোর",
"D30-2300074": "জোসমট স্টোর",
"D30-2300075": "আলমগীর ভ্যারাইটি স্টোর",
"D30-2300078": "মাইম",
"D30-2300079": "হৃদয় কসমেটিক্স",
"D30-2300080": "শাওন ষ্টোর",
"D30-2300081": "রাইসা ভ্যা্রাইটি স্টোর",
"D30-2300083": "ভাই ভাই ষ্টোর",
"D30-2300084": "রাজু স্টোর - ২টি",
"D30-2300085": "কাইস স্টোর",
"D30-2300086": "তিতাস স্টোর",
"D30-2300087": "ইদ্রিস স্টোর",
"D30-2300088": "রিয়াজ স্টোর",
"D30-2300091": "আজিজার স্টোর",
"D30-2300092": "মোস্তফা কামাল স্টোর",
"D30-2300093": "নাজমুল স্টোর",
"D30-2300095": "জিনিয়া স্টোর",
"D30-2300099": "মাসুদ স্টোর",
"D30-2300100": "বয়রাগি স্টোর",
"D30-2300101": "রাজু  ষ্টোর",
"D30-2300102": "কিবরিয়া স্টোর",
"D30-2300103": "মায়ের দোয়া স্টোর",
"D30-2300105": "মারিয়াম স্টোর",
"D30-2300108": "আব্দুর রাজ্জাক কসমেটিক্স স্টোর",
"D30-2300109": "দুই ভাই ষ্টোর",
"D30-2300110": "জোলিল স্টোর",
"D30-2300115": "দিপ ভ্যারাইটিস স্টোর",
"D30-2300117": "মা টেলিকম",
"D30-2300118": "আনোয়ার স্টোর",
"D30-2300119": "বাবুল ষ্টোর",
"D30-2300120": "আফতার স্টোর",
"D30-2300121": "রাবেয়া কনফেকশনারী",
"D30-2300123": "আতাউর স্টোর",
"D30-2300129": "আজিজ কসমেটিক্স",
"D30-2300131": "টোঙ্কো স্টোর",
"D30-2300133": "আরিফুল স্টোর",
"D30-2300135": "কোকন স্টোর",
"D30-2300136": "দিপু স্টোর",
"D30-2300137": "খাইরুল ভ্যারাইটিস স্টোর",
"D30-2300138": "মাজেদুর ষ্টোর",
"D30-2300141": "পংকজ এবং নিলয় স্টোর",
"D30-2300142": "শাইফান স্টোর এবং কসমেটিক্স",
"D30-2300143": "মুনেম ডিপাপ্টমেন্টাল ষ্টোর",
"D30-2300144": "সোবাহান স্টোর",
"D30-2300146": "হুমায়ুন ভ্যারাইটি",
"D30-2300147": "বিজয় স্টোর",
"D30-2300149": "বাবুল ষ্টোর",
"D30-2300153": "বিসমিল্লাহ ষ্টোর -১",
"D30-2300154": "মুরাদ স্টোর",
"D30-2300159": "রোহিম স্টোর",
"D30-2300160": "ভাই ভাই স্টোর",
"D30-2300161": "জোশেম স্টোর",
"D30-2300162": "রুবেল পান",
"D30-2300164": "আমজাদ স্টোর",
"D30-2300165": "আরএসএম স্টোর",
"D30-2300167": "জাকির স্টোর",
"D30-2300168": "আলম স্টোর",
"D30-2300170": "মোমোতাজ স্টোর",
"D30-2300171": "শরিফ স্টোর",
"D30-2300172": "মা- টেলিকম",
"D30-2300174": "ওপেন ষ্টোর",
"D30-2300176": "সাজ কসমেটিক",
"D30-2300178": "নুর ভ্যারাইটি",
"D30-2300179": "বাবু রাম স্টোর",
"D30-2300180": "পাইকারি বাজার",
"D30-2300181": "সোয়াত ষ্টোর",
"D30-2300182": "মোস্তফা ষ্টোর",
"D30-2300183": "জামান স্টোর",
"D30-2300186": "রবি স্টোর",
"D30-2300187": "সাহিল স্টোর",
"D30-2300190": "স্বপন স্টোর",
"D30-2300191": "শফিকুল স্টোর",
"D30-2300192": "অরজুন স্টোর",
"D30-2300194": "তানভির ষ্টোর",
"D30-2300196": "দুই কোন্না স্টোর",
"D30-2300197": "আইনুল স্টোর",
"D30-2300199": "বিসমিল্লাহ স্টোর",
"D30-2300203": "মা ভ্যারাইটি স্টোর",
"D30-2300208": "আল-মিজান ষ্টোর",
"D30-2300209": "রঙ্জিদ স্টোর",
"D30-2300211": "মেসার্স নুরজামান ষ্টোর",
"D30-2300212": "রাশেদুল ষ্টোর",
"D30-2300214": "বাবুল স্টোর",
"D30-2300215": "আরএম স্টোর",
"D30-2300216": "নাজমুল স্টোর",
"D30-2300218": "সহাগ ভ্যারাইটিস",
"D30-2300219": "আরিফ স্টোর",
"D30-2300221": "সেপালু স্টোর",
"D30-2300222": "হাবিবুর কসমেটিক্স",
"D30-2300223": "জাহাঙ্গীর স্টোর",
"D30-2300224": "হালিম স্টোর",
"D30-2300226": "সালাহুর স্টোর",
"D30-2300227": "আসিব কসমেটিক্স স্টোর",
"D30-2300228": "এম.এ স্টোর",
"D30-2300229": "নাহিদ ষ্টোর",
"D30-2300231": "বেলাল স্টোর",
"D30-2300232": "আতিকুর সেন্ট",
"D30-2300233": "মঞ্জুরুল স্টোর",
"D30-2300234": "বাবা-মা - স্টোর",
"D30-2300237": "আফিক স্টোর",
"D30-2300240": "আমিনুল ষ্টোর",
"D30-2300241": "সিয়াম স্টোর",
"D30-2300243": "তাপস স্টোর",
"D30-2300247": "আন্তাজুল স্টোর",
"D30-2300249": "মু-সাদমান স্টোর",
"D30-2300251": "ফাতেমা সবজি",
"D30-2300254": "মেরাজ ষ্টোর",
"D30-2300256": "জয়ী কসমেটিক্স",
"D30-2300257": "রাহাইন স্টোর",
"D30-2300260": "বিসনু স্টোর",
"D30-2300262": "আলম স্টোর",
"D30-2300263": "লালমিয়া স্টোর",
"D30-2300264": "নাইম স্টোর",
"D30-2300265": "জনায়েদ  কসমেটিক্স",
"D30-2300266": "মতিউর স্টোর",
"D30-2300269": "বিগ বাজার ষ্টোর",
"D30-2300270": "বিসমিল্লাহ স্টোর",
"D30-2300272": "মা স্টোর",
"D30-2300275": "দোয়েন ভ্যারাইটিস স্টোর",
"D30-2300276": "মানিক কালঘোর",
"D30-2300277": "রাজিব ষ্টোর",
"D30-2300278": "সালেহা স্টোর",
"D30-2300279": "অজয় স্টোর",
"D30-2300281": "রাজ্জাক স্টোর",
"D30-2300283": "এস এম ফ্যাশন",
"D30-2300285": "সেলিম ষ্টোর",
"D30-2300287": "সঞ্জয় স্টোর",
"D30-2300288": "নোমান স্টোর",
"D30-2300290": "বর্ষন ষ্টোর",
"D30-2300296": "নগেন ষ্টোর",
"D30-2300297": "জাহাঙ্গীর স্টোর",
"D30-2300300": "আতাউর স্টোর",
"D30-2300301": "আনিছুর স্টোর",
"D30-2300302": "মাহাবুর ষ্টোর",
"D30-2300303": "ধরনজয় স্টোর",
"D30-2300304": "নুরুল স্টোর",
"D30-2300307": "সানারুল স্টোর",
"D30-2300308": "আনোয়ার ষ্টোর",
"D30-2300310": "মায়ের স্টোর",
"D30-2300313": "অ্যানোয়ার স্টোর",
"D30-2300314": "আশাদ স্টোর",
"D30-2300315": "আবু সায়েম কসমেটিক্স",
"D30-2300318": "সাকিল স্টোর",
"D30-2300320": "সোহাগ কসমেটিক্স",
"D30-2300321": "সোহাগ স্টোর",
"D30-2300322": "উত্তম স্টোর",
"D30-2300323": "ভাই ভাই কোস",
"D30-2300326": "বাবা -মা ষ্টোর",
"D30-2300327": "আবদুল্লাহ ভারাইতি",
"D30-2300330": "রংতুলি ষ্টোর",
"D30-2300331": "বন্ধু স্টোর",
"D30-2300332": "দেবাশিস স্টোর",
"D30-2300333": "পলাশ স্টোর",
"D30-2300335": "মা ভ্য: স্টোর",
"D30-2300336": "মতিন স্টোর",
"D30-2300337": "এনামুল স্টোর",
"D30-2300340": "আবিদ স্টোর",
"D30-2300341": "বিসমিল্লাহ কর্নার",
"D30-2300342": "মোস্তফা স্টোর",
"D30-2300349": "তিন ভি স্টোর",
"D30-2300350": "আক্তার পান",
"D30-2300351": "এম.এস. সাহ স্টোর",
"D30-2300353": "আরারাত স্টোর",
"D30-2300355": "সাদেকুল স্টোর",
"D30-2300356": "সোস্তা বাজার",
"D30-2300357": "নানা নাতি ষ্টোর",
"D30-2300358": "মাস- নজরুল",
"D30-2300360": "রুবেল স্টোর",
"D30-2300362": "মাহি স্টোর",
"D30-2300363": "আজগর স্টোর",
"D30-2300365": "সাইফুল স্টোর",
"D30-2300367": "সিদ্দিক স্টোর",
"D30-2300368": "সুইটি কসমেটিক",
"D30-2300370": "মতিউর ষ্টোর",
"D30-2300374": "রুফাইদা ট্রেডার্স",
"D30-2300375": "ছাফা ষ্টোর",
"D30-2300376": "শামিম ষ্টোর",
"D30-2300379": "লিমা কসম্যাটিক",
"D30-2300380": "কুমকুম ষ্টোর",
"D30-2300382": "এসআরকে স্টোর",
"D30-2300383": "বুলু স্টোর",
"D30-2300384": "সুমন স্টোর",
"D30-2300385": "বুলু স্টোর",
"D30-2300387": "মহেস স্টোর",
"D30-2300389": "মা বাবা দোয়া",
"D30-2300390": "অ্যানোয়ার স্টোর",
"D30-2300391": "আব্দুল জলিল স্টোর",
"D30-2300395": "আনিকা স্টোর",
"D30-2300396": "রবিউল স্টোর",
"D30-2300397": "মুন্না স্টোর",
"D30-2321": "মৌসুমি ভ্যারাইটিস ষ্টোর",
"D30-2326": "ইউসুফ পান শপ",
"D30-2329": "র্ব্রাদাস ষ্টোর",
"D30-2330": "সাহাজাদা মোসলা স্টোর",
"D30-2331": "নাজিম স্টোর",
"D30-2332": "হারুন স্টোর",
"D30-2344626": "মেসার্স আরিফ স্টোর",
"D30-2344770": "জনোতা ফার্মেসি",
"D30-2368380": "মোঃ আয়েসুর রহমান",
"D30-2368421": "জুয়েল ইসলাম",
"D30-2377": "জাকির স্টোর",
"D30-2407": "জলিল স্টোর",
"D30-2416": "ভাগিনা স্টোর",
"D30-2444166": "বুলু স্টোর",
"D30-2444168": "হাসনাত স্টোর",
"D30-2444169": "মা বস্ত্র বিতান এন্ড কসমে্টিক্স",
"D30-2444171": "আজহারুল স্টোর",
"D30-2444172": "শুভ স্টোর",
"D30-2444173": "মশিউর স্টোর",
"D30-2444174": "পারিবারিক বাজার",
"D30-2444176": "প্রয়োজন স্টোর",
"D30-2444177": "এ এম ষ্টোর",
"D30-2444178": "এন.পি. স্টেশনারি",
"D30-2444182": "নুরু পান ষ্টোর",
"D30-2444183": "ফায়াস ষ্টোর",
"D30-2444188": "মফিজুল ষ্টোর",
"D30-2444191": "নানা-নাটি স্টোর",
"D30-2444196": "বুলেট স্টোর",
"D30-2444197": "রিয়াজ ভ্যারাইটিস স্টোর",
"D30-2444198": "সাহিন স্টোর",
"D30-2444200": "পেস্টি বেকারি",
"D30-2444201": "মাসুদ স্টোর",
"D30-2444203": "বিসমিল্লা ট্রেডার্স",
"D30-2444205": "তাপশ স্টোর",
"D30-2444206": "লক্ষী ষ্টোর",
"D30-2444207": "মিঠুন স্টোর",
"D30-2444208": "জিয়া স্টোর",
"D30-2444209": "রফিকুল স্টোর",
"D30-2444210": "জান্নাতুন স্টোর",
"D30-2444211": "আমিনুল ষ্টোর",
"D30-2444212": "উৎসব স্টোর",
"D30-2444215": "অর্জুন স্টোর",
"D30-2444216": "গোলাম মোস্তফা স্টোর",
"D30-2444217": "আরাফাত স্টোর",
"D30-2444218": "বাংলা কাপড় হাউজ",
"D30-2444220": "মিরাজ কসমেটিক্স",
"D30-2444221": "হৃদয় ও রিয়ান স্টোর",
"D30-2444223": "দুলাল স্টোর",
"D30-2444227": "আব্দুল জলিল স্টোর",
"D30-2444228": "মাসুদ ষ্টোর",
"D30-2444229": "দিপোক স্টোর",
"D30-2444232": "কৈলাশ ষ্টোর",
"D30-2444233": "জননী ষ্টোর",
"D30-2444234": "সামিউল স্টোর",
"D30-2444235": "জসিম পান ষ্টোর",
"D30-2444238": "দিপ্ত ট্রেডার্স",
"D30-2444239": "মেসার্স মেহেদি হাসান",
"D30-2444240": "জয়ন্তো স্টোর",
"D30-2444242": "মা বাবা স্টোর",
"D30-2444243": "সামিয়া কসমেটিক্স",
"D30-2444244": "প্রত্যয় ট্রেডাস",
"D30-2444245": "গুপ্ত স্টোর",
"D30-2444246": "লাবুদা ষ্টোর",
"D30-2444247": "সাকিব স্টোর",
"D30-2444249": "পারভীন ট্রেডার্স",
"D30-2444250": "মিথিলা ষ্টোর",
"D30-2444252": "ঠাকুর স্টোর",
"D30-2444254": "জাহিদ ষ্টোর",
"D30-2444255": "রঞ্জন স্টোর",
"D30-2444256": "জুয়েল ডিপার্টমেন এন/আল স্টোর",
"D30-2444257": "মাসুম স্টোর",
"D30-2444258": "রুমি স্টোর",
"D30-2444259": "বড় ভাই ষ্টোর",
"D30-2444260": "সুমাইয়া স্টোর",
"D30-2444263": "এলিন টেলিকম",
"D30-2444264": "সানজিদা কসমেটিক্স",
"D30-2444265": "গুন গুন ভ্যারাইটি স্টোর",
"D30-2444266": "পুরনোভা ভ্যারাইটি স্টোর",
"D30-2444267": "মানিক ভ্যারাইটি স্টোর",
"D30-2444268": "সর্ন ডিপারমেন্টাল ষ্টোর",
"D30-2444270": "নুর ষ্টোর",
"D30-2444272": "মাফিজুর স্টোর",
"D30-2444274": "সাগর স্টোর",
"D30-2444276": "হোসেন স্টোর",
"D30-2444277": "সাফিয়া রোজা",
"D30-2444278": "সুমাইয়া কসমেটিক্স",
"D30-2444279": "ইসমাইল",
"D30-2444280": "এআর রায়ান স্টোর",
"D30-2444281": "আল্লাহর দান স্টোর",
"D30-2444282": "বাবা মা স্টোর",
"D30-2444283": "ইয়াসিন স্টোর",
"D30-2444285": "নিসা বুটিক",
"D30-2444286": "সোহাগ স্টোর",
"D30-2444287": "তামান্নার স্টোর",
"D30-2444290": "ভাই ভাই ষ্টোর",
"D30-2444292": "ডিজিটাল মিডিয়া",
"D30-2444294": "ফাহামিদা ষ্টোর",
"D30-2444295": "ভাই ভাই ভ্যারাইটিজ ষ্টোর",
"D30-2444296": "আমিনুল স্টোর",
"D30-2444297": "মোদিনা সোবজি",
"D30-2444300": "রাজু স্টোর",
"D30-2444304": "তিন কন্যা ষ্টোর",
"D30-2444306": "সুবাদ এন্ড সেফাত ষ্টোর",
"D30-2444313": "বিসমিল্লাহ সেন্ট",
"D30-2444314": "এস কে এস ষ্টোর",
"D30-2444316": "মারিয়া ভ্যারাইটি স্টোর",
"D30-2444317": "মোস্তাকিম স্টোর",
"D30-2444318": "ভাই ভাই স্টোর",
"D30-2444319": "ইউসুফ স্টোর",
"D30-2444321": "প্রন্ন গ্রিহো ভ্যারাইটি স্টোর",
"D30-2444322": "সোফোল স্টোর",
"D30-2444323": "স্টুডেন্ট স্টোর",
"D30-2444324": "শেফালি কসমেটিক্স",
"D30-2444325": "তাসমিরা স্টোর",
"D30-2444326": "করিমুল স্টোর",
"D30-2444328": "ধোনেশর স্টোর",
"D30-2444329": "রোহানা স্টোর",
"D30-2444331": "সোহাগ  ষ্টোর",
"D30-2444332": "আরিফ ষ্টোর",
"D30-2444335": "রমজান স্টোর",
"D30-2444336": "আতিকা কসমেটিক্স",
"D30-2444337": "তারেক ষ্টোর",
"D30-2444339": "নাঈম ষ্টোর",
"D30-2444341": "সোমাজ উদ্দিন স্টোর",
"D30-2444343": "আলম ষ্টোর",
"D30-2444347": "বাবুল স্টোর",
"D30-2444348": "সিদ্দিক স্টোর",
"D30-2444353": "আমিনুল পান স্টোর",
"D30-2444354": "দুলাল স্টোর",
"D30-2444355": "বিসমিল্লাহ স্টোর",
"D30-2444356": "অ্যান্টোরা জাত",
"D30-2444358": "আনাস ডিপার্টমেন্টাল স্টোর",
"D30-2444359": "আজিদ পান স্টোর",
"D30-2444366": "মোজিবর স্টোর",
"D30-2444372": "আপেল ষ্টোর",
"D30-2444373": "মা বাবার দোয়া",
"D30-2444374": "নূর জামান",
"D30-2444378": "আবদুল্লাহ স্টোর",
"D30-2444379": "হাফিজার স্টোর",
"D30-2444380": "মেসার্স ফাহিম অ্যান্ড ব্রাদার্স",
"D30-2444381": "নূর কনফেকশনারি",
"D30-2444382": "সুমন স্টোর",
"D30-2444384": "খান পেপার",
"D30-2444387": "গোলাপ স্টোর",
"D30-2444389": "রিদয় স্টোর",
"D30-2444391": "আনিছা ষ্টোর",
"D30-2444392": "রফিক কসমেটিক্স",
"D30-2444393": "সঞ্জয় ষ্টোর",
"D30-2444394": "জাহাঙ্গীর ষ্টোর",
"D30-2444397": "দুই কন্যা ষ্টোর",
"D30-2444400": "পুলিস ক্যান্টিন",
"D30-2444403": "মারজিয়া কসমেটিক্স",
"D30-2444404": "মা মিষ্টান্ন",
"D30-2444406": "লাবিব স্টোর",
"D30-2444407": "দুই ভাই স্টোর",
"D30-2444408": "মা বাবা ভ্যারাইটিস স্টোর",
"D30-2444409": "ভাই বোন স্টোর",
"D30-2444410": "সাইফুল স্টোর",
"D30-2444412": "তরমুজের স্টোর",
"D30-2444416": "নিশাত ভেরাইটস স্টোর",
"D30-2444417": "মা ট্রেডার্স",
"D30-2444419": "মিথিলা কসমেটিক্স",
"D30-2444420": "অপূর্ব সৌরভ স্টোর",
"D30-2444421": "পলক স্টোর",
"D30-2444422": "নির্মল স্টোর",
"D30-2444423": "এস.আর ফুড ডেইলি শপিং",
"D30-2444424": "সৌরভ স্টোর",
"D30-2444425": "সাফোয়ান স্টোর",
"D30-2444426": "জামাল লাইব্রেরি অ্যান্ড কসমেটিক্স",
"D30-2444427": "পলক কসমেটিক্স পয়েন্ট",
"D30-2444429": "মালিহা গ্লো অ্যান্ড বিউটি",
"D30-2444430": "জাহাঙ্গীর স্টোর",
"D30-2444433": "দুই ভাই স্টোর",
"D30-2444438": "লাল বাবু স্টোর",
"D30-2444443": "দুলাল স্টোর",
"D30-2444446": "বাবু ষ্টোর",
"D30-2444451": "আরিফ ষ্টোর",
"D30-2444453": "সাঈদ স্টোর",
"D30-2444455": "দুই ভাই স্টোর ২",
"D30-2444456": "সালাম ষ্টোর",
"D30-2444457": "মনের সাজ ঘর",
"D30-2444458": "টেকনিক্যাল স্টোর",
"D30-2444459": "তাফসিরুল ডিপার্টমেন্টাল স্টোর",
"D30-2444461": "আলিফ স্টোর",
"D30-2444462": "সততা স্টোর",
"D30-2444463": "মা স্টোর",
"D30-2444464": "সুমন ষ্টোর",
"D30-2444467": "আজিম স্টোর",
"D30-2444468": "আর কে ট্রেডার্স",
"D30-2444471": "দুই বোন ষ্টোর",
"D30-2444472": "মারুফ স্টোর",
"D30-2444474": "জাকারিয়া স্টোর",
"D30-2444475": "সোহিদুল স্টোর",
"D30-2444479": "মাসুম স্টোর",
"D30-2444480": "সেলিম ষ্টোর",
"D30-2444481": "আশরাফ ষ্টোর",
"D30-2444489": "পরিমল স্টোর",
"D30-2444491": "মা বাবা দোয়া জেনারেল স্টোর",
"D30-2444493": "শোরিফুল স্টোর",
"D30-2444494": "পেপার হাউস",
"D30-2444497": "লিটন স্টোর",
"D30-2444498": "জনপ্রিয় টেলিকম",
"D30-2444500": "সোবুজ স্টোর",
"D30-2444502": "মা স্টোর",
"D30-2444503": "মাদানী ডিপার্টমেন্টাল স্টোর",
"D30-2444504": "হিমেল কসমেটিক্স",
"D30-2444506": "রবিউল স্টোর",
"D30-2444509": "কৃত্তিত্ত স্টোর",
"D30-2444510": "ভাই ভাই মিষ্টান্ন",
"D30-2444511": "জাহাঙ্গীর স্টোর",
"D30-2444514": "উথসো স্টোর",
"D30-2444518": "তসিকুল স্টোর",
"D30-2444519": "মিডলি কসমেটিক্স",
"D30-2444521": "সোহেল স্টোর",
"D30-2444522": "রকি স্টোর",
"D30-2444523": "সনিয়া স্টোর",
"D30-2444524": "আলভি স্টোর",
"D30-2444527": "শিফাত ট্রাদাস",
"D30-2444532": "শামীম স্টোর",
"D30-2444533": "আফসার স্টোর",
"D30-2444534": "মা স্টোর",
"D30-2444535": "নায়েম স্টোর",
"D30-2444536": "হারিসুল স্টোর",
"D30-2444537": "সেলিম স্টোর",
"D30-2444538": "খরসেড স্টোর",
"D30-2444539": "মামুন স্টোর",
"D30-2444540": "রবিউল স্টোর",
"D30-2444541": "রফিকুল স্টোর",
"D30-2444546": "জিহাদ স্টোর",
"D30-2444547": "মুর্শিদ স্টোর",
"D30-2444548": "এনায়েতুল স্টোর",
"D30-2444549": "মা কসমেটিক্স",
"D30-2444550": "সামিম স্টোর",
"D30-2444551": "ডি.এম. ভ্যারাইটি স্টোর",
"D30-2444552": "দুই ভাই ভ্যারাইটি স্টোর",
"D30-2444553": "আশরাফ স্টোর",
"D30-2444554": "এলিয়াস স্টোর",
"D30-2444556": "মিলন স্টোর",
"D30-2444557": "মাসুম স্টোর",
"D30-2444558": "আব্দুল কুদ্দুস স্টোর",
"D30-2444559": "ফারহান ট্রেডার্স",
"D30-2444562": "আল-ফাতাহ ডিপার্টমেন্টাল স্টোর",
"D30-2444563": "মোস্তফা স্টোর",
"D30-2444564": "সোহেল স্টোর",
"D30-2444565": "দিপু স্টোর",
"D30-2444566": "ভাই বন স্টোর",
"D30-2444567": "লুৎফর স্টোর",
"D30-2444568": "সাজ্জাদ স্টোর",
"D30-2444569": "সোরিফুল স্টোর",
"D30-2444572": "রব্বানি স্টোর",
"D30-2444578": "তানি ও তারেক ভ্যারাইটিস স্টোর",
"D30-2444582": "নিউ ভ্যারাইটিস স্টোর",
"D30-2444583": "সিন্থিয়া স্টোর",
"D30-2444584": "রফিকুল স্টোর",
"D30-2444586": "জাহাঙ্গীর স্টোর",
"D30-2444588": "ভাই বোন স্টোর",
"D30-2444589": "নজরুল স্টোর-১",
"D30-2444590": "আলী আরাফাত স্টোর",
"D30-2444591": "ওমিজুল স্টোর",
"D30-2444592": "মিজানুর স্টোর",
"D30-2444593": "আনারুল স্টোর",
"D30-2444594": "সাদিক স্টোর",
"D30-2444595": "সারোয়ার স্টোর",
"D30-2444596": "রাইসুল স্টোর",
"D30-2444597": "আল-আমিন স্টোর",
"D30-2444599": "বৃষ্টি স্টোর",
"D30-2444600": "রুহুল আমিন স্টোর",
"D30-2444602": "রেজাউল স্টোর",
"D30-2444603": "সাইদুর স্টোর",
"D30-2444604": "সুমন তালিকম",
"D30-2444606": "মিম ভেরুতেস স্টোর",
"D30-2444607": "কাজী স্টোর",
"D30-2444609": "আকাশ স্টোর",
"D30-2444610": "মানিক স্টোর",
"D30-2444614": "মিজানুর স্টোর",
"D30-2444615": "নাজমুল স্টোর",
"D30-2444616": "তোইয়োব স্টোর",
"D30-2444619": "রিফাত স্টোর",
"D30-2444620": "আজিজার স্টোর",
"D30-2444621": "গোফুর স্টোর",
"D30-2444623": "মাইজুল  স্টোর",
"D30-2444624": "রিঙ্কু স্টোর",
"D30-2444628": "জুয়েল কোং।",
"D30-2444631": "বাবু পান স্টোর",
"D30-2444633": "দুই বোন স্টোর",
"D30-2444634": "রুফে স্টোর",
"D30-2444635": "সাইফুল স্টোর",
"D30-2444637": "মালেক স্টোর",
"D30-2444638": "নাইম স্টোর",
"D30-2444639": "সুমন স্টোর",
"D30-2444640": "বেলাল স্টোর",
"D30-2444641": "ঝিলিক স্টোর",
"D30-2444642": "আনোয়ার স্টোর",
"D30-2444643": "এস এম বাজার",
"D30-2444644": "তিন ভাই স্টোর",
"D30-2444645": "খাজা স্টোর",
"D30-2444646": "রাইসুল স্টোর",
"D30-2444647": "আলেমা স্টোর",
"D30-2444648": "রিয়াদ রাহুল স্টোর",
"D30-2444649": "রিফাত স্টোর",
"D30-2444651": "স্বপন স্টর",
"D30-2444652": "নাইম স্টোর",
"D30-2444653": "মা বাবা ভ্যারাইটিস স্টোর",
"D30-2444654": "রেডিয়েটর স্টোর",
"D30-2444655": "আলম স্টোর",
"D30-2444657": "ভাই ভাই স্টোর",
"D30-2446581": "সোহেল স্টোর",
"D30-2446583": "মশিয়ুর  স্টোর",
"D30-2446584": "রায়হান স্টোর",
"D30-2446585": "দুলাল স্টোর",
"D30-2446588": "মোকারম স্টোর",
"D30-2446589": "অ্যালমগির স্টোর",
"D30-2446590": "আরিফ স্টোর",
"D30-2446592": "মেহেরুলস্টর",
"D30-2446593": "রাজু স্টোর",
"D30-2446594": "হুসেন স্টোর",
"D30-2446597": "মিজান স্টোর",
"D30-2446598": "নয়ন স্টোর",
"D30-2446599": "সৌরভ স্টোর",
"D30-2446604": "কৈলাস স্টোর",
"D30-2446605": "জননি স্টোর",
"D30-2446606": "সামিয়ুল স্টোর",
"D30-2446607": "জশিম স্টোর",
"D30-2446608": "মেহেদী টেলিকোম",
"D30-2446609": "আরিফুল স্টোর",
"D30-2446611": "মা স্টোর",
"D30-2446612": "আক্তার স্টোর",
"D30-2446613": "রগুনাথ স্টোর",
"D30-2446615": "মানিক শাহা স্টোর",
"D30-2446616": "তাপস স্টোর",
"D30-2446618": "ফাতেমা  স্টোর",
"D30-2446619": "প্রেমা স্টোর",
"D30-2446621": "মা কসমেটিক্স",
"D30-2446622": "আনারুল স্টোর",
"D30-2446626": "তিতাস স্টোর",
"D30-2446627": "আমিনুল ইসলাম",
"D30-2446628": "জোমিরুল স্টোর",
"D30-2446629": "খেরাজ স্টোর",
"D30-2446631": "আব্দুল খালেক স্টোর",
"D30-2446632": "স্নেহা স্টোর",
"D30-2446633": "আতিক স্টোর",
"D30-2446634": "সোহেল স্টোর",
"D30-2446635": "তোহিদুল স্টোর",
"D30-2446636": "ইব্রাহিম স্টোর",
"D30-2446637": "নূপুর স্টোর",
"D30-2446638": "নাতি স্টোর",
"D30-2446639": "সৌরভ স্টোর",
"D30-2446640": "পারভেজ স্টোর",
"D30-2446642": "মা বাবর দোয়া",
"D30-2446647": "রাবেয়া স্টোর",
"D30-2446648": "মনিম স্টোর",
"D30-2446649": "রাজ্জাক স্টোর",
"D30-2446650": "মা স্টোর",
"D30-2446651": "আলাম স্টোর",
"D30-2446652": "সোহেল স্টোর",
"D30-2446654": "সামিম স্টোর",
"D30-2446658": "আবিদ স্টোর",
"D30-2446659": "খুশি স্টোর",
"D30-2446661": "তামিম  স্টোর",
"D30-2446662": "আরিফ স্টোর",
"D30-2446664": "আসরাফুল স্টোর",
"D30-2446667": "রাকিব স্টোর",
"D30-2446671": "আর.এস ট্রেডার্স",
"D30-2446672": "স্ক্রিন সোচিন স্টোর",
"D30-2446673": "অভয় স্টোর",
"D30-2446674": "শ্রী শ্যামল স্টোর",
"D30-2446675": "আপন ষ্টোর",
"D30-2446676": "রিয়া কসমেটিক্স",
"D30-2446678": "সাইদুর স্টোর",
"D30-2446685": "আতিক স্টোর",
"D30-2446686": "শরিফ ষ্টোর",
"D30-2446687": "রোহিম স্টোর",
"D30-2446688": "গিয়াস স্টোর",
"D30-2446689": "ইমন স্টোর",
"D30-2446690": "রুবেল স্টোর",
"D30-2446691": "জিবন স্টোর",
"D30-2446692": "সামুন ষ্টোর",
"D30-2446693": "রাজু স্টোর",
"D30-2446694": "জিসান স্টোর",
"D30-2446696": "জয় ষ্টোর",
"D30-2446697": "ভাই ভাই স্টোর",
"D30-2446698": "নায়েফ স্টোর",
"D30-2446699": "জাকির ষ্টোর",
"D30-2446701": "ভাই বোন স্টোর",
"D30-2446708": "রেজাউল স্টোর",
"D30-2446711": "বাপ্পি ভ্যারাইটি স্টোর",
"D30-2446714": "রহমত স্টোর",
"D30-2446715": "সোহান স্টোর",
"D30-2446716": "আসরাফ স্টোর",
"D30-2446717": "খোকন স্টোর",
"D30-2446718": "সামিউল স্টোর",
"D30-2446719": "মনিরুল স্টোর",
"D30-2446722": "আরব স্টোর",
"D30-2446724": "রবিউল স্টোর",
"D30-2446726": "হুমায়ুন স্টোর",
"D30-2446727": "মেসার্স তনা স্টোর",
"D30-2446728": "লুৎফর স্টোর",
"D30-2446729": "মনোরঞ্জন স্টোর",
"D30-2446730": "আবদুল্লাহ স্টোর",
"D30-2446731": "ভাই ভাই স্টোর",
"D30-2446732": "অনুসরণ",
"D30-2446733": "মা কম্পিউটার",
"D30-2446734": "মাহেম স্টোর",
"D30-2446735": "মাহতাব স্টোর",
"D30-2446736": "শারাজুল স্টোর",
"D30-2446737": "আহমেদ পান স্টোর",
"D30-2446738": "লাজ ফার্মা",
"D30-2446740": "আল আমিন স্টোর",
"D30-2446741": "লেপন স্টোর",
"D30-2446742": "মুন্না স্টোর",
"D30-2446745": "ভাই বোন স্টোর",
"D30-2446746": "মা কনফেসনারি",
"D30-2446748": "রুবেল স্টোর",
"D30-2446749": "আমিনুল স্টোর",
"D30-2446753": "আলভি কনফেসনারি",
"D30-2446756": "দেলোয়ার",
"D30-2446757": "সাকিব স্টোর",
"D30-2446758": "মোদিউল স্টোর",
"D30-2446759": "মোতালেপ স্টোর",
"D30-2446760": "মা বাবা স্টোর",
"D30-2446761": "সম বাজার",
"D30-2446762": "ইমরান স্টোর",
"D30-2446763": "সাইফুল স্টোর",
"D30-2446764": "বাপ্পি স্টোর",
"D30-2446765": "আক্রাম স্টোর",
"D30-2446767": "আল আমিন স্টোর",
"D30-2446770": "পারভিন স্টোর",
"D30-2446772": "বৃষ্টি স্টোর",
"D30-2446774": "ভাই ভাই স্টোর",
"D30-2446778": "খোকন স্টোর",
"D30-2446779": "বিরল চাউলঘর",
"D30-2446781": "আমজাদ কসমেটিক্স",
"D30-2446784": "রাকিব স্টোর",
"D30-2446785": "হিরা স্টোর",
"D30-2446789": "আনন্দের স্টোর",
"D30-2446790": "জোগোদিস স্টোর",
"D30-2446792": "সেলিম স্টোর",
"D30-2446795": "মুন্না স্টোর",
"D30-2446796": "আজাদ স্টোর",
"D30-2446799": "কম্পিউটার কর্নার",
"D30-2446800": "লাবনি ভেরাসিটিজ স্টোর",
"D30-2446801": "ইত্তাদি বেকারি",
"D30-2446802": "এস এস পেপারস",
"D30-2446803": "মধুবন ডিপটিমেন্ট",
"D30-2446804": "ভাই বন স্টোর",
"D30-2446805": "আনিস স্টোর",
"D30-2446807": "পপুলাল কসমেটিক্স",
"D30-2446808": "মা কসম্যাটিক",
"D30-2446812": "ইয়াসিন স্টোর",
"D30-2446813": "আমিনুল স্টোর",
"D30-2446814": "সাকিব স্টোর",
"D30-2446815": "ইনসান ষ্টোর",
"D30-2446819": "প্রিন্স স্টোর",
"D30-2446822": "নাজমুল স্টোর",
"D30-2446825": "সামিয়া ষ্টোর",
"D30-2446826": "রাইসা স্টোর",
"D30-2446832": "আলা মিন স্টোর",
"D30-2446834": "শেখ ষ্টোর",
"D30-2446836": "আরবি স্টোর",
"D30-2446837": "শুভ",
"D30-2446838": "রাব্বা ষ্টোর",
"D30-2446840": "মঞ্জু স্টোর",
"D30-2446841": "ফরহাদ স্টোর",
"D30-2446842": "নজরুল ষ্টোর",
"D30-2446845": "ডালিম ষ্টোর",
"D30-2446849": "ব্রোটো স্টোর",
"D30-2446850": "শ্রাবন ষ্টোর",
"D30-2446851": "বোসাক স্টোর",
"D30-2446853": "শোনু",
"D30-2446854": "দিপক স্টোর",
"D30-2446855": "রানি ষ্টোর",
"D30-2446856": "জয় ঠাকুর",
"D30-2446857": "জয়নাল ষ্টোর",
"D30-2446858": "মকলেসুর স্টোর",
"D30-2446862": "হাজী স্টোর",
"D30-2446863": "মা জাতের স্টোর",
"D30-2446864": "শরিফুল ষ্টোর",
"D30-2446865": "একরামুল স্টোর",
"D30-2467": "সতোরূপা স্টোর",
"D30-2469": "তৌকির স্টোর",
"D30-2472": "মালেক স্টোর",
"D30-2512": "রেজাউল ষ্টোর",
"D30-2549576": "আকরাম স্টোর",
"D30-2549583": "জাহিদুল স্টোর",
"D30-2550879": "আলিফ স্টোর",
"D30-2550880": "মেসার্স মক্কা চাউল ঘর",
"D30-2550881": "শহিদুল লাইব্রেরি",
"D30-2550939": "আলী স্টোর",
"D30-2551022": "শৌরভ স্টোর",
"D30-2551023": "ভাই ভাই স্টোর",
"D30-2551080": "শুভ সকাল পান স্টোর",
"D30-2551081": "এ কামাল ভ্যারাইটি স্টোর",
"D30-2551356": "সাহেব বেকারি ও কনফেকশনারি",
"D30-2551423": "রিসাদ ডিপার্টমেন্টাল স্টোর",
"D30-2551473": "তাহের পান স্টোর",
"D30-2551474": "শোরিফুল স্টোর",
"D30-2551672": "মৌলোভি ট্রেডার্স",
"D30-2551740": "ফেরদৌস কনফেকশনারি",
"D30-2551767": "তোহিদ কসমেটিক্স",
"D30-2552973": "রুহুল স্টোর",
"D30-2558394": "শাকিল স্টোর",
"D30-2560": "বোতাম ঘোর",
"D30-2567": "সুমন লাইব্রেরি",
"D30-2570": "লামিশা ট্রেডার্স",
"D30-2573": "হালিম স্টোর",
"D30-2573554": "মোঃ ইসমাইল হোসেন",
"D30-2576": "আইডিয়াল কসমেটিক্স পিএস",
"D30-2580": "আল-মান্নান স্টোর",
"D30-2582": "বিসমিল্লাহ স্টোর",
"D30-2585": "ফারুক স্টোর",
"D30-2590": "লাবনি কসমেটিক্স",
"D30-2592": "সামিম কসমেটিক্স",
"D30-2594950": "রফিকুল",
"D30-2594952": "আবদুল্লাহ স্টোর",
"D30-2594953": "মা-বাবর দোয়া",
"D30-2594954": "লাব্বাইক স্টোর",
"D30-2594955": "রাকিব স্টোর",
"D30-2594956": "ওয়ায়ারেজ স্টোর",
"D30-2594957": "সাদেক স্টোর",
"D30-2594958": "মেসার্স ফয়জুল স্টোর",
"D30-2594960": "সাব্বির স্টোর",
"D30-2594961": "তরিকুল স্টোর",
"D30-2594962": "আক্তারুল স্টোর",
"D30-2594963": "আমির পান স্টোর",
"D30-2594964": "স্বপন স্টোর",
"D30-2594966": "প্রিয়াল কসমেটিক্স স্টোর",
"D30-2594967": "রাজ ডিপার্টমেন্টাল স্টোর",
"D30-2594969": "আফিয়াত স্টোর",
"D30-2594970": "মোদিনা কসমেটিক্স",
"D30-2594971": "নুসায়বা স্টোর",
"D30-2594972": "সিন্থিয়া স্টোর",
"D30-2594973": "মায়ে স্টোর",
"D30-2594975": "দিশা স্টোর",
"D30-2594977": "সরকার স্টোর",
"D30-2594979": "নিপা স্টোর",
"D30-2594981": "ননদো স্টোর",
"D30-2594984": "আবির স্টোর",
"D30-2594985": "সাধনা স্টোর",
"D30-2594987": "মাহির স্টোর",
"D30-2594988": "লাকি স্টোর",
"D30-2594989": "সাঈদ স্টোর",
"D30-2594990": "আশরাফুল স্টোর",
"D30-2594991": "ভাই বোন স্টোর",
"D30-2594993": "নূর ইসলাম স্টোর",
"D30-2594994": "বদরুল আলম স্টোর",
"D30-2594995": "ভাই বন ট্রেডার্স",
"D30-2594996": "আল-আমিন স্টোর",
"D30-2594998": "ঐতিজ্জো এবং ইন্দ্রেলা কসমেটিক্স",
"D30-2595001": "আবদুল মালেক স্টোর",
"D30-2595002": "মারুফা ইলেকট্রনিক্স",
"D30-2595003": "হুমায়ন স্টোর",
"D30-2595004": "শিরাজ স্টোর",
"D30-2595005": "প্রল্লব স্টোর",
"D30-2595006": "মিঠু স্টোর",
"D30-2595007": "সুমাইয়া স্টোর",
"D30-2595008": "শাওন স্টোর",
"D30-2595009": "ব্রিস্টি স্টোর",
"D30-2595011": "নূর ইসলাম স্টোর",
"D30-2595012": "মা টেলিকম",
"D30-2595013": "খাদিজা স্টোর",
"D30-2595014": "ওহিদুল স্টোর",
"D30-2595015": "মকবুল স্টোর",
"D30-2595018": "প্রীতি ভ্যারাইটিক্স",
"D30-2595019": "মহাবুব স্টোর",
"D30-2595020": "আনাচ স্টোর",
"D30-2595021": "ওবায়দুর স্টোর",
"D30-2595022": "জাকির স্টোর",
"D30-2595023": "নজরুল স্টোর",
"D30-2595024": "সাদিয়া স্টোর",
"D30-2595025": "আনিশা ফ্যাশন",
"D30-2595026": "আসাদ পান স্টোর",
"D30-2595027": "ফরিদুল.পান স্টোর",
"D30-2595028": "আলহাজ স্টোর",
"D30-2595029": "ফাতেমা স্টোর",
"D30-2595030": "মাহি স্টোর",
"D30-2595031": "গনেশ স্টোর",
"D30-2595032": "গনেশ স্টোর-২",
"D30-2595033": "বায়জিদ স্টোর",
"D30-2595035": "একটি স্টোর",
"D30-2595036": "শিহাব স্টোর",
"D30-2595037": "আল-আমিন স্টোর",
"D30-2595038": "মুরসালিন স্টোর",
"D30-2595039": "আয়াত স্টোর",
"D30-2595040": "বিসমিল্লাহ স্টোর",
"D30-2595042": "আতিক স্টোর",
"D30-2595044": "কনক স্টোর",
"D30-2595045": "মা-বাবর দুয়ার ট্রিলাস ও কসমেটিক্স",
"D30-2595048": "রুবেল স্টোর",
"D30-2595049": "বকুল স্টোর",
"D30-2595050": "আইডিয়াল কসমেটিক্স",
"D30-2595052": "পপুলাল স্টোর",
"D30-2595053": "নূর কসমেটিক্স",
"D30-2595054": "বিসমিল্লাহ স্টোর",
"D30-2595055": "সবুজ স্টোর",
"D30-2595056": "বাহাউদ্দিন স্টোর",
"D30-2595057": "বাঁধন স্টোর",
"D30-2595060": "মা-বাবা ভেরাইটস স্টোর",
"D30-2595061": "সিফাত স্টোর",
"D30-2595062": "মনির স্টোর",
"D30-2595063": "জাহিদ স্টোর",
"D30-2595064": "মেসার্স ধনঞ্জয় ট্রেডার্স",
"D30-2595065": "ডুই বন স্টোর",
"D30-2595066": "প্রশ্ন স্টোর",
"D30-2595068": "মাজহারুল স্টোর",
"D30-2595069": "সয়েব স্টোর",
"D30-2595071": "সোহেল স্টোর",
"D30-2595072": "পরিমল স্টোর",
"D30-2595074": "আমিরউদ্দিন স্টোর",
"D30-2595075": "স্নিগ্ধা স্টোর",
"D30-2595076": "মা বাবা কসমেটিক্স স্টোর",
"D30-2595077": "রিয়াজ উদ্দিন স্টোর",
"D30-2595078": "সৌরভ স্টোর",
"D30-2595079": "আশরাফুল স্টোর",
"D30-2595080": "হাবিবুর স্টোর",
"D30-2595081": "রিফাত স্টোর",
"D30-2595082": "শোহরাব স্টোর",
"D30-2595083": "সোহান ট্রেডার্স ও ভ্যারাইটিস স্টোর",
"D30-2595084": "রেজাউল স্টোর",
"D30-2595085": "সবুজ স্টোর",
"D30-2595089": "অনুসা মা স্টোর",
"D30-2595090": "মুহিন আবির ভ্যারাইটিস স্টোর",
"D30-2595091": "কাজী ভ্যারাইটিস স্টোর",
"D30-2595092": "আনারুল পান স্টোর",
"D30-2595093": "মা-বাবার দয়া কসমেটিক্স",
"D30-2595094": "প্রিয়া স্টোর",
"D30-2595095": "লিমন স্টোর",
"D30-2595096": "আয়শা স্টোর",
"D30-2595097": "সিয়াম স্টোর",
"D30-2595098": "শোয়ান স্টোর",
"D30-2595100": "দুই ভাই স্টোর",
"D30-2595102": "ফারিয়া স্টোর",
"D30-2595104": "মালেক স্টোর",
"D30-2595105": "দুই ভাই স্টোর",
"D30-2595106": "আবু সাঈদ স্টোর",
"D30-2595108": "কালাম স্টোর",
"D30-2595109": "আফতাব স্টোর",
"D30-2595110": "রাসেল স্টোর",
"D30-2595111": "সকাল স্টোর",
"D30-2595112": "দিনরাত স্টোর",
"D30-2595113": "রাধা স্টোর",
"D30-2595115": "মশিউর স্টোর",
"D30-2595116": "জিয়াউর স্টোর",
"D30-2595117": "মেহেদী স্টোর",
"D30-2595119": "দেশ সেবা স্টোর",
"D30-2595122": "ডেবোস মিতা স্টোর",
"D30-2595123": "ওড্রিজা স্টোর",
"D30-2595124": "দ্রুতি স্টোর",
"D30-2595125": "রবিউল স্টোর",
"D30-2595127": "হৃদয়ের স্টোর",
"D30-2595128": "সুমন স্টোর",
"D30-2595129": "নিউ বিসমিল্লাহ স্টোর",
"D30-2595130": "বিপুল স্টোর",
"D30-2595133": "তুবা স্টোর",
"D30-2595134": "বাঁধন স্টোর",
"D30-2595135": "রবিউল কসমেটিক্স",
"D30-2595136": "এনামুল  স্টোর",
"D30-2595137": "রুমাইশা স্টোর",
"D30-2595138": "ওপুর্বো স্টোর",
"D30-2595139": "পূর্ণব স্টোর",
"D30-2595140": "ফারুক পান স্টোর",
"D30-2595144": "আনিচুর স্টোর",
"D30-2595145": "মা ভ্যারাইটিস",
"D30-2595146": "ওবোসর ট্রেডার্স",
"D30-2595148": "খাইরুল স্টোর",
"D30-2595150": "বাবলুর স্টোর",
"D30-2595151": "রোহিম স্টোর",
"D30-2595152": "নূর স্টোর",
"D30-2595153": "হাবিবুর স্টোর",
"D30-2595154": "আরজুমান স্টোর",
"D30-2595155": "আয়াশা স্টোর",
"D30-2595156": "সহিবুল্লাহ স্টোর",
"D30-2595158": "দুই বোন স্টোর",
"D30-2595159": "ভাই বন ভ্যারাইটিস স্টোর",
"D30-2595160": "তাজু স্টোর",
"D30-2595161": "ভাই ভাই ডিপার্টমেন্টাল স্টোর",
"D30-2595162": "মা ভেরাউটেস স্টোর",
"D30-2595163": "মিমি স্টোর",
"D30-2595165": "লুৎফর স্টোর",
"D30-2595166": "সাথী ভেরাইটস স্টোর",
"D30-2595167": "ইতি টেলিকম",
"D30-2595168": "সাইফুল্লাহ স্টোর",
"D30-2595169": "রাহাত স্টোর",
"D30-2595170": "কুদ্দুস স্টোর",
"D30-2595171": "ফারুক স্টোর",
"D30-2595172": "তন্ময় স্টোর",
"D30-2595173": "আর্মি স্টোর",
"D30-2595175": "মা স্টোর",
"D30-2595176": "লুৎফর স্টোর",
"D30-2595177": "মুন্না স্টোর",
"D30-2595178": "সিরাজ স্টোর",
"D30-2595180": "নিউ ভাই ভাই ভাই স্টোর 2",
"D30-2595181": "আমোল স্টোর",
"D30-2595182": "সৌরভ স্টোর",
"D30-2595183": "কাওমি স্টোর",
"D30-2595184": "রনি স্টোর",
"D30-2595185": "লিয়াকত স্টোর",
"D30-2595186": "জরিনা স্টোর",
"D30-2595187": "মোদিনা স্টোর",
"D30-2595188": "মেসার্স অনিক ভ্যারাইটিস",
"D30-2595189": "আনারুল স্টোর",
"D30-2595190": "ওয়ালিউর স্টোর",
"D30-2595191": "মাজেদুর স্টোর",
"D30-2595192": "অনু শ্রী স্টোর",
"D30-2595193": "কামাল স্টোর",
"D30-2595194": "মা ভ্যারাইটিয়ার্স",
"D30-2595195": "রাব্বানী স্টোর",
"D30-2595196": "সাদিকুল স্টোর",
"D30-2595198": "সেকেন্দার স্টোর",
"D30-2595199": "সাব্বির স্টোর",
"D30-2595200": "আমিনুল স্টোর",
"D30-2595201": "মল্লিক স্টোর",
"D30-2595202": "তিন ভাই স্টোর",
"D30-2595203": "হারিসুল স্টোর",
"D30-2595204": "গনেশ স্টোর",
"D30-2595207": "তাজা এবং সহজ",
"D30-2595208": "বিনয় স্টোর",
"D30-2595209": "গোপাল স্টোর",
"D30-2595210": "অনু স্টোর",
"D30-2595211": "মানিক স্টোর",
"D30-2595212": "সোহাগ ভ্যারাইটি স্টোর",
"D30-2595213": "রুসদা কোস",
"D30-2595214": "ইব্রাহিম স্থির",
"D30-2595215": "সিরাজ ভ্যারাইটি স্টোর",
"D30-2595216": "রুবেল স্টোর",
"D30-2595217": "আজিজুল স্টোর",
"D30-2595218": "দুই ভাই স্টোর",
"D30-2595219": "২ ভাই ১ বোন",
"D30-2595220": "ছাহাল কসমেটিকস",
"D30-2595221": "চেয়ারম্যান স্টোর",
"D30-2595222": "আয়শা স্টোর",
"D30-2595223": "স্বপ্ন ডিপার্টমেন্টাল স্টোর",
"D30-2595225": "আরিশা স্টোর",
"D30-2595226": "আল-আমিন স্টোর",
"D30-2595227": "জান্নাত স্টোর",
"D30-2595228": "হিরা স্টোর",
"D30-2595229": "রায়হান ভ্যারাইটিস স্টোর",
"D30-2595230": "শ্রী শোর্মা স্টোর",
"D30-2595231": "ইমরান স্টোর",
"D30-2595232": "চন্দন স্টোর",
"D30-2595234": "দুই ভাই স্টোর",
"D30-2595235": "মিনহাজ হার্ডওয়্যার",
"D30-2595237": "রুখসানা স্টোর",
"D30-2595238": "রফিকুল স্টোর",
"D30-2595239": "মাহাবুর স্টোর",
"D30-2595240": "মাসুম স্টোর",
"D30-2595241": "বেলাল স্টোর",
"D30-2595242": "ভাই ভাই স্টোর",
"D30-2595243": "মন্টু স্টোর",
"D30-2595244": "সালমা ও সানজিদা স্টোর",
"D30-2595245": "রবিন স্টোর- ২",
"D30-2595247": "নাহিদা স্টোর",
"D30-2595248": "জাকির স্টোর",
"D30-2595249": "সিয়াম স্টোর",
"D30-2595251": "সেলিম স্টোর ২",
"D30-2595254": "কলি স্টোর",
"D30-2595256": "বিশাল স্টোর",
"D30-2595257": "আসিফ স্টোর",
"D30-2595258": "মা রাওশন ট্রেডার্স",
"D30-2595259": "জায়ানেস শপিং কমপ্লেক্স",
"D30-2595260": "দুই ভাই স্টোর",
"D30-2595261": "উজ্জল স্টোর",
"D30-2595262": "বাপ্পি স্টোর",
"D30-2595263": "ইদ্রিস স্টোর",
"D30-2595264": "লাবু কসমেটিক্স",
"D30-2595266": "পলাশ স্টোর",
"D30-2595267": "শাকিল ভ্যারাইটি",
"D30-2595269": "অনিক টেলিকম",
"D30-2595270": "তানহা স্টোর",
"D30-2595272": "মা স্টোর -২",
"D30-2595273": "ফেয়ার ডিপার্টমেন্টাল স্টোর",
"D30-2595274": "খুরশেদ স্টোর",
"D30-2595275": "মা বাবর দোয়া স্টোর",
"D30-2595277": "ইসলাম স্টোর",
"D30-2595278": "জনি স্টোর",
"D30-2595279": "সায়ান স্টোর",
"D30-2595280": "ইসমাইল স্টোর",
"D30-2595281": "টমিজ স্টোর",
"D30-2595282": "সুমন স্টোর",
"D30-2595283": "মুক্তার দোকান",
"D30-2595284": "বুলবুল স্টোর",
"D30-2595285": "রাহাত স্টোর",
"D30-2595287": "সিমা স্টোর",
"D30-2595289": "মিলাদ স্টোর",
"D30-2595291": "নুর স্টোর",
"D30-2595293": "আহসান স্টোর",
"D30-2595294": "মোজাহারুল স্টোর",
"D30-2595295": "রাকিব টি স্টোর",
"D30-2595296": "রানা স্টোর",
"D30-2595298": "গণেশ স্টোর",
"D30-2595299": "তিন ভাই স্টোর",
"D30-2595300": "বিমল স্টোর",
"D30-2595301": "নুরজমাল স্টোর",
"D30-2595302": "আনিসুর স্টোর",
"D30-2595304": "রুবেল স্টোর",
"D30-2595305": "সিন্থিয়া স্টোর",
"D30-2595307": "হিরু স্টোর",
"D30-2595308": "রাজ ফুড অ্যান্ড কনফ্যাক্টনারি",
"D30-2595309": "চিত্র স্টোর",
"D30-2595310": "কামাল স্টোর",
"D30-2595311": "লুৎফর স্টোর",
"D30-2595312": "ফেরদস স্টোর",
"D30-2595313": "সাজ্জাদ স্টোর",
"D30-2595314": "তুহিন স্টোর",
"D30-2595315": "মোস্তাকিম স্টোর",
"D30-2595316": "ভাই ভাই ট্রেডার্স",
"D30-2595318": "দিনবন্ধু স্টোর",
"D30-2595319": "ইসরাত স্টোর",
"D30-2595320": "মিম স্টোর",
"D30-2595321": "রাব্বি স্টোর",
"D30-2595322": "মা-বাবার দুয়া কসমেটিক্স অ্যান্ড ভ্যারিয়াটিস স্টোর",
"D30-2595323": "আব্দুর রশিদ স্টোর",
"D30-2595325": "বারি স্টোর",
"D30-2595327": "খোরশেদ স্টোর",
"D30-2595328": "রুকাইয়া স্টোর",
"D30-2595329": "গুলজার স্টোর",
"D30-2595330": "মা-বাবার স্টোর",
"D30-2595331": "নোবাব স্টোর",
"D30-2595332": "আল্লাহর দান স্টোর",
"D30-2595333": "চন্দন ভ্যারাইটিজ স্টোর",
"D30-2595334": "মাসুম বেকারি",
"D30-2595336": "রোশনি এন্টারপ্রাইজ",
"D30-2595337": "রাজু স্টোর",
"D30-2595339": "তালুকদার স্টোর",
"D30-2595340": "ভাই ভাই স্টোর",
"D30-2595341": "রাসেল স্টোর",
"D30-2595342": "দিপু স্টোর",
"D30-2595343": "গৌতম স্টোর",
"D30-2595344": "ভাই ভাই স্টোর",
"D30-2595346": "ফারিয়া স্টোর",
"D30-2595347": "ফাহিম স্টোর",
"D30-2595348": "মমিন স্টোর",
"D30-2595351": "নাজমুল স্টোর",
"D30-2595353": "একতা স্টোর",
"D30-2595354": "হৃদয় স্টোর",
"D30-2595355": "স্বপন স্টোর",
"D30-2595356": "ভাই ভাই স্টোর",
"D30-2595357": "ভাই বোন স্টোর",
"D30-2595359": "আব্দুল আজিজ স্টোর",
"D30-2595360": "বিপুল স্টোর",
"D30-2595361": "লামিয়া স্টোর",
"D30-2595365": "আয়শা স্টোর",
"D30-2595366": "দুই ভাই স্টোর",
"D30-2595367": "বাহার স্টোর",
"D30-2595369": "উজ্জল স্টোর",
"D30-2595371": "সাজ্জাদ রেশন ও কসমেটিক্স",
"D30-2595374": "তালেব ভ্যারাইটি স্টোর",
"D30-2595375": "মঞ্জুরুল স্টোর",
"D30-2595376": "ফারুক কসমেটিক্স",
"D30-2595377": "ভাই বোন স্টোর",
"D30-2601": "জহুরুল স্টোর",
"D30-2604": "তাহের স্টোর",
"D30-2605": "জুলফিকার স্টোর",
"D30-2607": "বেনারসি মুদি ডোকান",
"D30-2628447": "ফেমাস ভ্যারাইটিস স্টোর",
"D30-2628448": "আরিফুল টেলিকম",
"D30-2628449": "রবিউল স্টোর",
"D30-2628450": "রাজিব স্টোর",
"D30-2628451": "আসমা স্টোর",
"D30-2628452": "মোজাম্মেল স্টোর",
"D30-2628453": "ওবাইদুর স্টোর",
"D30-2628454": "মা  ট্রেডার্স",
"D30-2628455": "পান্না স্টোর",
"D30-2628456": "শুনিল স্টোর",
"D30-2628457": "লিটন ভ্যারাইটিস স্টোর",
"D30-2628458": "এরসাদ স্টোর",
"D30-2628459": "শাহাজান স্টোর",
"D30-2628460": "দুই ভাই স্টোর",
"D30-2628461": "সোহেল স্টোর",
"D30-2628462": "সাজ্জাদ স্টোর",
"D30-2628463": "মাহফুজ স্টোর",
"D30-2628464": "সাইদুর স্টোর",
"D30-2628465": "গনোপতি পান স্টোর",
"D30-2628466": "জোয়া ভেরাইটস স্টোর",
"D30-2628467": "সাগর পান স্টোর",
"D30-2628468": "আব্দুর রহিম স্টোর",
"D30-2628470": "ফারুক স্টোর",
"D30-2628471": "বাবু স্টোর",
"D30-2628473": "এনামুল স্টোর",
"D30-2628474": "সালাম স্টোর",
"D30-2628475": "সোহেল স্টোর",
"D30-2628476": "মেসার্স রিয়া এন্টারপ্রাইজ",
"D30-2628477": "মা কসমেটিক্স",
"D30-2628478": "ধোনজয় পান স্টোর",
"D30-2628479": "লিখন স্টোর",
"D30-2628480": "ব্ল স্কাই স্টোর",
"D30-2628481": "কামাল ডিমঘর",
"D30-2628482": "আল-আমিন স্টোর",
"D30-2628483": "মোকারম স্টোর",
"D30-2628484": "সোহেল স্টোর",
"D30-2628485": "রফিকুল স্টোর",
"D30-2628486": "সততা টেলিকম এন্ড ভ্যারাইটিস স্টোর",
"D30-2628487": "সেলিম স্টোর",
"D30-2628488": "জাহাঙ্গীর স্টোর",
"D30-2628489": "আমিনুল স্টোর",
"D30-2628490": "সাহিন স্টোর",
"D30-2628491": "শুভ স্টোর",
"D30-2628494": "রতন স্টোর",
"D30-2628495": "গোবিন্দ স্টোর",
"D30-2628496": "শ্যামল স্টোর",
"D30-2628497": "বিসমিল্লাহ স্টোর",
"D30-2628498": "জামান বেকারি",
"D30-2628500": "মানিক স্টোর",
"D30-2628501": "জববার স্টোর",
"D30-2628503": "মিজান স্টোর",
"D30-2628505": "রাকিব স্টোর",
"D30-2628506": "সাহেব বেকারি",
"D30-2628510": "রেজাউল স্টোর",
"D30-2628511": "সাদেকুল স্টোর",
"D30-2628512": "সাজঘরের স্টোর",
"D30-2628513": "কৃতি স্টোর",
"D30-2628514": "মিম ভ্যারাইটি স্টোর",
"D30-2628515": "শাকিল স্টোর",
"D30-2628516": "এরফান আলী স্টোর",
"D30-2628517": "সুপেন স্টোর",
"D30-2628518": "নাসির স্টোর",
"D30-2628520": "চিত্ররঞ্জন স্টোর",
"D30-2628521": "মিঠুন স্টোর",
"D30-2628522": "সাহিন স্টোর",
"D30-2628523": "রফিকুল স্টোর",
"D30-2628526": "জয়দেব স্টোর",
"D30-2628527": "কেশোব স্টোর",
"D30-2628528": "করিম স্টোর",
"D30-2628529": "মা ট্রেডার্স",
"D30-2628530": "চন্দন স্টোর",
"D30-2632771": "রানা স্টোর",
"D30-2632772": "রুবাল সেন্ট",
"D30-2632833": "মাসুম বেকারি",
"D30-2632942": "বনশাই কনফ্যাকশনারি",
"D30-2639240": "ঢাকা সাপ্লাইস",
"D30-2639763": "ফ্রেন্ডস ফুড এবং বেকারি",
"D30-2641446": "জে.আলম",
"D30-2641551": "আদিল স্টোর",
"D30-2641652": "মোঃ সোহরাব হোসেন",
"D30-2641653": "মোঃ কছির উদ্দিন",
"D30-2641864": "ডেইলি নিড স্টোর",
"D30-2643081": "ফাহিম স্টোর",
"D30-2644866": "নাইস ফুড আন্ড বেকারি",
"D30-2644867": "ভাই ভাই ফোল ভ্যান্ডার",
"D30-2645250": "দিনাজপুর স্টোর",
"D30-2645441": "মা ভ্যারাইটি স্টোর",
"D30-2663": "রশিদ স্টোর",
"D30-2699": "ওহিদুল স্টোর",
"D30-2704": "বাবু ষ্টোর",
"D30-2714": "মোকসেদুল স্টোর",
"D30-2715": "ফারুক স্টোর",
"D30-2718414": "রাইশা ফাস্টফুড এবং কসমেটিক্স",
"D30-2718415": "আব্দুর জব্বার স্টোর",
"D30-2718416": "গোজেন স্টোর",
"D30-2718417": "মুন্নি স্টোর",
"D30-2718418": "জিবনব স্টোর",
"D30-2718419": "ইয়াকুব স্টোর",
"D30-2718420": "নিরব স্টোর",
"D30-2718421": "শুর্জকান্ত স্টোর",
"D30-2718422": "শিখা স্টোর",
"D30-2718423": "মা ভ্যারাইটিস স্টোর",
"D30-2718424": "হিরা স্টোর",
"D30-2718425": "পরিমল স্টোর",
"D30-2718426": "শেমল স্টোর",
"D30-2718427": "আফ্রিন",
"D30-2718428": "রকি স্টোর",
"D30-2718429": "ভাই ভাই স্টোর",
"D30-2718430": "ফতিক স্টোর",
"D30-2718431": "হারুন স্টোর",
"D30-2718432": "শুরেশ স্টোর",
"D30-2718433": "প্রদিপ স্টোর",
"D30-2718435": "ওবাইদুল স্টোর",
"D30-2718436": "আলম স্টোর",
"D30-2718437": "টরিকুল স্টোর",
"D30-2718442": "দিপা স্টোর",
"D30-2718443": "আশ্রাফুল স্টোর",
"D30-2718444": "পার্ভেজ স্টোর",
"D30-2718446": "কমল কসমেটিক্স",
"D30-2718453": "শরিফুল স্টোর",
"D30-2718454": "এসডি এগ্রো স্টোর",
"D30-2718456": "রাজ্জাক স্টোর",
"D30-2718457": "আরিফ স্টোর",
"D30-2718458": "আপ্পলে স্টোর",
"D30-2718459": "শা আলম স্টোর",
"D30-2718460": "সরকার স্টোর",
"D30-2718461": "আনোয়ার স্টোর",
"D30-2718462": "হামিদুল স্টোর",
"D30-2718463": "হাফিযুল স্টোর",
"D30-2718464": "আজাহারুল স্টোর",
"D30-2718465": "হসসাইন স্টোর",
"D30-2718467": "রাফিকুল ফাল্ল স্টোর",
"D30-2718469": "ভাই ভাই স্টোর",
"D30-2718470": "আহাদ স্টোর",
"D30-2718471": "হাবিব স্টোর",
"D30-2718472": "জয়ন্তো স্টোর",
"D30-2718473": "খাইরুল স্টোর",
"D30-2718474": "মা স্টোর",
"D30-2718475": "মুক্তা স্টোর",
"D30-2718476": "সাইদুল স্টোর",
"D30-2718477": "মোহনা স্টোর",
"D30-2718478": "গাযি স্টোর",
"D30-2718479": "ইব্রাহিম স্টোর",
"D30-2718480": "নাজিম স্টোর",
"D30-2718481": "জাহাঙ্গীর স্টোর",
"D30-2718482": "রুহুল আমিন স্টোর",
"D30-2718483": "হানিফ স্টোর",
"D30-2718484": "হযরত স্টোর",
"D30-2718485": "জাকির স্টোর",
"D30-2718486": "শরিফুল স্টোর",
"D30-2718487": "সোহেল স্টোর",
"D30-2718488": "খবির স্টোর",
"D30-2718489": "ফজর আলী স্টোর",
"D30-2718490": "লতিফ স্টোর",
"D30-2718491": "শামীম স্টোর",
"D30-2718492": "নজরুল স্টোর",
"D30-2718493": "রফিক স্টোর",
"D30-2718494": "আন্বার স্টোর",
"D30-2718495": "তপন স্টোর",
"D30-2718496": "মাহাবুর স্টোর",
"D30-2718497": "সাদ্দাম স্টোর",
"D30-2718498": "প্রদিপ স্টোর",
"D30-2718499": "ভাই ভাই স্টোর",
"D30-2718500": "জিসুন স্টোর",
"D30-2718501": "রুস্তম স্টোর",
"D30-2718502": "সাদ্দাম স্টোর",
"D30-2718503": "মনয়ার  স্টোর",
"D30-2718504": "সাজু স্টোর",
"D30-2718505": "গিয়াশ ঊদ্দিন স্টোর",
"D30-2718506": "ভাই ভাই স্টোর ২",
"D30-2718507": "আলমগির স্টোর",
"D30-2718508": "কালিদাস স্টোর",
"D30-2718509": "মাস্টার স্টোর",
"D30-2718510": "শলেমান  স্টোর",
"D30-2718511": "আবির আশিক স্টোর",
"D30-2718512": "মনলহেন স্টোর",
"D30-2718513": "মস্তাকিন  স্টোর",
"D30-2718514": "আদিত্ত স্টোর",
"D30-2718515": "মিঠুন স্টোর",
"D30-2718516": "রাজু স্টোর",
"D30-2718517": "রাসেল স্টোর",
"D30-2718518": "আল করিম ভ্যারাইটি স্টোর",
"D30-2718519": "ভাই ভাই স্টোর",
"D30-2718520": "মামুন স্টোর",
"D30-2718521": "নাসির স্টোর",
"D30-2718522": "লিটন স্টোর",
"D30-2718524": "সাদিয়া স্টোর",
"D30-2718525": "জলিল স্টোর",
"D30-2718526": "মাসুদি স্টোর",
"D30-2718527": "মেসার্স রোজি ট্রেডার্স",
"D30-2718528": "রাজু স্টোর ২",
"D30-2718530": "বিপিন স্টোর,",
"D30-2718531": "শান্ত স্টোর",
"D30-2718532": "হায়াত স্টোর",
"D30-2718536": "নূর ইসলাম স্টোর",
"D30-2718540": "হক স্টোর",
"D30-2718541": "লিমন স্টোর",
"D30-2718542": "মান্নান স্টোর",
"D30-2718543": "মনসুর স্টোর",
"D30-2718544": "শুকুর স্টোর",
"D30-2718545": "ণুর স্টোর",
"D30-2718546": "জয়নাথ স্টোর",
"D30-2718548": "জাহাঙ্গীর স্টোর",
"D30-2718549": "রাসেল স্টোর",
"D30-2718550": "আলমগীর স্টোর",
"D30-2718551": "হাকিম স্টোর",
"D30-2718552": "কাদের স্টোর",
"D30-2718556": "শাকিব স্টোর",
"D30-2718557": "ণুরুল্লাহ স্টোর",
"D30-2718558": "পারুল স্টোর",
"D30-2718559": "গৌতম স্টোর",
"D30-2718560": "জয় লক্ষ্মী স্টোর",
"D30-2718561": "শাহ আলম স্টোর",
"D30-2718562": "জুনায়েত স্টোর",
"D30-2718563": "কামাল স্টোর",
"D30-2718564": "মানিক স্টোর",
"D30-2718565": "বাদশা স্টোর",
"D30-2718566": "পরেশ স্টোর",
"D30-2718567": "আস্লাম স্টোর",
"D30-2718569": "রাজু স্টোর",
"D30-2718570": "রাব্বি স্টোর",
"D30-2718571": "ইউনুস স্টোর",
"D30-2718572": "রিমা স্টোর",
"D30-2718573": "শ্যামল স্টোর",
"D30-2718574": "শান্তিকান্ত স্টোর",
"D30-2718575": "ভরত স্টোর",
"D30-2718576": "মাসুদ স্টোর",
"D30-2718578": "শিরাজুল স্টোর",
"D30-2718579": "শাততা স্টোর",
"D30-2718580": "পুজা স্টোর",
"D30-2718581": "বেলাল স্টোর",
"D30-2718582": "মামুন স্টোর",
"D30-2718583": "আজিজুল স্টোর",
"D30-2718584": "সোহাগ স্টোর",
"D30-2718585": "শাইদুর স্টোর",
"D30-2718586": "শুরেশ স্টোর",
"D30-2718589": "মোকছেদ স্টোর",
"D30-2718590": "আনোয়ার স্টোর",
"D30-2718591": "মামুন স্টোর",
"D30-2718592": "আরমান স্টোর",
"D30-2718593": "শামসুল স্টোর",
"D30-2718594": "শামিম স্টোর",
"D30-2718595": "সাইদ স্টোর",
"D30-2718597": "র‍্যাটন স্টোর",
"D30-2718598": "ণাইম ছস্মেতিচস",
"D30-2718599": "ইত্তাদি স্টোর",
"D30-2718601": "নন্দিনি স্টোর",
"D30-2718602": "আরিফ স্টোর",
"D30-2718603": "আল আমিন স্টোর ২",
"D30-2718604": "রুবেল স্টোর",
"D30-2718605": "তিন ভাই স্টোর",
"D30-2718606": "আরমান স্টোর",
"D30-2718608": "নারায়ণ স্টোর",
"D30-2718609": "জিয়া স্টোর",
"D30-2718611": "বন্ধু ভারিয়েতিয়েস স্টোর",
"D30-2718612": "রাসেল স্টোর",
"D30-2718613": "আল-আমিন স্টোর",
"D30-2718614": "আনোয়ার স্টোর",
"D30-2718615": "রাবেয়া স্টোর",
"D30-2718617": "মাহাবুর স্টোর",
"D30-2718618": "জাকির স্টোর",
"D30-2718619": "শহেল স্টোর",
"D30-2718620": "মায়ের দোয়া স্টোর",
"D30-2718621": "মনোরঞ্জন স্টোর",
"D30-2718622": "তোফাজল স্টোর",
"D30-2718623": "রবিউল স্টোর",
"D30-2718626": "মদ। রামজান আলি",
"D30-2718628": "মোঃ আমির আলী",
"D30-2718629": "মালেক স্টোর",
"D30-2718630": "মোঃ শাহাবুদ্দিন",
"D30-2718631": "ষপন শেন",
"D30-2718632": "মদ শহিদুল",
"D30-2718633": "মোঃ বেলাল",
"D30-2718634": "আব্দুল হালিম",
"D30-2718635": "মদ। বাবুল",
"D30-2718636": "সফিকুল স্টোর",
"D30-2718637": "বেলাল স্টোর",
"D30-2718638": "সানজিদা স্টোর",
"D30-2718639": "সাহিন স্টোর",
"D30-2718640": "কৃষ্ণ কান্ত স্টোর",
"D30-2718641": "সোহিদুল্লাহ স্টোর",
"D30-2718642": "মুন স্টোর",
"D30-2718643": "জাহাঙ্গীর স্টোর",
"D30-2718644": "মেজোর স্টোর",
"D30-2718645": "আল-আমিন স্টোর",
"D30-2718646": "সোরিফুল স্টোর",
"D30-2718647": "ওহেদ স্টোর",
"D30-2718648": "আনারুল স্টোর",
"D30-2718649": "জোসিম স্টোর",
"D30-2718650": "আজিজুর স্টোর",
"D30-2718651": "জীবন স্টোর",
"D30-2718652": "বুধু স্টোর",
"D30-2718653": "রহিম স্টোর",
"D30-2718654": "মোকারম স্টোর",
"D30-2718655": "আবু হায়াদ স্টোর",
"D30-2718656": "মারুফ স্টোর",
"D30-2723": "সিরাজুল স্টোর",
"D30-2736076": "মাসুদ স্টোর",
"D30-2736077": "দুই বই ষ্টোর",
"D30-2736078": "আলম স্টোর",
"D30-2736080": "মানিক স্টোর",
"D30-2736081": "পাপ্পু স্টোর",
"D30-2736082": "তাসিন এবং তাবাসুম বেকারি",
"D30-2736083": "মরিয়ম স্টোর",
"D30-2736084": "আসাদ মেডিসিন পানেল",
"D30-2736085": "বোধুয়া কসমেটিক্স",
"D30-2736086": "তারেক স্টোর",
"D30-2736087": "ওয়াসিম স্টোর",
"D30-2736088": "মেরাজ স্টোর",
"D30-2736089": "হাসান স্টোর",
"D30-2736090": "ইমন স্টোর",
"D30-2736091": "সাব্বির স্টোর",
"D30-2736092": "চার ভাই স্টোর",
"D30-2736093": "ইস্রায়েল স্টোর",
"D30-2736095": "সোনালী সুতস",
"D30-2736096": "সুরাইয়া স্টোর",
"D30-2736098": "জুলফিকুর স্টোর",
"D30-2736099": "নিতাই স্টোর",
"D30-2736100": "রাইশা রেলওয়ে ফাস্ট ফুড",
"D30-2736101": "ফ্রেন্ডস ফুড",
"D30-2736102": "ফ্রেন্ডস মেডিকেল",
"D30-2736103": "ফজল স্টোর",
"D30-2736104": "মেসার্স সোহান মেডিসিন কর্নার",
"D30-2736105": "মোগল সোর",
"D30-2736106": "ভাই বোন ডিপার্টমেন্টাল",
"D30-2736107": "মা ভান্ডার",
"D30-2736108": "মোবারক সোর",
"D30-2736109": "ভাই ভাই কনফেকশনারি",
"D30-2736110": "মিজান ফার্মেসি",
"D30-2736111": "গোলাম আজম আদর্শ মুডু স্টোর",
"D30-2736112": "মোশারফ স্টোর",
"D30-2736113": "মিনার পান স্টোর",
"D30-2736114": "তানভীর মন্তাসা ট্রেডাস",
"D30-2736115": "সালাম ভেরাইটিস স্টোর",
"D30-2736116": "মাজেদুর মোসলা স্টোর",
"D30-2736117": "৪ ব্রাদার্স স্টোর",
"D30-2736118": "আব্দুর রহমান স্টোর",
"D30-2736119": "ভাই ভাই ট্রেডার্স",
"D30-2736120": "তিন কোন্না স্টোর",
"D30-2736121": "বাসির স্টোর",
"D30-2736122": "এম ডি জাহিদুল",
"D30-2736123": "রকি স্টোর",
"D30-2736124": "আরিফুল ট্রেডার্স",
"D30-2736125": "জামাল স্টোর",
"D30-2736126": "বিষ্ণু স্টোর",
"D30-2736127": "মিন্টু সৎ",
"D30-2736128": "শোঙ্গার স্টোর",
"D30-2736129": "বিসমিল্লাহ ফিড এবং জেড ল এইচ ভেরাইটিস স্টোর",
"D30-2736130": "স্বপ্নের কনফেশনারি",
"D30-2736131": "রমনী কসমেটিক",
"D30-2736132": "ওহনা স্টোর",
"D30-2736133": "রতন মেডিকেল স্টোর",
"D30-2736134": "হাসিনা ফার্মেসি",
"D30-2736135": "মেসার্স সুলোভ স্টোর",
"D30-2736136": "দিনাজপুর ওশাদ বিতান",
"D30-2736137": "মান্নান ট্রেডার এস.",
"D30-2736138": "মোকারম স্টোর",
"D30-2736139": "ভাই ভাই স্টোর",
"D30-2736140": "মেসার্স তৌফিক স্টোর",
"D30-2736142": "বাঁধন স্টোর",
"D30-2736143": "কাহারোল ফার্মা",
"D30-2736145": "সোহিদুল স্টোর",
"D30-2736146": "শাহজাহান স্টোর",
"D30-2736147": "জামান স্টোর",
"D30-2736148": "ভাই ভাই স্টোর",
"D30-2736149": "সবুজ কসমেটিকস",
"D30-2736150": "ভাই ভাই ট্রেডার্স",
"D30-2736152": "এফএম স্টোর",
"D30-2736153": "তানজিন স্ট",
"D30-2736154": "ওয়াজিহা",
"D30-2736155": "দেলয়ার স্টোর",
"D30-2736156": "হাবিবুর স্টোর",
"D30-2736157": "মিন্টু সৎ",
"D30-2736158": "রানা স্টোর",
"D30-2736159": "মোবারক স্টোর",
"D30-2736160": "মা স্টোর",
"D30-2736161": "রাকিব স্টোর",
"D30-2736162": "ইত্যাদি ট্রেডার্স",
"D30-2736163": "মা টেলিকম",
"D30-2736164": "মেসার্স মুয়াজ ফার্মেসি",
"D30-2736165": "আলমগীর স্টোর",
"D30-2736166": "মেসার্স মেডিসিন হাউস",
"D30-2736167": "রাকিব স্টোর",
"D30-2736169": "মেম্বার এবং ব্রাদাস ট্রেডার্স",
"D30-2736170": "গৌতম স্টোর",
"D30-2736173": "মেসার্স অনু ডিপাটমেন্টাল স্টোর",
"D30-2736174": "এম/স ফারুক মেডিকেল স্টোর",
"D30-2736175": "মদ.এমন",
"D30-2736176": "আকরাম স্টোর",
"D30-2736177": "রকি স্টোর",
"D30-2736178": "আফজাল সুপার সপ",
"D30-2736179": "সোবুজ স্টোর",
"D30-2736180": "শাহীন ফরমেচি",
"D30-2736181": "রনি স্টোর",
"D30-2736182": "সাবদারুল স্টোর",
"D30-2736183": "বকুল স্টোর",
"D30-2736184": "আরিফ স্টোর",
"D30-2736185": "জীবন স্টোর",
"D30-2736186": "মরিয়াম স্টোর",
"D30-2736187": "মোঃ আলমগীর",
"D30-2736188": "শ্রদ্ধা স্টোর",
"D30-2736189": "মিনহা স্টোর",
"D30-2736190": "মদ.মুন্না",
"D30-2736191": "তৌফিক স্টোর",
"D30-2736192": "মামুন স্টোর",
"D30-2736193": "বিসমেল্লাহ ফিড জেডএলএইচ স্টোর",
"D30-2736194": "সরকার ফার্মেসি",
"D30-2736195": "মার্শাল সৎ",
"D30-2736196": "যায়েদ স্টোর",
"D30-2736197": "আনোয়ার",
"D30-2736198": "মীম স্টোর",
"D30-2736199": "আতাবুর স্টোর",
"D30-2736200": "মনির সেন্ট",
"D30-2736201": "বেবি কসমেটিক্স ও কনফেকশনারি",
"D30-2736202": "রশিদুল স্টোর",
"D30-2736203": "মদ.রাব্বি",
"D30-2736204": "জারিফ সৎ",
"D30-2736205": "স.ম ডিপার্টমেন্টাল স্টোর",
"D30-2736206": "লুফার স্টোর",
"D30-2736207": "প্রিয়ন্তি স্টোর",
"D30-2736208": "ইব্রাহিম স্টোর",
"D30-2736209": "সাহিন স্টোর",
"D30-2736210": "আকাশ স্টোর",
"D30-2736212": "মা.ভি ভি সৎ",
"D30-2736213": "আরিফ স্টোর",
"D30-2736214": "রতন স্টোর",
"D30-2736215": "বেলাল স্টোর",
"D30-2736216": "মেসার্স ইদ্রিস স্টোর",
"D30-2736218": "আসাদ স্টোর",
"D30-2736219": "কসবা কসমেটিক এবং ভারিয়াটিস",
"D30-2736220": "এমডি সারওয়ার",
"D30-2736221": "রিয়া ষ্টোর",
"D30-2736222": "ইন্টেক্স ফ্যাশন এবং কসমেটিক্স",
"D30-2736223": "মাজেদুর পান স্টোর",
"D30-2736224": "মজিবুল স্টোর",
"D30-2736226": "দুই বোন বাড়িটি ষ্টোর",
"D30-2736227": "আসরাফুল স্টোর",
"D30-2736228": "মোঃ আতাউর",
"D30-2736229": "গার্মেন্টস এবং কসমেটিক্স স্টোর",
"D30-2736230": "রনি স্টোর",
"D30-2736231": "আল আমিন ফল",
"D30-2736232": "সাব্বির স্টোর",
"D30-2736233": "এমডি শাইন",
"D30-2736234": "আলমগীর স্টোর",
"D30-2736235": "মহিন্দ্র স্টোর",
"D30-2736236": "রাইজ রাফা ট্রেডার্স",
"D30-2736237": "ইমরান স্টোর",
"D30-2736238": "অয়ন",
"D30-2736239": "কালাম স্টোর",
"D30-2736240": "মোঃ রাজিব ইসলাম",
"D30-2736241": "এম, স গালিব ভার্সিটি স্টোর",
"D30-2736242": "কৈলাশ স্টোর",
"D30-2736243": "মা ডিম গোর",
"D30-2736244": "আরফিন স্টোর",
"D30-2736245": "বিসমিল্লাহ পেপারস হাউস",
"D30-2736246": "ওহেদ স্টোর",
"D30-2736247": "বিব্লপ স্টোর",
"D30-2736248": "সানজিদা টেলিকম",
"D30-2736249": "ঐকিও কনফেকশনারি",
"D30-2736250": "ফরিদ স্টোর",
"D30-2736251": "আরিফ স্টোর",
"D30-2736252": "আকরাম ষ্টোর",
"D30-2736253": "কিবরিয়া চা স্টোর",
"D30-2736254": "মা বাবর দোয়া ডিপার্মেন্টাল স্টোর",
"D30-2736256": "বীরগঞ্জ ডিপার্টমেন্টাল স্টোর",
"D30-2736257": "মেসার্স সুজন স্টোর",
"D30-2736259": "জান্নাত স্টোর",
"D30-2736260": "নুর বেকারি বীরগঞ্জ",
"D30-2736261": "ওবায়দুর স্টোর",
"D30-2736262": "এস. আলম",
"D30-2736263": "রাজ ভ্যারাইটিস স্টোর",
"D30-2736264": "রুবাইয়া",
"D30-2736265": "জাহাঙ্গীর স্টোর",
"D30-2736266": "শরিয়া স্টোর",
"D30-2736267": "বাবু স্টোর",
"D30-2736268": "ফারাজ স্টোর",
"D30-2736269": "আল্লাহ ভোরোশা",
"D30-2736270": "মাজেদুর স্টোর",
"D30-2736271": "বাপ্পি স্টোর",
"D30-2736272": "সততা লাইব্রেরি ও স্টেশনারি",
"D30-2736273": "নুরি কসমেটিক্স",
"D30-2736274": "রিফাত ভ্যারাইটি স্টোর",
"D30-2736275": "সিয়াম স্টোর",
"D30-2736276": "মুসফিরাত স্টোর",
"D30-2736277": "রশিদুল স্টোর",
"D30-2736278": "সাহিন স্টোর",
"D30-2736279": "সাকিল স্টোর",
"D30-2736281": "রেদুয়ান স্টোর",
"D30-2736282": "মোস্তফা স্টোর",
"D30-2736287": "তিন ভাই স্টোর",
"D30-2736288": "মুসলিম স্টোর",
"D30-2736289": "শাহিন স্টোর",
"D30-2736290": "নূরজামাল স্টোর",
"D30-2736291": "সিদ্দিক স্টোর",
"D30-2736292": "মইনুল স্টোর",
"D30-2736293": "ইসাবুল স্টোর",
"D30-2736294": "আতিকুর স্টোর",
"D30-2736295": "বি আর বি স্টোর",
"D30-2736296": "অভয় ষ্টোর",
"D30-2736297": "মুক্তার স্টোর",
"D30-2736298": "বিসমিল্লাহ স্টোর",
"D30-2736299": "মা স্টোর",
"D30-2736302": "স্বপন পান স্টোর",
"D30-2736303": "জাহাঙ্গীর স্টোর ১",
"D30-2736304": "মা বাবর দোয়া",
"D30-2736305": "আনিকা স্টোর",
"D30-2736306": "মা স্টোর",
"D30-2736307": "ইমরান স্টোর",
"D30-2736308": "সুমাইয়া কনফেকশনারি",
"D30-2736309": "সালাম স্টোর",
"D30-2736310": "বাবু স্টোর",
"D30-2736311": "ইসারুল স্টোর",
"D30-2736312": "সজীব স্টোর",
"D30-2736313": "রাজন স্টোর",
"D30-2736314": "কৃষ্ণ স্টোর",
"D30-2736315": "আরিফুল কনফেক্শনারি",
"D30-2736316": "আব্দুল্লাহ ভ্যারাইটি স্টোর",
"D30-2736317": "জনতা কসমেটিক্স",
"D30-2736318": "ভাই ভাই কনফেকশনারি",
"D30-2736320": "ফিরোজ ষ্টোর",
"D30-2736321": "নূর বাকারী",
"D30-2736322": "সুসান্তো স্টোর",
"D30-2736323": "নূর ফার্মেসী",
"D30-2736324": "মেয়ের দোয়া",
"D30-2736325": "সৌরভ এন্টার পুরস্কার",
"D30-2736326": "যোগেশ স্টোর",
"D30-2736327": "আরজয়শ্রী স্টোর",
"D30-2736328": "মেসার্স সালিফ স্টোর",
"D30-2736329": "নাফিসা টেলিকম",
"D30-2736330": "দিপানিতা বাড়িটি",
"D30-2736331": "হাসান স্টোর",
"D30-2736332": "সাব্বির স্টোর",
"D30-2736334": "রুবেল পান স্টোর",
"D30-2736335": "শফিকুল স্টোর",
"D30-2736336": "সজিব স্টোর",
"D30-2736337": "মঞ্জু স্টোর",
"D30-2736338": "বাড়িসহ স্টোর",
"D30-2736339": "সাব্বির কনফেকশনারি",
"D30-2736341": "অন্ননা স্টোর",
"D30-2736342": "হ্যাপি স্টোর",
"D30-2736343": "রাসেল স্টোর",
"D30-2736344": "হোসিন",
"D30-2736345": "সিলন স্টোর",
"D30-2736346": "সিমুল স্টোর",
"D30-2736347": "আরএম ট্রেডার্স",
"D30-2736348": "আরিফ মিসেনারি স্টোর",
"D30-2736349": "মিম এন্টার পুরস্কার",
"D30-2736350": "শামিম বস্তালয়",
"D30-2736351": "সামিম ব্রস্তালয় এবং কসমেটিক্স",
"D30-2736352": "শামিম স্টোর",
"D30-2736354": "হায়দার স্টোর",
"D30-2736355": "আবির ষ্টোর",
"D30-2736356": "মুরসালীন স্টোর",
"D30-2736357": "সাজু স্টোর",
"D30-2736358": "আনিসুর",
"D30-2736359": "ওমর ফারুক স্টোর",
"D30-2736360": "ভাই ভাই স্টোর",
"D30-2736361": "লাল পান জাহিদ ভ্যারাইটিস স্টোর",
"D30-2736362": "টিন বোন স্টোর",
"D30-2736363": "মা ভ্যারাইটিস-০২",
"D30-2736364": "আকাশ স্টোর",
"D30-2736365": "আয়েশা ভ্যারাইটিস স্টোর",
"D30-2736366": "মা স্টোর",
"D30-2736367": "দুই ভাই",
"D30-2736368": "অয়েল কাম বিসনেস পইন্ট",
"D30-2736369": "ইশরাত কসমেটিক্স",
"D30-2736372": "মেসার্স সততা মেডিকেল স্টোর",
"D30-2736373": "তানজিমুল ষ্টোর",
"D30-2736375": "বিসমিল্লাহ স্টোর",
"D30-2736376": "সাইফ ফার্মা অ্যান্ড ডিপার্টমেন্টাল স্টোর",
"D30-2736377": "মুক্তার স্টোর",
"D30-2736378": "নূর জাহান ডিপার্টমেন্টাল স্টোর",
"D30-2736380": "বাবু স্টোর",
"D30-2736381": "অনন্যা ফেসন",
"D30-2736382": "মোজাহারুল স্টোর",
"D30-2736383": "রফিকুল ইসলাম",
"D30-2736384": "নুরুজ্জমান স্টোর",
"D30-2736385": "নূরাইন ভেরাইটি স্টোর",
"D30-2736386": "পাইলটের স্টোর",
"D30-2736388": "জিলানি স্টোর",
"D30-2736389": "টিয়া টেলিকম ও স্টেশনারি",
"D30-2736390": "শিমা স্টোর",
"D30-2736391": "এম+ওয়াই",
"D30-2736392": "মারুফ স্টোর",
"D30-2736393": "পপুলার মেডিকেল স্টোর",
"D30-2736394": "রাশেদুল পান স্টোর",
"D30-2736395": "ভাই ভাই স্টোর",
"D30-2736396": "সামিম স্টোর",
"D30-2736397": "সামিম স্টোর",
"D30-2736398": "ফেরদৌস স্টোর",
"D30-2736399": "আবরার ফুড এবং বেভারেজ",
"D30-2736400": "মুস্তাকিম স্টোর",
"D30-2736401": "আয়াত মেডিসিন",
"D30-2736403": "টপন পান স্টোর",
"D30-2736404": "আপন স্টোর",
"D30-2736405": "হায়দুল স্টোর",
"D30-2736406": "সাবাড় স্টোর",
"D30-2736407": "অপুর্ব স্টোর",
"D30-2736409": "পারভেজ স্টোর",
"D30-2736410": "রাকিব রিসাদ ভ্যারাইটি স্টোর",
"D30-2736411": "এ এন স্টোর",
"D30-2736412": "আবাবিল স্টোর",
"D30-2736413": "আলম স্টোর",
"D30-2736415": "মন্টু ভ্যারাইটি স্টোর",
"D30-2736416": "বি জি বি ক্যান্টিন ১",
"D30-2736417": "ফায়ারিয়া স্টোর",
"D30-2736418": "রেফাত স্টেশনারি",
"D30-2736419": "আরনো পূর্ণ ট্রেডিং",
"D30-2736420": "আবির স্টোর",
"D30-2736421": "শফিক স্টোর",
"D30-2736422": "চান স্টোর",
"D30-2736423": "আব্দুল হালিম মিস্টি পান স্টোর",
"D30-2736424": "সিফাত শামীম টেলিকম",
"D30-2736425": "মেমোরি পেস্ট্রি শপ",
"D30-2736426": "টিন ভাই কসমেটিকস",
"D30-2736427": "মনি টেলিকম",
"D30-2736428": "সোহেল স্টোর",
"D30-2736429": "নুর আলম স্টোর",
"D30-2736431": "মেসার্স আরব স্টোর",
"D30-2736432": "সায়মা জান্নাত স্টোর",
"D30-2736433": "ইউসুফ আলী স্টোর",
"D30-2736435": "স্টোরের পাশে",
"D30-2736436": "অন্ত স্টোর",
"D30-2736437": "জানান স্টোর",
"D30-2736438": "মাহিরা স্টোর",
"D30-2736439": "ওমসেদ স্টোর",
"D30-2736440": "বিসমিল্লাহ ভ্যারাইটি স্টোর",
"D30-2736441": "রাশিকুল স্টোর",
"D30-2736442": "আদ্দোহা ভেরাইটি স্টোর",
"D30-2736443": "জিম স্টোর",
"D30-2736445": "নৱকান্ত স্টোর",
"D30-2736446": "রিপা স্টোর",
"D30-2736447": "মমিন মধু ও সুইটস",
"D30-2736448": "নাহিদ স্টোর",
"D30-2736449": "মামুন স্ট্রিট",
"D30-2736450": "মা বাড়িটি সৎ",
"D30-2736451": "আনিস সেন্ট",
"D30-2736452": "নূরে স্টোর",
"D30-2736453": "অরুণা স্টোর",
"D30-2736454": "ভাই ভাই স্টোর",
"D30-2736455": "রফিক স্টোর",
"D30-2736456": "সাইদুল স্টোর",
"D30-2736457": "আজিজুর স্টোর",
"D30-2736458": "বিসমিল্লাহ কসমেটিক্স",
"D30-2736459": "আরসাদ স্টোর",
"D30-2736460": "অপূর্ব স্টোর",
"D30-2736462": "মোস্তাকিম স্টোর",
"D30-2736463": "রাহাদ আবিদ স্টোর",
"D30-2736464": "বিপ্লব স্টোর",
"D30-2736465": "মোসারফ জাতের স্টোর",
"D30-2736466": "রোকন ভ্যারাইটি স্টোর",
"D30-2736467": "সারমিন স্টোর",
"D30-2736468": "সোরোবর শপ",
"D30-2736469": "বিসমিল্লাহ রাসেদ",
"D30-2736471": "জাফোর স্টোর",
"D30-2736473": "রিমি আয়াত সাজগুর",
"D30-2736474": "মোকারম পান স্টোর",
"D30-2736475": "আক্তার স্টোর",
"D30-2736476": "নিরঞ্জন স্টোর ২",
"D30-2736477": "কোবাদ স্টোর",
"D30-2736478": "তামিম তালহা স্টোর",
"D30-2736479": "আরাফাত স্টোর",
"D30-2736480": "র জামান স্টোর",
"D30-2736481": "সেলিম স্টোর",
"D30-2736482": "ফিরোজ স্টোর",
"D30-2736483": "অনুপম স্টোর",
"D30-2736484": "অল মামুন স্টোর",
"D30-2736486": "মুক্তাদির স্টোর",
"D30-2736487": "আমিনুল স্টোর",
"D30-2736489": "হাম্মাদ ট্রেডার্স",
"D30-2736490": "মোতাহার স্টোর",
"D30-2736491": "শুভ স্টোর",
"D30-2736492": "আমিনুল স্টোর",
"D30-2736494": "নজরুল স্টোর",
"D30-2736495": "চান মিয়া স্টোর",
"D30-2736496": "দাদি নাতি ভেরাইটি স্টোর",
"D30-2736497": "হইচই খেলাঘর",
"D30-2736498": "শাহ কনফেকশনারি",
"D30-2736499": "মুক্তা ফ্যাশন কর্নার",
"D30-2736500": "রিহান স্টোর",
"D30-2736503": "শ্রীজিতা মার্ট",
"D30-2736505": "বিসমিল্লাহ স্টোর",
"D30-2736506": "সাহারিয়া স্টোর",
"D30-2736508": "লুনাস স্টোর",
"D30-2736509": "সোহেল স্টোর",
"D30-2736510": "গনেশ স্টোর",
"D30-2736511": "তানভীর স্টোর",
"D30-2736512": "তাজ স্ট্রিট",
"D30-2736513": "সঞ্জিত স্টেশনারি",
"D30-2736514": "জুয়েল ভ্যারাইটি স্টোর",
"D30-2736515": "মকবুল স্টোর",
"D30-2736516": "ভাই ভাই ষ্টোর ০১",
"D30-2736517": "ভাই বোন স্টোর",
"D30-2736519": "রাজ্জাক স্টোর",
"D30-2736520": "তোফাজ্জল ষ্টোর",
"D30-2736521": "মা বাবর দোয়া",
"D30-2736522": "কার্তিক স্টোর",
"D30-2736523": "ফজলুল স্টোর",
"D30-2736524": "লাবিবা স্টোর",
"D30-2736525": "আমির হামজা স্টোর",
"D30-2736526": "শালোম স্টোর",
"D30-2736527": "আয়শা এন্টারপ্রাইজ",
"D30-2736528": "সৌমিক স্টোর",
"D30-2736529": "দুই ভাই স্টোর",
"D30-2736530": "চার ভাই স্টোর",
"D30-2736531": "পল্লব পান",
"D30-2736532": "জাফর স্টোর",
"D30-2736533": "রমজান স্টোর",
"D30-2736534": "হাসান গ্রাম পুলিশ",
"D30-2736535": "রোইসুল স্টোর",
"D30-2736536": "মেসার্স মা ট্রেডার্স",
"D30-2736537": "সৌখিন স্টোর",
"D30-2736539": "মনসুর স্টোর",
"D30-2736540": "মিমি কনফেকশনারি",
"D30-2736541": "বাচ্চু স্টোর",
"D30-2736542": "মিমি ফুডস",
"D30-2736543": "আবির স্টোর",
"D30-2736544": "শামীম স্টোর",
"D30-2736545": "সাগর স্টোর",
"D30-2736546": "বিথি কসমেটিক্স",
"D30-2736547": "হাসান স্টোর",
"D30-2736548": "মা ডিপার্টমেন্টাল স্টোর",
"D30-2736549": "অভি তীর্থ এন্টারপ্রাইস",
"D30-2736550": "জয়ন্ত স্টোর",
"D30-2736551": "রাহাত স্টোর",
"D30-2736552": "আনন্দ স্টোর",
"D30-2736553": "আবির স্টোর",
"D30-2736554": "ভাই বোইন সেন্ট",
"D30-2736555": "অবিনাস ফল স্টোর",
"D30-2736556": "খান, স্টোর মুন্সি",
"D30-2736557": "জান্নাত কসমেটিক্স",
"D30-2736558": "বাবুল স্টোর",
"D30-2736559": "রনি স্টোর",
"D30-2736560": "নবীউল স্টোর",
"D30-2736561": "সুমন স্টোর",
"D30-2736562": "র, স, ক্যান্টিন, এবং, স্টোর",
"D30-2736564": "শাহিন টেলিকম",
"D30-2736565": "রকি,স্টোর",
"D30-2736566": "নায়েম স্টোর",
"D30-2736568": "মেম্বার স্টোর",
"D30-2736569": "হবু, স্টোর",
"D30-2736570": "মা ভ্যারাইটি স্টোর",
"D30-2736571": "মোতাহার স্টোর",
"D30-2736572": "কলি, স্টোর",
"D30-2736573": "বিপ্লব টেলিকম",
"D30-2736574": "স্নেহা, স্টোর",
"D30-2736575": "রুবেল স্টোর",
"D30-2736576": "আর্নিকা স্টোর",
"D30-2736577": "রকি স্টোর",
"D30-2736578": "বর্ষা স্টোর",
"D30-2736579": "মা, স্টোর",
"D30-2736580": "পেস্ট্রি হাউস",
"D30-2736581": "শাহজাদা স্টোর",
"D30-2736582": "তাবাস্সুম, স্টোর",
"D30-2736583": "তানহা স্টোর",
"D30-2736584": "মা স্টোর",
"D30-2736585": "সেলিম স্টোর",
"D30-2736586": "রশনি স্টোর",
"D30-2736587": "এ আর এস ডিপার্টমেন্টাল স্টোর",
"D30-2736588": "দিবা-রাত্রি স্টোর",
"D30-2736589": "আবু তালেব",
"D30-2736590": "রাজু",
"D30-2736591": "দুই ভাই পান স্টোর",
"D30-2736592": "মেসার্স সজিব স্টোর",
"D30-2736593": "সাগর ষ্টোর",
"D30-2736594": "রাজেন",
"D30-2736595": "শহিদুল",
"D30-2736596": "এম.এ. তারাদাস",
"D30-2736597": "সেভিয়ার চাল ঘোর",
"D30-2736598": "এম/স আক্তারুল স্টোর",
"D30-2736599": "মহিদুল ভ্যারাইটিস স্টোর",
"D30-2736600": "ধনেশর",
"D30-2736602": "বাবু স্টোর",
"D30-2736603": "বাবলুর রশিদ",
"D30-2736604": "কাজি স্টোর",
"D30-2736605": "সাব-স্টোর",
"D30-2736606": "জীবন স্টোর",
"D30-2736607": "মামুন কসমেটিক্স",
"D30-2736608": "সাবিন ট্রেডাস",
"D30-2736609": "সুমাইয়া স্টোর",
"D30-2736610": "জান্নাত স্টোর",
"D30-2736611": "নিউ ভাই ভাই স্টোর",
"D30-2736612": "রুপা এবং রিচি",
"D30-2736613": "নির্মল স্টোর",
"D30-2736614": "বিসমিল্লা কষ্মাতিস",
"D30-2736615": "এম/স আরিফ কষ্মাতিস",
"D30-2736616": "সাব্বির কনফেকশনারি",
"D30-2736617": "ফোর বি",
"D30-2736618": "রোটন স্টোর",
"D30-2736619": "মিতালী মেডিকেল স্টোর",
"D30-2736620": "রিফাত ভ্যারাইটিস স্টোর",
"D30-2736621": "আবেদ আলি স্টোর",
"D30-2736622": "এস আর ডিপারমেন্টাল স্টোর",
"D30-2736623": "শিমু ষ্টোর",
"D30-2736624": "আকরাম স্টোর",
"D30-2736625": "সোহানা",
"D30-2736626": "নিশাত স্টোর",
"D30-2736628": "দুই বোন স্টোর",
"D30-2736629": "রুকাইয়া স্টোর",
"D30-2736630": "টিউলিপ ফ্যাশন",
"D30-2736631": "মোজাহারুল",
"D30-2736632": "চিন্টু স্টোর",
"D30-2736633": "আনিসুর স্টোর",
"D30-2736634": "ফারুক ফোল ভ্যান্ডার",
"D30-2736635": "মা  বাবা ভেরাইটিস",
"D30-2736636": "হামিদুর স্টোর",
"D30-2736637": "সহাইল স্টোর",
"D30-2736638": "নাজমুল স্টোর",
"D30-2736639": "রহিম স্টোর",
"D30-2736640": "লুৎফর স্টোর",
"D30-2736641": "মুসলিমিমা স্টোর",
"D30-2736642": "বাবু স্টোর",
"D30-2736644": "মির্তিকা, খালেক স্টোর",
"D30-2736645": "সাদ্দাম স্টোর",
"D30-2736646": "মমতাজ স্টোর",
"D30-2736647": "রফিকুল স্টোর",
"D30-2736648": "সামিউল স্টোর",
"D30-2736649": "গনি পান স্টোর",
"D30-2736650": "জসিম স্টোর",
"D30-2736651": "এম, এ, কে, স্টোর",
"D30-2736652": "বাবু ভ্যারাইটি স্টোর",
"D30-2736654": "আবুল হোসেন স্টোর",
"D30-2736655": "রশিদ স্টোর",
"D30-2736656": "নতুন ইউসুফ বেকারি",
"D30-2736657": "মুহাম্মদ স্টোর",
"D30-2736658": "সোহেল স্টোর",
"D30-2736659": "বেলাল স্টোর",
"D30-2736660": "জারা স্টোর",
"D30-2736661": "জননী স্টোর",
"D30-2736662": "রাজু স্টোর",
"D30-2736663": "নাজমা স্টোর",
"D30-2736664": "আঁখি স্টোর",
"D30-2736665": "সিজান স্টোর",
"D30-2736666": "মোস্তফা স্টোর",
"D30-2736667": "জাহাঙ্গীর স্টোর",
"D30-2736668": "রশিদ স্টোর",
"D30-2736670": "সঞ্জিতা স্টোর",
"D30-2736671": "মিন্টু স্টোর",
"D30-2736672": "উত্তম স্টোর",
"D30-2736673": "নাঈম স্টোর",
"D30-2736674": "জয়, স্টোর",
"D30-2736675": "জলিল স্টোর",
"D30-2736676": "মিজান স্টোর",
"D30-2736677": "হুমায়ুন কবির স্টোর",
"D30-2736678": "মহুয় বিজনেস কর্নার",
"D30-2736679": "মা বাবা দাওয়া",
"D30-2736680": "মিলন স্টোর",
"D30-2736681": "এম/স আনিসুর কষ্মাতিস",
"D30-2736683": "ভাই ভাই স্টোর",
"D30-2736684": "টুক টুকি",
"D30-2736686": "মোহনা স্টোর",
"D30-2736687": "রুহুল কাপড়",
"D30-2736688": "মাসুদ স্টোর",
"D30-2736689": "তোজাম্মেল স্টোর",
"D30-2736690": "দিয়া স্টোর",
"D30-2736691": "গোল্ডেন ফার্মা",
"D30-2736692": "বাপ্পি স্টোর",
"D30-2736693": "বিকাশ স্টোর",
"D30-2736694": "লতিফ স্টোর",
"D30-2736695": "আল-আমিন স্টোর",
"D30-2736696": "ইমন স্টোর",
"D30-2736698": "এরশাদ স্টোর",
"D30-2736699": "ওনন্যা স্টোর",
"D30-2736700": "আরজিনা স্টোর",
"D30-2736701": "মতিউর স্টোর",
"D30-2736703": "নীল কুমার স্টোর",
"D30-2736704": "রুহুল স্টোর",
"D30-2736705": "জাকির স্টোর",
"D30-2736706": "ঈশিতা স্টোর",
"D30-2736707": "গোলাপ স্টোর",
"D30-2736708": "সুমন ভ্যারাইটি স্টোর",
"D30-2736709": "মোক্তার স্টোর",
"D30-2736710": "মিম ট্রেডাস",
"D30-2736711": "সাদিয়া স্টোর",
"D30-2736712": "সুবোল স্টোর",
"D30-2736713": "আশিক স্টোর",
"D30-2736714": "সেলিম স্টোর",
"D30-2736715": "বিসমিল্লা স্টোর",
"D30-2736716": "পাচ ভাই স্টোর",
"D30-2736717": "ডিব্বো স্টোর",
"D30-2736718": "মশিউর স্টোর",
"D30-2736719": "লুবিৎ ইলেকট্রিক",
"D30-2736720": "মঞ্জুরুল স্টোর",
"D30-2736722": "মতিবুর স্টোর",
"D30-2736723": "মিম স্টোর",
"D30-2736724": "আরাফাত ভ্যারাইটিস স্টোর",
"D30-2736725": "সোহেল স্টোর",
"D30-2736726": "জামশেদ ডিপার্টমেটাল",
"D30-2736727": "মুরাদ টেলিকম",
"D30-2736728": "হাসি এবং খুসি ট্রেডার্স",
"D30-2736729": "জননি কসমেটিক্স ০১",
"D30-2736730": "জীবন স্টোর",
"D30-2736732": "রনি স্টোর",
"D30-2736733": "আমদাদুল স্টোর",
"D30-2736734": "আনোয়ার কসমেটিক্স",
"D30-2736735": "পারভেজ কসমেটিক্স",
"D30-2736736": "মাসুদ স্টোর",
"D30-2736737": "পাটোয়ারী ডিপার্মেন্টাল স্টোর",
"D30-2736738": "বন্ধু কনফেকশনারি",
"D30-2736739": "লাল ভ্যারাইটিস স্টোর",
"D30-2736740": "সাত্তার স্টোর",
"D30-2736741": "রাসেল বিভাগীয় স্টোর",
"D30-2736742": "মিফতাহুল জান্নাত স্টোর",
"D30-2736743": "আরমান স্টোর",
"D30-2736744": "আজহার স্টোর",
"D30-2736745": "জয়নুল স্টোর",
"D30-2736746": "ভাই ভাই কম্পিউটার",
"D30-2736747": "হাফিজুর স্টোর",
"D30-2736748": "নুরালোম স্টোর",
"D30-2736749": "আসাদুল স্টোর",
"D30-2736750": "রহমান স্টোর",
"D30-2736751": "মোজাম্মেল স্টোর",
"D30-2736752": "রাকিব স্টোর",
"D30-2736753": "ফ্যামেলি ভ্যারাইটিস স্টোর",
"D30-2736755": "এআরএস ফার্মেসি",
"D30-2736756": "মমিনুল স্টোর",
"D30-2736757": "বাদল মেডিসিন",
"D30-2736758": "রায়হান স্টেশনারি",
"D30-2736759": "আরিফুল স্টোর",
"D30-2736762": "পৰিয়াল কসমেটিক বাড়ি",
"D30-2736763": "মা বাবার দোয়া",
"D30-2736765": "মিনারুল স্টোর",
"D30-2736766": "মায়ের দোয়া স্টোর",
"D30-2736767": "নওয়াব ট্রেডার্স",
"D30-2736768": "তিশা স্টোর",
"D30-2736769": "মাহাবুর স্টোর",
"D30-2736770": "পাওয়ার পয়েন্ট স্টোর",
"D30-2736771": "পলাশ স্টোর",
"D30-2736772": "কুদ্দেস স্টোর",
"D30-2736773": "শামসুদ্দিন স্টোর",
"D30-2736774": "মৌ মিম স্টোর",
"D30-2736775": "জাহিদ স্টোর",
"D30-2736776": "সাঈদ স্টোর",
"D30-2736778": "মাহবুব ফ্যামাসি",
"D30-2736779": "আলী ভেরাইটিস ষ্টোর",
"D30-2736780": "আবদুল্লাহ স্টোর",
"D30-2736782": "মরিওম স্টোর",
"D30-2736783": "সানা ডিপার্টমেন্ট স্টোর",
"D30-2736784": "নিউ মেডিসিন",
"D30-2736785": "তুবা ভ্যারাইটি স্টোর",
"D30-2736786": "মেডিসিন ওয়ার্ল্ড",
"D30-2736787": "রামিসা ফার্মেসি",
"D30-2736788": "জিল্লুর স্টোর",
"D30-2736789": "মশিউর স্টোর",
"D30-2736790": "সাইফুল টেলিকম",
"D30-2736791": "আরশাদুল স্টোর",
"D30-2736792": "আইনুল স্টোর",
"D30-2736793": "হাবিব স্টোর",
"D30-2736794": "শরীফ ফার্মেসী",
"D30-2736796": "মুক্তি ভেরিটি স্টোর",
"D30-2736797": "রকি মেডিসিন মার্ট",
"D30-2736798": "মোজিবর স্টোর",
"D30-2736799": "সানু ফার্মাসি",
"D30-2736800": "জনসেবা ফার্মেসি",
"D30-2736801": "এম/স মা বাবা ফার্মেসী",
"D30-2736802": "রাকিব পান স্টোর",
"D30-2736803": "জুয়েল স্টোর",
"D30-2736804": "বলাই স্টোর",
"D30-2736805": "হেলথ কর্নার ফার্মেসী",
"D30-2736806": "ওশেস ট্রেডার্স",
"D30-2736807": "রিয়াদ ট্রেডাস",
"D30-2736808": "পুডো বেকারি",
"D30-2736809": "এম/স রাইসা ট্রেডার্স",
"D30-2736810": "মুন্না স্টোর",
"D30-2736811": "মমতাজ স্টোর",
"D30-2736812": "মিলন স্টোর",
"D30-2736813": "শরিফুল স্টোর",
"D30-2736814": "জয় স্টোর",
"D30-2736816": "ভাই ভাই স্টোর",
"D30-2736818": "রাজু স্টোর ১",
"D30-2736819": "সোনালী ঔষধ কর্নার",
"D30-2736820": "মা মেডিসিন হাউস",
"D30-2736821": "সওদাগর ফার্মা",
"D30-2736822": "নাইমে",
"D30-2736824": "রনি স্টোর",
"D30-2736825": "আফজাল সুপার শপ",
"D30-2736826": "তৈমুর স্টোর",
"D30-2736827": "সোলালী ফার্মেসী",
"D30-2736828": "তোহিদ স্টোর",
"D30-2736829": "আজাদ ফার্মেসি",
"D30-2736830": "হাবিব স্টোর",
"D30-2736831": "দুর্জয় স্টোর",
"D30-2736832": "অমল স্টোর",
"D30-2736834": "ফজলে রাব্বি স্টোর",
"D30-2736835": "আবু তাহের স্টোর",
"D30-2736837": "শারমিন স্টোর",
"D30-2736838": "রুবেল পান স্টোর",
"D30-2736839": "তরুন স্টোর",
"D30-2736840": "নাজমুল স্টোর",
"D30-2736841": "তাজুল স্টোর",
"D30-2736842": "অনিক স্টোর",
"D30-2736843": "সুভো ইন্ডাস্ট্রিস স্টোর",
"D30-2736844": "বেলাল স্টোর",
"D30-2736846": "আতাউর স্টোর",
"D30-2736847": "বালাল পান",
"D30-2736848": "ফাহিমা স্টোর",
"D30-2736849": "খুশি স্টোর",
"D30-2736850": "ঝন্টু স্তরও",
"D30-2736851": "সবুজার স্টোর",
"D30-2736852": "ভাই ভাই স্টোর",
"D30-2736853": "কান্তিবাচ ফুড",
"D30-2736854": "মা ফার্মেসী",
"D30-2736855": "জনি ফটোস্ট্যাট এবং মিষ্টান্ন",
"D30-2736856": "আমিনুল স্টোর",
"D30-2736857": "বিসমিল্লাহ ভ্যারাইটিস স্টোর",
"D30-2736858": "শরিফুল স্টোর",
"D30-2736859": "রেনাউলট স্টোর",
"D30-2736860": "বকুল ষ্টোর",
"D30-2736861": "বাবু স্টোর",
"D30-2736862": "এম/স মা বাবা মেডিসিন কর্নার",
"D30-2736863": "জনি স্টোর",
"D30-2736864": "মা ভ্যারাইটি স্টোর",
"D30-2736865": "তাজমুল স্টোর",
"D30-2736866": "সাকিব মেডিকেল",
"D30-2736867": "আয়ান ফার্মেসী",
"D30-2736869": "কাসেম স্টোর",
"D30-2736870": "জীবন ষ্টোর",
"D30-2736871": "রুমার স্টোর",
"D30-2736872": "আরিফ স্টোর",
"D30-2736873": "মা ফার্মেসি",
"D30-2736874": "ফাহিম স্টোর",
"D30-2736875": "বাসুদেব ভান্ডার",
"D30-2736878": "সেভ লাইফ পারমেসি",
"D30-2736879": "লামিন ফার্মেসি",
"D30-2736881": "রাহাত ভ্যারাইটিজ স্টোর",
"D30-2736882": "রাবেয়া ফার্মেসি",
"D30-2736883": "আফরোজা ফার্মেসী",
"D30-2736884": "সানজিদ স্টোর",
"D30-2736886": "এ যে এম স্টোর",
"D30-2736887": "জোহির স্টোর",
"D30-2736888": "রাকিব ভ্যারাইটি স্টোর",
"D30-2736889": "শরিফুল স্টোর",
"D30-2736890": "সহিদুল স্টোর",
"D30-2736891": "উজ্জ্বল স্টোর",
"D30-2736892": "নয়ন স্টোর",
"D30-2736893": "সাইমন স্টোর",
"D30-2736894": "সিয়াম স্টোর",
"D30-2736895": "আরবি স্টোর",
"D30-2736896": "শফি স্টোর",
"D30-2736897": "মাহিন ট্রেডার্স",
"D30-2736898": "রিয়া স্টোর",
"D30-2736899": "আশিকুর স্টোর",
"D30-2736900": "আয়সা এন্টারপ্রাইজ",
"D30-2736901": "সুমন",
"D30-2736902": "তাহমিদ স্টোর",
"D30-2736903": "মিল্টন ফুড গড়",
"D30-2736904": "ইসরাত মেডিকেল স্টোর",
"D30-2736905": "দেয়ার স্টোর",
"D30-2736907": "মাহমিদুল স্টোর",
"D30-2736908": "দিগন্ত ফার্মাসি",
"D30-2736909": "বিসমিল্লাহ ফার্মাসি",
"D30-2736910": "ভাই ভাই স্টোর",
"D30-2736911": "সফল স্টোর",
"D30-2736916": "শেফালি স্টোর",
"D30-2736917": "হারুন স্টোর",
"D30-2736919": "আব্দুল্লাহ ফার্মাসি",
"D30-2736920": "রুস্তম পান স্টোর",
"D30-2736921": "নূর মেডিকেল স্টোর",
"D30-2736922": "কবির স্টোর",
"D30-2736923": "খুরশিদা ফার্মা",
"D30-2736924": "শাহীন স্টোর",
"D30-2736927": "ইভান স্টোর",
"D30-2736928": "ইমন ফার্মেসি",
"D30-2736930": "মা কসমেটিক্স ২",
"D30-2736931": "সাজু ফার্মেসী",
"D30-2736934": "মাসুদ স্টোর",
"D30-2736935": "মোজাহার স্টোর",
"D30-2736936": "আলমগীর স্টোর",
"D30-2736937": "অনন্যা স্টোর",
"D30-2736938": "মুরনা স্টোর",
"D30-2736939": "রবিউল স্টোর",
"D30-2736940": "মিজানুর স্টোর",
"D30-2736941": "আহাদ স্টোর",
"D30-2736942": "নজিবুদ্দিন স্টোর",
"D30-2736943": "সাইদুর স্টোর",
"D30-2736944": "তহিদা ফার্মেসি",
"D30-2736946": "ভাই ভাই স্টোর",
"D30-2736947": "রোজা ফার্মেসি",
"D30-2736948": "দাদা নাতি স্টোর",
"D30-2736949": "জুলমত স্টোর",
"D30-2736950": "নাইম স্টোর",
"D30-2736951": "মাস সারথি ফার্মাসি",
"D30-2736952": "রানু স্টোর",
"D30-2736953": "স্টার স্টোর",
"D30-2736954": "সাগর টেলিকম",
"D30-2736955": "আক্কাস স্টোর",
"D30-2736956": "চৌধুরী স্টোর",
"D30-2736957": "আক্তার পান স্টোর",
"D30-2736958": "সৈয়দ স্টোর",
"D30-2736959": "আকরামুল স্টোর",
"D30-2736960": "দুই ভাই স্টোর-২",
"D30-2736962": "মেসার্স মোদিনা ফার্মেসি",
"D30-2736963": "আপন ভেরাসিটি স্টোর",
"D30-2736964": "রব্বানি স্টোর",
"D30-2736965": "ইউসুফ বেকারি",
"D30-2736967": "নূর হার্ডওয়্যার ভ্যারাইটি স্টোর",
"D30-2736968": "ফারুক স্টোর",
"D30-2736969": "ও্মর স্টোর",
"D30-2736970": "শফিউর স্টোর",
"D30-2736971": "সাইদুর স্টোর",
"D30-2736973": "আলাউদ্দিন ট্রেডার্স",
"D30-2736974": "ফিরোজ স্টোর",
"D30-2736975": "আইনুল হক স্টোর",
"D30-2736976": "বিশ্বনাথ পান স্টোর",
"D30-2736977": "দুলাল ষ্টোর",
"D30-2736978": "ভাই ভাই ষ্টোর",
"D30-2736980": "বন্ধু টেলিকম এবং ভ্যারাইটি স্টোর",
"D30-2736986": "জলিল স্টোর",
"D30-2736987": "আনোয়ার স্টোর",
"D30-2736988": "মতিউর স্টোর",
"D30-2736989": "ইমরান স্টোর",
"D30-2736990": "আনোয়ার স্টোর",
"D30-2736991": "আজিজ স্টোর",
"D30-2736992": "বরকত উল্লাহ স্টোর",
"D30-2736994": "এ-১৯ ভেরাইটিস স্টোর",
"D30-2736995": "সুলতান স্টোর",
"D30-2736996": "মুক্তি/মুসকান",
"D30-2736997": "আতিয়া ফার্মেসি",
"D30-2736998": "আনকন স্টোর",
"D30-2736999": "ফারিয়া স্টোর",
"D30-2744694": "রায় ট্রেডার্স",
"D30-2744695": "মিলন স্টোর",
"D30-2744696": "ভাই বোন স্টোর",
"D30-2744697": "সবুজ স্টোর",
"D30-2744698": "মিজানুর স্টোর",
"D30-2744699": "সোহেল স্টোর",
"D30-2744700": "মাহিন স্টোর",
"D30-2744701": "জিহাদ স্টোর",
"D30-2744702": "আতিক কনফেকশনারি",
"D30-2744703": "মাহফুজ স্টোর",
"D30-2744704": "সবুজ স্টোর",
"D30-2744705": "গৌরভ স্টোর",
"D30-2744706": "বাহার স্টোর",
"D30-2744707": "রাজ্জাক স্টোর",
"D30-2744708": "আরিফুল স্টোর",
"D30-2744709": "নূরজামাল স্টোর",
"D30-2744710": "অন্তরা স্টোর",
"D30-2744711": "টসলিম স্টোর",
"D30-2744712": "আলতাব স্টোর",
"D30-2744713": "আলিয়ান কসমেটিক্স",
"D30-2744714": "রনি স্টোর",
"D30-2744715": "আবির স্টোর",
"D30-2744716": "ইমাম স্টোর",
"D30-2744717": "থ্রি স্টার স্টোর",
"D30-2744718": "মুসাফি মেডিসিন স্টোর",
"D30-2744719": "জামিল কনফেকশনারি",
"D30-2744720": "আনিসা বেকারি",
"D30-2744721": "মুগধো স্টোর",
"D30-2744722": "মায়ের দুয়া স্টোর",
"D30-2744723": "জিহান স্মার্ট মুধি ঘর",
"D30-2744724": "হায়দার স্টোর",
"D30-2744725": "মিম ফার্মেসি",
"D30-2744726": "বিশ্বজিৎ ভ্যারাইটিস স্টোর",
"D30-2744727": "দুই ভাই স্টোর",
"D30-2744728": "হেলাল চাওল ঘর",
"D30-2744729": "সাদেকুল ইসলাম",
"D30-2744730": "আজাদ স্টোর",
"D30-2744731": "ভাই ভাই কনফেকশনারি",
"D30-2744732": "হাবু মিষ্টান্ন",
"D30-2744733": "ইরফান স্টোর",
"D30-2744734": "দাদা নাতি স্টোর",
"D30-2744735": "উমোর স্টোর",
"D30-2744736": "দুই বন স্টোর",
"D30-2744737": "পুবালি কনফেকশনারী",
"D30-2744738": "দুই বন ভ্যারাইটিস স্টোর",
"D30-2744739": "ভাই বন স্টোর",
"D30-2744740": "মা বাবার দোয়া ভ্যারাইটিস স্টোর",
"D30-2744741": "জামাই শশুর স্টোর",
"D30-2744742": "সিফাত স্টোর",
"D30-2744743": "সাহিন স্টোর",
"D30-2744744": "সবকিছুর স্টোর",
"D30-2744745": "বকুল স্টোর",
"D30-2744746": "বাবুল স্টোর",
"D30-2744747": "জননি স্টোর",
"D30-2744748": "আলমগীর স্টোর",
"D30-2744749": "ওহিদুর স্টোর",
"D30-2744750": "ইমরান স্টোর",
"D30-2744751": "খাইরুল স্টোর",
"D30-2744752": "ইরফান স্টোর",
"D30-2744753": "আজিজুল স্টোর",
"D30-2744754": "মেঘ রূপ ভ্যারাইটিস স্টোর",
"D30-2744755": "নাহার স্টোর",
"D30-2744756": "শেলি স্টোর",
"D30-2744757": "আলিয়া কনফেকশনারি এবং খাবারের স্টোর",
"D30-2744758": "আলহামদুলিল্লাহ স্টোর",
"D30-2744759": "মিনারুল স্টোর",
"D30-2744762": "মা ট্রেডার্স",
"D30-2744763": "পৰিয়াল এন্টারপ্রাইজ",
"D30-2744764": "রুবেল স্টোর",
"D30-2744765": "ভাই ভাই স্টোর ২",
"D30-2744767": "বাবু স্টোর",
"D30-2744768": "মালিহা ভ্যারাইটি স্টোর",
"D30-2744769": "মেহেদী স্টোর",
"D30-2744770": "ফরিদুল স্টোর",
"D30-2744771": "ফয়জুল স্টোর",
"D30-2744772": "ইব্রাহিম স্টোর",
"D30-2744773": "ইতি স্টোর",
"D30-2744774": "মিহাদ স্টোর",
"D30-2744775": "মফিজুল স্টোর",
"D30-2744776": "আশরাফি স্টোর",
"D30-2744777": "নূর আলামিন স্টোর",
"D30-2744779": "উজ্জাল স্টোর",
"D30-2744780": "দুই বোন স্টোর-০২",
"D30-2744781": "শাহানুর স্টোর",
"D30-2744782": "মুসলিম স্টোর",
"D30-2744783": "আরিফুল স্টোর",
"D30-2744784": "কামাল ষ্টোর",
"D30-2744785": "তানভীর রাইসা স্টোর",
"D30-2744786": "খাদেমুল স্টোর",
"D30-2744787": "রাশিদুল স্টোর",
"D30-2744788": "মিজান স্টোর",
"D30-2744789": "জুয়েল রানা স্টোর",
"D30-2744790": "মুন্না স্টোর",
"D30-2744791": "রোহিম স্টোর",
"D30-2744792": "শোরিফুল ভ্রাটিস স্টোর",
"D30-2744793": "শাহাজান স্টোর",
"D30-2744794": "রিফাত স্টোর",
"D30-2744795": "সায়েম স্টোর",
"D30-2744796": "রাহুল পান স্টোর",
"D30-2744797": "তসলিম স্টোর",
"D30-2744798": "এস.এস. কুন্ডু স্টোর",
"D30-2744799": "আর.টি. কসমেটিক্স",
"D30-2744801": "বাবুল স্টোর",
"D30-2744802": "সালাম স্টোর",
"D30-2744805": "এন স্টোর",
"D30-2744807": "রিপন কসমেটিক্স",
"D30-2744808": "ইমান স্টোর",
"D30-2744809": "জাহাঙ্গীর স্টোর",
"D30-2744810": "রাব্বি স্টোর",
"D30-2744811": "ওবায়দুর ষ্টোর",
"D30-2744812": "মোশলেম স্টোর",
"D30-2744813": "সফিকুল স্টোর",
"D30-2744815": "ইমরান স্টোর",
"D30-2744816": "মদ.আলফারাব্বি সোহাগ",
"D30-2744817": "চন্দন স্টোর",
"D30-2744818": "মেসাস পপুলার ট্রেডার্স",
"D30-2744819": "জোননি.৩ কসমেটিক্স",
"D30-2744820": "আবিদ কসমেটিক্স",
"D30-2744821": "শাগর স্টোর",
"D30-2744822": "মামুন স্টোর",
"D30-2744823": "শাকিল স্টোর",
"D30-2744824": "সাকিব স্টোর",
"D30-2744825": "মা স্টোর",
"D30-2744826": "মেসাস দুলি স্টোর",
"D30-2744827": "দেলোয়ার স্টোর",
"D30-2744828": "আরাম স্টোর",
"D30-2744829": "দুই ভাই স্টোর",
"D30-2744830": "সাদ্দাম স্টোর",
"D30-2744831": "এম জে স্টোর",
"D30-2744832": "মা ফার্মেসি",
"D30-2744833": "বিসমিল্লাহ স্টোর অ্যান্ড মোহাম্মদ টেলিকম",
"D30-2744835": "সুনীল স্টোর",
"D30-2744836": "হ্যাবিট স্টোর",
"D30-2744837": "সাকিল স্টোর",
"D30-2744838": "নানেক নাটি স্টোর",
"D30-2744839": "সুলতানপুর ফার্মেসি মিনি সুপার শপ",
"D30-2744840": "সাগর পান স্টোর",
"D30-2744841": "হাফশা সংগ্রহ",
"D30-2744842": "আমদাদুল স্টোর",
"D30-2744843": "ভাই ভাই স্টোর",
"D30-2744844": "আল-আমিন",
"D30-2744845": "মহসিন স্টোর",
"D30-2744846": "সিদ্দিক স্টোর",
"D30-2744847": "ভাই বোন স্টোর",
"D30-2744848": "মা চাউল ঘর স্টোর",
"D30-2744849": "মা বাবা স্টোর অ্যান্ড টেলিকম",
"D30-2744850": "আলামিন স্টোর",
"D30-2744851": "মা কসমেটিক্স অ্যান্ড ভ্যারাইটিস স্টোর",
"D30-2744852": "দুই ভাই কসমেটিক্স",
"D30-2744853": "আব্দুর রহমান স্টোর",
"D30-2744854": "হৃদয় ও রিয়াদের বৈচিত্র্য",
"D30-2744855": "সাজ্জাত স্টোর",
"D30-2744856": "সাগর স্টোর",
"D30-2744857": "তিন ভাই স্টোর",
"D30-2744858": "বিন্তি স্টোর",
"D30-2744859": "জিহাদ স্টোর",
"D30-2744860": "রোনো রিক",
"D30-2744861": "সামিউল ভ্যারাইটি স্টোর",
"D30-2744862": "শ্শ তাড়াশ",
"D30-2744863": "ফ্রেন্ডস স্টোসোনারে",
"D30-2744864": "নুর ভ্যারাইটিস স্টোর",
"D30-2744865": "রনি স্টোর",
"D30-2744866": "আসরাফুল স্টোর",
"D30-2744867": "ভাই ভাই স্টোর",
"D30-2744868": "লিটন স্টোর",
"D30-2744869": "স্টুডেন্ট স্টোর",
"D30-2744870": "শুভ সেন্ট ২",
"D30-2744871": "ম্যাসেস ইরাম ট্রেডার্স",
"D30-2744872": "ব্রাদার্স স্টোর",
"D30-2744874": "মেসার্স সোজল স্টোর",
"D30-2744875": "রাতুল ভ্যারিয়াটিস স্টোর",
"D30-2744876": "মুনতাহা স্টোর",
"D30-2744877": "আনামুল স্টোর",
"D30-2744878": "বাবু স্টোর",
"D30-2744879": "নাসির স্টোর",
"D30-2744880": "রুবেল স্টোর",
"D30-2744881": "কাদের স্টোর",
"D30-2744883": "স্দান স্টোর",
"D30-2744884": "মোহাম্মদ স্টেশনারি",
"D30-2744885": "মোস্তাকিন স্টোর",
"D30-2744886": "লাবিব স্টোর",
"D30-2744887": "আরিফ স্টোর",
"D30-2744888": "শুভ স্টোর",
"D30-2744889": "আল আমিন স্টোর",
"D30-2744890": "ভাই জান কসমেটিক্স",
"D30-2744891": "বাসকুরুনী স্টোর",
"D30-2744892": "আমির স্টোর",
"D30-2744893": "মুরাদ স্টোর",
"D30-2744895": "স্মরণজিৎ স্টোর",
"D30-2744896": "চৌধুরী ভ্যারাইটিস স্টোর",
"D30-2744897": "নানা নাতি স্টোর",
"D30-2744898": "মা বাবার দোয়া ভ্যারাইটিস স্টোর",
"D30-2744899": "আয়াত জাতের স্টোর",
"D30-2744900": "রিজওয়ান স্টোর",
"D30-2744901": "আয়াত স্টোর",
"D30-2744902": "লিয়াকত স্টোর",
"D30-2744903": "ভাই ভাই কনফেকশনারি",
"D30-2744904": "আল্লাহ দান স্টোর",
"D30-2744905": "আলহামদুলিল্লাহ স্টোর",
"D30-2744906": "মারিয়াম কনফেকশনারি",
"D30-2744907": "পারভিন স্টোর",
"D30-2744908": "মালেহা স্টোর",
"D30-2744909": "হোসেন ব্রাদার্স",
"D30-2744910": "মেসার্স বিসমিল্লাহ কসমেটিক্স",
"D30-2744911": "সাদেক স্টোর",
"D30-2744912": "মেডিকেল স্টোর",
"D30-2744913": "ফরিদুল স্টোর",
"D30-2744914": "আতিকা ষ্টোর",
"D30-2744915": "ডিভাইস ওয়ার্ল্ড",
"D30-2744916": "রিপন স্টোর",
"D30-2744917": "সোহাগ স্টোর",
"D30-2744918": "এম/স ফাহিম ফারিয়া স্টোর",
"D30-2744919": "এম. এ. সামোগ্রি স্টোর",
"D30-2744920": "নিশান স্টোর",
"D30-2744921": "বাবু পানশপ",
"D30-2744923": "শাহিন স্টোর",
"D30-2744924": "নিপুন স্টোর",
"D30-2744925": "রোমজান স্টোর",
"D30-2744926": "মামা ভাগিনা স্টোর",
"D30-2744927": "জোহার ষ্টোর",
"D30-2744928": "স্নিকধা স্টোর",
"D30-2744929": "সুজান ভারিটিজ স্টোর",
"D30-2744930": "বিপ্লব মিষ্টান্ন",
"D30-2744931": "হুমায়রা",
"D30-2744932": "মেসার্স আজাদ ট্রেডার্স",
"D30-2744933": "ফাহিম স্টেশনারি",
"D30-2744934": "এম/স মাহাদী বাড়িটি স্টোর",
"D30-2744935": "আরিফ স্টোর",
"D30-2744936": "লুকম্যান স্টোর",
"D30-2744937": "রিপন স্টোর",
"D30-2744938": "মোদিনা ভ্যারাইটি স্টোর",
"D30-2744939": "জোনোনি কসমেটিক্স ৩",
"D30-2744941": "পোর্টফোলিও স্টোর",
"D30-2744942": "নবো রঞ্জন স্টোর",
"D30-2744944": "মোঃ মোস্তফা",
"D30-2744947": "বিল্লাহ স্টোর",
"D30-2744949": "মইনুল স্টোর",
"D30-2744950": "এম/স রাহাত স্টোর",
"D30-2744951": "আব্দুল্লাহ ট্রেডার্স",
"D30-2744953": "আফিয়া স্টোর",
"D30-2744954": "ধিপেন স্টোর",
"D30-2744955": "ভাই বোন স্টোর",
"D30-2744956": "তোরিকুল স্টোর",
"D30-2744958": "রিমন স্টোর",
"D30-2744959": "রিফাত স্টোর",
"D30-2744960": "বিজয় বাকালে",
"D30-2744961": "আবিদ ডিপার্টমেন্টাল ষ্টোর",
"D30-2744963": "মুমু জেনারেল স্টোর",
"D30-2744964": "রুহিদাস দশ ভান্ডার",
"D30-2744965": "আমিনুল স্টোর",
"D30-2744966": "মাহানেস স্টোর",
"D30-2744967": "সাদ্দাম স্টোর-০২",
"D30-2744968": "আরাফাত স্টোর",
"D30-2744969": "মাইশা স্টোর",
"D30-2744970": "ভাই বোন স্টোর",
"D30-2744971": "ভাই ভাই স্টোর",
"D30-2744972": "মহবুর স্টোর",
"D30-2744973": "রাসেল মিষ্টান্ন",
"D30-2744974": "সুলতান স্টোর",
"D30-2744975": "আলিফ স্টোর",
"D30-2744976": "মিলন স্টোর",
"D30-2744977": "এ এন্ড জে স্টেশনারি",
"D30-2744978": "মিমি স্টোর",
"D30-2744979": "মের্সাস মোস্তফা ষ্টোর",
"D30-2744980": "সঞ্জয় ভারিটিজ এবং কফি শপ",
"D30-2744981": "রফিকুল স্টোর - ০২",
"D30-2744982": "মা বাবর দোয়া স্টোর",
"D30-2744983": "আদিত্য ভ্যারাইটিস",
"D30-2744984": "লোকমান স্টোর",
"D30-2744986": "সেলিম স্টোর",
"D30-2744988": "মেঘলা স্টোর",
"D30-2744989": "এম/স সততা স্টোর",
"D30-2744990": "বাসর স্টোর",
"D30-2744991": "সুস্ময় স্টোর",
"D30-2744992": "এম/স জারিন স্টোর",
"D30-2744993": "লক্ষ্মী স্টোর",
"D30-2744994": "মা বাবার স্টোর",
"D30-2744995": "ইত্যাদি ভেরাইটিজ স্টোর",
"D30-2744996": "মাসুদ স্টোর",
"D30-2744998": "আফজাল সুপার শপ",
"D30-2744999": "নিরব স্টোর",
"D30-2745000": "মেসার্স শাকিল কসমেটিক্স",
"D30-2745001": "আরিফ স্টোর",
"D30-2745002": "ভাই ভাই স্টোর",
"D30-2745003": "মেসার্স মা ভ্যা্রাইটি স্টোর",
"D30-2745004": "বাসুদেব স্টোর",
"D30-2745005": "আরিফ স্টোর",
"D30-2745006": "সাদিয়া কম্পিউটার এবং ভ্যারাইটিস",
"D30-2745007": "উত্তরা ফুডস",
"D30-2745008": "মসলেম স্টোর",
"D30-2745009": "মুন্না স্টোর",
"D30-2745010": "পারভেজ স্টোর",
"D30-2745011": "নাজমুল স্টোর",
"D30-2745012": "ভাই বোন ষ্টোর",
"D30-2745013": "শেওলি স্টোর",
"D30-2745014": "নজরুল স্টোর",
"D30-2745015": "নূর ভার্সিটি স্টোর",
"D30-2745016": "বাবুল স্টোর",
"D30-2745017": "হাসিনুর স্টোর",
"D30-2745018": "উৎপল স্টোর",
"D30-2745019": "আলিৰ স্টোর",
"D30-2745020": "শোপন স্টোর",
"D30-2745021": "আয়াত স্টোর",
"D30-2745022": "শামীম স্টোর",
"D30-2745023": "অনুসরণ",
"D30-2745025": "সালেন স্টোর",
"D30-2745026": "সৌরভ স্টোর",
"D30-2745027": "মাহির স্টোর",
"D30-2745029": "অনুসরণ",
"D30-2745030": "দেলোয়ার স্টেশনারী",
"D30-2745031": "ফটো বাজার স্টুডিও",
"D30-2745032": "মোহেনা ট্রেডার্স",
"D30-2745033": "সন্তোষ ইলেক্ট্রনিক্স",
"D30-2745034": "তোবারক স্টোর",
"D30-2745035": "ফারুক স্টোর",
"D30-2745037": "খরসেদ স্টোর",
"D30-2745038": "মামুন স্টোর",
"D30-2745039": "প্রিয়জিত স্টোর",
"D30-2745040": "ইয়াসিন স্টোর",
"D30-2745042": "মিম স্টোর",
"D30-2745043": "শহিদুল স্টোর",
"D30-2745044": "মায়ের আশীর্বাদ স্টোর",
"D30-2745045": "মোমোটাস স্টোর",
"D30-2745046": "টাচ এন্ড টেক",
"D30-2745047": "মাহিন স্টোর",
"D30-2745048": "আশিকুর স্টোর",
"D30-2745050": "মমিনুল স্টোর",
"D30-2745051": "হক টেলিকম",
"D30-2745052": "বাব্বি স্টোর",
"D30-2745053": "এম/স সুবর্ণা স্টোর",
"D30-2745054": "আলীম স্টোর",
"D30-2745055": "কেয়া ফার্মেসি",
"D30-2745056": "পূষ্পিতা কসমেটিক",
"D30-2745057": "সানি কসমেটিক্স",
"D30-2745058": "সাজু ট্রেডার্স",
"D30-2745059": "তিন ভাই লন্ড্রি এবং ভ্যারাইটিস স্টোর",
"D30-2745060": "রাকিব স্টোর",
"D30-2745061": "এম/স নোৱালম স্টোর",
"D30-2745062": "এম/স জারিন এন্টারপ্রাইস",
"D30-2745063": "মেসার্স ফাহিম ভ্যারাইটিস স্টোর",
"D30-2745064": "আলিফ স্টোর",
"D30-2745065": "দীপক স্টোর",
"D30-2745066": "সামিয়া লামিয়া স্টোর",
"D30-2745067": "ইউসুফ ভাড়াইতেস স্টোর",
"D30-2745068": "কালু স্টোর",
"D30-2745069": "আফসার পান স্টোর",
"D30-2745070": "আরিয়ান স্টোর",
"D30-2745071": "মা জেনারেল স্টোর",
"D30-2745072": "আনসার ক্যান্টিন",
"D30-2745073": "বিসমিল্লাহ কসমেটিকস",
"D30-2749": "রফিক স্টোর",
"D30-2760": "ডবøু ষ্টোর",
"D30-2771": "মান্নান স্টোর ২",
"D30-2803": "ব্রিস্টি স্টোর",
"D30-2810449": "মোঃ রিপন হক চৌধুরী",
"D30-2833": "ভাই ভাই স্টোর ১",
"D30-2848": "মেসার্স জামান ট্রেডার্স",
"D30-2849": "পূর্ণিমা ডি স্টোর",
"D30-2854": "চন্দন স্টোর",
"D30-2856": "মেসার্স জামান ব্রাদার্স",
"D30-2857": "জুয়েল স্টোর",
"D30-2859": "শোপন স্টোর ২",
"D30-2860": "গৌতম স্টোর",
"D30-2860808": "বিসমিল্লাহ স্টোর",
"D30-2860809": "আলম স্টোর",
"D30-2860810": "সায়েম ফার্নিচার",
"D30-2860811": "মাফ ভ্যারাইটিস ও কসমেটিক্স",
"D30-2860812": "রিজোয়ান স্টোর",
"D30-2860813": "মা কসম্যাটিক",
"D30-2860814": "নুপুর স্টোর",
"D30-2860815": "মিলন স্টোর",
"D30-2860816": "হাসিবুল স্টোর",
"D30-2860817": "লিমা স্টোর",
"D30-2860818": "লিজন স্টোর",
"D30-2860819": "তারেক স্টোর",
"D30-2860820": "মামুন স্টুডিও & কসমেটিক্স",
"D30-2860821": "সজিব স্টোর",
"D30-2860822": "আমজাদ স্টোর",
"D30-2860823": "ভাই ভাই স্টোর",
"D30-2860824": "দুই বোন স্টোর",
"D30-2860825": "রেজা স্টোর",
"D30-2860826": "ফারুকের স্টোর",
"D30-2860827": "আতিকা স্টোর",
"D30-2860828": "পারভেজ স্টোর",
"D30-2860829": "মেসার্স মা ট্রেডার্স",
"D30-2860830": "দুই ভাই স্টোর",
"D30-2860831": "জিসান এন্টারপ্রাইজ",
"D30-2860832": "আলি স্টোর",
"D30-2860833": "মা স্টোর",
"D30-2860834": "আজম স্টোর",
"D30-2860835": "এম.এ ব্রাদার",
"D30-2860836": "আল বারাক",
"D30-2860837": "জুয়েল স্টোর",
"D30-2860838": "হিমেল স্টোর",
"D30-2860839": "মোস্তফা স্টোর",
"D30-2860840": "আপন টেলিকম",
"D30-2860841": "তরঙ্গ",
"D30-2860842": "আবদুল্লাহ স্টোর",
"D30-2860843": "শ্যামল স্টোর",
"D30-2860844": "ইয়াকুব স্টোর",
"D30-2860845": "লিটন স্টোর",
"D30-2860846": "অ্মিত স্টোর",
"D30-2860847": "বিহান কনফেকসোনারি",
"D30-2860848": "মিলন চা স্টোর",
"D30-2860849": "মানিক স্টোর",
"D30-2860850": "মালিহা স্টোর",
"D30-2860851": "আয়াত স্টোর",
"D30-2860852": "রাকিব স্টোর",
"D30-2860853": "শাপলা স্টোর",
"D30-2860854": "তামিম স্টোর",
"D30-2860855": "সাহিন স্টোর",
"D30-2860856": "রাফি স্টোর",
"D30-2860857": "জুই স্টোর",
"D30-2860858": "মা বাবা দোয়া-২",
"D30-2860859": "মা বাবা দোয়া এবং কনফেকশনারি",
"D30-2860860": "আবু জার স্টোর",
"D30-2860861": "দেলোয়ার চাওল ঘর",
"D30-2860862": "জিহান কসমেটিক্স",
"D30-2860863": "ভাই ভাই স্টোর",
"D30-2860864": "মাইশা স্টোর",
"D30-2860865": "নুর ভ্যারাইটি স্টোর",
"D30-2860866": "জান্নাত কসমেটিক্স",
"D30-2860867": "জেরিন কসমেটিক্স",
"D30-2860868": "মুসকান কসমেটিক্স",
"D30-2860869": "মফিজুর দোকান",
"D30-2860870": "ফরিদুল স্টোর",
"D30-2860871": "ইমরান স্টোর",
"D30-2860872": "সজীব স্টোর",
"D30-2860873": "মোবারক স্টোর",
"D30-2860874": "আশি স্টোর",
"D30-2860875": "রেজাউল স্টোর",
"D30-2860876": "নিষাদ স্টোর",
"D30-2860877": "রোহিদুল স্টোর",
"D30-2860878": "তিন কন্না স্টোর",
"D30-2860879": "জশিম স্টোর",
"D30-2860880": "ভাই ভাই স্টোর",
"D30-2860881": "আপেল স্টোর",
"D30-2860882": "আল আমিন স্টোর",
"D30-2860883": "হামিদুর দোকান",
"D30-2860884": "রুমানা স্টোর",
"D30-2860885": "ভাই ভাই স্টোর",
"D30-2860886": "মৃত্যুঞ্জির দোকান",
"D30-2860887": "ইব্রাহিম স্টোর",
"D30-2860888": "মুসলিম স্টোর",
"D30-2860889": "জাহিদ স্টোর",
"D30-2860890": "মা বাবা দোয়া ষ্টোর",
"D30-2860891": "বিনোদ স্টোর",
"D30-2860892": "ভাই বোন স্টোর",
"D30-2860893": "আলাল স্টোর",
"D30-2860894": "শামিম স্টোর",
"D30-2860895": "মমতাজ কনফেশনারি",
"D30-2860896": "হারুন স্টোর",
"D30-2860897": "প্রান্ত স্টোর",
"D30-2860898": "বিসমিল্লাহ স্টোর",
"D30-2860899": "কাজল স্টোর",
"D30-2860900": "খাইরুল স্টোর",
"D30-2860901": "অশোক স্টোর",
"D30-2860902": "লাল ষ্টোর",
"D30-2860903": "মা স্টোর",
"D30-2860904": "সলিম স্টোর",
"D30-2860905": "আদনান স্টোর",
"D30-2860906": "বিয়ের বাজার",
"D30-2860907": "দুলাল স্টোর-২",
"D30-2860908": "আমতাজুল স্টোর",
"D30-2860909": "নজরুল স্টোর",
"D30-2860910": "জাহিদ স্টোর",
"D30-2860911": "বিসমিল্লাহ স্টোর",
"D30-2860912": "মুসলিম স্টোর",
"D30-2860913": "নূর ভ্যারাইটি স্টোর",
"D30-2860914": "মিম স্টোর",
"D30-2860915": "মনির স্টোর",
"D30-2860916": "ফরহাদ স্টোর",
"D30-2860917": "মা স্টোর",
"D30-2860918": "মিজান স্টোর",
"D30-2860919": "লিটন স্টোর",
"D30-2860920": "ইমন স্টোর",
"D30-2860921": "সরকার স্টোর",
"D30-2860922": "পূর্ণ স্টোর",
"D30-2860923": "মা কসমেটিক্স",
"D30-2860924": "মা কসম্যাটিকস",
"D30-2860925": "খিতিস স্টোর",
"D30-2860926": "রনি মেডিকেল স্টোর",
"D30-2860927": "মানিক স্টোর",
"D30-2860928": "সোহাগ স্টোর",
"D30-2860929": "তারা মিয়া স্টোর",
"D30-2860930": "খাদেমুল স্টোর",
"D30-2860931": "ভ্যারাইটি জাত",
"D30-2860932": "সিয়াম স্টোর",
"D30-2860933": "হিরা স্টোর",
"D30-2860934": "রবিউল স্টোর",
"D30-2860935": "রূপসা কসমেটিক্স",
"D30-2860936": "মা স্টোর",
"D30-2860937": "জবা ফার্মেসি",
"D30-2860938": "রংধনু স্টোর",
"D30-2860939": "এফ/কে ডিপার্টমেন্টাল স্টোর",
"D30-2860940": "ইউনিটি এক্সপ্রেস",
"D30-2860941": "আবু স্টোর",
"D30-2860942": "অর্জুন স্টোর",
"D30-2860943": "অপেক্ষা স্টোর",
"D30-2860944": "গোবিন্দ স্টোর",
"D30-2860945": "জি এস ভ্যারাইটিস স্টোর",
"D30-2860946": "সাজু স্টোর",
"D30-2860947": "গোলাপ স্টোর",
"D30-2860948": "মিজান স্টোর",
"D30-2860949": "হাট বাজার স্টোর",
"D30-2860950": "আতিফ ভ্যারাইটি স্টোর",
"D30-2860951": "সুমন স্টোর",
"D30-2860952": "মেসার্স হাসেম স্টোর",
"D30-2860953": "রবিউল স্টোর",
"D30-2860954": "শাহিন স্টোর",
"D30-2860955": "রেজা ফার্মেসি",
"D30-2860956": "মোহনা ফার্মেসি",
"D30-2860957": "এনামুল ফার্মেসি",
"D30-2860958": "মা ডিজিটাল স্টুডিও",
"D30-2860959": "আমসার স্টোর",
"D30-2860960": "খান স্টোর",
"D30-2860961": "আখি স্টোর",
"D30-2860962": "অনুপ স্টোর",
"D30-2860963": "মাহিন রোকোমাদি স্টোর",
"D30-2860964": "রংধনু স্টোর",
"D30-2860965": "ফাহিম স্টোর",
"D30-2860966": "মা কনফেকশনারি",
"D30-2860967": "মরিয়ম স্টোর",
"D30-2860968": "মাইমুনা স্টোর",
"D30-2860969": "ফুয়াদ স্টোর",
"D30-2860970": "রাওসান স্টোর",
"D30-2860971": "মা ভ্যারাইটিস",
"D30-2860972": "মা ডিপার্টমেন্টাল স্টোর",
"D30-2860973": "রাসেল স্টোর",
"D30-2860974": "রফিক স্টোর",
"D30-2860975": "জগন্নাথ সুইট",
"D30-2860976": "জোব্বার স্টোর",
"D30-2860977": "প্রতাশা স্টোর",
"D30-2860978": "জয় তপু স্টোর",
"D30-2860979": "শুজন স্টোর",
"D30-2860980": "সততা ভ্যারিটি স্টোর",
"D30-2860981": "সাহিন স্টোর",
"D30-2860982": "আবুল স্টোর",
"D30-2860983": "মাজেদুল স্টোর",
"D30-2860984": "ফাহিম স্টোর",
"D30-2860985": "কামরুল স্টোর",
"D30-2860986": "মাহিয়া মাহি",
"D30-2860987": "দুই ভাই স্টোর",
"D30-2860988": "রাইসা স্টোর",
"D30-2860989": "শ্রীশ্রী স্টোর",
"D30-2860990": "বাবু স্টোর",
"D30-2860991": "লাবু স্টোর",
"D30-2860992": "জাহির স্টোর",
"D30-2860993": "সাইদী ব্যবসায়ীরা",
"D30-2860994": "ভাই ভাই স্টোর",
"D30-2860995": "হাকিম স্টোর",
"D30-2860996": "খালেদুর স্টোর",
"D30-2860997": "বারি স্টোর-২",
"D30-2860998": "আকবর স্টোর",
"D30-2860999": "সিয়াম স্টোর",
"D30-2861000": "মা কসম্যাটিকস",
"D30-2861001": "মান্নান স্টোর",
"D30-2861003": "আবুল স্টোর",
"D30-2861004": "বিজলি ডিজিটাল স্টুডিও",
"D30-2861005": "সুকুমার স্টোর",
"D30-2861006": "সোটোটা স্টোর",
"D30-2861007": "ওপিআই ডিপাটমেন্টাল স্টোর",
"D30-2861008": "আকশা স্টোর",
"D30-2861009": "নিউ ভ্যারাইটি স্টোর",
"D30-2861010": "উম্মে কুলসুম লাইব্রেরি",
"D30-2861011": "সেলিম স্টোর",
"D30-2861012": "জিসান স্টোর",
"D30-2861013": "মুক্তা স্টোর",
"D30-2861014": "ভাই ভাই স্টোর",
"D30-2861015": "ময়মুনা স্টোর",
"D30-2861016": "মনিরা স্টোর",
"D30-2861017": "সাজু স্টোর",
"D30-2861018": "রোহিদুল স্টোর",
"D30-2861019": "উজ্জল দোকান",
"D30-2861020": "মনসুর স্টোর",
"D30-2861021": "সাজ্জাদ স্টোর",
"D30-2861022": "সোফিউল স্টোর",
"D30-2861023": "রাসেল স্টোর",
"D30-2861024": "মা বাবা দোয়া ষ্টোর",
"D30-2861025": "আরাফাত স্টোর",
"D30-2861026": "রুবেল স্টোর",
"D30-2861027": "সম্পা স্টোর",
"D30-2861028": "বাবুল স্টোর",
"D30-2861029": "ভাই ভাই স্টোর",
"D30-2861030": "ফাহিম স্টোর",
"D30-2861031": "নূর জান্নাত",
"D30-2861032": "ভাই ভাই স্টোর",
"D30-2861033": "মা বাবা স্টোর",
"D30-2861034": "এমডি রিফাত",
"D30-2861035": "আজিম উদ্দিন",
"D30-2861036": "সিমুল স্টোর",
"D30-2861037": "জন্নাত ভ্যারাইটি স্টোর",
"D30-2861038": "মেহেদী স্টোর",
"D30-2861039": "সোমা কসমেটিক্স",
"D30-2861040": "হাফিজুল স্টোর ২",
"D30-2861041": "সোহেল স্টোর-১",
"D30-2861042": "কালাম স্টোর",
"D30-2861043": "রিপু স্টোর",
"D30-2861044": "জয়ন্তো স্টোর",
"D30-2861045": "মোর্তুজা স্টোর",
"D30-2861046": "সোতদল স্টেশনারি",
"D30-2861047": "হাফিজুর স্টোর",
"D30-2861048": "ভাই ভাই স্টোর",
"D30-2861049": "আশিক স্টোর",
"D30-2861050": "আবদুর রহিম স্টোর",
"D30-2861051": "দিপ্ত ভ্যারাইটি স্টোর",
"D30-2861052": "নুর স্টোর",
"D30-2861053": "স্নেহা স্টোর",
"D30-2861054": "ইউসুফ স্টোর",
"D30-2861055": "থ্রি ষ্টোর",
"D30-2861056": "সাথী স্টোর",
"D30-2861057": "আমির উদ্দিন স্টোর",
"D30-2861058": "রহমান স্টোর",
"D30-2861059": "অভিজিৎ স্টোর",
"D30-2861060": "জিহাদ স্টোর",
"D30-2861061": "সঞ্জয়",
"D30-2861062": "একোটা স্টোর",
"D30-2861063": "শরিফ স্টোর",
"D30-2861064": "সাধন স্টোর",
"D30-2861065": "আজমুল স্টোর",
"D30-2861066": "এস.এস. আলামিন স্টোর",
"D30-2861067": "হামিদুর স্টোর",
"D30-2861068": "টুইন বেবি স্টোর",
"D30-2861069": "রুস্টম স্টোর",
"D30-2861070": "রিশাদ স্টোর",
"D30-2861071": "সিয়াম স্টোর-২",
"D30-2861072": "সিরাজুল স্টোর",
"D30-2861073": "ভাই বোন স্টোর",
"D30-2861074": "সিয়াম স্টোর-১",
"D30-2861075": "মায়াদুর স্টোর",
"D30-2861076": "লাবু স্টোর",
"D30-2861077": "চমোক স্টোর",
"D30-2861078": "মতিন স্টোর",
"D30-2861079": "এম এ সিদ্দিকা স্টোর",
"D30-2861080": "রাব্বি স্টোর",
"D30-2861081": "মাসুদ স্টোর",
"D30-2861082": "রেডওয়ান স্টোর",
"D30-2861083": "লাইবুর স্টোর",
"D30-2861084": "হেলাল স্টোর",
"D30-2861085": "রাজক স্টোর",
"D30-2861086": "সিয়াম স্টোর",
"D30-2861087": "দেখুন এবং স্টোরটি লাইভ করুন",
"D30-2861088": "মুক্তা স্টোর",
"D30-2861089": "মামা ভাগিনা ষ্টোর",
"D30-2861090": "রোহিত স্টোর",
"D30-2861091": "সতন স্টোর",
"D30-2861092": "সোহাগ স্টোর",
"D30-2861093": "শহিদুল স্টোর",
"D30-2861094": "রহিম স্টোর",
"D30-2861095": "বিরল টেলিকম",
"D30-2861096": "আদর্শ ষ্টোর",
"D30-2861097": "আয়াজ বাজার",
"D30-2861098": "সিমরা সারা ভ্যারাইটি",
"D30-2861099": "ওম কনফেশনারি",
"D30-2861100": "নাফিজ স্টোর",
"D30-2861101": "আল আমিন স্টোর",
"D30-2861102": "হাজ্জাজ স্টোর",
"D30-2861103": "বিসমিল্লাহ স্টোর",
"D30-2861104": "ফাতেমা ট্রেডার্স",
"D30-2861105": "রাই কনফেকশনারি",
"D30-2862": "এম এস ব্রার্দাস",
"D30-2863": "মমতাজ স্টোর",
"D30-2866385": "সোহিদুল স্টোর",
"D30-2866386": "গম-গবেষণা ক্যান্টাইন",
"D30-2866387": "শামীম স্টোর",
"D30-2866389": "মায়ের দোয়া স্টোর",
"D30-2866390": "চক্রবর্তী ষ্টোর",
"D30-2866391": "লিটন স্টোর",
"D30-2866392": "তুহিন স্টোর",
"D30-2866393": "ডি রহমান স্টোর",
"D30-2866394": "মেসার্স ছাপা স্টোর",
"D30-2866395": "আলী স্টোর",
"D30-2875": "ললিি ষ্টোর",
"D30-2877": "কার্তিক স্টোর",
"D30-2883523": "ইত্যাদি স্টোর",
"D30-2883524": "মেসার্স রবিউল স্টোর",
"D30-2883525": "ফুলকলি দোকান",
"D30-2883526": "সানিহা কসমেটিক",
"D30-2883527": "আলহামদুলিল্লাহ ডিপার্টমেন্টাল স্টোর",
"D30-2883528": "হাবিবা প্রসাধনী",
"D30-2883529": "আবদুল্লাহ কসমেটিক",
"D30-2883530": "আবদুল্লাহ স্টোর",
"D30-2883531": "আসাদ কনফেকশনারি",
"D30-2883532": "মা বাবর দোয়া স্টোর",
"D30-2883533": "জামান স্টোর",
"D30-2883536": "মৌসুমী স্টোর",
"D30-2883547": "উদম কম্পিউটার",
"D30-2883548": "মোঃ মামুনুরে স্টোর",
"D30-2883549": "মেসার্স সাজ্জাদ স্টোর",
"D30-2883551": "সুমন স্টোর",
"D30-2883552": "মুসফিয়া ভেরাইটিস স্টোর",
"D30-2883553": "ভাই ভাই স্টোর",
"D30-2883571": "আব্দুল রহমান সেন্ট",
"D30-2883572": "অদ্রিক ভ্যারাইটিজ স্টোর",
"D30-2883573": "আতিক স্টোর",
"D30-2883577": "মাসুদ ভেরিটিস",
"D30-2883578": "রাসেদুল স্টোর",
"D30-2883579": "লিমন এন্টারপ্রাইজ",
"D30-2883580": "রায়হান স্টোর ২",
"D30-2883581": "জারিন তাবাসসুম",
"D30-2883582": "হামিম স্টোর",
"D30-2883583": "সাগর সেন্ট",
"D30-2883584": "আনোয়ার স্টোর",
"D30-2883585": "আলম এগ আড়ং",
"D30-2883586": "রোমজান স্টোর",
"D30-2883587": "মেসার্স প্রাপ্তি ট্রেডার্স",
"D30-2883588": "জাইফা স্টোর",
"D30-2883590": "মংলা প্যান স্টোর",
"D30-2883594": "সেন্টার পয়েন্ট",
"D30-2883595": "রেজু স্টোর",
"D30-2883596": "ভি ভি প্রসাধনী",
"D30-2883597": "ভাই ভাই প্রসাধনী",
"D30-2883598": "মায়ার ধোয়া",
"D30-2883599": "তোহিদ সেন্ট",
"D30-2883600": "নীল স্বপ্ন",
"D30-2883601": "ম্যাক্স টেলিকন",
"D30-2883602": "পি এইচ স্টোর",
"D30-2883603": "শাহিন স্টোর",
"D30-2883604": "মা মিস্টি প্যান স্টোর",
"D30-2883605": "জিহাদ স্টোর",
"D30-2883606": "মেসার্স আরবি স্টোর",
"D30-2883607": "মিকাইল স্টোর",
"D30-2883608": "শাথি স্টোর",
"D30-2883609": "পোলোবি ডিপার্টমেন্টাল স্টোর",
"D30-2883610": "শাহজালাল স্ট্রিট",
"D30-2883611": "সানজিদা কসমেটিকস",
"D30-2883612": "রোলেক্স বেকারি",
"D30-2883613": "সুজন স্টোর",
"D30-2883614": "শাহা স্টোর",
"D30-2883615": "এ.পি. স্টোর",
"D30-2883617": "আজিফা স্টোর",
"D30-2883618": "ডোলন স্টোর",
"D30-2883619": "শুভেচ্ছা প্রসাধনী",
"D30-2883620": "হালাল দোকান",
"D30-2883621": "বুল বুল স্টোর",
"D30-2883622": "বিসমিল্লাহ স্টোর",
"D30-2883624": "বিসমিলা কসমেটিস",
"D30-2883625": "আনিকা",
"D30-2883626": "আধুনিক কসমেটিস-২",
"D30-2883630": "ইমরান স্টোর",
"D30-2883637": "রমজান আলী",
"D30-2883657": "সোটোটা সেন্ট",
"D30-2884": "জিল্লুর স্টোর",
"D30-2885": "রাজু স্টোর",
"D30-2886": "সাগর স্টোর",
"D30-2888": "বাদল স্টোর",
"D30-2890": "মামুন ইভা কসমেটিক্স",
"D30-2891": "রোকি কসমেটিক্স",
"D30-2892": "রেজাউল স্টোর",
"D30-2917": "তুসার লাইব্রেরি",
"D30-2920": "ডাবডেস স্টোর",
"D30-2925": "দুই ভাই স্টোর",
"D30-2928": "নিশিকান্ত স্টোর",
"D30-2933": "দয়েল পান শপ",
"D30-2934": "সুবাহান ষ্টোর",
"D30-2935": "হাসান স্টোর",
"D30-2950": "মাহি সামি কসমেটিক্স",
"D30-2958": "রাহমান স্টোর",
"D30-2963": "মোহির স্টোর",
"D30-2981": "আমিনুল ষ্টোর",
"D30-2989": "জুনুন স্টোর",
"D30-3004": "গফার স্টোর",
"D30-3009": "বেপারি চাউল ঘোর",
"D30-3014": "বিসমিল্লাহ ভ্যারাইটি ষ্টোর",
"D30-3018": "চ্যান ডিপার্টমেন্টাল স্টোর",
"D30-3021": "রন্টু স্টোর",
"D30-3041": "আন্থু স্টোর",
"D30-3046": "জামান বেকারি",
"D30-3057": "আমিনুল স্টোর",
"D30-3067": "নিতাই স্টোর",
"D30-3079": "সোমাহার স্টোর",
"D30-3080": "কুদ্দুস পেপারস",
"D30-3083": "মোঃ মুরাদ গিফট অ্যান্ড কসমেটিক্স",
"D30-3135": "তাজমুল পান",
"D30-3136": "রুবেল স্টোর",
"D30-3190": "মিঠুন স্টোর",
"D30-3246": "আইয়ুব স্টোর",
"D30-3253": "বিনিময় স্টোর",
"D30-3254": "বিল্লা স্টোর",
"D30-3260": "আজিজ স্টোর",
"D30-3332": "ডপি রলসিন্সে",
"D30-3337": "মিনা বাজার",
"D30-3340": "স্বপ্ন কসমেটিক্স",
"D30-3368": "আসাদ স্টোর",
"D30-3379": "নয়ন স্টোর",
"D30-3380": "মামুন ষ্টোর",
"D30-3386": "জান্নাত ভ্যারাইটি স্টোর",
"D30-3400": "জাহাঙ্গীর স্টোর",
"D30-3417": "সোহাগ স্টোর",
"D30-3419": "জান্নাত স্টোর",
"D30-3420": "মোস্তফা স্টোর",
"D30-3548": "মোতালেব স্টোর",
"D30-3561": "রফিকুল  ষ্টোর",
"D30-3577": "ফরহাদ ষ্টোর",
"D30-3582": "রাজু ষ্টোর",
"D30-3609": "নাহিদ স্টোর",
"D30-3644": "সুমোনা স্টোর",
"D30-3669": "আমির স্টোর",
"D30-3686": "মিলন পান",
"D30-3691": "সিফাত কসমেটিক্স",
"D30-3692": "সালাম কসমেটিক্স",
"D30-3732": "মাহিয়া স্টোর",
"D30-3769": "দুই বোন ষ্টোর",
"D30-3771": "ভাই ভাই স্টোর",
"D30-3778": "ব্র্যাক লার্নিং সেন্টার",
"D30-3788": "পুষ্পিতা কসমেটিক্স",
"D30-3789": "নাসিম স্টোর",
"D30-3793": "শাহালম ভ্যারাইটিস স্টোর",
"D30-3794": "তাহের স্টোর",
"D30-3797": "হযরত ওয়াজ ষ্টোর",
"D30-3840": "মা ভ্যারাইটি স্টোর",
"D30-3854": "মন্টু পান স্টোর",
"D30-3856": "ফরিদুল স্টোর",
"D30-3859": "লিপি স্টোর",
"D30-3863": "আবু সাইদ স্টোর",
"D30-3868": "আবুবকর স্টোর",
"D30-3876": "মনির ষ্টোর",
"D30-3877": "মুকুল ষ্টোর",
"D30-3878": "বিসমিল্লাহ স্টোর",
"D30-3881": "সোরিফ স্টোর",
"D30-3885": "জয় স্টোর",
"D30-3886": "বিসমিল্লাহ স্টোর",
"D30-3901": "আবদুল্লাহ স্টোর",
"D30-3903": "আমিনুল স্টোর",
"D30-3906": "মিম স্টোর",
"D30-3914": "সাহাবুদ্দিন ষ্টোর",
"D30-3919": "জয় স্টোর",
"D30-3922": "এফ.আর ট্রেডার্স",
"D30-3934": "তোরিকুল স্টোর",
"D30-3939": "ইসমাইল ষ্টোর",
"D30-3941": "খালেক স্টোর",
"D30-3942": "কৃষ্ণা কসমিটিক্স",
"D30-3943": "লিটন স্টোর",
"D30-3945": "মিঠুন স্টোর",
"D30-3946": "মোমিন স্টোর",
"D30-3951": "রকিব ​​স্টোর",
"D30-3953": "রঞ্জিত স্টোর",
"D30-3954": "রুবেল স্টোর",
"D30-3968": "বাঁধন স্টোর",
"D30-3970": "গণেশ ষ্টোর",
"D30-3971": "লিটন স্টোর",
"D30-3972": "মাধব স্টোর",
"D30-3975": "মোয়াজ্জম স্টোর",
"D30-3985": "পরিবার ভ্যারাইটি স্টোর",
"D30-3986": "সবুজ স্টোর",
"D30-3987": "সিরাজ স্টোর",
"D30-3988": "রব্বানী ষ্টোর",
"D30-3991": "লোকি স্টোর",
"D30-3992": "খলিল স্টোর",
"D30-4003": "রিপা স্টোর",
"D30-4006": "আল্লাহর দান স্টোর",
"D30-4007": "জনি স্টোর",
"D30-4020": "মোহর আলী স্টোর",
"D30-4031": "ফারুক স্টোর",
"D30-4042": "মকবুল স্টোর",
"D30-4046": "রহমান স্টোর",
"D30-4050": "সাহিনুর স্টোর",
"D30-4058": "নূর ইরশাদ স্টোর",
"D30-4089": "মৌ কনফেকশনারি",
"D30-4091": "ইদ্রিশ আলী",
"D30-4095": "শামিরুল ষ্টোর",
"D30-4097": "আব্দুল মান্নান স্টোর",
"D30-4143": "দয়ার ভান্ডার",
"D30-4145": "মিঠুন স্টোর",
"D30-4149": "অরুণ বিভাগীয়",
"D30-4151": "সাইফুল স্টোর",
"D30-4154": "পারভেজ স্টোর",
"D30-4156": "মোমিন স্টোর",
"D30-4160": "সঞ্জীব স্টোর",
"D30-4167": "মর্জিনা স্টোর",
"D30-4171": "নূর ইসলাম পান শপ",
"D30-4177": "বাবুল স্টোর",
"D30-4179": "বাবু স্টোর",
"D30-4185": "জুলফিকার স্টোর",
"D30-4194": "তুহিন স্টোর",
"D30-4196": "আজিজ স্টোর",
"D30-4197": "মোকলেসুর ষ্টোর",
"D30-4202": "দাবেশ স্টোর",
"D30-4204": "শাহা স্টোর",
"D30-4208": "সাহা কসমেটিক্স",
"D30-4210": "স্বপ্ন ভ্যারাইটি স্টোর",
"D30-4212": "মোস্তফা স্টোর",
"D30-4221": "বিকরমপুর ৩",
"D30-4223": "জননি কসমেটিক্স",
"D30-4225": "জননি স্টোর ২",
"D30-4228": "মা ভ্যারাইটি স্টোর",
"D30-4229": "মাসুম ষ্টোর",
"D30-4234": "নিউ ভাই ভাই স্টোর",
"D30-4236": "অপরূপা সাজ ঘর",
"D30-4237": "আর.বি.আর স্টোর",
"D30-4238": "রাকা কসমেটিক্স",
"D30-4242": "সোহেল রানা স্টোর",
"D30-4243": "ভি ভি স্টোর",
"D30-4244": "ভাই ভাই মোসলা",
"D30-4249": "আরিফ কনফ্যাকশনারি",
"D30-4259": "দুই ভাই কনফেকশনারী",
"D30-4265": "শিশির স্টোর",
"D30-4270": "অন্তরা স্টোর",
"D30-4271": "আফজাল স্টোর",
"D30-4305": "রিফাত স্টোর",
"D30-4327": "মুন্না পান শপ",
"D30-4347": "ইব্রাহিম স্টোর",
"D30-4353": "ওয়েসিস কালেকশন",
"D30-4370": "মামুন স্টোর",
"D30-4377": "মান্নান ষ্টোর",
"D30-4382": "আসাদুল স্টোর",
"D30-4384": "নাসির অ্যান্ড সন্স",
"D30-4385": "তিন কন্না স্টোর",
"D30-4389": "মা বাবর দোয়া স্টোর",
"D30-4396": "রাজু স্টোর",
"D30-4403": "মামা ভাগনিা ষ্টোর",
"D30-4413": "লাবনি স্টোর",
"D30-4428": "রাসেল ট্রেডার্স",
"D30-4437": "নূর ইসলাম ষ্টোর",
"D30-4450": "গোপাল স্টোর",
"D30-4453": "এম এস ষ্টোর",
"D30-4456": "মা স্টোর",
"D30-4458": "উত্তর বেঙ্গালুরু চৌলঘর",
"D30-4459": "পার্থো স্টোর",
"D30-4474": "হাসান স্টোর",
"D30-4476": "ভাই ভাই মুদি ষ্টোর",
"D30-4478": "ভাই ভাই স্টোর",
"D30-4479": "বিসাল স্টোর",
"D30-4480": "খাইরুল স্টোর",
"D30-4494": "রবিউল স্টোর",
"D30-4497": "সায়েম ডিপার্টমেন্টাল স্টোর",
"D30-4498": "সালাম স্টোর",
"D30-4499": "রুবেল খান স্টোর",
"D30-4503": "ফোর ভাই স্টোর",
"D30-4505": "সুবল স্টোর",
"D30-4506": "ইউসুফ ট্রেডিং",
"D30-4507": "রবিউল স্টোর ২",
"D30-4517": "হাতেম আলী স্টোর",
"D30-4518": "মা কসমেটিক্স",
"D30-4535": "আলম র্ব্রাদাস",
"D30-4536": "ফাহিম স্টোর (ডব্লিউএস)",
"D30-4538": "আমিনুল স্টোর",
"D30-4543": "আজহার স্টোর",
"D30-4544": "বি ডি ফুডস",
"D30-4550": "মা কালী স্টোর",
"D30-4555": "মাসুম স্টোর",
"D30-4570": "আনসার স্টোর",
"D30-4590": "হ্যাপি ট্রি হোটেল এন্ড রেস্টুরেন্ট",
"D75-2180905": "সাদিয়া ভ্যারাইটি স্টোর",
"D75-2180909": "শাওন ষ্টোর",
"D75-2180925": "নতুন মা ঔষধ কর্নার",
"D75-2180961": "মালেক চায়ের স্টোর",
"D75-2181046": "ইউসুফ বেকারি",
"D75-2181068": "ফ্লেভার কনফ্যাকশনারি",
"D75-2181070": "রুচি বেকারি",
"D75-2181074": "সাজু ডিপাট্মেন্টাল স্টোর এবং টেলিকম",
"D75-2181109": "রনি টি হাউস",
"D75-2181111": "রোলেক্স বেকারি",
"D75-2181117": "ইউসুফ বাকারি",
"D75-2181119": "মাসুম বাকারি",
"D75-2181126": "শারমিন স্টোর",
"D75-2181224": "মিসু স্টোর",
"D75-2181280": "এম.এস ফার্মেসী",
"D75-2181289": "রোলেক্স বেকারি",
"D75-2181294": "হাসমত ডিপার্টমেন্ট স্টোর",
"D75-2181312": "সেহাব স্টোর",
"D75-2181318": "ফ্রেন্ডস ফুড",
"D75-2181324": "বিএ ফার্মেসী",
"D75-2181370": "আলামিন স্টোর",
"D75-2181385": "জোহান স্টোর",
"D75-2181430": "সাদ্দাম ফুড এন্ড ডিপিটি",
"D75-2181461": "আবসার স্টোর",
"D75-2181493": "বাবা মায়ের দুয়া ডিপার্ট্মেন্টাল স্টোর",
"D75-2181503": "মানিক টি",
"D75-2181509": "মঞ্জুরুল স্টোর",
"D75-2181516": "ফ্রেন্ডস বেকারি",
"D75-2181640": "সোহিদ স্টোর",
"D75-2181681": "তোহিদুল স্টোর",
"D75-2181697": "শাহালম বিভাগীয়",
"D75-2181730": "রিদম  ম্যাডিক্যাল স্টোর",
"D75-2181740": "সাগর ভ্যারাইটিস স্টোর",
"D75-2181770": "ভাই ভাই স্টোর",
"D75-2181822": "রফিকুল স্টোর",
"D75-2249630": "মৌসুমী ও সন্স",
"D75-2249640": "রতন কনফেকশনারী",
"D75-2249782": "মা কসমেটিক্স",
"D75-2249885": "মা বাবা ফার্মেসি",
"D75-2249908": "তাসকুর ষ্টোর",
"D75-2249914": "তাজমল ষ্টোর",
"D75-2252497": "বোশাক স্টোর",
"D75-2252515": "আনিকা স্টোর",
"D75-2252531": "লিটন পান স্টোর",
"D75-2252535": "মা ইলেকট্রনিক্স",
"D75-2252613": "বাদল ভ্যারাইটিস মুড়ি স্টোর",
"D75-2252625": "মেসার্স সিদ্দিক স্টোর",
"D75-2252905": "নূর কনফেকশনারি",
"D75-2252909": "বিউটি স্টোর",
"D75-2252913": "মাসুম স্টোর",
"D75-2256646": "রহমান স্টোর",
"D75-2276012": "স্বপন ফার্মেসি",
"D75-2276017": "নিয়ামত স্টোর",
"D75-2276019": "নিউ মা ভাইরাটি",
"D75-2333440": "রাইশা ভ্যারাইটিজ স্টোর",
"D75-2344678": "মেসার্স কনক ফার্মেসি",
"D75-2371018": "বিপ্লব স্টোর",
"D75-2371020": "এস এম ডিপার্টমেন্টাল",
"D75-2371021": "সুবর্ণা মিষ্টান্ন",
"D75-2371022": "সুমন ভ্যারাইটি স্টোর",
"D75-2371024": "আর এফ ইন্টারন্যাশনাল ফার্মেসি",
"D75-2371027": "সাদিক ডিপার্টমেন্টাল স্টোর",
"D75-2371028": "বিসমিল্লা কসমেটিক্স",
"D75-2371029": "মাহাবুব ফার্মাসি",
"D75-2371030": "মিলন স্টোর",
"D75-2371045": "অনন্যা স্টোর",
"D75-2371050": "সিফাত স্টোর",
"D75-2371052": "সেতু স্টোর",
"D75-2371062": "রাফি এন্টার প্রাইজ",
"D75-2371145": "শাহ আলম স্টোর",
"D75-2371146": "দিপু স্টোর",
"D75-2371152": "তুবা ভ্যারাইটি স্টোর",
"D75-2371185": "কৃঞ্চ ষ্টোর",
"D75-2371261": "মা স্টোর",
"D75-2371262": "মোহন স্টোর",
"D75-2371266": "জাহাঙ্গীর ষ্টোর",
"D75-2371273": "শাহিন মেডিকেল ষ্টোর",
"D75-2371279": "সিনথিয়া ভ্যারাইটি ষ্টোর",
"D75-2371285": "সাধনা ষ্টোর",
"D75-2528121": "রফিক ফার্মেসি",
"D75-2528132": "ইয়াজুল ফামেসী",
"D75-2528136": "সোহেল স্টোর",
"D75-2528141": "রাইসা রেলওয়ে ফাস্ট ফুড",
"D75-2528143": "মুন্না স্টোর",
"D75-2528144": "ফেন্ডস",
"D75-2528151": "ফাহিম স্টোর",
"D75-2528154": "রাজু ফুড কনফেকশনারী",
"D75-2528155": "ইশা মেডিকেল স্টোর",
"D75-2528166": "মালিহা স্টোর",
"D75-2528185": "মদিনা কসমেটিক",
"D75-2528186": "আরবি স্টোর",
"K79-2265749": "আব্দুল ষ্টোর",
}


def find_customer(text_eng: str) -> tuple[str, str]:
    """Finds the first known C Code in the text and returns (C Code, C Name)."""
    first_seen = ""
    for m in CODE_PATTERN.finditer(text_eng):
        prefix, digits = m.group(1).upper(), m.group(2)
        if not first_seen:
            first_seen = f"{prefix}-{digits}"
        code = f"{prefix}-{digits}"
        if code in CUSTOMER_MAP:
            return code, CUSTOMER_MAP[code]
    return first_seen or "N/A", "N/A"


# C Code-এর ঠিক পরে (বা নিচের লাইনে) বন্ধনীর ভেতরের লেখা, যেমন: D30-0397 এর নিচে (বোসরহাট ১)
ADDR_AFTER_CODE = re.compile(r"\s*[\(（]\s*([^)）\n]{1,60}?)\s*[\)）]")
ADDR_ANYWHERE = re.compile(r"[\(（]\s*([^)）]{1,60}?)\s*[\)）]")


def find_address(text_eng: str, code: str, page=None, rect=None) -> str:
    """C Code-এর নিচের (বা পাশের) ঠিকানা খুঁজে বের করে। না পেলে N/A।"""
    if not code or code == "N/A":
        return "N/A"

    # ১) টেক্সটে কোডের ঠিক পরেই (...) থাকলে সেটাই ঠিকানা
    for m in CODE_PATTERN.finditer(text_eng):
        if f"{m.group(1).upper()}-{m.group(2)}" != code:
            continue
        a = ADDR_AFTER_CODE.match(text_eng, m.end())
        if a and a.group(1).strip():
            return a.group(1).strip()

    # ২) পজিশন দেখে: কোডের লাইনের ঠিক নিচের লাইন
    if page is not None and rect is not None:
        try:
            words = page.get_text("words", clip=rect) or []
            groups = {}
            for w in words:
                groups.setdefault((w[5], w[6]), []).append(w)
            lines = []
            for ws in groups.values():
                ws.sort(key=lambda w: w[0])
                lines.append({
                    "x0": min(w[0] for w in ws), "x1": max(w[2] for w in ws),
                    "y0": min(w[1] for w in ws), "y1": max(w[3] for w in ws),
                    "text": normalize_text(" ".join(w[4] for w in ws)),
                })
            lines.sort(key=lambda l: (l["y0"], l["x0"]))

            idx = None
            for k, l in enumerate(lines):
                for m in CODE_PATTERN.finditer(l["text"]):
                    if f"{m.group(1).upper()}-{m.group(2)}" == code:
                        idx = k
                        break
                if idx is not None:
                    break

            if idx is not None:
                cl = lines[idx]
                lh = max(cl["y1"] - cl["y0"], 8)
                below = [
                    l for l in lines
                    if l is not cl
                    and l["y0"] >= cl["y1"] - lh * 0.5
                    and l["y0"] - cl["y1"] < lh * 2.5
                    and l["x1"] >= cl["x0"] - 20
                    and l["x0"] <= cl["x1"] + 60
                ]
                below.sort(key=lambda l: l["y0"])
                for l in below[:3]:
                    p = ADDR_ANYWHERE.search(l["text"])
                    if p and p.group(1).strip():
                        return p.group(1).strip()
                if below:
                    t = below[0]["text"].strip().strip("()（）").strip()
                    if t:
                        return t[:60]
        except Exception:
            pass
    return "N/A"

BANGLA_DATE_PATTERN = re.compile(
    r"(?<![\d.,/\-])(0?[1-9]|[12]\d|3[01])\s+([\u0980-\u09FF][\u0980-\u09FF\s]{0,14}?)\s*(20\d{2})(?!\d)"
)
BANGLA_MONTHS = ["জানুয়ারি", "ফেব্রুয়ারি", "মার্চ", "এপ্রিল", "মে", "জুন",
                 "জুলাই", "আগস্ট", "সেপ্টেম্বর", "অক্টোবর", "নভেম্বর", "ডিসেম্বর"]

def repair_bangla_month(token: str) -> str | None:
    s = token.replace(" ", "")
    if not s:
        return None
    best_score, best_month, best_ratio = 0.0, None, 0.0
    for m in BANGLA_MONTHS:
        ratio = difflib.SequenceMatcher(None, s, m).ratio()
        score = ratio + (0.3 if s[0] == m[0] else 0.0) + (0.1 if s[-1] == m[-1] else 0.0)
        if score > best_score:
            best_score, best_month, best_ratio = score, m, ratio
    if best_month and best_ratio >= 0.4 and (s[0] == best_month[0] or best_ratio >= 0.7):
        return best_month
    return None

def to_bangla_digits(text: str) -> str:
    return text.translate(str.maketrans(ENGLISH_DIGITS, BANGLA_DIGITS))

def find_bottom_date(ordered_text: str) -> str:
    best_pos, best = -1, "N/A"
    for m in BANGLA_DATE_PATTERN.finditer(ordered_text):
        month = repair_bangla_month(m.group(2))
        if month is None:
            continue
        if m.start() > best_pos:
            best_pos = m.start()
            best = to_bangla_digits(f"{int(m.group(1))} {month} {m.group(3)}")
    return best

def build_output_pdf(pdf_bytes: bytes, items: list, width: float, height: float) -> bytes:
    src_doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    out_doc = fitz.open()
    half_h = height / 2.0
    for i in range(0, len(items), 2):
        new_page = out_doc.new_page(width=width, height=height)
        for j, item in enumerate(items[i:i + 2]):
            target = fitz.Rect(0, j * half_h, width, (j + 1) * half_h)
            new_page.show_pdf_page(target, src_doc, item["page_num"], clip=fitz.Rect(*item["rect"]))
    data = out_doc.tobytes()
    out_doc.close()
    src_doc.close()
    return data

# ------------------------------------------------------------------------------
# 2. HELPER FUNCTIONS
# ------------------------------------------------------------------------------
def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    return text.translate(TRANSLATION_TABLE)

def extract_fourth_number_from_mat(text_eng: str) -> float | None:
    normalized_text = WHITESPACE_PATTERN.sub(" ", text_eng)
    for match in MAT_PATTERN.finditer(normalized_text):
        num_part = match.group(2)
        numbers = NUM_PATTERN.findall(num_part)
        if len(numbers) >= 4:
            try:
                return float(numbers[3])
            except ValueError:
                pass
    all_nums = NUM_PATTERN.findall(normalized_text)
    if len(all_nums) >= 4 and any(kw in text_eng for kw in ["মাট", "মোট", "mat", "mot"]):
        try:
            return float(all_nums[3])
        except ValueError:
            pass
    return None

def check_location_match(cleaned_text: str, cleaned_target: str) -> bool:
    if not cleaned_target:
        return True
    if cleaned_target in cleaned_text:
        return True
    return fuzz.partial_ratio(cleaned_target, cleaned_text) >= 65

# ------------------------------------------------------------------------------
# 3. PAGE CONFIG & CUSTOM CSS
# ------------------------------------------------------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+Bengali:wght@400;600;700&display=swap');

:root{
  --gold:#f2a900; --gold-soft:#ffd75e; --butter:#fff3c4; --cream:#fffbea;
  --ink:#3b2f10; --muted:#8a7440; --line:#f3e2a9;
  --shadow:0 10px 30px rgba(212,160,23,.18); --shadow-lg:0 16px 40px rgba(212,160,23,.30);
}

.stApp{
  background:linear-gradient(135deg,#fffdf2 0%,#fff6d6 30%,#fdebb0 55%,#fff6d6 80%,#fffdf2 100%);
  color:var(--ink);
  font-family:'Noto Sans Bengali',Arial,sans-serif;
}
.block-container{padding-top:2.6rem !important; padding-bottom:1.5rem !important;}
.hero{
  display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center;
  background:linear-gradient(120deg,#ffe58a,#ffd34d 55%,#f7b500); color:#4a3500;
  padding:5px 14px; border-radius:12px; box-shadow:0 6px 16px rgba(212,160,23,.28);
  border:1px solid #ffe9a3; margin-bottom:8px;
}
.hero h1{margin:0; padding:0; font-size:17px; line-height:1.35; font-weight:700;}
.hero p{margin:0; font-size:11px; line-height:1.3; opacity:.85}

.step-title{
  display:flex; align-items:center; gap:8px; font-weight:700; font-size:15px;
  color:var(--ink); margin:0 0 6px 0;
}
.step-num{
  display:inline-flex; align-items:center; justify-content:center; width:26px; height:26px;
  border-radius:50%; background:linear-gradient(135deg,#ffd34d,#f2a900); color:#4a3500;
  font-size:14px; box-shadow:0 3px 8px rgba(242,169,0,.45);
}
.quick-title{font-size:12.5px; font-weight:700; color:var(--muted); margin:4px 0 0 0;}

/* Buttons */
.stButton>button, .stDownloadButton>button{
  border:none; border-radius:12px; font-weight:700; font-size:15px; padding:.55rem 1rem;
  background:linear-gradient(135deg,#ffd34d,#f2a900); color:#3b2800;
  box-shadow:0 6px 16px rgba(242,169,0,.35);
  transition:transform .15s ease, box-shadow .15s ease, filter .15s ease;
}
.stButton>button:hover, .stDownloadButton>button:hover{
  transform:translateY(-2px); box-shadow:0 10px 22px rgba(242,169,0,.5); filter:brightness(1.05); color:#3b2800;
}
.stButton>button:active, .stDownloadButton>button:active{
  transform:translateY(1px) scale(.98); box-shadow:0 2px 6px rgba(242,169,0,.4);
}
.stDownloadButton>button{
  background:linear-gradient(135deg,#34c97b,#17a35a); color:#fff;
  box-shadow:0 6px 16px rgba(23,163,90,.35);
}
.stDownloadButton>button:hover{box-shadow:0 10px 22px rgba(23,163,90,.5); color:#fff;}
.stDownloadButton>button p, .stDownloadButton>button span{color:#fff !important;}

/* Summary cards */
.stat-grid{display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:6px 0 10px 0;}
.stat-card{
  display:flex; align-items:center; gap:12px; background:#fff; border-radius:16px;
  padding:12px 16px; border:1px solid var(--line); border-left:6px solid var(--c);
  box-shadow:0 6px 18px rgba(212,160,23,.15); transition:transform .15s ease, box-shadow .15s ease;
}
.stat-card:hover{transform:translateY(-3px); box-shadow:0 12px 26px rgba(212,160,23,.28);}
.stat-icon{
  font-size:22px; width:42px; height:42px; display:flex; align-items:center; justify-content:center;
  border-radius:12px; background:var(--bg);
}
.stat-label{font-size:12px; color:var(--muted); font-weight:600; line-height:1.2;}
.stat-value{font-size:22px; font-weight:800; color:var(--ink); line-height:1.2;}
.ok-bar{
  display:flex; align-items:center; gap:10px; background:linear-gradient(120deg,#e7fbef,#d3f5e1);
  border:1px solid #9fe3bd; color:#0f5132; padding:10px 16px; border-radius:14px;
  font-weight:600; font-size:14px; box-shadow:0 4px 12px rgba(23,163,90,.15); min-height:46px;
}
.warn-bar{
  background:#fff4d6; border:1px solid #ffd34d; color:#6b4a00; padding:10px 16px;
  border-radius:14px; font-weight:600; font-size:14px;
}
@media (max-width:900px){ .stat-grid{grid-template-columns:repeat(2,1fr);} }
</style>
""", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# 3B. LIVE ANIMATION (CSS + HELPERS)  — বড় পর্দার সংস্করণ
# ------------------------------------------------------------------------------
# (প্রতি পেজ কাটার সময়, প্রতি হাফ-পেজ সার্চের সময়) সেকেন্ডে
ANIM_SPEEDS = {
    "🐢 ধীরে": (1.6, 0.9),
    "🚶 মাঝারি": (0.9, 0.45),
    "🚀 দ্রুত": (0.35, 0.15),
    "⏭️ অ্যানিমেশন ছাড়া": None,
}
CUT_BUDGET = 40.0      # কাটার ধাপে সর্বোচ্চ মোট সময় (বড় পিডিএফ হলে নিজে থেকে দ্রুত হবে)
SEARCH_BUDGET = 40.0   # সার্চের ধাপে সর্বোচ্চ মোট সময়
THUMB_W = 380          # অ্যানিমেশনে পেজের প্রস্থ (px) — আরও বড় চাইলে এই সংখ্যা বাড়ান (যেমন 460)

st.markdown("""
<style>
@property --n{syntax:'<integer>';inherits:false;initial-value:0;}
@keyframes cnt{from{--n:0;}}
.cnt{counter-reset:num var(--n);animation:cnt 1.4s ease-out both;}
.cnt::after{content:counter(num);}

@keyframes fadeUp{from{opacity:0;transform:translateY(18px) scale(.96);}to{opacity:1;transform:none;}}
@keyframes popIn{0%{opacity:0;transform:scale(.5);}70%{transform:scale(1.1);}100%{opacity:1;transform:scale(1);}}
@keyframes shineBar{to{background-position:200% 0;}}
@keyframes fadeOut{to{opacity:0;}}

.stat-card{animation:fadeUp .6s cubic-bezier(.2,.8,.2,1) both;}
.stat-card:nth-child(2){animation-delay:.12s;}
.stat-card:nth-child(3){animation-delay:.24s;}
.stat-card:nth-child(4){animation-delay:.36s;}

/* স্টেজ (বড় পর্দা) */
.stage{background:#fff;border:1px solid var(--line);border-radius:22px;padding:18px 28px 24px;
  box-shadow:var(--shadow-lg);margin:10px 0 16px;animation:fadeUp .4s both;}
.stage-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;
  font-weight:800;color:var(--ink);font-size:20px;}
.stage-badge{background:linear-gradient(135deg,#ffd34d,#f2a900);color:#3b2800;padding:5px 18px;
  border-radius:99px;font-size:15px;box-shadow:0 4px 10px rgba(242,169,0,.4);}
.pbar{height:12px;border-radius:99px;background:#fff3c4;overflow:hidden;margin:12px 0 8px;}
.pbar>i{display:block;height:100%;border-radius:99px;transition:width .3s;
  background:linear-gradient(90deg,#ffd34d,#f2a900,#ffd34d);background-size:200% 100%;
  animation:shineBar 1.2s linear infinite;}
.cut-flex{display:flex;gap:44px;align-items:center;justify-content:center;flex-wrap:wrap;padding:26px 36px 14px;}
.cut-info{flex:1;min-width:340px;max-width:620px;}
.ex-row{background:#fffbea;border:1px solid var(--line);border-radius:12px;padding:10px 16px;
  margin:8px 0;font-size:17px;line-height:1.5;animation:fadeUp .5s both;}

/* ধাপ ১: কাটা */
.paper{position:relative;flex:none;}
.half{position:absolute;left:0;width:100%;height:50%;box-sizing:border-box;background-color:#fff;
  background-size:100% 200%;background-repeat:no-repeat;border:1px solid #ecd48a;
  box-shadow:0 8px 20px rgba(0,0,0,.15);}
.half.top{top:0;background-position:0 0;animation:splitTop var(--d) ease both;}
.half.bot{bottom:0;background-position:0 100%;animation:splitBot var(--d) ease both;}
@keyframes splitTop{0%,55%{transform:none;}100%{transform:translateY(-18px) rotate(-1.4deg);}}
@keyframes splitBot{0%,55%{transform:none;}100%{transform:translateY(18px) rotate(1.4deg);}}
.cutline{position:absolute;left:0;top:50%;width:0;height:0;border-top:4px dashed #e0568b;z-index:3;
  animation:draw calc(var(--d)*.5) linear both, fadeOut calc(var(--d)*.2) calc(var(--d)*.55) both;}
@keyframes draw{to{width:100%;}}
.scissor{position:absolute;top:50%;left:0;z-index:4;font-size:40px;transform:translate(-50%,-50%);
  animation:snip calc(var(--d)*.5) linear both, fadeOut calc(var(--d)*.2) calc(var(--d)*.55) both;}
@keyframes snip{from{left:0;}to{left:100%;}}

/* ধাপ ২: সার্চ */
.sbox{position:relative;flex:none;overflow:hidden;box-sizing:border-box;background-color:#fff;
  background-size:100% 200%;background-repeat:no-repeat;border:1px solid #ecd48a;border-radius:10px;
  box-shadow:0 8px 20px rgba(0,0,0,.15);}
.scan{position:absolute;left:0;width:100%;height:4px;z-index:2;
  background:linear-gradient(90deg,transparent,#3b82f6,transparent);box-shadow:0 0 18px #3b82f6;
  animation:sweep calc(var(--d)*.8) ease-in-out both;}
@keyframes sweep{from{top:0;}to{top:100%;}}
.lens{position:absolute;z-index:3;font-size:46px;animation:lensMove calc(var(--d)*.8) ease-in-out both;}
@keyframes lensMove{0%{left:5%;top:0;}50%{left:60%;top:45%;}100%{left:20%;top:85%;opacity:0;}}
.sbox.keep{animation:glowG .5s calc(var(--d)*.55) both;}
.sbox.drop{animation:glowR .5s calc(var(--d)*.55) both;}
@keyframes glowG{to{box-shadow:0 0 0 5px #17a35a,0 10px 26px rgba(23,163,90,.45);}}
@keyframes glowR{to{box-shadow:0 0 0 5px #e0568b,0 10px 26px rgba(224,86,139,.45);opacity:.6;}}
.stamp{position:absolute;left:0;right:0;bottom:12px;margin:auto;width:fit-content;padding:6px 20px;
  border-radius:99px;font-weight:800;font-size:17px;color:#fff;z-index:5;
  animation:popIn .4s calc(var(--d)*.6) both;}
.keep .stamp{background:#17a35a;} .drop .stamp{background:#e0568b;}
.chk{display:flex;justify-content:space-between;gap:12px;border-radius:12px;padding:10px 16px;margin:8px 0;
  font-size:17px;font-weight:600;animation:fadeUp .4s both;}
.chk.ok{background:#e7fbef;border:1px solid #9fe3bd;color:#0f5132;}
.chk.no{background:#fde4ee;border:1px solid #f4a9c6;color:#7a1a3f;}
.chk em{font-style:normal;}
.counters{display:flex;gap:14px;margin-top:12px;font-weight:800;font-size:19px;}
.c-ok{background:#dcf7e8;color:#0f5132;padding:6px 18px;border-radius:99px;}
.c-no{background:#fde4ee;color:#7a1a3f;padding:6px 18px;border-radius:99px;}
.ticker{display:flex;gap:8px;flex-wrap:wrap;padding:0 36px 6px;min-height:34px;justify-content:center;}
.tk{font-size:14px;font-weight:700;padding:4px 14px;border-radius:99px;animation:popIn .35s both;}
.tk.ok{background:#dcf7e8;color:#0f5132;} .tk.no{background:#fde4ee;color:#7a1a3f;}

/* ধাপ ৩: ফলাফল */
.sheets{display:flex;gap:20px;flex-wrap:wrap;justify-content:center;padding:22px 10px 10px;}
.sheet{display:flex;flex-direction:column;background:#fff;border:1px solid #ecd48a;border-radius:8px;
  box-shadow:0 10px 22px rgba(212,160,23,.30);animation:popIn .6s both;overflow:hidden;}
.sh{flex:1;background-size:100% 200%;background-repeat:no-repeat;}
.sh:first-child{border-bottom:1px dashed #f0dc9c;}
.sheet.more{align-items:center;justify-content:center;font-weight:800;font-size:34px;color:#b77d00;
  background:#fff3c4;}
.reveal-msg{text-align:center;font-weight:700;font-size:18px;color:#0f5132;
  background:linear-gradient(120deg,#e7fbef,#d3f5e1);
  border:1px solid #9fe3bd;border-radius:16px;padding:14px 20px;margin-top:12px;animation:fadeUp .6s 1s both;}

/* প্রিভিউ */
.pv-bar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;
  background:#fff;border:1px solid var(--line);border-radius:14px;padding:8px 16px;margin:6px 0 10px;
  font-weight:700;color:var(--ink);box-shadow:0 4px 12px rgba(212,160,23,.12);}
</style>
""", unsafe_allow_html=True)


def _esc(s):
    return htmllib.escape(str(s))


def page_thumb(page, width=THUMB_W):
    """পেজের ছোট ছবি (data-URL) বানায়।"""
    zoom = (width * 1.3) / page.rect.width
    pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
    try:
        return "data:image/jpeg;base64," + base64.b64encode(pix.tobytes("jpeg", jpg_quality=65)).decode()
    except Exception:
        return "data:image/png;base64," + base64.b64encode(pix.tobytes("png")).decode()


def intro_html(name, total):
    return (
        '<div class="stage">'
        f'<div class="stage-head"><span>📂 {_esc(name)} লোড হচ্ছে…</span>'
        f'<span class="stage-badge">{total} পেজ পাওয়া গেছে</span></div>'
        '<div class="pbar"><i style="width:100%"></i></div></div>'
    )


def cut_scene_html(thumb, page_no, total, ratio, new_halves, d):
    H = int(THUMB_W * ratio)
    pct = int(page_no / total * 100)
    rows = "".join(
        f'<div class="ex-row" style="animation-delay:{d * 0.9 + k * 0.12:.2f}s">'
        f'<b>{"উপরের" if it["rect"].y0 == 0 else "নিচের"} অংশ</b><br>'
        f'🆔 {_esc(it["c_code"])} · 👤 {_esc(it["c_name"])}<br>'
        f'📍 {_esc(it["c_addr"])} · 📅 {_esc(it["c_date"])}</div>'
        for k, it in enumerate(new_halves)
    )
    return (
        '<div class="stage">'
        '<div class="stage-head"><span>✂️ ধাপ ১: আসল পিডিএফ মাঝ বরাবর কাটা হচ্ছে</span>'
        f'<span class="stage-badge">পেজ {page_no} / {total}</span></div>'
        f'<div class="pbar"><i style="width:{pct}%"></i></div>'
        '<div class="cut-flex">'
        f'<div class="paper" style="width:{THUMB_W}px;height:{H}px;--d:{d:.2f}s">'
        f'<div class="half top" style="background-image:url({thumb})"></div>'
        f'<div class="half bot" style="background-image:url({thumb})"></div>'
        '<div class="cutline"></div><div class="scissor">✂️</div></div>'
        '<div class="cut-info">'
        f'<div class="ex-row">📄 মূল পেজ {page_no} → ২টি হাফ-পেজ হচ্ছে</div>'
        f'{rows}</div></div></div>'
    )


def explain_half(h, term, loc, quick_kw, min_val, specific_vals):
    """প্রতিটি হাফ-পেজে কোন কোন চেক হলো তার তালিকা (শুধু দেখানোর জন্য)।"""
    checks = []
    if term:
        hit = term in h["clean_text_lower"]
        checks.append(("🔤 টেক্সট ফিল্টার", not hit, "শব্দ পাওয়া গেছে → বাদ" if hit else "শব্দ নেই"))
    if loc:
        ok = check_location_match(h["clean_text_no_space"], loc)
        checks.append(("📍 জায়গার নাম", ok, "মিলেছে" if ok else "মেলেনি → বাদ"))
    if quick_kw:
        kw_hit = next((kw for kw in quick_kw
                       if WHITESPACE_PATTERN.sub("", normalize_text(kw)).lower() in h["clean_text_lower"]), None)
        checks.append(("⚡ কুইক কীওয়ার্ড", kw_hit is not None,
                       f"'{kw_hit}' পাওয়া গেছে" if kw_hit else "কিছু মেলেনি"))
    if min_val is not None or specific_vals:
        v = h["fourth_num"]
        ok = not ((min_val is not None and v <= min_val) or (specific_vals and v in specific_vals))
        checks.append(("🔢 ৪র্থ সংখ্যা", ok, f"{v:g}" + ("" if ok else " → বাদ")))
    if not checks:
        checks.append(("✅ ফিল্টার", True, "কোনো শর্ত দেওয়া নেই"))
    return checks


def search_scene_html(thumb, ratio, idx, total, h_item, checks, keep, kept, removed, ticker, d):
    H = int(THUMB_W * ratio / 2)
    bgpos = "0 0" if h_item["rect"].y0 == 0 else "0 100%"
    pct = int(idx / total * 100)
    chk = "".join(
        f'<div class="chk {"ok" if ok else "no"}" style="animation-delay:{k * d * 0.2:.2f}s">'
        f'<span>{label}</span><em>{"✔" if ok else "✘"} {_esc(note)}</em></div>'
        for k, (label, ok, note) in enumerate(checks)
    )
    tick = "".join(f'<span class="tk {c}">{ic} {_esc(code)}</span>' for ic, c, code in ticker[-8:])
    cls = "keep" if keep else "drop"
    stamp = "✅ রাখা হলো" if keep else "🗑️ বাদ"
    return (
        '<div class="stage">'
        '<div class="stage-head"><span>🔍 ধাপ ২: সার্চ ও ফিল্টার চলছে</span>'
        f'<span class="stage-badge">হাফ-পেজ {idx} / {total}</span></div>'
        f'<div class="pbar"><i style="width:{pct}%"></i></div>'
        '<div class="cut-flex">'
        f'<div class="sbox {cls}" style="width:{THUMB_W}px;height:{H}px;--d:{d:.2f}s;'
        f'background-image:url({thumb});background-position:{bgpos}">'
        f'<div class="scan"></div><div class="lens">🔍</div><div class="stamp">{stamp}</div></div>'
        '<div class="cut-info">'
        f'<div class="ex-row">🆔 <b>{_esc(h_item["c_code"])}</b> · 👤 {_esc(h_item["c_name"])}<br>'
        f'📍 {_esc(h_item["c_addr"])} · 📅 {_esc(h_item["c_date"])}</div>'
        f'{chk}'
        f'<div class="counters"><span class="c-ok">✅ রাখা: {kept}</span>'
        f'<span class="c-no">🗑️ বাদ: {removed}</span></div>'
        '</div></div>'
        f'<div class="ticker">{tick}</div></div>'
    )


def reveal_html(items, thumbs, ratio, kept_n, removed_n, out_pages):
    SW = 150
    shown = items[:12]
    sheets = ""
    for s, i in enumerate(range(0, len(shown), 2)):
        parts = "".join(
            f'<div class="sh" style="background-image:url({thumbs[it["page_num"]]});'
            f'background-position:{"0 0" if it["rect"].y0 == 0 else "0 100%"}"></div>'
            for it in shown[i:i + 2]
        )
        sheets += (f'<div class="sheet" style="width:{SW}px;height:{int(SW * ratio)}px;'
                   f'animation-delay:{s * 0.18:.2f}s">{parts}</div>')
    extra = out_pages - (len(shown) + 1) // 2
    if extra > 0:
        sheets += (f'<div class="sheet more" style="width:{SW}px;height:{int(SW * ratio)}px;'
                   f'animation-delay:1.2s">+{extra}</div>')
    return (
        '<div class="stage">'
        '<div class="stage-head"><span>🎉 ধাপ ৩: ফলাফল প্রস্তুত!</span>'
        f'<span class="stage-badge">{out_pages} পেজের নতুন পিডিএফ</span></div>'
        f'<div class="sheets">{sheets}</div>'
        f'<div class="reveal-msg">✅ {kept_n} টি হাফ-পেজ রাখা হয়েছে · 🗑️ {removed_n} টি বাদ · '
        f'🖨️ {out_pages} পেজে মার্জ হয়েছে</div></div>'
    )


# ------------------------------------------------------------------------------
# 3C. মেমো প্রিভিউ (ডাউনলোডের আগে সবগুলো মেমো দেখা)
# ------------------------------------------------------------------------------
def render_preview(result, selected, out_bytes, run_id):
    mode_memo = "📄 আলাদা আলাদা মেমো"
    mode_page = "🖨️ ডাউনলোডের পিডিএফ যেভাবে হবে (পেজ আকারে)"

    c1, c2, c3 = st.columns([3, 1.2, 1.4])
    mode = c1.radio("প্রিভিউয়ের ধরন", [mode_memo, mode_page], key=f"pv_mode_{run_id}", horizontal=True)
    per_row = c2.selectbox("এক সারিতে", [1, 2, 3], index=1, key=f"pv_cols_{run_id}")
    per_page = c3.selectbox("এক পাতায় কয়টি", [6, 12, 24, 48], index=1, key=f"pv_pp_{run_id}")

    memo_mode = (mode == mode_memo)
    total_items = len(selected) if memo_mode else -(-len(selected) // 2)
    total_pv_pages = max(1, -(-total_items // per_page))

    pv_page = st.number_input(
        f"প্রিভিউ পাতা নম্বর (মোট {total_pv_pages} পাতা)",
        min_value=1, max_value=total_pv_pages, value=1, step=1, key=f"pv_page_{run_id}",
    )
    pv_page = int(pv_page)
    start = (pv_page - 1) * per_page
    end = min(start + per_page, total_items)

    st.markdown(
        f'<div class="pv-bar"><span>👁️ প্রিভিউ: {start + 1}–{end} / {total_items} টি '
        f'{"মেমো" if memo_mode else "আউটপুট পেজ"}</span><span>পাতা {pv_page} / {total_pv_pages}</span></div>',
        unsafe_allow_html=True,
    )

    zoom = {1: 1.8, 2: 1.4, 3: 1.05}[per_row]
    imgs = []
    try:
        if memo_mode:
            src = fitz.open(stream=result["pdf_bytes"], filetype="pdf")
            for i in range(start, end):
                it = selected[i]
                pix = src[it["page_num"]].get_pixmap(
                    matrix=fitz.Matrix(zoom, zoom), clip=fitz.Rect(*it["rect"]), alpha=False)
                cap = (f"#{i + 1} · {it['c_code']} · {it['c_name']} · 📍 {it['c_addr']} · 📅 {it['c_date']}")
                imgs.append((pix.tobytes("png"), cap))
            src.close()
        else:
            out = fitz.open(stream=out_bytes, filetype="pdf")
            for i in range(start, end):
                pix = out[i].get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
                pair = selected[i * 2:i * 2 + 2]
                cap = f"আউটপুট পেজ {i + 1} · " + " | ".join(f"{p['c_code']}" for p in pair)
                imgs.append((pix.tobytes("png"), cap))
            out.close()
    except Exception as e:
        st.error(f"❌ প্রিভিউ বানানো যায়নি: {e}")
        return

    for r in range(0, len(imgs), per_row):
        cols = st.columns(per_row)
        for col, (img, cap) in zip(cols, imgs[r:r + per_row]):
            with col:
                with st.container(border=True):
                    st.image(img, caption=cap)


# ------------------------------------------------------------------------------
# 4. USER INTERFACE LAYOUT
# ------------------------------------------------------------------------------
st.markdown("""
<header class="hero">
  <h1>📄 D-CODE Memo Print &amp; Advanced Filter (পিডিএফ সম্পাদন)</h1>
  <p>PDF আপলোড করুন → ফিল্টার দিন → হাফ-পেজ কেটে নতুন পিডিএফ তৈরি করুন</p>
</header>
""", unsafe_allow_html=True)

col1, col2, col3 = st.columns(3, gap="medium")

with col1:
    with st.container(border=True):
        st.markdown('<div class="step-title"><span class="step-num">১</span> PDF ফাইল আপলোড</div>', unsafe_allow_html=True)
        uploaded_file = st.file_uploader("আপনার মূল পিডিএফ ফাইলটি আপলোড করুন", type=["pdf"])

with col2:
    with st.container(border=True):
        st.markdown('<div class="step-title"><span class="step-num">২</span> টেক্সট ফিল্টার</div>', unsafe_allow_html=True)
        duplicate_text_input = st.text_input("নির্দিষ্ট শব্দ/লেখা (যেমন: Duplicate):", value="")
        location_input = st.text_input("জায়গার নাম (মিল থাকা হাফ-পাতা রাখা হবে):", value="")

with col3:
    with st.container(border=True):
        st.markdown('<div class="step-title"><span class="step-num">৩</span> নম্বর ফিল্টার ও শর্তসমূহ</div>', unsafe_allow_html=True)
        min_val_input = st.text_input("সর্বনিম্ন মান (৪র্থ সংখ্যা ছোট/সমান হলে বাদ):", value="")
        specific_vals_input = st.text_input("নির্দিষ্ট সংখ্যাসমূহ (কমা দিয়ে আলাদা করুন):", value="")
        st.markdown('<div class="quick-title">⚡ কুইক প্রায়োরিটি চেকবক্স</div>', unsafe_allow_html=True)
        chk_market = st.checkbox("🛒 মার্কেট রিটার্ন")
        chk_b2b = st.checkbox("📦 বিটুবি অর্ডার")
        chk_expiry = st.checkbox("⏳ মেয়াদ উত্তীর্ণ")

_, btn_a, btn_b, _ = st.columns([1, 2, 2, 1], gap="medium")
process_btn = btn_a.button("🚀 প্রসেস এবং মার্জ করুন", use_container_width=True)
clear_btn = btn_b.button("🔄 রিসেট করুন", use_container_width=True)

speed_choice = st.radio("🎬 লাইভ অ্যানিমেশনের গতি", list(ANIM_SPEEDS.keys()), index=1, horizontal=True)

# ফলাফলের সারসংক্ষেপ ও ডাউনলোড (উপরে দেখানোর জন্য জায়গা ধরে রাখা হলো)
summary_slot = st.container()
# লাইভ অ্যানিমেশন এই জায়গায় দেখাবে
anim_slot = st.container()

if clear_btn:
    st.session_state.pop("result", None)
    st.rerun()

with st.container():
    st.markdown('<div class="step-title"><span class="step-num">৪</span> Memo ফলাফল ও ডেটা টেবিল</div>', unsafe_allow_html=True)

    if uploaded_file is not None and process_btn:
        st.session_state.pop("result", None)
        try:
            pdf_bytes = uploaded_file.read()
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            total_original_pages = len(doc)

            first_page = doc[0]
            orig_width = first_page.rect.width
            orig_height = first_page.rect.height
            ratio = orig_height / orig_width

            speed = ANIM_SPEEDS.get(speed_choice)      # None = অ্যানিমেশন বন্ধ
            stage = anim_slot.empty()
            thumbs = {}
            progress_bar = st.progress(0) if not speed else None
            status_text = st.empty() if not speed else None

            if speed:
                stage.markdown(intro_html(uploaded_file.name, total_original_pages), unsafe_allow_html=True)
                time.sleep(0.7)

            # ---------------- ধাপ ১: মাঝ বরাবর কাটা ----------------
            d_cut = min(speed[0], CUT_BUDGET / total_original_pages) if speed else 0
            all_halves = []
            for page_num in range(total_original_pages):
                page = doc[page_num]
                w = page.rect.width
                h = page.rect.height
                mid_h = h / 2.0

                top_rect = fitz.Rect(0, 0, w, mid_h)
                bot_rect = fitz.Rect(0, mid_h, w, h)

                new_halves = []
                for rect in [top_rect, bot_rect]:
                    raw_text = page.get_text("text", clip=rect) or ""
                    text_eng = normalize_text(raw_text)
                    clean_text_no_space = WHITESPACE_PATTERN.sub("", text_eng)

                    fourth_num = extract_fourth_number_from_mat(text_eng)
                    c_code, c_name = find_customer(text_eng)
                    c_addr = find_address(text_eng, c_code, page, rect)

                    blocks = [b for b in (page.get_text("blocks", clip=rect) or []) if b[6] == 0]
                    blocks.sort(key=lambda b: (round(b[1], 1), b[0]))
                    ordered_text = normalize_text("\n".join(b[4] for b in blocks))
                    c_date = find_bottom_date(ordered_text)

                    item = {
                        "page_num": page_num,
                        "rect": rect,
                        "raw_text": raw_text,
                        "text_eng": text_eng,
                        "clean_text_no_space": clean_text_no_space,
                        "clean_text_lower": clean_text_no_space.lower(),
                        "fourth_num": fourth_num if fourth_num is not None else 0.0,
                        "c_code": c_code,
                        "c_name": c_name,
                        "c_addr": c_addr,
                        "c_date": c_date,
                    }
                    all_halves.append(item)
                    new_halves.append(item)

                if speed:
                    thumbs[page_num] = page_thumb(page)
                    stage.markdown(
                        cut_scene_html(thumbs[page_num], page_num + 1, total_original_pages, ratio, new_halves, d_cut),
                        unsafe_allow_html=True,
                    )
                    time.sleep(d_cut)
                else:
                    progress_bar.progress((page_num + 1) / total_original_pages)
                    status_text.text(f"ধাপ ১ (মাঝ বরাবর কাটছে): পেজ {page_num + 1} / {total_original_pages}")

            # ---------------- ফিল্টারের হিসাব ----------------
            clean_search_term = WHITESPACE_PATTERN.sub("", duplicate_text_input.strip().lower()) if duplicate_text_input.strip() else ""
            clean_target_loc = WHITESPACE_PATTERN.sub("", normalize_text(location_input.strip())) if location_input.strip() else ""

            part_b_pool = []
            for h_item in all_halves:
                should_delete = False
                if clean_search_term and clean_search_term in h_item["clean_text_lower"]:
                    should_delete = True
                if not should_delete and clean_target_loc:
                    if not check_location_match(h_item["clean_text_no_space"], clean_target_loc):
                        should_delete = True
                if not should_delete:
                    part_b_pool.append(h_item)

            quick_keywords = []
            if chk_market: quick_keywords.append("টার্ন")
            if chk_b2b: quick_keywords.append("অর্ডার")
            if chk_expiry: quick_keywords.extend(["উত্তী", "আউট", "শেষ", "অনবো", "ক্ষতিগ্রস্থ", "MRP"])

            priority_pool = []
            if quick_keywords:
                for h_item in part_b_pool:
                    is_match = any(WHITESPACE_PATTERN.sub("", normalize_text(kw)).lower() in h_item["clean_text_lower"] for kw in quick_keywords)
                    if is_match: priority_pool.append(h_item)

            min_val_cleaned = normalize_text(min_val_input.strip())
            min_val = float(min_val_cleaned) if min_val_cleaned else None

            specific_vals = set()
            if specific_vals_input.strip():
                for x in normalize_text(specific_vals_input).split(","):
                    if x.strip():
                        try: specific_vals.add(float(x.strip()))
                        except ValueError: pass

            number_filtered_pool = []
            if min_val is not None or len(specific_vals) > 0:
                for h_item in part_b_pool:
                    fourth_num = h_item["fourth_num"]
                    if fourth_num is not None:
                        if min_val is not None and fourth_num <= min_val: continue
                        if len(specific_vals) > 0 and fourth_num in specific_vals: continue
                    number_filtered_pool.append(h_item)

            combined_dict = {}
            if quick_keywords:
                for item in priority_pool: combined_dict[(item["page_num"], item["rect"].y0, item["rect"].y1)] = item
            if min_val is not None or len(specific_vals) > 0:
                for item in number_filtered_pool: combined_dict[(item["page_num"], item["rect"].y0, item["rect"].y1)] = item

            final_valid_halves = part_b_pool if not quick_keywords and min_val is None and len(specific_vals) == 0 else list(combined_dict.values())

            # ---------------- ধাপ ২: সার্চ অ্যানিমেশন ----------------
            if speed:
                final_keys = {(it["page_num"], it["rect"].y0) for it in final_valid_halves}
                n_all = len(all_halves)
                d_search = min(speed[1], SEARCH_BUDGET / max(n_all, 1))
                kept = removed = 0
                ticker = []
                for idx, h_item in enumerate(all_halves, start=1):
                    keep = (h_item["page_num"], h_item["rect"].y0) in final_keys
                    kept += 1 if keep else 0
                    removed += 0 if keep else 1
                    ticker.append(("✅" if keep else "🗑️", "ok" if keep else "no", h_item["c_code"]))
                    checks = explain_half(h_item, clean_search_term, clean_target_loc,
                                          quick_keywords, min_val, specific_vals)
                    stage.markdown(
                        search_scene_html(thumbs[h_item["page_num"]], ratio, idx, n_all, h_item,
                                          checks, keep, kept, removed, ticker, d_search),
                        unsafe_allow_html=True,
                    )
                    time.sleep(d_search)

                # ---------------- ধাপ ৩: ফলাফল সামনে আসা ----------------
                out_pages = -(-len(final_valid_halves) // 2)
                stage.markdown(
                    reveal_html(final_valid_halves, thumbs, ratio, len(final_valid_halves),
                                n_all - len(final_valid_halves), out_pages),
                    unsafe_allow_html=True,
                )
                time.sleep(2.6)
                stage.empty()
            else:
                progress_bar.empty()
                status_text.empty()

            st.session_state["run_counter"] = st.session_state.get("run_counter", 0) + 1
            st.session_state["result"] = {
                "run_id": st.session_state["run_counter"],
                "pdf_bytes": pdf_bytes,
                "file_name": uploaded_file.name,
                "orig_width": orig_width,
                "orig_height": orig_height,
                "total_original_pages": total_original_pages,
                "text_filtered": len(part_b_pool),
                "halves": [
                    {
                        "page_num": it["page_num"],
                        "rect": (it["rect"].x0, it["rect"].y0, it["rect"].x1, it["rect"].y1),
                        "pos": "উপরে" if it["rect"].y0 == 0 else "নিচে",
                        "fourth_num": it["fourth_num"],
                        "c_code": it["c_code"],
                        "c_name": it["c_name"],
                        "c_addr": it["c_addr"],
                        "c_date": it["c_date"],
                    }
                    for it in final_valid_halves
                ],
            }
            doc.close()
        except Exception as e:
            st.error(f"❌ একটি সমস্যা হয়েছে: {str(e)}")

    result = st.session_state.get("result")
    if result:
        try:
            halves = result["halves"]
            run_id = result["run_id"]

            if not halves:
                st.warning("⚠️ আপনার দেওয়া শর্ত অনুযায়ী কোনো হাফ-পেজ খুঁজে পাওয়া যায়নি।")
            else:
                n = len(halves)
                sel_key = f"sel_{run_id}"
                if sel_key not in st.session_state:
                    st.session_state[sel_key] = [True] * n
                sel = st.session_state[sel_key]
                bump_key = f"bump_{run_id}"
                if bump_key not in st.session_state:
                    st.session_state[bump_key] = 0

                def fourth_text(h):
                    return f"৳ {h['fourth_num']:.2f}" if h["fourth_num"] > 0 else "N/A"

                def date_sort_key(s):
                    m = re.match(r"(\d+)\s+(\S+)\s+(\d{4})", s.translate(str.maketrans(BANGLA_DIGITS, ENGLISH_DIGITS)))
                    if not m or m.group(2) not in BANGLA_MONTHS: return (9999, 99, 99)
                    return (int(m.group(3)), BANGLA_MONTHS.index(m.group(2)), int(m.group(1)))

                with st.container(border=True):
                    st.markdown("### 🔎 ডেটা সার্চ ও ফিল্টার")
                    f1, f2, f3, f4 = st.columns([2, 2, 1.2, 1.5])
                    search_q = f1.text_input("সার্চ (C Code / C Name / ঠিকানা / তারিখ ...)", key=f"f_q_{run_id}")
                    date_options = sorted({h["c_date"] for h in halves}, key=date_sort_key)
                    sel_dates = f2.multiselect("📅 তারিখ (খালি = সব)", date_options, key=f"f_d_{run_id}")
                    pos_f = f3.selectbox("অবস্থান", ["সব", "উপরে", "নিচে"], key=f"f_p_{run_id}")
                    state_f = f4.selectbox("নির্বাচনের অবস্থা", ["সব", "শুধু নির্বাচিত", "শুধু বাদ দেওয়া"], key=f"f_s_{run_id}")

                    tokens = search_q.strip().lower().split()
                    visible = []
                    for i, h in enumerate(halves):
                        hay = " ".join([h["c_code"], h["c_name"], h.get("c_addr", ""), h["c_date"], str(h["page_num"] + 1), h["pos"], fourth_text(h)]).lower()
                        if tokens and not all(t in hay for t in tokens): continue
                        if sel_dates and h["c_date"] not in sel_dates: continue
                        if pos_f != "সব" and h["pos"] != pos_f: continue
                        if state_f == "শুধু নির্বাচিত" and not sel[i]: continue
                        if state_f == "শুধু বাদ দেওয়া" and sel[i]: continue
                        visible.append(i)

                    b1, b2, _ = st.columns([1.4, 1.4, 3])
                    if b1.button("✅ দৃশ্যমান সব নির্বাচন", key=f"b_all_{run_id}", use_container_width=True):
                        for i in visible: sel[i] = True
                        st.session_state[bump_key] += 1
                        st.rerun()
                    if b2.button("⬜ দৃশ্যমান সব বাদ", key=f"b_none_{run_id}", use_container_width=True):
                        for i in visible: sel[i] = False
                        st.session_state[bump_key] += 1
                        st.rerun()

                if not visible:
                    st.info("🔍 এই সার্চ/ফিল্টারে কোনো সারি মেলেনি।")
                else:
                    ed_key = f"ed_{run_id}_{st.session_state[bump_key]}"
                    snap_key = f"snap_{ed_key}"
                    if snap_key not in st.session_state:
                        st.session_state[snap_key] = [sel[i] for i in visible]
                    snap = st.session_state[snap_key]

                    df = pd.DataFrame([
                        {
                            "নির্বাচন": snap[pos],
                            "ক্রম": i + 1,
                            "মূল পেজ": halves[i]["page_num"] + 1,
                            "হাফ-পেজ অবস্থান": halves[i]["pos"],
                            "C Code": halves[i]["c_code"],
                            "C Name": halves[i]["c_name"],
                            "ঠিকানা": halves[i].get("c_addr", "N/A"),
                            "তারিখ": halves[i]["c_date"],
                            "৪র্থ সংখ্যা / মূল্য": fourth_text(halves[i]),
                        }
                        for pos, i in enumerate(visible)
                    ])

                    edited_df = st.data_editor(
                        df, key=ed_key, hide_index=True, use_container_width=True,
                        disabled=[c for c in df.columns if c != "নির্বাচন"],
                        column_config={"নির্বাচন": st.column_config.CheckboxColumn("নির্বাচন", default=True)}
                    )
                    for pos, i in enumerate(visible):
                        sel[i] = bool(edited_df["নির্বাচন"].iloc[pos])

                selected = [halves[i] for i in visible if sel[i]]
                total_matched = len(selected)
                total_pages = -(-total_matched // 2)
                out_bytes = None

                with summary_slot:
                    stats = [
                        ("📑", "মূল পেজ সংখ্যা", result["total_original_pages"], "#f2a900", "#fff3c4"),
                        ("🔤", "টেক্সট ফিল্টারকৃত", result["text_filtered"], "#3b82f6", "#e3eeff"),
                        ("📥", "ডাউনলোডে যাবে", total_matched, "#17a35a", "#dcf7e8"),
                        ("🖨️", "আউটপুট পেজ", total_pages, "#e0568b", "#fde4ee"),
                    ]
                    cards = "".join(
                        f'<div class="stat-card" style="--c:{c};--bg:{bg}"><div class="stat-icon">{ic}</div>'
                        f'<div><div class="stat-label">{lb}</div>'
                        f'<div class="stat-value"><span class="cnt" style="--n:{val}"></span> টি</div></div></div>'
                        for ic, lb, val, c, bg in stats
                    )
                    st.markdown(f'<div class="stat-grid">{cards}</div>', unsafe_allow_html=True)

                    if total_matched > 0:
                        out_bytes = build_output_pdf(result["pdf_bytes"], selected, result["orig_width"], result["orig_height"])
                        file_size_kb = len(out_bytes) / 1024
                        original_name = result["file_name"]
                        name_part, ext_part = original_name.rsplit(".", 1) if "." in original_name else (original_name, "pdf")
                        download_filename = f"{name_part}_{random.randint(1, 9)}.{ext_part}"

                        ok_col, dl_col = st.columns([3, 2], gap="medium")
                        ok_col.markdown(
                            f'<div class="ok-bar">✨ সফলভাবে প্রসেস সম্পন্ন হয়েছে! (ফাইলের সাইজ: {file_size_kb:.1f} KB)</div>',
                            unsafe_allow_html=True,
                        )
                        dl_col.download_button(
                            label="📥 মার্জ করা পিডিএফ ডাউনলোড করুন",
                            data=out_bytes,
                            file_name=download_filename,
                            mime="application/pdf",
                            use_container_width=True,
                        )
                    else:
                        st.markdown('<div class="warn-bar">⚠️ টেবিলে দেখানো সারিগুলোর মধ্যে কোনোটিই নির্বাচন করা নেই।</div>', unsafe_allow_html=True)

                # ---------------- ডাউনলোডের আগে মেমো প্রিভিউ ----------------
                st.markdown('<div class="step-title"><span class="step-num">৫</span> ডাউনলোডের আগে মেমো প্রিভিউ</div>', unsafe_allow_html=True)
                if total_matched == 0:
                    st.info("প্রিভিউ দেখানোর জন্য টেবিল থেকে অন্তত একটি মেমো নির্বাচন করুন।")
                else:
                    show_pv = st.toggle(
                        f"👁️ সবগুলো মেমো প্রিভিউ দেখুন ({total_matched} টি)",
                        key=f"pv_on_{run_id}",
                    )
                    if show_pv:
                        render_preview(result, selected, out_bytes, run_id)
        except Exception as e:
            st.error(f"❌ একটি সমস্যা হয়েছে: {str(e)}")
    elif not (uploaded_file is not None and process_btn):
        st.info("দয়া করে বাম দিক থেকে পিডিএফ ফাইল আপলোড করে 'প্রসেস এবং মার্জ করুন' বাটনে ক্লিক করুন।")

st.markdown("<div style='text-align: center; color: #8a7440; font-size: 12px; padding: 10px 0;'>✨ Developed with kishor 01852792728</div>", unsafe_allow_html=True)