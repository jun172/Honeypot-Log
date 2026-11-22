import json
from collections import Counter
from google.cloud import bigquery
import pandas as pd

PROJECT_ID = "honeypot-logs"
TABLE_ID = f"{PROJECT_ID}.honeypot_dataset.run_googleapis_com_stdout"

QUERY = f"""
SELECT
  timestamp,
  jsonPayload
FROM
  `{TABLE_ID}`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
"""


def parse_payload(val):
    if isinstance(val, dict):
        return val
    if isinstance(val, str) and val:
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return {}
    return {}


def main():
    client = bigquery.Client(project=PROJECT_ID)
    df = client.query(QUERY).to_dataframe()

    if df.empty:
        print("対象期間のログが見つかりませんでした。")
        return

    payloads = [parse_payload(x) for x in df["jsonPayload"]]
    req_rows = []
    events = Counter()

    for ts, p in zip(df["timestamp"], payloads):
        ev = p.get("event", "unknown")
        events[ev] += 1
        if ev == "request":
            headers = p.get("headers") or {}
            ua_list = headers.get("User-Agent") or headers.get("user-agent") or []
            ua = ua_list[0] if ua_list else ""
            req_rows.append({
                "ts": ts,
                "src_ip": p.get("src_ip", ""),
                "method": p.get("method", ""),
                "path": p.get("path", ""),
                "user_agent": ua,
                "body_len": p.get("body_read_len", 0),
                "body_sha256": p.get("body_sha256", ""),
                "body": p.get("body", ""),
            })

    print("=== イベント種別件数 ===")
    for k, v in events.most_common():
        print(f"  {k}: {v}")

    if not req_rows:
        print("request イベントはまだありません。")
        return

    req_df = pd.DataFrame(req_rows)

    print("\n=== 送信元IP 上位10件 ===")
    print(req_df["src_ip"].value_counts().head(10))

    print("\n=== パス別 上位10件 ===")
    print(req_df["path"].value_counts().head(10))

    print("\n=== User-Agent 上位10件 ===")
    print(req_df["user_agent"].value_counts().head(10))

    # よくある探索パスの簡易タグ付け例
    suspicious_keywords = [".env", "wp-login", "phpmyadmin", "actuator", "shell", "cmd", "config"]
    matched = req_df[
        req_df["path"].str.lower().apply(lambda s: any(kw in s for kw in suspicious_keywords))
    ]
    print(f"\n=== 典型スキャン系キーワード一致件数: {len(matched)} 件 ===")
    if not matched.empty:
        print(matched[["ts", "src_ip", "method", "path"]].head(10))


if __name__ == "__main__":
    main()
    