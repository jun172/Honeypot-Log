let categoryChart = null;
let eventSource = null;
let isStreamPaused = false;
let seenEventIds = new Set();
let latestData = null;
let searchQuery = "";
let renderRafId = null;

const EXCLUDE_GOOGLE_AND_PRIVATE = true;
const MAX_SEEN_EVENT_IDS = 100000;
const ALLOWED_HOURS = new Set([6, 24, 72, 168, 8760]);
const DEFAULT_LIMIT = 2000;
const MAX_LIMIT = 10000;
const RECONNECT_BASE_DELAY_MS = 3000;
const RECONNECT_MAX_DELAY_MS = 30000;
let reconnectTimerId = null;
let reconnectAttempt = 0;
const ALLOWED_BADGE_CLASSES = new Set([
  "badge-danger",
  "badge-purple",
  "badge-warning",
  "badge-info",
  "badge-success",
]);

function readStoredLang() {
  try {
    const saved = localStorage.getItem("honeypot_lang");
    return saved === "en" ? "en" : "ja";
  } catch (_) {
    return "ja";
  }
}

function writeStoredLang(lang) {
  try {
    localStorage.setItem("honeypot_lang", lang);
  } catch (_) {
    // ストレージ利用不可時は無視
  }
}

let currentLang = readStoredLang();

const I18N = {
  ja: {
    nav_dashboard: "ダッシュボード",
    nav_env: "開発環境・構成",
    back_to_dash: "← ダッシュボードへ戻る",
    period_label: "集計期間:",
    period_6h: "直近 6時間",
    period_24h: "直近 24時間",
    period_72h: "直近 3日間",
    period_168h: "直近 7日間",
    period_all: "全期間 (All)",
    pause_btn: "一時停止",
    resume_btn: "再開",
    refresh_btn: "即時取得",
    connecting: "ストリーム接続中...",
    fetch_error: "取得エラー",
    kpi_total: "総検知イベント数 (異常度≥80%)",
    kpi_total_sub: "高異常度攻撃ログを表示中",
    kpi_ips: "攻撃元ユニークIP",
    kpi_anomaly: "高異常度アラート (≥80%)",
    kpi_anomaly_sub: "Isolation Forest + 教師なしクラスタ",
    kpi_cost: "GCP 月間推定コスト",
    country_panel_title: "観測国・国旗一覧",
    country_panel_sub: "IPから解決した国名・国旗",
    no_countries: "表示対象の国データがありません",
    chart_title: "ML 攻撃カテゴリ分布",
    analytics_panel_title: "右側分析サマリー（クラスタ・攻撃手口・標的パス）",
    analytics_panel_sub: "教師なしクラスタリング & 異常度≥80%詳細",
    clusters_title: "教師なしクラスタ分布",
    tactics_title: "主な攻撃手口 (Top 6)",
    paths_title: "標的エンドポイント (Top 6)",
    high80_title: "高異常度イベント抜粋 (≥80%)",
    no_analytics_data: "集計対象データがありません",
    country_rank_title: "国別攻撃ランキング (Top 10)",
    ip_rank_title: "攻撃元 IP / ISP ランキング (Top 10)",
    th_rank: "順位",
    th_country: "国・地域",
    th_count: "検知数",
    th_ip: "IPアドレス",
    th_isp: "ISP / 組織",
    th_tactic: "主な手口",
    th_times: "回数",
    stream_title: "リアルタイム攻撃検知ストリーム（攻撃内容・ML/統計根拠付き）",
    search_placeholder: "IP・国・ISP・クラスタ・攻撃内容・ペイロードで検索（例: 91.92.40.12）",
    clear_btn: "クリア",
    sse_note: "SSE プッシュ配信（3秒間隔）",
    th_time: "時刻 (UTC)",
    th_source: "攻撃元",
    th_ml: "ML分類 / クラスタ",
    th_anomaly: "AI異常度",
    th_payload: "攻撃内容・分析根拠・ペイロード詳細",
    countries_observed: (n) => `${n} ヶ国から観測`,
    quota_label: (pct) => `Logging無料枠消化率: ${pct}%`,
    updated_label: (t) => `リアルタイム受信: ${t}`,
    filtered_label: (shown, total) => `表示中: ${shown} / ${total} 件`,
    all_label: (total) => `全 ${total} 件`,
    ip_row_title: "クリックでこのIPをストリーム検索",
    country_chip_title: "クリックでこの国をストリーム検索",
    cluster_chip_title: "クリックでこのクラスタをストリーム検索",
    unit_count: "件",
  },
  en: {
    nav_dashboard: "Dashboard",
    nav_env: "Dev Env & Stack",
    back_to_dash: "← Back to Dashboard",
    period_label: "Window:",
    period_6h: "Last 6 Hours",
    period_24h: "Last 24 Hours",
    period_72h: "Last 3 Days",
    period_168h: "Last 7 Days",
    period_all: "All History",
    pause_btn: "Pause",
    resume_btn: "Resume",
    refresh_btn: "Refresh Now",
    connecting: "Connecting stream...",
    fetch_error: "Fetch error",
    kpi_total: "Total Detected Events (≥80%)",
    kpi_total_sub: "Showing high-anomaly attack logs",
    kpi_ips: "Unique Source IPs",
    kpi_anomaly: "High Anomaly Alerts (≥80%)",
    kpi_anomaly_sub: "Isolation Forest + Unsupervised Clusters",
    kpi_cost: "Est. Monthly GCP Cost",
    country_panel_title: "Observed Countries & Flags",
    country_panel_sub: "Flags & country names resolved from IPs",
    no_countries: "No country data available",
    chart_title: "ML Attack Categories",
    analytics_panel_title: "Analytics Summary (Clusters, Tactics & Target Paths)",
    analytics_panel_sub: "Unsupervised Clustering & Anomaly ≥80% Details",
    clusters_title: "Unsupervised Clusters",
    tactics_title: "Top Attack Tactics (Top 6)",
    paths_title: "Top Target Endpoints (Top 6)",
    high80_title: "High Anomaly Events (≥80%)",
    no_analytics_data: "No analytics data available",
    country_rank_title: "Top Countries (Top 10)",
    ip_rank_title: "Top Source IPs / ISPs (Top 10)",
    th_rank: "Rank",
    th_country: "Country / Region",
    th_count: "Events",
    th_ip: "IP Address",
    th_isp: "ISP / Organization",
    th_tactic: "Top Tactic",
    th_times: "Hits",
    stream_title: "Live Attack Detection Stream (With Attack Summary & ML/Stats Basis)",
    search_placeholder: "Filter by IP, country, ISP, cluster, summary, or payload",
    clear_btn: "Clear",
    sse_note: "SSE push stream (3s interval)",
    th_time: "Time (UTC)",
    th_source: "Source",
    th_ml: "ML Class / Cluster",
    th_anomaly: "Anomaly",
    th_payload: "Attack Summary, Analysis Basis & Payload",
    countries_observed: (n) => `Observed across ${n} ${n === 1 ? "country" : "countries"}`,
    quota_label: (pct) => `Logging free tier usage: ${pct}%`,
    updated_label: (t) => `Live update: ${t}`,
    filtered_label: (shown, total) => `Showing: ${shown} / ${total}`,
    all_label: (total) => `Total: ${total}`,
    ip_row_title: "Click to filter stream by this IP",
    country_chip_title: "Click to filter stream by this country",
    cluster_chip_title: "Click to filter stream by this cluster",
    unit_count: "",
  },
};

function t(key) {
  return I18N[currentLang]?.[key] ?? I18N.ja[key] ?? key;
}

function sanitizeText(val, fallback = "", maxLen = 1000) {
  if (val === null || val === undefined) return fallback;
  const cleaned = String(val).replace(/[\u0000-\u001F\u007F-\u009F]/g, " ");
  return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen)}…` : cleaned;
}

function toSafeText(val, fallback = "", maxLen = 1000) {
  return sanitizeText(val, fallback, maxLen);
}

function getValidatedHours() {
  const hoursEl = document.getElementById("hours-select");
  if (!hoursEl) return 8760;
  const parsed = Number(hoursEl.value);
  return ALLOWED_HOURS.has(parsed) ? parsed : 8760;
}

function createTextEl(tagName, text, className = "") {
  const el = document.createElement(tagName);
  if (className) {
    el.className = className;
  }
  el.textContent = toSafeText(text);
  return el;
}

function isPublicIpv4Str(ip) {
  const s = toSafeText(ip, "", 64).trim();
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s)) return false;
  const octets = s.split(".").map(Number);
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return false;
  if (octets[0] === 0 || octets[0] === 10 || octets[0] === 127) return false;
  if (octets[0] === 169 && octets[1] === 254) return false;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return false;
  if (octets[0] === 192 && octets[1] === 168) return false;
  return true;
}

function isGoogleOrPrivateEntry(entry) {
  if (!EXCLUDE_GOOGLE_AND_PRIVATE || !entry || typeof entry !== "object") {
    return false;
  }
  const ip = toSafeText(entry.ip, "", 64).trim().toLowerCase();
  if (!ip || ip === "private" || ip === "unknown" || !isPublicIpv4Str(ip)) {
    return true;
  }

  const isp = toSafeText(entry.isp).toLowerCase();
  if (isp.includes("google")) {
    return true;
  }

  const country = toSafeText(entry.country).toLowerCase();
  const countryJa = toSafeText(entry.country_ja).trim();
  if (
    country.includes("private") ||
    country.includes("local") ||
    countryJa.includes("ローカル") ||
    countryJa.includes("プライベート")
  ) {
    return true;
  }

  return false;
}

function getSafeBadgeClass(candidate) {
  return ALLOWED_BADGE_CLASSES.has(candidate) ? candidate : "badge-info";
}

function getCategoryBadgeClass(category) {
  const cat = toSafeText(category);
  if (cat.includes("RCE")) return getSafeBadgeClass("badge-danger");
  if (cat.includes("Credential")) return getSafeBadgeClass("badge-purple");
  if (cat.includes("SQLi") || cat.includes("XSS")) return getSafeBadgeClass("badge-warning");
  if (cat.includes("Brute")) return getSafeBadgeClass("badge-info");
  return getSafeBadgeClass("badge-success");
}

function getAnomalyBadgeClass(score) {
  const num = Number(score);
  if (Number.isFinite(num) && num >= 80) return getSafeBadgeClass("badge-danger");
  if (Number.isFinite(num) && num >= 60) return getSafeBadgeClass("badge-warning");
  return getSafeBadgeClass("badge-info");
}

function getCountryLabel(item) {
  if (!item || typeof item !== "object") return "Unknown";
  if (currentLang === "en") {
    return toSafeText(item.country_en || item.country || item.country_ja, "Unknown", 100);
  }
  return toSafeText(item.country_ja || item.country || item.country_en, "不明", 100);
}

function getAttackSummaryText(ev) {
  if (!ev || typeof ev !== "object") return "";
  if (currentLang === "en") {
    return toSafeText(ev.attack_summary_en || ev.attack_summary, "", 260);
  }
  return toSafeText(ev.attack_summary || ev.attack_summary_en, "", 260);
}

function applySearchFilter(queryText) {
  const input = document.getElementById("ip-search-input");
  const normalized = sanitizeText(queryText || "", "", 200);
  if (input) {
    input.value = normalized;
  }
  searchQuery = normalized;
  if (latestData) {
    scheduleRenderTables(latestData);
  }
}

function applyLanguage(lang) {
  currentLang = lang === "en" ? "en" : "ja";
  writeStoredLang(currentLang);
  document.documentElement.lang = currentLang;

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.getAttribute("data-i18n");
    const val = t(k);
    if (typeof val === "string") {
      el.textContent = val;
    }
  });

  const searchInput = document.getElementById("ip-search-input");
  if (searchInput) {
    searchInput.placeholder = t("search_placeholder");
  }

  const toggleBtn = document.getElementById("toggle-stream-btn");
  if (toggleBtn) {
    toggleBtn.textContent = isStreamPaused ? t("resume_btn") : t("pause_btn");
  }

  const jaBtn = document.getElementById("lang-ja-btn");
  const enBtn = document.getElementById("lang-en-btn");
  if (jaBtn && enBtn) {
    const isJa = currentLang === "ja";
    jaBtn.classList.toggle("active", isJa);
    enBtn.classList.toggle("active", !isJa);
    jaBtn.setAttribute("aria-pressed", String(isJa));
    enBtn.setAttribute("aria-pressed", String(!isJa));
  }

  const envJa = document.getElementById("env-content-ja");
  const envEn = document.getElementById("env-content-en");
  if (envJa && envEn) {
    envJa.style.display = currentLang === "ja" ? "flex" : "none";
    envEn.style.display = currentLang === "en" ? "flex" : "none";
  }

  if (latestData) {
    applyDashboardData(latestData);
  }
}

function renderCountryFlagsList(topCountries, timeline) {
  const container = document.getElementById("country-flags-list");
  if (!container) return;

  const aggregated = new Map();

  if (Array.isArray(topCountries)) {
    topCountries.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const countryJa = toSafeText(item.country_ja, "").trim();
      const countryEn = toSafeText(item.country_en || item.country, "").trim();
      const lowerEn = countryEn.toLowerCase();
      if (
        EXCLUDE_GOOGLE_AND_PRIVATE &&
        (lowerEn.includes("private") ||
          lowerEn.includes("local") ||
          countryJa.includes("ローカル") ||
          countryJa.includes("プライベート"))
      ) {
        return;
      }
      const key = (countryEn || countryJa || "Unknown").toLowerCase();
      const cntNum = Number(item.count);
      const count = Number.isFinite(cntNum) && cntNum >= 0 ? cntNum : 0;
      const prev = aggregated.get(key);
      if (!prev) {
        aggregated.set(key, {
          flag: toSafeText(item.flag, "🌐", 16),
          country: toSafeText(item.country, "Unknown", 100),
          country_ja: countryJa,
          country_en: countryEn,
          count,
        });
      } else {
        prev.count += count;
      }
    });
  }

  if (aggregated.size === 0) {
    getAllObservedTimeline(timeline).forEach((ev) => {
      const countryJa = toSafeText(ev.country_ja, "").trim();
      const countryEn = toSafeText(ev.country_en || ev.country, "").trim();
      const key = (countryEn || countryJa || "Unknown").toLowerCase();
      const prev = aggregated.get(key);
      if (!prev) {
        aggregated.set(key, {
          flag: toSafeText(ev.flag, "🌐", 16),
          country: toSafeText(ev.country, "Unknown", 100),
          country_ja: countryJa,
          country_en: countryEn,
          count: 1,
        });
      } else {
        prev.count += 1;
      }
    });
  }

  const list = Array.from(aggregated.values()).sort((a, b) => b.count - a.count);
  const fragment = document.createDocumentFragment();

  if (list.length === 0) {
    fragment.appendChild(createTextEl("p", t("no_countries"), "muted"));
    container.replaceChildren(fragment);
    return;
  }

  const grid = document.createElement("div");
  grid.className = "country-flag-grid";

  list.forEach((item) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "country-flag-chip";
    chip.title = t("country_chip_title");

    const labelText = getCountryLabel(item);
    const unit = t("unit_count");
    chip.appendChild(createTextEl("span", toSafeText(item.flag, "🌐", 16), "country-flag-icon"));
    chip.appendChild(createTextEl("span", labelText, "country-flag-name"));
    chip.appendChild(
      createTextEl(
        "span",
        `${item.count.toLocaleString()}${unit ? " " + unit : ""}`,
        "country-flag-count"
      )
    );

    chip.addEventListener("click", () => {
      applySearchFilter(labelText);
    });

    grid.appendChild(chip);
  });

  fragment.appendChild(grid);
  container.replaceChildren(fragment);
}

function renderRightAnalytics(rightAnalytics) {
  const panel = document.getElementById("right-analytics-panel");
  if (!panel) return;

  const ra = rightAnalytics && typeof rightAnalytics === "object" ? rightAnalytics : {};
  const clusters = Array.isArray(ra.cluster_breakdown) ? ra.cluster_breakdown : [];
  const tactics = Array.isArray(ra.top_tactics) ? ra.top_tactics : [];
  const paths = Array.isArray(ra.top_paths) ? ra.top_paths : [];
  const high80 = Array.isArray(ra.above_80_events) ? ra.above_80_events : [];

  if (!clusters.length && !tactics.length && !paths.length && !high80.length) {
    panel.replaceChildren(createTextEl("p", t("no_analytics_data"), "muted"));
    return;
  }

  const grid = document.createElement("div");
  grid.className = "arch-grid";

  const clusterBox = document.createElement("div");
  clusterBox.className = "arch-box";
  clusterBox.appendChild(createTextEl("h3", t("clusters_title")));
  if (clusters.length) {
    const ul = document.createElement("ul");
    clusters.slice(0, 6).forEach((cl) => {
      const li = document.createElement("li");
      const label = toSafeText(cl.label, "Cluster", 100);
      const cnt = Number(cl.count) || 0;
      const share = Number(cl.share_pct) || 0;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "country-flag-chip";
      btn.title = t("cluster_chip_title");
      btn.appendChild(createTextEl("span", label, "country-flag-name"));
      btn.appendChild(createTextEl("span", `${cnt.toLocaleString()} (${share}%)`, "country-flag-count"));
      btn.addEventListener("click", () => applySearchFilter(label));
      li.appendChild(btn);
      ul.appendChild(li);
    });
    clusterBox.appendChild(ul);
  } else {
    clusterBox.appendChild(createTextEl("p", t("no_analytics_data"), "muted"));
  }
  grid.appendChild(clusterBox);

  const tacticBox = document.createElement("div");
  tacticBox.className = "arch-box";
  tacticBox.appendChild(createTextEl("h3", t("tactics_title")));
  if (tactics.length) {
    const ul = document.createElement("ul");
    tactics.slice(0, 6).forEach((tc) => {
      const li = document.createElement("li");
      const name = toSafeText(tc.tactic, "Unknown", 100);
      const cnt = Number(tc.count) || 0;
      const share = Number(tc.share_pct) || 0;
      li.textContent = `${name} — ${cnt.toLocaleString()} (${share}%)`;
      ul.appendChild(li);
    });
    tacticBox.appendChild(ul);
  } else {
    tacticBox.appendChild(createTextEl("p", t("no_analytics_data"), "muted"));
  }
  grid.appendChild(tacticBox);

  const pathBox = document.createElement("div");
  pathBox.className = "arch-box";
  pathBox.appendChild(createTextEl("h3", t("paths_title")));
  if (paths.length) {
    const ul = document.createElement("ul");
    paths.slice(0, 6).forEach((p) => {
      const li = document.createElement("li");
      const ep = toSafeText(p.endpoint, "/", 120);
      const cnt = Number(p.count) || 0;
      li.appendChild(createTextEl("code", ep));
      li.appendChild(document.createTextNode(` (${cnt.toLocaleString()})`));
      ul.appendChild(li);
    });
    pathBox.appendChild(ul);
  } else {
    pathBox.appendChild(createTextEl("p", t("no_analytics_data"), "muted"));
  }
  grid.appendChild(pathBox);

  const highBox = document.createElement("div");
  highBox.className = "arch-box";
  highBox.appendChild(createTextEl("h3", `${t("high80_title")} (${Number(ra.above_80_count) || 0})`));
  if (high80.length) {
    const ul = document.createElement("ul");
    high80.slice(0, 5).forEach((ev) => {
      const li = document.createElement("li");
      const ip = toSafeText(ev.ip, "", 64);
      const score = Number(ev.anomaly_score) || 0;
      const sum = toSafeText(ev.attack_summary || ev.category, "", 120);
      li.appendChild(createTextEl("code", ip));
      li.appendChild(document.createTextNode(` [${score}%] ${sum}`));
      ul.appendChild(li);
    });
    highBox.appendChild(ul);
  } else {
    highBox.appendChild(createTextEl("p", t("no_analytics_data"), "muted"));
  }
  grid.appendChild(highBox);

  panel.replaceChildren(grid);
}

function updateCategoryChart(categories) {
  const canvas = document.getElementById("category-chart");
  if (!canvas || typeof Chart === "undefined") return;

  const safeCategories =
    categories && typeof categories === "object" ? categories : {};
  const ctx = canvas.getContext("2d");
  const labels = Object.keys(safeCategories).map((k) => toSafeText(k, "Unknown", 80));
  const values = Object.values(safeCategories).map((v) => {
    const num = Number(v);
    return Number.isFinite(num) && num >= 0 ? num : 0;
  });
  const palette = ["#f43f5e", "#a855f7", "#f59e0b", "#38bdf8", "#10b981", "#64748b"];

  if (categoryChart) {
    categoryChart.data.labels = labels;
    categoryChart.data.datasets[0].data = values;
    categoryChart.data.datasets[0].backgroundColor = palette.slice(0, labels.length);
    categoryChart.update("none");
    return;
  }

  categoryChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: palette.slice(0, labels.length),
          borderColor: "#131a2a",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#e6edf7",
            boxWidth: 12,
            padding: 14,
            font: { size: 12 },
          },
        },
      },
    },
  });
}

function getAllObservedTimeline(timeline) {
  if (!Array.isArray(timeline)) return [];
  return timeline.filter(
    (ev) => ev && typeof ev === "object" && !isGoogleOrPrivateEntry(ev)
  );
}

function getFilteredTimeline(timeline) {
  const baseList = getAllObservedTimeline(timeline);
  const q = searchQuery.trim().toLowerCase();
  if (!q) return baseList;

  return baseList.filter((ev) => {
    const haystack = [
      ev.ip,
      ev.country,
      ev.country_ja,
      ev.country_en,
      ev.isp,
      ev.category,
      ev.attack_summary,
      ev.attack_summary_en,
      ev.analysis_basis,
      ev.cluster_label,
      ev.method,
      ev.path,
      ev.payload,
      ev.timestamp,
    ]
      .filter((v) => v !== null && v !== undefined)
      .map((v) => sanitizeText(v, "", 500))
      .join(" ")
      .toLowerCase();
    return haystack.includes(q);
  });
}

function renderCountryTable(topCountries) {
  const countryBody = document.getElementById("country-table-body");
  if (!countryBody) return;

  const items = (Array.isArray(topCountries) ? topCountries : []).filter((item) => {
    if (!item || typeof item !== "object" || !EXCLUDE_GOOGLE_AND_PRIVATE) return true;
    const country = toSafeText(item.country).toLowerCase();
    const countryJa = toSafeText(item.country_ja).trim();
    return (
      !country.includes("private") &&
      !country.includes("local") &&
      !countryJa.includes("ローカル") &&
      !countryJa.includes("プライベート")
    );
  });

  const fragment = document.createDocumentFragment();
  items.slice(0, 10).forEach((item, idx) => {
    const tr = document.createElement("tr");

    const tdRank = createTextEl("td", `#${idx + 1}`);
    const tdCountry = createTextEl(
      "td",
      `${toSafeText(item.flag, "🌐", 16)} ${getCountryLabel(item)}`
    );

    const tdCount = document.createElement("td");
    tdCount.className = "num";
    const countNum = Number(item.count);
    tdCount.appendChild(
      createTextEl("strong", Number.isFinite(countNum) ? countNum.toLocaleString() : "0")
    );

    tr.appendChild(tdRank);
    tr.appendChild(tdCountry);
    tr.appendChild(tdCount);
    fragment.appendChild(tr);
  });

  countryBody.replaceChildren(fragment);
}

function renderIpTable(topIps) {
  const ipBody = document.getElementById("ip-table-body");
  if (!ipBody) return;

  const items = (Array.isArray(topIps) ? topIps : []).filter(
    (item) => item && typeof item === "object" && !isGoogleOrPrivateEntry(item)
  );

  const fragment = document.createDocumentFragment();
  items.slice(0, 10).forEach((item) => {
    const ipStr = toSafeText(item.ip, "", 64);
    const tr = document.createElement("tr");
    tr.className = "clickable-ip-row";
    tr.title = t("ip_row_title");

    const tdIp = document.createElement("td");
    tdIp.appendChild(createTextEl("code", ipStr));

    const tdCountry = createTextEl(
      "td",
      `${toSafeText(item.flag, "🌐", 16)} ${getCountryLabel(item)}`
    );
    const tdIsp = createTextEl("td", toSafeText(item.isp, "Unknown ISP", 150));

    const tdTactic = document.createElement("td");
    const tacticStr = toSafeText(item.top_category, "Unknown", 80);
    tdTactic.appendChild(
      createTextEl("span", tacticStr, `badge ${getCategoryBadgeClass(tacticStr)}`)
    );

    const tdCount = document.createElement("td");
    tdCount.className = "num";
    const countNum = Number(item.count);
    tdCount.appendChild(
      createTextEl("strong", Number.isFinite(countNum) ? countNum.toLocaleString() : "0")
    );

    tr.addEventListener("click", () => {
      applySearchFilter(ipStr);
    });

    tr.appendChild(tdIp);
    tr.appendChild(tdCountry);
    tr.appendChild(tdIsp);
    tr.appendChild(tdTactic);
    tr.appendChild(tdCount);
    fragment.appendChild(tr);
  });

  ipBody.replaceChildren(fragment);
}

function renderTimelineTable(timeline) {
  const timelineBody = document.getElementById("timeline-table-body");
  const filterCountEl = document.getElementById("filter-count");
  if (!timelineBody) return;

  const fullList = getAllObservedTimeline(timeline);
  const filtered = getFilteredTimeline(timeline);

  if (filterCountEl) {
    filterCountEl.textContent = searchQuery.trim()
      ? I18N[currentLang].filtered_label(filtered.length, fullList.length)
      : I18N[currentLang].all_label(fullList.length);
  }

  const nextSeen = new Set();
  const trackNew = seenEventIds.size > 0;
  const fragment = document.createDocumentFragment();

  filtered.forEach((ev) => {
    const tsStr = toSafeText(ev.timestamp, "", 40);
    const ipStr = toSafeText(ev.ip, "", 64);
    const pathStr = toSafeText(ev.path, "/", 300);
    const methodStr = toSafeText(ev.method, "GET", 20);
    const payloadStr = toSafeText(ev.payload, "", 400);
    const categoryStr = toSafeText(ev.category, "Unknown", 80);
    const clusterStr = toSafeText(ev.cluster_label, "", 100);
    const summaryStr = getAttackSummaryText(ev);
    const basisStr = toSafeText(ev.analysis_basis, "", 240);
    const scoreNum = Number(ev.anomaly_score);
    const safeScore = Number.isFinite(scoreNum)
      ? Math.max(0, Math.min(100, Math.round(scoreNum)))
      : 0;

    const evId = toSafeText(ev.id, "", 128) || `${tsStr}_${ipStr}_${methodStr}_${pathStr}`;
    if (nextSeen.size < MAX_SEEN_EVENT_IDS) {
      nextSeen.add(evId);
    }

    const isNew = trackNew && !seenEventIds.has(evId);
    const timeShort = tsStr.replace("T", " ").slice(0, 19);
    const reqPreview = `${methodStr} ${pathStr}${payloadStr ? " | " + payloadStr : ""}`;

    const tr = document.createElement("tr");
    if (isNew) {
      tr.className = "new-event-row";
    }

    const tdTime = document.createElement("td");
    tdTime.appendChild(createTextEl("code", timeShort));

    const tdSource = document.createElement("td");
    tdSource.appendChild(
      document.createTextNode(
        `${toSafeText(ev.flag, "🌐", 16)} ${getCountryLabel(ev)} `
      )
    );
    tdSource.appendChild(createTextEl("code", ipStr));
    tdSource.appendChild(document.createElement("br"));
    tdSource.appendChild(createTextEl("span", toSafeText(ev.isp, "Unknown ISP", 150), "muted"));

    const tdMl = document.createElement("td");
    tdMl.appendChild(
      createTextEl("span", categoryStr, `badge ${getCategoryBadgeClass(categoryStr)}`)
    );
    if (clusterStr) {
      tdMl.appendChild(document.createElement("br"));
      tdMl.appendChild(createTextEl("span", clusterStr, "muted"));
    }

    const tdAnomaly = document.createElement("td");
    tdAnomaly.appendChild(
      createTextEl("span", `${safeScore}%`, `badge ${getAnomalyBadgeClass(safeScore)}`)
    );

    const tdPayload = document.createElement("td");
    if (summaryStr) {
      tdPayload.appendChild(createTextEl("strong", summaryStr, "attack-summary-text"));
      tdPayload.appendChild(document.createElement("br"));
    }
    if (basisStr) {
      tdPayload.appendChild(createTextEl("span", basisStr, "muted analysis-basis-text"));
      tdPayload.appendChild(document.createElement("br"));
    }
    tdPayload.appendChild(createTextEl("code", reqPreview));

    tr.appendChild(tdTime);
    tr.appendChild(tdSource);
    tr.appendChild(tdMl);
    tr.appendChild(tdAnomaly);
    tr.appendChild(tdPayload);
    fragment.appendChild(tr);
  });

  timelineBody.replaceChildren(fragment);
  seenEventIds = nextSeen;
}

function renderTables(data) {
  if (!data || typeof data !== "object") return;
  renderCountryFlagsList(data.top_countries, data.timeline);
  renderRightAnalytics(data.right_analytics);
  renderCountryTable(data.top_countries);
  renderIpTable(data.top_ips);
  renderTimelineTable(data.timeline);
}

function scheduleRenderTables(data) {
  if (renderRafId !== null) {
    cancelAnimationFrame(renderRafId);
  }
  renderRafId = requestAnimationFrame(() => {
    renderRafId = null;
    renderTables(data);
  });
}

function computeDerivedStats(data) {
  const observedTimeline = getAllObservedTimeline(data.timeline);
  const ipSet = new Set();
  const countrySet = new Set();
  const categories = {};
  let highAnomalyCount = 0;

  observedTimeline.forEach((ev) => {
    if (ev.ip) ipSet.add(toSafeText(ev.ip, "", 64));
    const cLabel = toSafeText(ev.country_en || ev.country || ev.country_ja, "", 100);
    if (cLabel) countrySet.add(cLabel);
    const cat = toSafeText(ev.category, "Unknown", 80);
    categories[cat] = (categories[cat] || 0) + 1;
    if (Number(ev.anomaly_score) >= 80) {
      highAnomalyCount += 1;
    }
  });

  return {
    totalAttacks: observedTimeline.length,
    uniqueIps: ipSet.size,
    uniqueCountries: countrySet.size,
    highAnomalyCount,
    categories,
  };
}

function applyDashboardData(data) {
  if (!data || typeof data !== "object") return;
  latestData = data;
  if (!document.getElementById("kpi-total")) return;

  const modeBadge = document.getElementById("mode-badge");
  if (modeBadge) {
    if (data.is_demo_mode) {
      modeBadge.textContent = "DEMO FALLBACK";
      modeBadge.className = "badge badge-warning";
    } else {
      modeBadge.textContent = "GCP LIVE";
      modeBadge.className = "badge badge-success";
    }
  }

  const cost = data.cost && typeof data.cost === "object" ? data.cost : {};
  const derived = computeDerivedStats(data);

  const estUsd = Number(cost.estimated_monthly_usd) || 0;
  const estJpy = Number(cost.estimated_monthly_jpy) || 0;
  const quotaPct = Number(cost.logging_free_tier_pct) || 0;

  document.getElementById("kpi-total").textContent = derived.totalAttacks.toLocaleString();
  document.getElementById("kpi-ips").textContent = derived.uniqueIps.toLocaleString();
  document.getElementById("kpi-countries-sub").textContent =
    I18N[currentLang].countries_observed(derived.uniqueCountries);
  document.getElementById("kpi-anomaly").textContent = derived.highAnomalyCount.toLocaleString();
  document.getElementById("kpi-cost").textContent =
    `$${estUsd.toFixed(2)} (¥${Math.round(estJpy).toLocaleString()})`;
  document.getElementById("kpi-quota").textContent =
    I18N[currentLang].quota_label(quotaPct);

  renderCountryFlagsList(data.top_countries, data.timeline);
  renderRightAnalytics(data.right_analytics);
  updateCategoryChart(derived.categories);
  scheduleRenderTables(data);

  const lastUpdated = document.getElementById("last-updated");
  if (lastUpdated) {
    const nowStr = new Date().toLocaleTimeString(
      currentLang === "en" ? "en-US" : "ja-JP"
    );
    lastUpdated.textContent = I18N[currentLang].updated_label(nowStr);
  }
}

function getClampedLimit(rawLimit = DEFAULT_LIMIT) {
  const num = Number(rawLimit);
  if (!Number.isFinite(num)) return DEFAULT_LIMIT;
  return Math.max(1, Math.min(MAX_LIMIT, Math.round(num)));
}

async function fetchOnce() {
  const hours = getValidatedHours();
  const limit = getClampedLimit(DEFAULT_LIMIT);
  try {
    const res = await fetch(
      `/api/stats?hours=${encodeURIComponent(hours)}&limit=${encodeURIComponent(limit)}`,
      { cache: "no-store" }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    applyDashboardData(data);
  } catch (err) {
    console.error("Failed to fetch stats:", err);
    const lastUpdated = document.getElementById("last-updated");
    if (lastUpdated) lastUpdated.textContent = t("fetch_error");
  }
}

function clearReconnectTimer() {
  if (reconnectTimerId !== null) {
    clearTimeout(reconnectTimerId);
    reconnectTimerId = null;
  }
}

function scheduleReconnect() {
  clearReconnectTimer();
  if (isStreamPaused) return;
  const delay = Math.min(
    RECONNECT_MAX_DELAY_MS,
    RECONNECT_BASE_DELAY_MS * Math.pow(2, Math.min(reconnectAttempt, 4))
  );
  reconnectAttempt += 1;
  reconnectTimerId = setTimeout(() => {
    reconnectTimerId = null;
    if (!isStreamPaused) {
      connectStream();
    }
  }, delay);
}

function connectStream() {
  disconnectStream();
  if (isStreamPaused) return;

  const hours = getValidatedHours();
  const limit = getClampedLimit(DEFAULT_LIMIT);
  const streamBadge = document.getElementById("stream-badge");
  const liveDot = document.getElementById("live-dot");

  if (streamBadge) {
    streamBadge.textContent = "SSE CONNECTING";
    streamBadge.className = "badge badge-info";
  }

  const source = new EventSource(
    `/api/stream?hours=${encodeURIComponent(hours)}&limit=${encodeURIComponent(limit)}`
  );
  eventSource = source;

  source.addEventListener("stats", (event) => {
    if (isStreamPaused || eventSource !== source) return;
    reconnectAttempt = 0;
    if (streamBadge) {
      streamBadge.textContent = "SSE LIVE";
      streamBadge.className = "badge badge-success";
    }
    if (liveDot) liveDot.classList.remove("paused");
    try {
      if (typeof event.data === "string" && event.data.length > 10_000_000) {
        throw new Error("SSE payload too large");
      }
      const data = JSON.parse(event.data);
      applyDashboardData(data);
    } catch (e) {
      console.error("SSE parse error:", e);
    }
  });

  source.addEventListener("end", () => {
    if (eventSource !== source) return;
    source.close();
    eventSource = null;
    reconnectAttempt = 0;
    if (!isStreamPaused) {
      scheduleReconnect();
    }
  });

  source.onerror = () => {
    if (eventSource !== source) return;
    source.close();
    eventSource = null;
    if (streamBadge) {
      streamBadge.textContent = "RECONNECTING";
      streamBadge.className = "badge badge-warning";
    }
    if (liveDot) liveDot.classList.add("paused");
    scheduleReconnect();
  };
}

function disconnectStream() {
  clearReconnectTimer();
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const jaBtn = document.getElementById("lang-ja-btn");
  const enBtn = document.getElementById("lang-en-btn");
  if (jaBtn) jaBtn.addEventListener("click", () => applyLanguage("ja"));
  if (enBtn) enBtn.addEventListener("click", () => applyLanguage("en"));

  applyLanguage(currentLang);

  if (
    document.getElementById("country-flags-list") ||
    document.getElementById("timeline-table-body")
  ) {
    connectStream();

    const refreshBtn = document.getElementById("refresh-btn");
    if (refreshBtn) refreshBtn.addEventListener("click", fetchOnce);

    const hoursSelect = document.getElementById("hours-select");
    if (hoursSelect) {
      hoursSelect.addEventListener("change", () => {
        seenEventIds.clear();
        if (isStreamPaused) {
          fetchOnce();
        } else {
          connectStream();
        }
      });
    }

    const toggleBtn = document.getElementById("toggle-stream-btn");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", (e) => {
        isStreamPaused = !isStreamPaused;
        const btn = e.currentTarget;
        const streamBadge = document.getElementById("stream-badge");
        const liveDot = document.getElementById("live-dot");

        if (isStreamPaused) {
          disconnectStream();
          btn.textContent = t("resume_btn");
          if (streamBadge) {
            streamBadge.textContent = "PAUSED";
            streamBadge.className = "badge badge-warning";
          }
          if (liveDot) liveDot.classList.add("paused");
        } else {
          btn.textContent = t("pause_btn");
          connectStream();
        }
      });
    }

    const searchInput = document.getElementById("ip-search-input");
    const clearBtn = document.getElementById("clear-search-btn");

    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        searchQuery = sanitizeText(e.target.value || "", "", 200);
        if (latestData) scheduleRenderTables(latestData);
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        applySearchFilter("");
      });
    }

    window.addEventListener("beforeunload", disconnectStream);
  }
});