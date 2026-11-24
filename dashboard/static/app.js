let mapInstance = null;
let markerLayer = null;
let categoryChart = null;
let eventSource = null;
let isStreamPaused = false;
let seenEventIds = new Set();
let latestData = null;
let searchQuery = "";
let renderRafId = null;

const EXCLUDE_GOOGLE_AND_PRIVATE = true;
const MAX_SEEN_EVENT_IDS = 100000;
const ALLOWED_HOURS = new Set([6, 24, 72, 168]);
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
    pause_btn: "一時停止",
    resume_btn: "再開",
    refresh_btn: "即時取得",
    connecting: "ストリーム接続中...",
    fetch_error: "取得エラー",
    kpi_total: "総検知イベント数",
    kpi_total_sub: "観測ログ全件表示中",
    kpi_ips: "攻撃元ユニークIP",
    kpi_anomaly: "高異常度アラート (≥75%)",
    kpi_anomaly_sub: "Isolation Forest 異常検知",
    kpi_cost: "GCP 月間推定コスト",
    map_title: "攻撃元ジオロケーションマップ",
    map_sub: "ip-api.com バッチ解決",
    chart_title: "ML 攻撃カテゴリ分布",
    country_rank_title: "国別攻撃ランキング (Top 10)",
    ip_rank_title: "攻撃元 IP / ISP ランキング (Top 10)",
    th_rank: "順位",
    th_country: "国・地域",
    th_count: "検知数",
    th_ip: "IPアドレス",
    th_isp: "ISP / 組織",
    th_tactic: "主な手口",
    th_times: "回数",
    stream_title: "リアルタイム攻撃検知ストリーム（全観測ログ常時表示）",
    search_placeholder: "IP・国・ISP・ペイロードで検索（例: 91.92.40.12）",
    clear_btn: "クリア",
    sse_note: "SSE プッシュ配信（3秒間隔）",
    th_time: "時刻 (UTC)",
    th_source: "攻撃元",
    th_ml: "ML分類",
    th_anomaly: "AI異常度",
    th_payload: "リクエスト / ペイロード詳細",
    countries_observed: (n) => `${n} ヶ国から観測`,
    quota_label: (pct) => `Logging無料枠消化率: ${pct}%`,
    updated_label: (t) => `リアルタイム受信: ${t}`,
    filtered_label: (shown, total) => `表示中: ${shown} / ${total} 件`,
    all_label: (total) => `全 ${total} 件`,
    ip_row_title: "クリックでこのIPをストリーム検索",
    popup_ip: "IP",
    popup_isp: "ISP",
    popup_count: "検知数",
    popup_tactic: "手口",
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
    pause_btn: "Pause",
    resume_btn: "Resume",
    refresh_btn: "Refresh Now",
    connecting: "Connecting stream...",
    fetch_error: "Fetch error",
    kpi_total: "Total Detected Events",
    kpi_total_sub: "Showing all observed logs",
    kpi_ips: "Unique Source IPs",
    kpi_anomaly: "High Anomaly Alerts (≥75%)",
    kpi_anomaly_sub: "Isolation Forest detection",
    kpi_cost: "Est. Monthly GCP Cost",
    map_title: "Source Geolocation Map",
    map_sub: "ip-api.com batch lookup",
    chart_title: "ML Attack Categories",
    country_rank_title: "Top Countries (Top 10)",
    ip_rank_title: "Top Source IPs / ISPs (Top 10)",
    th_rank: "Rank",
    th_country: "Country / Region",
    th_count: "Events",
    th_ip: "IP Address",
    th_isp: "ISP / Organization",
    th_tactic: "Top Tactic",
    th_times: "Hits",
    stream_title: "Live Attack Detection Stream (All Observed Logs)",
    search_placeholder: "Filter by IP, country, ISP, or payload (e.g. 91.92.40.12)",
    clear_btn: "Clear",
    sse_note: "SSE push stream (3s interval)",
    th_time: "Time (UTC)",
    th_source: "Source",
    th_ml: "ML Class",
    th_anomaly: "Anomaly",
    th_payload: "Request / Payload Details",
    countries_observed: (n) => `Observed across ${n} ${n === 1 ? "country" : "countries"}`,
    quota_label: (pct) => `Logging free tier usage: ${pct}%`,
    updated_label: (t) => `Live update: ${t}`,
    filtered_label: (shown, total) => `Showing: ${shown} / ${total}`,
    all_label: (total) => `Total: ${total}`,
    ip_row_title: "Click to filter stream by this IP",
    popup_ip: "IP",
    popup_isp: "ISP",
    popup_count: "Events",
    popup_tactic: "Tactic",
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

function toSafeText(val, fallback = "") {
  return sanitizeText(val, fallback, 1000);
}

function getValidatedHours() {
  const hoursEl = document.getElementById("hours-select");
  if (!hoursEl) return 24;
  const parsed = Number(hoursEl.value);
  return ALLOWED_HOURS.has(parsed) ? parsed : 24;
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

function initMap() {
  const mapEl = document.getElementById("attack-map");
  if (!mapEl || typeof L === "undefined") return;
  if (mapInstance) return;

  mapInstance = L.map("attack-map", {
    center: [25, 15],
    zoom: 2,
    worldCopyJump: true,
  });

  const tileLayer = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors",
    maxZoom: 19,
  });
  tileLayer.on("tileerror", () => {
    // 外部タイル取得失敗時もダッシュボード全体を止めない
  });
  tileLayer.addTo(mapInstance);

  markerLayer = L.layerGroup().addTo(mapInstance);
}

function buildPopupElement(pt) {
  const container = document.createElement("div");
  container.style.color = "#0f172a";
  container.style.fontSize = "13px";
  container.style.lineHeight = "1.4";

  const titleEl = document.createElement("strong");
  titleEl.textContent = `${toSafeText(pt.flag, "🌐", 16)} ${toSafeText(pt.country, "Unknown", 100)}`;
  container.appendChild(titleEl);
  container.appendChild(document.createElement("br"));

  const ipLabel = document.createTextNode(`${t("popup_ip")}: `);
  const ipCode = createTextEl("code", toSafeText(pt.ip, "", 64));
  container.appendChild(ipLabel);
  container.appendChild(ipCode);
  container.appendChild(document.createElement("br"));

  const ispLine = document.createTextNode(`${t("popup_isp")}: ${toSafeText(pt.isp, "Unknown ISP", 150)}`);
  container.appendChild(ispLine);
  container.appendChild(document.createElement("br"));

  const countNum = Number(pt.count);
  const safeCount = Number.isFinite(countNum) && countNum >= 0 ? countNum : 0;
  const unit = t("unit_count");
  const countLabel = document.createTextNode(`${t("popup_count")}: `);
  const countStrong = createTextEl(
    "strong",
    `${safeCount}${unit ? " " + unit : ""}`
  );
  container.appendChild(countLabel);
  container.appendChild(countStrong);
  container.appendChild(document.createElement("br"));

  const tacticLine = document.createTextNode(
    `${t("popup_tactic")}: ${toSafeText(pt.category, "Unknown", 80)}`
  );
  container.appendChild(tacticLine);

  return container;
}

function updateMarkers(points) {
  if (!markerLayer) return;
  markerLayer.clearLayers();

  if (!Array.isArray(points)) return;

  points.slice(0, 500).forEach((pt) => {
    if (!pt || typeof pt !== "object" || isGoogleOrPrivateEntry(pt)) return;
    const lat = Number(pt.lat);
    const lon = Number(pt.lon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
    if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return;

    const countNum = Number(pt.count);
    const safeCount = Number.isFinite(countNum) && countNum >= 0 ? countNum : 1;
    const radius = Math.min(22, 6 + safeCount * 2);

    const marker = L.circleMarker([lat, lon], {
      radius,
      fillColor: "#f43f5e",
      color: "#fda4af",
      weight: 1.5,
      opacity: 0.9,
      fillOpacity: 0.55,
    });

    marker.bindPopup(buildPopupElement(pt));
    marker.addTo(markerLayer);
  });
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
      ev.isp,
      ev.category,
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
      `${toSafeText(item.flag, "🌐", 16)} ${toSafeText(item.country, "Unknown", 100)}`
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
      `${toSafeText(item.flag, "🌐", 16)} ${toSafeText(item.country, "Unknown", 100)}`
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
      const input = document.getElementById("ip-search-input");
      if (input) input.value = ipStr;
      searchQuery = ipStr;
      if (latestData) scheduleRenderTables(latestData);
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
      document.createTextNode(`${toSafeText(ev.flag, "🌐", 16)} `)
    );
    tdSource.appendChild(createTextEl("code", ipStr));
    tdSource.appendChild(document.createElement("br"));
    tdSource.appendChild(createTextEl("span", toSafeText(ev.isp, "Unknown ISP", 150), "muted"));

    const tdMl = document.createElement("td");
    tdMl.appendChild(
      createTextEl("span", categoryStr, `badge ${getCategoryBadgeClass(categoryStr)}`)
    );

    const tdAnomaly = document.createElement("td");
    tdAnomaly.appendChild(
      createTextEl("span", `${safeScore}%`, `badge ${getAnomalyBadgeClass(safeScore)}`)
    );

    const tdPayload = document.createElement("td");
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
    if (ev.country) countrySet.add(toSafeText(ev.country, "", 100));
    const cat = toSafeText(ev.category, "Unknown", 80);
    categories[cat] = (categories[cat] || 0) + 1;
    if (Number(ev.anomaly_score) >= 75) {
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

  updateMarkers(data.map_points);
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

async function fetchOnce() {
  const hours = getValidatedHours();
  try {
    const res = await fetch(
      `/api/stats?hours=${encodeURIComponent(hours)}&limit=50000`,
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

function connectStream() {
  disconnectStream();
  if (isStreamPaused) return;

  const hours = getValidatedHours();
  const streamBadge = document.getElementById("stream-badge");
  const liveDot = document.getElementById("live-dot");

  if (streamBadge) {
    streamBadge.textContent = "SSE CONNECTING";
    streamBadge.className = "badge badge-info";
  }

  eventSource = new EventSource(
    `/api/stream?hours=${encodeURIComponent(hours)}&limit=50000`
  );

  eventSource.addEventListener("stats", (event) => {
    if (isStreamPaused) return;
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

  eventSource.onerror = () => {
    if (streamBadge) {
      streamBadge.textContent = "RECONNECTING";
      streamBadge.className = "badge badge-warning";
    }
    if (liveDot) liveDot.classList.add("paused");
  };
}

function disconnectStream() {
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

  if (document.getElementById("attack-map")) {
    initMap();
    connectStream();

    window.addEventListener("resize", () => {
      if (mapInstance) {
        mapInstance.invalidateSize();
      }
    });

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
        if (searchInput) searchInput.value = "";
        searchQuery = "";
        if (latestData) scheduleRenderTables(latestData);
      });
    }

    window.addEventListener("beforeunload", disconnectStream);
  }
});