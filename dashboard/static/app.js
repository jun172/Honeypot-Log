let eventSource = null;
let isStreamPaused = false;
let seenEventIds = new Set();
let latestData = null;
let searchQuery = "";
let renderRafId = null;

const EXCLUDE_GOOGLE_AND_PRIVATE = true;
const MAX_SEEN_EVENT_IDS = 100000;
const ALLOWED_HOURS = new Set([1, 6, 24, 168, 8760]);
const ALLOWED_LIMITS = new Set([200, 1000, 2000, 10000]);
const DEFAULT_LIMIT = 2000;
const MAX_LIMIT = 10000;
const RECONNECT_BASE_DELAY_MS = 3000;
const RECONNECT_MAX_DELAY_MS = 30000;
let reconnectTimerId = null;
let reconnectAttempt = 0;

const ALLOWED_BADGE_CLASSES = new Set([
  "badge-danger",
  "badge-warning",
  "badge-info",
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
    // 無視
  }
}

let currentLang = readStoredLang();

const I18N = {
  ja: {
    nav_dashboard: "ログ",
    nav_env: "構成",
    period_1h: "1時間",
    period_6h: "6時間",
    period_24h: "24時間",
    period_168h: "7日間",
    period_all: "全期間",
    limit_200: "200件",
    limit_1000: "1,000件",
    limit_2000: "2,000件",
    limit_10000: "10,000件",
    pause_btn: "停止",
    resume_btn: "再開",
    refresh_btn: "更新",
    connecting: "接続中...",
    fetch_error: "取得エラー",
    kpi_total: "検知件数",
    kpi_ips: "ユニークIP",
    kpi_anomaly: "高異常度 (≥80%)",
    kpi_cost: "推定月額コスト",
    no_countries: "国データなし",
    search_placeholder: "IP・国・内容で検索...",
    clear_btn: "クリア",
    th_time: "時刻",
    th_source: "送信元",
    th_anomaly: "異常度",
    th_payload: "攻撃内容",
    detail_open: "JSON",
    updated_label: (t) => t,
    filtered_label: (shown, total) => `${shown}/${total}件`,
    all_label: (total) => `${total}件`,
    unit_count: "件",
  },
  en: {
    nav_dashboard: "Logs",
    nav_env: "Stack",
    period_1h: "1h",
    period_6h: "6h",
    period_24h: "24h",
    period_168h: "7d",
    period_all: "All",
    limit_200: "200",
    limit_1000: "1,000",
    limit_2000: "2,000",
    limit_10000: "10,000",
    pause_btn: "Pause",
    resume_btn: "Resume",
    refresh_btn: "Refresh",
    connecting: "Connecting...",
    fetch_error: "Error",
    kpi_total: "Events",
    kpi_ips: "Unique IPs",
    kpi_anomaly: "High (≥80%)",
    kpi_cost: "Est. Monthly",
    no_countries: "No countries",
    search_placeholder: "Search IP, country, summary...",
    clear_btn: "Clear",
    th_time: "Time",
    th_source: "Source",
    th_anomaly: "Score",
    th_payload: "Summary",
    detail_open: "JSON",
    updated_label: (t) => t,
    filtered_label: (shown, total) => `${shown}/${total}`,
    all_label: (total) => `${total}`,
    unit_count: "",
  },
};

function t(key) {
  return I18N[currentLang]?.[key] ?? I18N.ja[key] ?? key;
}

function sanitizeText(val, fallback = "", maxLen = 0) {
  if (val === null || val === undefined) return fallback;
  const cleaned = String(val).replace(/[\u0000-\u001F\u007F-\u009F]/g, " ");
  if (maxLen > 0 && cleaned.length > maxLen) {
    return `${cleaned.slice(0, maxLen)}…`;
  }
  return cleaned;
}

function toSafeText(val, fallback = "", maxLen = 0) {
  return sanitizeText(val, fallback, maxLen);
}

function getValidatedHours() {
  const hoursEl = document.getElementById("hours-select");
  if (!hoursEl) return 8760;
  const parsed = Number(hoursEl.value);
  return ALLOWED_HOURS.has(parsed) ? parsed : 8760;
}

function getClampedLimit(rawLimit = null) {
  if (rawLimit !== null && rawLimit !== undefined) {
    const num = Number(rawLimit);
    if (!Number.isFinite(num)) return DEFAULT_LIMIT;
    return Math.max(1, Math.min(MAX_LIMIT, Math.round(num)));
  }
  const limitEl = document.getElementById("limit-select");
  if (!limitEl) return DEFAULT_LIMIT;
  const parsed = Number(limitEl.value);
  if (ALLOWED_LIMITS.has(parsed)) return parsed;
  if (!Number.isFinite(parsed)) return DEFAULT_LIMIT;
  return Math.max(1, Math.min(MAX_LIMIT, Math.round(parsed)));
}

function syncExportLinks() {
  const hours = getValidatedHours();
  const limit = getClampedLimit();
  const query = `hours=${encodeURIComponent(hours)}&limit=${encodeURIComponent(limit)}`;

  const logLink = document.getElementById("export-log-btn");
  if (logLink) {
    logLink.setAttribute("href", `/api/export/log.txt?${query}`);
    logLink.setAttribute("download", `log_${hours}h.txt`);
  }

  const jsonlLink = document.getElementById("export-jsonl-btn");
  if (jsonlLink) {
    jsonlLink.setAttribute("href", `/api/export/attacks.jsonl?${query}`);
    jsonlLink.setAttribute("download", `detected_attacks_${hours}h.jsonl`);
  }
}

function createTextEl(tagName, text, className = "") {
  const el = document.createElement(tagName);
  if (className) el.className = className;
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
  if (!EXCLUDE_GOOGLE_AND_PRIVATE || !entry || typeof entry !== "object") return false;
  const ip = toSafeText(entry.ip, "", 64).trim().toLowerCase();
  if (!ip || ip === "private" || ip === "unknown" || !isPublicIpv4Str(ip)) return true;
  if (toSafeText(entry.isp).toLowerCase().includes("google")) return true;

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
  const summary =
    currentLang === "en"
      ? toSafeText(ev.attack_summary_en || ev.attack_summary, "", 300)
      : toSafeText(ev.attack_summary || ev.attack_summary_en, "", 300);
  if (summary) return summary;
  return `${toSafeText(ev.method, "GET")} ${toSafeText(ev.path, "/")}`;
}

function getFullRequestDetailText(ev) {
  if (!ev || typeof ev !== "object") return "";
  const methodStr = toSafeText(ev.method, "GET");
  const pathStr = toSafeText(ev.path, "/");
  const fullPayload = toSafeText(ev.payload_full || ev.payload || "");
  const prettyFull = toSafeText(ev.raw_json_pretty_full || ev.raw_json_pretty || "");

  const parts = [`${methodStr} ${pathStr}`];
  if (fullPayload) parts.push(fullPayload);
  if (prettyFull) parts.push(prettyFull);
  return parts.join("\n");
}

function applySearchFilter(queryText) {
  const input = document.getElementById("ip-search-input");
  const normalized = sanitizeText(queryText || "", "", 200);
  if (input) input.value = normalized;
  searchQuery = normalized;
  if (latestData) scheduleRenderTimeline(latestData);
}

function applyLanguage(lang) {
  currentLang = lang === "en" ? "en" : "ja";
  writeStoredLang(currentLang);
  document.documentElement.lang = currentLang;

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.getAttribute("data-i18n");
    const val = t(k);
    if (typeof val === "string") el.textContent = val;
  });

  const searchInput = document.getElementById("ip-search-input");
  if (searchInput) searchInput.placeholder = t("search_placeholder");

  const toggleBtn = document.getElementById("toggle-stream-btn");
  if (toggleBtn) toggleBtn.textContent = isStreamPaused ? t("resume_btn") : t("pause_btn");

  const jaBtn = document.getElementById("lang-ja-btn");
  const enBtn = document.getElementById("lang-en-btn");
  if (jaBtn && enBtn) {
    const isJa = currentLang === "ja";
    jaBtn.classList.toggle("active", isJa);
    enBtn.classList.toggle("active", !isJa);
    jaBtn.setAttribute("aria-pressed", String(isJa));
    enBtn.setAttribute("aria-pressed", String(!isJa));
  }

  if (latestData) applyDashboardData(latestData);
}

function getAllObservedTimeline(timeline) {
  if (!Array.isArray(timeline)) return [];
  return timeline.filter((ev) => ev && typeof ev === "object" && !isGoogleOrPrivateEntry(ev));
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
      ev.category,
      ev.attack_summary,
      ev.attack_summary_en,
      ev.method,
      ev.path,
      ev.payload_full,
      ev.payload,
      ev.timestamp,
    ]
      .filter((v) => v !== null && v !== undefined)
      .map((v) => sanitizeText(v, ""))
      .join(" ")
      .toLowerCase();
    return haystack.includes(q);
  });
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
          country_ja: countryJa,
          country_en: countryEn,
          country: toSafeText(item.country, "Unknown", 100),
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
          country_ja: countryJa,
          country_en: countryEn,
          country: toSafeText(ev.country, "Unknown", 100),
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
    fragment.appendChild(createTextEl("span", t("no_countries"), "muted"));
    container.replaceChildren(fragment);
    return;
  }

  const grid = document.createElement("div");
  grid.className = "country-flag-grid";

  list.forEach((item) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "country-flag-chip";

    const labelText = getCountryLabel(item);
    const unit = t("unit_count");
    chip.appendChild(createTextEl("span", toSafeText(item.flag, "🌐", 16), "country-flag-icon"));
    chip.appendChild(createTextEl("span", labelText));
    chip.appendChild(
      createTextEl(
        "span",
        `${item.count.toLocaleString()}${unit ? " " + unit : ""}`,
        "country-flag-count"
      )
    );

    chip.addEventListener("click", () => {
      applySearchFilter(searchQuery === labelText ? "" : labelText);
    });
    grid.appendChild(chip);
  });

  fragment.appendChild(grid);
  container.replaceChildren(fragment);
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
    const pathStr = toSafeText(ev.path, "/");
    const methodStr = toSafeText(ev.method, "GET", 20);
    const summaryStr = getAttackSummaryText(ev);
    const scoreNum = Number(ev.anomaly_score);
    const safeScore = Number.isFinite(scoreNum)
      ? Math.max(0, Math.min(100, Math.round(scoreNum)))
      : 0;

    const evId = toSafeText(ev.id, "", 128) || `${tsStr}_${ipStr}_${methodStr}_${pathStr.slice(0, 80)}`;
    if (nextSeen.size < MAX_SEEN_EVENT_IDS) nextSeen.add(evId);

    const isNew = trackNew && !seenEventIds.has(evId);
    const timeShort = tsStr.replace("T", " ").slice(0, 19);
    const fullDetailText = getFullRequestDetailText(ev);

    const tr = document.createElement("tr");
    if (isNew) tr.className = "new-event-row";

    const tdTime = document.createElement("td");
    tdTime.appendChild(createTextEl("code", timeShort));

    const tdSource = document.createElement("td");
    tdSource.appendChild(
      document.createTextNode(`${toSafeText(ev.flag, "🌐", 16)} ${getCountryLabel(ev)} `)
    );
    tdSource.appendChild(createTextEl("code", ipStr));

    const tdAnomaly = document.createElement("td");
    tdAnomaly.appendChild(
      createTextEl("span", `${safeScore}%`, `badge ${getAnomalyBadgeClass(safeScore)}`)
    );

    const tdPayload = document.createElement("td");
    tdPayload.appendChild(createTextEl("div", summaryStr, "attack-summary-text"));

    const detailsEl = document.createElement("details");
    detailsEl.className = "payload-details";
    const summaryEl = document.createElement("summary");
    summaryEl.textContent = t("detail_open");
    const preEl = document.createElement("pre");
    preEl.className = "json-full-detail";
    preEl.appendChild(createTextEl("code", fullDetailText));
    detailsEl.appendChild(summaryEl);
    detailsEl.appendChild(preEl);
    tdPayload.appendChild(detailsEl);

    tr.appendChild(tdTime);
    tr.appendChild(tdSource);
    tr.appendChild(tdAnomaly);
    tr.appendChild(tdPayload);
    fragment.appendChild(tr);
  });

  timelineBody.replaceChildren(fragment);
  seenEventIds = nextSeen;
}

function scheduleRenderTimeline(data) {
  if (renderRafId !== null) cancelAnimationFrame(renderRafId);
  renderRafId = requestAnimationFrame(() => {
    renderRafId = null;
    if (!data || typeof data !== "object") return;
    renderCountryFlagsList(data.top_countries, data.timeline);
    renderTimelineTable(data.timeline);
  });
}

function computeDerivedStats(data) {
  const observedTimeline = getAllObservedTimeline(data.timeline);
  const ipSet = new Set();
  let highAnomalyCount = 0;

  observedTimeline.forEach((ev) => {
    if (ev.ip) ipSet.add(toSafeText(ev.ip, "", 64));
    if (Number(ev.anomaly_score) >= 80) highAnomalyCount += 1;
  });

  return {
    totalAttacks: observedTimeline.length,
    uniqueIps: ipSet.size,
    highAnomalyCount,
  };
}

function applyDashboardData(data) {
  if (!data || typeof data !== "object") return;
  latestData = data;
  if (!document.getElementById("kpi-total")) return;

  const cost = data.cost && typeof data.cost === "object" ? data.cost : {};
  const derived = computeDerivedStats(data);
  const estUsd = Number(cost.estimated_monthly_usd) || 0;

  document.getElementById("kpi-total").textContent = derived.totalAttacks.toLocaleString();
  document.getElementById("kpi-ips").textContent = derived.uniqueIps.toLocaleString();
  document.getElementById("kpi-anomaly").textContent = derived.highAnomalyCount.toLocaleString();
  document.getElementById("kpi-cost").textContent = `$${estUsd.toFixed(2)}`;

  syncExportLinks();
  scheduleRenderTimeline(data);

  const lastUpdated = document.getElementById("last-updated");
  if (lastUpdated) {
    const nowStr = new Date().toLocaleTimeString(currentLang === "en" ? "en-US" : "ja-JP");
    lastUpdated.textContent = I18N[currentLang].updated_label(nowStr);
  }
}

async function fetchOnce() {
  syncExportLinks();
  const hours = getValidatedHours();
  const limit = getClampedLimit();
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
    if (!isStreamPaused) connectStream();
  }, delay);
}

function connectStream() {
  disconnectStream();
  syncExportLinks();
  if (isStreamPaused) return;

  const hours = getValidatedHours();
  const limit = getClampedLimit();
  const streamBadge = document.getElementById("stream-badge");
  const liveDot = document.getElementById("live-dot");

  const source = new EventSource(
    `/api/stream?hours=${encodeURIComponent(hours)}&limit=${encodeURIComponent(limit)}`
  );
  eventSource = source;

  source.addEventListener("stats", (event) => {
    if (isStreamPaused || eventSource !== source) return;
    reconnectAttempt = 0;
    if (streamBadge) {
      streamBadge.textContent = "LIVE";
      streamBadge.className = "badge badge-success";
    }
    if (liveDot) liveDot.classList.remove("paused");
    try {
      if (typeof event.data === "string" && event.data.length > 25_000_000) {
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
    if (!isStreamPaused) scheduleReconnect();
  });

  source.onerror = () => {
    if (eventSource !== source) return;
    source.close();
    eventSource = null;
    if (streamBadge) {
      streamBadge.textContent = "RETRY";
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
  syncExportLinks();

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
        syncExportLinks();
        seenEventIds.clear();
        if (isStreamPaused) fetchOnce();
        else connectStream();
      });
    }

    const limitSelect = document.getElementById("limit-select");
    if (limitSelect) {
      limitSelect.addEventListener("change", () => {
        syncExportLinks();
        seenEventIds.clear();
        if (isStreamPaused) fetchOnce();
        else connectStream();
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
        if (latestData) scheduleRenderTimeline(latestData);
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", () => applySearchFilter(""));
    }

    window.addEventListener("beforeunload", disconnectStream);
  }
});