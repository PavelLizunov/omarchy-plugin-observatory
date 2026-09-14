(() => {
  "use strict";

  const select = typeof document !== "undefined" ? document.querySelector("#language-select") : null;
  const stats = typeof document !== "undefined" ? document.querySelector("#stats") : null;
  const note = typeof document !== "undefined" ? document.querySelector("#translation-note") : null;
  let messages = {};
  let statistics = null;
  let release = null;
  let activeRequestId = 0;

  const format = (value, locale) => new Intl.NumberFormat(locale).format(value);

  function getEditorialLocales(rel) {
    if (!rel) return ["en", "ru"];
    // Consume actual current schema contract release.locales with validated safe strings
    if (Array.isArray(rel.locales)) {
      const valid = rel.locales.filter((l) => typeof l === "string" && /^[a-zA-Z0-9_-]+$/.test(l));
      if (valid.length > 0) return valid;
    }
    // Accept the optional alternate key without assuming it exists in older exports.
    if (Array.isArray(rel.canonical_editorial_locales)) {
      const legacy = rel.canonical_editorial_locales.filter((l) => typeof l === "string" && /^[a-zA-Z0-9_-]+$/.test(l));
      if (legacy.length > 0) return legacy;
    }
    return ["en", "ru"];
  }

  function validateStatistics(data) {
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new Error("Malformed statistics: expected a JSON object");
    }
    const keys = ["records", "chunks", "anchors"];
    const allMissing = keys.every((k) => data[k] === undefined);
    if (allMissing) {
      return { empty: true, records: 0, chunks: 0, anchors: 0 };
    }
    for (const k of keys) {
      const val = data[k];
      if (typeof val !== "number" || !Number.isInteger(val) || val < 0 || !Number.isFinite(val)) {
        throw new Error(`Malformed statistics: ${k} must be a finite non-negative integer`);
      }
    }
    const allZero = keys.every((k) => data[k] === 0);
    if (allZero) {
      return { empty: true, records: 0, chunks: 0, anchors: 0 };
    }
    return {
      empty: false,
      records: data.records,
      chunks: data.chunks,
      anchors: data.anchors
    };
  }

  function applyMessages(locale) {
    if (typeof document === "undefined") return;
    document.documentElement.lang = locale;
    document.title = messages.page_title || document.title;
    document.querySelectorAll("[data-i18n]").forEach((node) => {
      const value = messages[node.dataset.i18n];
      if (value) node.textContent = value;
    });
    document.querySelectorAll("[data-i18n-aria]").forEach((node) => {
      const value = messages[node.dataset.i18nAria];
      if (value) node.setAttribute("aria-label", value);
    });
    if (note) {
      const editorialLocales = getEditorialLocales(release);
      note.hidden = !release || editorialLocales.includes(locale);
    }
    renderStats(locale);
  }

  function renderMessage(className, text) {
    if (!stats) return;
    const message = document.createElement("p");
    message.className = className;
    message.textContent = text;
    stats.replaceChildren(message);
  }

  function renderStats(locale) {
    if (!stats || !statistics) return;
    if (statistics.empty) {
      renderMessage("empty", messages.empty || "No release statistics were found.");
      return;
    }
    const rows = [
      [statistics.records, messages.records || "plugin records"],
      [statistics.chunks, messages.chunks || "Level-1 chunks"],
      [statistics.anchors, messages.anchors || "evidence anchors"]
    ];
    stats.replaceChildren(...rows.map(([value, label]) => {
      const item = document.createElement("div");
      item.className = "stat";
      const number = document.createElement("span");
      number.className = "stat-value";
      number.textContent = format(value, locale);
      const caption = document.createElement("span");
      caption.className = "stat-label";
      caption.textContent = label;
      item.append(number, caption);
      return item;
    }));
  }

  async function load(locale) {
    const requestId = ++activeRequestId;
    const loadingText = messages.loading || stats?.querySelector(".loading")?.textContent || "Loading release statistics…";
    renderMessage("loading", loadingText);
    try {
      const [localeResponse, statsResponse, releaseResponse] = await Promise.all([
        fetch(`../content/${encodeURIComponent(locale)}.json`),
        fetch("../release/statistics.json"),
        fetch("../release/release.json")
      ]);
      if (!localeResponse.ok || !statsResponse.ok || !releaseResponse.ok) {
        throw new Error("HTTP error: failed to fetch local data files");
      }
      const loadedMessages = await localeResponse.json();
      if (typeof loadedMessages !== "object" || loadedMessages === null || Array.isArray(loadedMessages)) {
        throw new Error("Malformed content data");
      }
      const loadedStats = await statsResponse.json();
      const validatedStats = validateStatistics(loadedStats);

      const loadedRelease = await releaseResponse.json();
      if (typeof loadedRelease !== "object" || loadedRelease === null || Array.isArray(loadedRelease)) {
        throw new Error("Malformed release metadata");
      }

      if (requestId !== activeRequestId) {
        return; // Ignore stale / out-of-order response
      }

      messages = loadedMessages;
      statistics = validatedStats;
      release = loadedRelease;
      applyMessages(locale);
    } catch (error) {
      if (requestId !== activeRequestId) {
        return; // Ignore errors from superseded requests
      }
      console.error(error);
      if (note && !release) {
        note.hidden = true;
      }
      renderMessage("error", messages.load_error || "The local data files could not be loaded. Serve this directory over HTTP instead of opening index.html directly.");
    }
  }

  if (select) {
    select.addEventListener("change", () => load(select.value));
    load(select.value);
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      validateStatistics,
      getEditorialLocales,
      load,
      applyMessages,
      renderStats,
      renderMessage
    };
  }
})();
