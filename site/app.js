(() => {
  "use strict";

  const select = document.querySelector("#language-select");
  const stats = document.querySelector("#stats");
  let messages = {};
  let statistics = null;
  let release = null;

  const format = (value, locale) => new Intl.NumberFormat(locale).format(value);

  function applyMessages(locale) {
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
    const note = document.querySelector("#translation-note");
    note.hidden = !release || release.canonical_editorial_locales.includes(locale);
    renderStats(locale);
  }

  function renderMessage(className, text) {
    const message = document.createElement("p");
    message.className = className;
    message.textContent = text;
    stats.replaceChildren(message);
  }

  function renderStats(locale) {
    if (!statistics) return;
    const rows = [
      [statistics.records, messages.records],
      [statistics.chunks, messages.chunks],
      [statistics.anchors, messages.anchors]
    ].filter(([value]) => typeof value === "number" && !Number.isNaN(value));
    if (!rows.length) {
      renderMessage("empty", messages.empty || "No release statistics were found.");
      return;
    }
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
    try {
      const [localeResponse, statsResponse, releaseResponse] = await Promise.all([
        fetch(`../content/${locale}.json`),
        fetch("../release/statistics.json"),
        fetch("../release/release.json")
      ]);
      if (!localeResponse.ok || !statsResponse.ok || !releaseResponse.ok) throw new Error("HTTP error");
      messages = await localeResponse.json();
      statistics = await statsResponse.json();
      release = await releaseResponse.json();
      applyMessages(locale);
    } catch (error) {
      console.error(error);
      renderMessage("error", messages.load_error || "Could not load local release data.");
    }
  }

  select.addEventListener("change", () => load(select.value));
  load(select.value);
})();
