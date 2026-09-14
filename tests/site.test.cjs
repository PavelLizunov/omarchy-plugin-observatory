const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const appCode = fs.readFileSync(path.join(__dirname, "../site/app.js"), "utf8");
const appModule = require("../site/app.js");

// 1. Direct unit tests for exported functions
test("validateStatistics: accepts valid finite non-negative integers", () => {
  const input = { records: 3086, chunks: 311, anchors: 10310 };
  const res = appModule.validateStatistics(input);
  assert.equal(res.empty, false);
  assert.equal(res.records, 3086);
  assert.equal(res.chunks, 311);
  assert.equal(res.anchors, 10310);
});

test("validateStatistics: accepts empty object as empty dataset", () => {
  const res = appModule.validateStatistics({});
  assert.equal(res.empty, true);
  assert.equal(res.records, 0);
});

test("validateStatistics: accepts all-zero counts as empty dataset", () => {
  const res = appModule.validateStatistics({ records: 0, chunks: 0, anchors: 0 });
  assert.equal(res.empty, true);
  assert.equal(res.records, 0);
});

test("validateStatistics: rejects negative counts", () => {
  assert.throws(
    () => appModule.validateStatistics({ records: -1, chunks: 311, anchors: 10310 }),
    /finite non-negative integer/
  );
});

test("validateStatistics: rejects non-integer floats", () => {
  assert.throws(
    () => appModule.validateStatistics({ records: 3086.5, chunks: 311, anchors: 10310 }),
    /finite non-negative integer/
  );
});

test("validateStatistics: rejects string numbers", () => {
  assert.throws(
    () => appModule.validateStatistics({ records: "3086", chunks: 311, anchors: 10310 }),
    /finite non-negative integer/
  );
});

test("validateStatistics: rejects NaN and Infinity", () => {
  assert.throws(
    () => appModule.validateStatistics({ records: NaN, chunks: 311, anchors: 10310 }),
    /finite non-negative integer/
  );
  assert.throws(
    () => appModule.validateStatistics({ records: Infinity, chunks: 311, anchors: 10310 }),
    /finite non-negative integer/
  );
});

test("validateStatistics: rejects non-object or null input", () => {
  assert.throws(() => appModule.validateStatistics(null), /expected a JSON object/);
  assert.throws(() => appModule.validateStatistics([1, 2, 3]), /expected a JSON object/);
  assert.throws(() => appModule.validateStatistics("string"), /expected a JSON object/);
});

test("getEditorialLocales: resolves validated safe strings from release.locales", () => {
  assert.deepEqual(appModule.getEditorialLocales({ locales: ["en", "ru"] }), ["en", "ru"]);
  // Filters out non-strings, empty strings, and unsafe identifiers
  assert.deepEqual(appModule.getEditorialLocales({ locales: ["en", 123, null, "../bad", "ru"] }), ["en", "ru"]);
});

test("getEditorialLocales: uses documented legacy fallback canonical_editorial_locales when locales is absent/empty", () => {
  assert.deepEqual(appModule.getEditorialLocales({ canonical_editorial_locales: ["en", "ru"] }), ["en", "ru"]);
  assert.deepEqual(appModule.getEditorialLocales({ locales: [], canonical_editorial_locales: ["en", "ru"] }), ["en", "ru"]);
  assert.deepEqual(appModule.getEditorialLocales({ locales: [123, {}], canonical_editorial_locales: ["en", "ru"] }), ["en", "ru"]);
});

test("getEditorialLocales: falls back to safe default [en, ru] on null/empty/invalid input", () => {
  assert.deepEqual(appModule.getEditorialLocales(null), ["en", "ru"]);
  assert.deepEqual(appModule.getEditorialLocales({}), ["en", "ru"]);
  assert.deepEqual(appModule.getEditorialLocales({ locales: "not-array" }), ["en", "ru"]);
});

// 2. DOM fixture tests executing actual site/app.js in Node VM
function createDomFixture(initialLocale = "en") {
  class MockElement {
    constructor(tagName, id = "", className = "") {
      this.tagName = tagName.toUpperCase();
      this.id = id;
      this.className = className;
      this.textContent = "";
      this.children = [];
      this.parentNode = null;
      this.attributes = new Map();
      this.dataset = {};
      this.hidden = false;
      this.value = "";
      this._eventListeners = new Map();
    }
    setAttribute(name, val) { this.attributes.set(name, String(val)); }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    addEventListener(event, fn) {
      if (!this._eventListeners.has(event)) this._eventListeners.set(event, []);
      this._eventListeners.get(event).push(fn);
    }
    dispatchEvent(event) {
      const fns = this._eventListeners.get(event.type) || [];
      for (const fn of fns) fn(event);
    }
    append(...nodes) {
      for (const node of nodes) {
        node.parentNode = this;
        this.children.push(node);
      }
    }
    replaceChildren(...nodes) {
      this.children = [];
      for (const node of nodes) {
        node.parentNode = this;
        this.children.push(node);
      }
    }
    querySelector(sel) {
      return this.querySelectorAll(sel)[0] || null;
    }
    querySelectorAll(sel) {
      const results = [];
      const match = (el) => {
        if (sel.startsWith("#") && el.id === sel.slice(1)) return true;
        if (sel.startsWith(".") && el.className && el.className.split(" ").includes(sel.slice(1))) return true;
        if (sel.startsWith("[data-i18n-aria]") && "i18nAria" in el.dataset) return true;
        if (sel.startsWith("[data-i18n]") && "i18n" in el.dataset) return true;
        return false;
      };
      const walk = (node) => {
        if (match(node)) results.push(node);
        for (const child of node.children) walk(child);
      };
      for (const child of this.children) walk(child);
      return results;
    }
  }

  const documentElement = new MockElement("html");
  documentElement.lang = initialLocale;

  const doc = {
    documentElement,
    title: "Initial Title",
    createElement(tag) { return new MockElement(tag); },
    querySelector(sel) {
      if (sel === "#language-select") return select;
      if (sel === "#stats") return stats;
      if (sel === "#translation-note") return translationNote;
      return null;
    },
    querySelectorAll(sel) {
      const results = [];
      const walk = (node) => {
        if (sel === "[data-i18n]" && "i18n" in node.dataset) results.push(node);
        if (sel === "[data-i18n-aria]" && "i18nAria" in node.dataset) results.push(node);
        for (const c of node.children) walk(c);
      };
      walk(body);
      return results;
    }
  };

  const body = new MockElement("body");
  const select = new MockElement("select", "language-select");
  select.value = initialLocale;

  const stats = new MockElement("div", "stats");
  const loadingDiv = new MockElement("div", "", "loading");
  loadingDiv.dataset.i18n = "loading";
  loadingDiv.textContent = "Loading release statistics…";
  stats.append(loadingDiv);

  const translationNote = new MockElement("p", "translation-note", "translation-note");
  translationNote.hidden = true;
  translationNote.dataset.i18n = "translation_note";

  const heroBody = new MockElement("p", "", "lede");
  heroBody.dataset.i18n = "hero_body";

  const nav = new MockElement("nav");
  nav.dataset.i18nAria = "nav_label";

  body.append(select, translationNote, heroBody, stats, nav);
  documentElement.append(body);

  return { doc, select, stats, translationNote, heroBody, nav };
}

function runInDom(dom, mockFetch, customConsole = console) {
  const sandbox = {
    document: dom.doc,
    fetch: mockFetch,
    Intl,
    console: customConsole,
    encodeURIComponent,
    Promise,
    Array,
    Object,
    Number,
    Error,
    module: { exports: {} }
  };
  vm.createContext(sandbox);
  vm.runInContext(appCode, sandbox);
  return sandbox;
}

test("DOM: successful real-data load renders stats and sets locale", async () => {
  const dom = createDomFixture("en");
  const realEn = JSON.parse(fs.readFileSync(path.join(__dirname, "../content/en.json"), "utf8"));
  const realStats = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/statistics.json"), "utf8"));
  const realRelease = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/release.json"), "utf8"));

  const mockFetch = async (url) => {
    if (url.includes("content/en.json")) return { ok: true, json: async () => realEn };
    if (url.includes("release/statistics.json")) return { ok: true, json: async () => realStats };
    if (url.includes("release/release.json")) return { ok: true, json: async () => realRelease };
    return { ok: false, status: 404 };
  };

  runInDom(dom, mockFetch);
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(dom.doc.documentElement.lang, "en");
  assert.equal(dom.translationNote.hidden, true);

  const statItems = dom.stats.querySelectorAll(".stat");
  assert.equal(statItems.length, 3);
  assert.equal(statItems[0].children[0].textContent, "3,086");
  assert.equal(statItems[0].children[1].textContent, "plugin records");
  assert.equal(statItems[1].children[0].textContent, "311");
  assert.equal(statItems[2].children[0].textContent, "10,310");
});

test("DOM: locale switch to Russian hides translation note and updates copy", async () => {
  const dom = createDomFixture("ru");
  const realRu = JSON.parse(fs.readFileSync(path.join(__dirname, "../content/ru.json"), "utf8"));
  const realStats = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/statistics.json"), "utf8"));
  const realRelease = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/release.json"), "utf8"));

  const mockFetch = async (url) => {
    if (url.includes("content/ru.json")) return { ok: true, json: async () => realRu };
    if (url.includes("release/statistics.json")) return { ok: true, json: async () => realStats };
    if (url.includes("release/release.json")) return { ok: true, json: async () => realRelease };
    return { ok: false, status: 404 };
  };

  runInDom(dom, mockFetch);
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(dom.doc.documentElement.lang, "ru");
  assert.equal(dom.translationNote.hidden, true);
  const statItems = dom.stats.querySelectorAll(".stat");
  assert.equal(statItems.length, 3);
  assert.equal(statItems[0].children[1].textContent, "записей о плагинах");
});

test("DOM: non-editorial locale (de) shows translation note", async () => {
  const dom = createDomFixture("de");
  const realDe = JSON.parse(fs.readFileSync(path.join(__dirname, "../content/de.json"), "utf8"));
  const realStats = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/statistics.json"), "utf8"));
  const realRelease = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/release.json"), "utf8"));

  const mockFetch = async (url) => {
    if (url.includes("content/de.json")) return { ok: true, json: async () => realDe };
    if (url.includes("release/statistics.json")) return { ok: true, json: async () => realStats };
    if (url.includes("release/release.json")) return { ok: true, json: async () => realRelease };
    return { ok: false, status: 404 };
  };

  runInDom(dom, mockFetch);
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(dom.doc.documentElement.lang, "de");
  assert.equal(dom.translationNote.hidden, false);
});

test("DOM: empty statistics renders empty state", async () => {
  const dom = createDomFixture("en");
  const realEn = JSON.parse(fs.readFileSync(path.join(__dirname, "../content/en.json"), "utf8"));
  const realRelease = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/release.json"), "utf8"));

  const mockFetch = async (url) => {
    if (url.includes("content/en.json")) return { ok: true, json: async () => realEn };
    if (url.includes("release/statistics.json")) return { ok: true, json: async () => ({ records: 0, chunks: 0, anchors: 0 }) };
    if (url.includes("release/release.json")) return { ok: true, json: async () => realRelease };
    return { ok: false, status: 404 };
  };

  runInDom(dom, mockFetch);
  await new Promise((r) => setTimeout(r, 20));

  const emptyMsg = dom.stats.querySelector(".empty");
  assert.ok(emptyMsg, "Empty message element should be rendered");
  assert.equal(emptyMsg.textContent, realEn.empty);
});

test("DOM: HTTP failure renders error state", async () => {
  const dom = createDomFixture("en");
  const mockFetch = async () => ({ ok: false, status: 500 });
  const quietConsole = { ...console, error: () => {} };

  runInDom(dom, mockFetch, quietConsole);
  await new Promise((r) => setTimeout(r, 20));

  const errorMsg = dom.stats.querySelector(".error");
  assert.ok(errorMsg, "Error message element should be rendered");
  assert.match(errorMsg.textContent, /could not be loaded/i);
});

test("DOM: malformed JSON renders error state", async () => {
  const dom = createDomFixture("en");
  const mockFetch = async (url) => {
    if (url.includes("content/en.json")) return { ok: true, json: async () => { throw new SyntaxError("Unexpected token"); } };
    return { ok: true, json: async () => ({}) };
  };
  const quietConsole = { ...console, error: () => {} };

  runInDom(dom, mockFetch, quietConsole);
  await new Promise((r) => setTimeout(r, 20));

  const errorMsg = dom.stats.querySelector(".error");
  assert.ok(errorMsg, "Error message element should be rendered on malformed JSON");
});

test("DOM: malformed statistics (negative integer) renders error state", async () => {
  const dom = createDomFixture("en");
  const realEn = JSON.parse(fs.readFileSync(path.join(__dirname, "../content/en.json"), "utf8"));
  const realRelease = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/release.json"), "utf8"));

  const mockFetch = async (url) => {
    if (url.includes("content/en.json")) return { ok: true, json: async () => realEn };
    if (url.includes("release/statistics.json")) return { ok: true, json: async () => ({ records: -5, chunks: 311, anchors: 10310 }) };
    if (url.includes("release/release.json")) return { ok: true, json: async () => realRelease };
    return { ok: false, status: 404 };
  };
  const quietConsole = { ...console, error: () => {} };

  runInDom(dom, mockFetch, quietConsole);
  await new Promise((r) => setTimeout(r, 20));

  const errorMsg = dom.stats.querySelector(".error");
  assert.ok(errorMsg, "Error element should be rendered when statistics count is negative");
});

test("DOM: async race / out-of-order locale resolution ignores superseded responses", async () => {
  const dom = createDomFixture("en");
  const realEn = JSON.parse(fs.readFileSync(path.join(__dirname, "../content/en.json"), "utf8"));
  const realRu = JSON.parse(fs.readFileSync(path.join(__dirname, "../content/ru.json"), "utf8"));
  const realStats = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/statistics.json"), "utf8"));
  const realRelease = JSON.parse(fs.readFileSync(path.join(__dirname, "../release/release.json"), "utf8"));

  let resolveRu;
  const slowRuPromise = new Promise((resolve) => { resolveRu = resolve; });

  const mockFetch = async (url) => {
    if (url.includes("content/ru.json")) {
      await slowRuPromise;
      return { ok: true, json: async () => realRu };
    }
    if (url.includes("content/en.json")) {
      return { ok: true, json: async () => realEn };
    }
    if (url.includes("release/statistics.json")) return { ok: true, json: async () => realStats };
    if (url.includes("release/release.json")) return { ok: true, json: async () => realRelease };
    return { ok: false, status: 404 };
  };

  const sandbox = runInDom(dom, mockFetch);
  // Initial load is 'en', wait for it
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(dom.doc.documentElement.lang, "en");

  // Trigger load('ru') which will hang on slowRuPromise
  dom.select.value = "ru";
  sandbox.module.exports.load("ru");

  // Immediately trigger load('en') which resolves quickly
  dom.select.value = "en";
  sandbox.module.exports.load("en");
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(dom.doc.documentElement.lang, "en");

  // Now let the slow 'ru' request finish
  resolveRu();
  await new Promise((r) => setTimeout(r, 20));

  // The lang must STILL be 'en' because 'ru' was superseded
  assert.equal(dom.doc.documentElement.lang, "en");
  assert.equal(dom.heroBody.textContent, realEn.hero_body);
});
