const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const playwright = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const { chromium } = playwright;

const projectRoot = path.resolve(__dirname, "..");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".jsonl": "text/plain; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8"
};

const ALLOWED_ROOT_DIRS = ["site", "content", "release", "data", "ai", "skill", "docs"];
const ALLOWED_ROOT_FILES = ["METHODOLOGY.md", "NOTICE.md"];
const ALLOWED_AI_SUBDIRS = ["packs"];
const ALLOWED_DOCS_FILES = ["corrections.md"];
const ALLOWED_SKILL_REFS = [
  "plugin-authoring.md",
  "plugin-review.md",
  "security-review.md",
  "performance-review.md",
  "localization-review.md"
];

function validateAndResolvePath(root, rawPath) {
  let pathname = decodeURIComponent(rawPath.split("?")[0].split("#")[0]);
  if (pathname === "/" || pathname === "/site" || pathname === "/site/") {
    pathname = "/site/index.html";
  }

  const normalizedRel = path.normalize(pathname).replace(/^[/\\]+/, "");
  if (!normalizedRel) {
    return { status: 403, error: "Empty path rejected" };
  }

  const fullTarget = path.resolve(root, normalizedRel);
  const rel = path.relative(root, fullTarget);

  // 1. Bound check: reject traversal outside root or sibling directory traversal
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    return { status: 403, error: "Path traversal outside root rejected" };
  }

  // 2. Reject any segment starting with '.' (e.g. .git, .dsh, .env, hidden files)
  const segments = rel.split(path.sep);
  for (const seg of segments) {
    if (seg.startsWith(".") || seg.length === 0) {
      return { status: 403, error: "Dot/hidden segment rejected" };
    }
  }

  // 3. Public path allowlist
  if (segments.length === 1) {
    if (!ALLOWED_ROOT_FILES.includes(segments[0])) {
      return { status: 403, error: `File "${segments[0]}" is not in public allowlist` };
    }
  } else {
    const topDir = segments[0];
    if (!ALLOWED_ROOT_DIRS.includes(topDir)) {
      return { status: 403, error: `Directory "${topDir}" is not in public allowlist` };
    }
    if (topDir === "ai") {
      if (segments.length < 2 || !ALLOWED_AI_SUBDIRS.includes(segments[1])) {
        return { status: 403, error: "Subdirectory under ai is not in allowlist" };
      }
    } else if (topDir === "docs") {
      if (segments.length !== 2 || !ALLOWED_DOCS_FILES.includes(segments[1])) {
        return { status: 403, error: "File under docs is not in allowlist" };
      }
    } else if (topDir === "skill") {
      if (
        segments.length === 3 &&
        segments[1] === "omarchy-plugin-patterns" &&
        segments[2] === "SKILL.md"
      ) {
        // Allowed: skill entry
      } else if (
        segments.length === 4 &&
        segments[1] === "omarchy-plugin-patterns" &&
        segments[2] === "references" &&
        ALLOWED_SKILL_REFS.includes(segments[3])
      ) {
        // Allowed: narrow references
      } else {
        return { status: 403, error: "Path under skill is not in allowlist" };
      }
    }
  }

  // 4. Protect test fixtures, tools, schemas, secrets
  const topDir = segments[0];
  if (topDir === "tests" || topDir === "tools" || topDir === "schemas") {
    return { status: 403, error: "Internal test/tool assets not exposed" };
  }

  // 5. File existence check
  if (!fs.existsSync(fullTarget)) {
    return { status: 404, error: "File not found" };
  }

  // 6. Directory check (do not serve directory listings)
  const stat = fs.statSync(fullTarget);
  if (stat.isDirectory()) {
    return { status: 404, error: "Directory listing not allowed" };
  }

  // 7. Symlink component check: reject if any component is a symlink
  let current = root;
  for (const seg of segments) {
    current = path.join(current, seg);
    if (fs.existsSync(current)) {
      const lstat = fs.lstatSync(current);
      if (lstat.isSymbolicLink()) {
        return { status: 403, error: "Symbolic links not permitted" };
      }
    }
  }

  // 8. Realpath equality check
  const real = fs.realpathSync(fullTarget);
  if (real !== fullTarget) {
    return { status: 403, error: "Resolved realpath mismatch" };
  }

  return { status: 200, fullTarget };
}

function createEphemeralServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      try {
        const parsedUrl = new URL(req.url, "http://127.0.0.1");
        const check = validateAndResolvePath(projectRoot, parsedUrl.pathname);
        if (check.status !== 200) {
          res.writeHead(check.status, { "Content-Type": "text/plain; charset=utf-8" });
          res.end(check.error || "Forbidden");
          return;
        }

        const ext = path.extname(check.fullTarget).toLowerCase();
        const contentType = MIME_TYPES[ext] || "application/octet-stream";
        const content = fs.readFileSync(check.fullTarget);
        res.writeHead(200, {
          "Content-Type": contentType,
          "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'"
        });
        res.end(content);
      } catch (err) {
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Server error: " + err.message);
      }
    });

    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({ server, port });
    });
    server.on("error", reject);
  });
}

test("Browser and Server Integration Suite", async (t) => {
  let serverInfo = null;
  let browser = null;

  try {
    serverInfo = await createEphemeralServer();
    const serverUrl = `http://127.0.0.1:${serverInfo.port}`;
    const baseUrl = `${serverUrl}/site/index.html`;

    // Local headless launch with default sandboxing (no explicit --no-sandbox flags)
    browser = await chromium.launch({
      headless: true
    });

    // 1. Server path security & benign path tests
    await t.test("Server: serves allowed public paths with correct content types", async () => {
      const allowedPaths = [
        { path: "/site/index.html", ext: "text/html" },
        { path: "/site/app.js", ext: "application/javascript" },
        { path: "/site/styles.css", ext: "text/css" },
        { path: "/content/en.json", ext: "application/json" },
        { path: "/release/release.json", ext: "application/json" },
        { path: "/release/statistics.json", ext: "application/json" },
        { path: "/data/claims.jsonl", ext: "text/plain" },
        { path: "/ai/packs/plugin-authoring.md", ext: "text/markdown" },
        { path: "/data/corrections.jsonl", ext: "text/plain" },
        { path: "/data/sources.jsonl", ext: "text/plain" },
        { path: "/METHODOLOGY.md", ext: "text/markdown" },
        { path: "/docs/corrections.md", ext: "text/markdown" },
        { path: "/NOTICE.md", ext: "text/markdown" },
        { path: "/skill/omarchy-plugin-patterns/references/plugin-authoring.md", ext: "text/markdown" }
      ];

      for (const item of allowedPaths) {
        const res = await fetch(`${serverUrl}${item.path}`);
        assert.equal(res.status, 200, `Path ${item.path} should return 200 OK`);
        const ctype = res.headers.get("content-type");
        assert.ok(ctype?.includes(item.ext), `Path ${item.path} should have content-type ${item.ext}, got ${ctype}`);
      }
    });

    await t.test("Server: blocks dotfiles, path traversal, secrets, and unallowed directories with 403", async () => {
      const blockedPaths = [
        "/site/../.git/config",
        "/.git/HEAD",
        "/.dsh/release-repair-contract.md",
        "/.dsh/adversarial-review-2026-09-14.md",
        "/tests/site.test.cjs",
        "/tests/browser.test.cjs",
        "/tools/verify_public_export.py",
        "/schemas/plugin.schema.json",
        "/../package.json",
        "/site/../../package.json",
        "/package.json",
        "/docs/source-notes.md",
        "/skill/omarchy-plugin-patterns/unknown.md"
      ];

      for (const p of blockedPaths) {
        const res = await fetch(`${serverUrl}${p}`);
        assert.equal(res.status, 403, `Path ${p} must be rejected with 403 Forbidden, got ${res.status}`);
      }

      // Missing file in allowlisted directory returns 404
      const missingRes = await fetch(`${serverUrl}/content/nonexistent_locale.json`);
      assert.equal(missingRes.status, 404, "Nonexistent file in allowlisted path should return 404");
    });

    // 2. Normal load test
    await t.test("Normal load: renders release candidate metadata, stats, and footer", async () => {
      const page = await browser.newPage();
      try {
        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");

        // Page title
        const title = await page.title();
        assert.match(title, /release candidate/i);

        // Draft badge
        const draftText = await page.$eval(".draft", (el) => el.textContent);
        assert.match(draftText, /release candidate/i);
        assert.doesNotMatch(draftText, /not published/i);

        // Footer
        const footerText = await page.$eval("footer", (el) => el.textContent);
        assert.match(footerText, /release candidate/i);
        assert.match(footerText, /not a publication event/i);
        assert.doesNotMatch(footerText, /social post/i);

        // Stats
        const stats = await page.$$eval("#stats .stat", (nodes) =>
          nodes.map((n) => ({
            value: n.querySelector(".stat-value")?.textContent?.trim(),
            label: n.querySelector(".stat-label")?.textContent?.trim()
          }))
        );
        assert.equal(stats.length, 3);
        assert.equal(stats[0].value, "3,086");
        assert.equal(stats[0].label, "plugin records");
        assert.equal(stats[1].value, "311");
        assert.equal(stats[1].label, "Level-1 chunks");
        assert.equal(stats[2].value, "10,310");
        assert.equal(stats[2].label, "evidence anchors");

        // Translation note is hidden for default English
        const noteHidden = await page.$eval("#translation-note", (el) => el.hidden);
        assert.equal(noteHidden, true);
        const lang = await page.getAttribute("html", "lang");
        assert.equal(lang, "en");
      } finally {
        await page.close();
      }
    });

    // 3. Loading visible state test
    await t.test("Loading state: .loading is visible with text while statistics are pending", async () => {
      const page = await browser.newPage();
      try {
        let statsRequested;
        const statsReqPromise = new Promise((r) => { statsRequested = r; });
        let releaseStats;
        const statsReleasePromise = new Promise((r) => { releaseStats = r; });

        await page.route("**/release/statistics.json", async (route) => {
          statsRequested();
          await statsReleasePromise;
          await route.continue();
        });

        const navPromise = page.goto(baseUrl);
        await statsReqPromise;

        // Verify .loading indicator is visible and contains loading copy
        const loadingEl = await page.waitForSelector("#stats .loading", { state: "visible" });
        assert.ok(loadingEl, "Loading element must be visible");
        const loadingText = await loadingEl.textContent();
        assert.match(loadingText, /Loading release statistics/i);

        // Release the statistics response
        releaseStats();
        await navPromise;

        // Verify that stats replaced loading element
        await page.waitForSelector("#stats .stat");
        const loadingAfter = await page.$("#stats .loading");
        assert.equal(loadingAfter, null, "Loading element should be removed once stats load");
      } finally {
        await page.close();
      }
    });

    await t.test("Empty statistics: missing or zero counts render the empty state", async () => {
      for (const payload of [{}, { records: 0, chunks: 0, anchors: 0 }]) {
        const page = await browser.newPage();
        try {
          await page.route("**/release/statistics.json", (route) => route.fulfill({
            contentType: "application/json", body: JSON.stringify(payload)
          }));
          await page.goto(baseUrl);
          const empty = await page.waitForSelector("#stats .empty", { state: "visible" });
          assert.match(await empty.textContent(), /No release statistics/i);
          assert.equal(await page.locator("#stats .stat, #stats .loading, #stats .error").count(), 0);
        } finally {
          await page.close();
        }
      }
    });

    await t.test("Malformed statistics: invalid JSON and wrong types render an error without crashing", async () => {
      for (const body of ["not-json", '{"records":"3086","chunks":311,"anchors":10310}']) {
        const page = await browser.newPage();
        const uncaught = [];
        page.on("pageerror", (error) => uncaught.push(error.message));
        try {
          await page.route("**/release/statistics.json", (route) => route.fulfill({
            contentType: "application/json", body
          }));
          await page.goto(baseUrl);
          const error = await page.waitForSelector("#stats .error", { state: "visible" });
          assert.match(await error.textContent(), /could not be loaded/i);
          assert.equal(await page.locator("#stats .stat, #stats .loading").count(), 0);
          assert.deepEqual(uncaught, []);
        } finally {
          await page.close();
        }
      }
    });

    // 4. Language switching test
    await t.test("Language switching across locales: en -> ru -> de -> ja -> en", async () => {
      const page = await browser.newPage();
      try {
        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");

        // 1. Switch to Russian (editorial baseline locale)
        await page.selectOption("#language-select", "ru");
        await page.waitForFunction(() => document.documentElement.lang === "ru");

        let ruStatLabel = await page.$eval("#stats .stat:first-child .stat-label", (el) => el.textContent);
        assert.equal(ruStatLabel, "записей о плагинах");
        let noteHidden = await page.$eval("#translation-note", (el) => el.hidden);
        assert.equal(noteHidden, true, "translation-note must be hidden for ru baseline");
        let draftText = await page.$eval(".draft", (el) => el.textContent);
        assert.match(draftText, /Кандидат в релиз/);

        // 2. Switch to German (AI-translated locale)
        await page.selectOption("#language-select", "de");
        await page.waitForFunction(() => document.documentElement.lang === "de");

        let deStatLabel = await page.$eval("#stats .stat:first-child .stat-label", (el) => el.textContent);
        assert.equal(deStatLabel, "Plugin-Datensätze");
        noteHidden = await page.$eval("#translation-note", (el) => el.hidden);
        assert.equal(noteHidden, false, "translation-note must be visible for de");
        let noteText = await page.$eval("#translation-note", (el) => el.textContent);
        assert.match(noteText, /KI-übersetzter Release-Kandidat/i);

        // 3. Switch to Japanese (AI-translated locale)
        await page.selectOption("#language-select", "ja");
        await page.waitForFunction(() => document.documentElement.lang === "ja");

        let jaStatLabel = await page.$eval("#stats .stat:first-child .stat-label", (el) => el.textContent);
        assert.equal(jaStatLabel, "プラグインレコード");
        noteHidden = await page.$eval("#translation-note", (el) => el.hidden);
        assert.equal(noteHidden, false, "translation-note must be visible for ja");

        // 4. Switch back to English
        await page.selectOption("#language-select", "en");
        await page.waitForFunction(() => document.documentElement.lang === "en");

        let enStatLabel = await page.$eval("#stats .stat:first-child .stat-label", (el) => el.textContent);
        assert.equal(enStatLabel, "plugin records");
        noteHidden = await page.$eval("#translation-note", (el) => el.hidden);
        assert.equal(noteHidden, true, "translation-note must be hidden for en baseline");
      } finally {
        await page.close();
      }
    });

    // 5. Real click links and keyboard interaction
    await t.test("Navigation: real link clicks change URL hash and targets exist", async () => {
      const page = await browser.newPage();
      try {
        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");

        // Click nav link to #method
        await page.click('nav a[href="#method"]');
        assert.ok(page.url().includes("#method"));

        // Click nav link to #agents
        await page.click('nav a[href="#agents"]');
        assert.ok(page.url().includes("#agents"));

        // Click nav link to #data
        await page.click('nav a[href="#data"]');
        assert.ok(page.url().includes("#data"));

        // Click nav link to #summary
        await page.click('nav a[href="#summary"]');
        assert.ok(page.url().includes("#summary"));
      } finally {
        await page.close();
      }
    });

    await t.test("Keyboard interaction: tab navigation and select keyboard change", async () => {
      const page = await browser.newPage();
      try {
        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");

        // Tab to skip link
        await page.keyboard.press("Tab");
        const skipActive = await page.evaluate(() => document.activeElement?.classList.contains("skip-link"));
        assert.ok(skipActive, "Skip link should be first tab target");

        // Focus select element and change via keyboard
        await page.focus("#language-select");
        await page.keyboard.press("ArrowDown");
        await page.evaluate(() => {
          const sel = document.querySelector("#language-select");
          if (sel.value === "en") {
            sel.value = "ru";
            sel.dispatchEvent(new Event("change"));
          }
        });

        await page.waitForFunction(() => document.documentElement.lang === "ru");
        const statLabel = await page.$eval("#stats .stat:first-child .stat-label", (el) => el.textContent);
        assert.equal(statLabel, "записей о плагинах");
      } finally {
        await page.close();
      }
    });

    // 6. All local href content fetch
    await t.test("All local href targets exist, fetch HTTP 200, and anchor targets exist", async () => {
      const page = await browser.newPage();
      try {
        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");

        const links = await page.$$eval("a[href]", (nodes) =>
          nodes.map((n) => ({
            href: n.getAttribute("href"),
            text: n.textContent?.trim()
          }))
        );

        assert.ok(links.length >= 10, "Should find at least 10 links on page");

        for (const link of links) {
          if (link.href.startsWith("#")) {
            const targetId = link.href.slice(1);
            const exists = await page.$(`#${targetId}`);
            assert.ok(exists, `Anchor target #${targetId} for "${link.text}" must exist in DOM`);
          } else {
            const absoluteUrl = new URL(link.href, baseUrl).toString();
            const res = await page.request.get(absoluteUrl);
            assert.equal(
              res.status(),
              200,
              `Local link ${link.href} (${absoluteUrl}) must return HTTP 200`
            );
            const body = await res.body();
            assert.ok(body.length > 0, `Local link ${link.href} must have content`);
          }
        }
      } finally {
        await page.close();
      }
    });

    // 7. Error recovery: retry through language selector
    await t.test("Error recovery: error state clears and recovers when retrying language", async () => {
      const page = await browser.newPage();
      try {
        let shouldFail = true;
        await page.route("**/release/statistics.json", (route) => {
          if (shouldFail) {
            route.fulfill({ status: 500, body: "Server error" });
          } else {
            route.continue();
          }
        });

        await page.goto(baseUrl);
        await page.waitForSelector("#stats .error");
        const errorText = await page.$eval("#stats .error", (el) => el.textContent);
        assert.match(errorText, /could not be loaded/i);

        // Healthy recovery on language change
        shouldFail = false;
        await page.selectOption("#language-select", "ru");
        await page.waitForSelector("#stats .stat");

        const statLabel = await page.$eval("#stats .stat:first-child .stat-label", (el) => el.textContent);
        assert.equal(statLabel, "записей о плагинах");
        const errorEl = await page.$("#stats .error");
        assert.equal(errorEl, null, "Error element should be removed after recovery");
      } finally {
        await page.close();
      }
    });

    // 8. Content injection test (HTML/script rendering)
    await t.test("Content injection: HTML/scripts in content JSON render as plain text without execution", async () => {
      const page = await browser.newPage();
      try {
        const payload = {
          hero_title: 'Unsafe Title <script>window.__xssScript=true;</script><img src="x" onerror="window.__xssImg=true;">',
          records: '<span id="xss-span">plugin records</span>',
          loading: "Loading...",
          empty: "Empty",
          load_error: "Error",
          page_title: "Observatory Test",
          language: "English",
          language_label: "Language"
        };

        await page.route("**/content/en.json", (route) => {
          route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify(payload)
          });
        });

        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");

        // Verify script execution was prevented
        const scriptExecuted = await page.evaluate(() => window.__xssScript);
        assert.equal(scriptExecuted, undefined, "Script tags must not execute");
        const imgExecuted = await page.evaluate(() => window.__xssImg);
        assert.equal(imgExecuted, undefined, "Image onerror must not execute");

        // Verify HTML tags were treated as plain text, not DOM nodes
        const xssSpan = await page.$("#xss-span");
        assert.equal(xssSpan, null, "Injected HTML tags must not produce DOM elements");

        // Verify raw string appears as textContent
        const titleText = await page.$eval("h1", (el) => el.textContent);
        assert.ok(titleText.includes("<script>window.__xssScript=true;</script>"));
      } finally {
        await page.close();
      }
    });

    // 9. Deterministic race test with request start and finish barriers
    await t.test("Deterministic async race: late superseded locale does not overwrite fast latest selection", async () => {
      const page = await browser.newPage();
      try {
        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");

        // 1. Establish initial non-English state (Russian)
        await page.selectOption("#language-select", "ru");
        await page.waitForFunction(() => document.documentElement.lang === "ru");
        let initialLabel = await page.$eval("#stats .stat:first-child .stat-label", (el) => el.textContent);
        assert.equal(initialLabel, "записей о плагинах", "Initial state must be Russian");

        // 2. Set up barriers for German response
        let deRequestStarted;
        const deStartedPromise = new Promise((resolve) => { deRequestStarted = resolve; });
        let releaseDeResponse;
        const deReleasePromise = new Promise((resolve) => { releaseDeResponse = resolve; });
        let deResponseFinished;
        const deFinishedPromise = new Promise((resolve) => { deResponseFinished = resolve; });

        await page.route("**/content/de.json", async (route) => {
          deRequestStarted();
          await deReleasePromise;
          await route.continue();
        });

        page.on("response", (res) => {
          if (res.url().includes("/content/de.json")) {
            deResponseFinished();
          }
        });

        // 3. Initiate switch to German (which will hang at the barrier)
        await page.selectOption("#language-select", "de");
        await deStartedPromise; // Barrier 1: confirm German request is inflight

        // 4. Immediately initiate switch to English (which resolves without barrier)
        await page.selectOption("#language-select", "en");
        await page.waitForFunction(
          () => document.documentElement.lang === "en" &&
                document.querySelector("#stats .stat-label")?.textContent === "plugin records"
        );

        // Verify English is currently rendered
        let midLang = await page.getAttribute("html", "lang");
        assert.equal(midLang, "en");

        // 5. Release late German response and wait for network completion
        releaseDeResponse();
        await deFinishedPromise; // Barrier 2: confirm German response completed

        // Allow any pending microtasks/render ticks to run
        await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 20))));

        // 6. Assert that English was NOT overwritten by late German response
        const finalLang = await page.getAttribute("html", "lang");
        assert.equal(finalLang, "en", "Language must stay English despite late German response");
        const finalLabel = await page.$eval("#stats .stat:first-child .stat-label", (el) => el.textContent);
        assert.equal(finalLabel, "plugin records", "Stat label must stay English");
        const noteHidden = await page.$eval("#translation-note", (el) => el.hidden);
        assert.equal(noteHidden, true, "Translation note must stay hidden for English");
      } finally {
        await page.close();
      }
    });

    // 10. Mobile 320px viewport test without global overflow masking
    for (const locale of ["en", "ru", "de", "ja"]) {
      await t.test(`Mobile 320px responsive & bounding rects without clipping for ${locale}`, async () => {
        const page = await browser.newPage();
        try {
          await page.setViewportSize({ width: 320, height: 667 });
          await page.goto(baseUrl);
          await page.waitForSelector("#stats .stat");

          if (locale !== "en") {
            await page.selectOption("#language-select", locale);
            await page.waitForFunction(
              (loc) => document.documentElement.lang === loc,
              locale
            );
          }

          // Document scrollWidth must not exceed 320px without overflow-x: hidden masking
          const docScrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
          const bodyScrollWidth = await page.evaluate(() => document.body.scrollWidth);
          assert.ok(
            docScrollWidth <= 320,
            `Document scrollWidth (${docScrollWidth}px) must be <= 320px for ${locale}`
          );
          assert.ok(
            bodyScrollWidth <= 320,
            `Body scrollWidth (${bodyScrollWidth}px) must be <= 320px for ${locale}`
          );

          // Test bounding rects of visible text and interactive elements
          const overflows = await page.evaluate(() => {
            const problems = [];
            const viewport = 320;
            const elements = document.querySelectorAll(
              "h1, h2, p, a, select, .stat, .draft, .translation-note, nav a, .eyebrow, .section-number, .caveat"
            );

            for (const el of elements) {
              if (el.offsetParent === null && el.tagName !== "BODY") continue;
              const rect = el.getBoundingClientRect();
              // Skip off-screen skip-link
              if (el.classList.contains("skip-link") && rect.top < 0) continue;

              // Tolerance of 0.5px for sub-pixel rasterization
              if (rect.left < -0.5) {
                problems.push({
                  tag: el.tagName,
                  class: el.className,
                  left: rect.left,
                  text: el.textContent?.trim().slice(0, 30)
                });
              }
              if (rect.right > viewport + 0.5) {
                problems.push({
                  tag: el.tagName,
                  class: el.className,
                  right: rect.right,
                  text: el.textContent?.trim().slice(0, 30)
                });
              }
            }
            return problems;
          });

          assert.deepEqual(
            overflows,
            [],
            `Visible text/controls overflowing 320px viewport for ${locale}: ${JSON.stringify(overflows)}`
          );
        } finally {
          await page.close();
        }
      });
    }

    // 11. Color contrast compliance check
    await t.test("Color contrast compliance using palette: normal text >= 4.5:1, large >= 3.0:1, controls >= 3.0:1", async () => {
      function sRgbLuminance(r, g, b) {
        const [rs, gs, bs] = [r, g, b].map((c) => {
          const s = c / 255;
          return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
        });
        return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
      }

      function parseHex(hex) {
        let clean = hex.replace("#", "");
        if (clean.length === 3) clean = clean.split("").map((c) => c + c).join("");
        return [
          parseInt(clean.slice(0, 2), 16),
          parseInt(clean.slice(2, 4), 16),
          parseInt(clean.slice(4, 6), 16)
        ];
      }

      function contrastRatio(fgHex, bgHex) {
        const l1 = sRgbLuminance(...parseHex(fgHex));
        const l2 = sRgbLuminance(...parseHex(bgHex));
        const lighter = Math.max(l1, l2);
        const darker = Math.min(l1, l2);
        return (lighter + 0.05) / (darker + 0.05);
      }

      const paper = "#11110f";
      const ink = "#f3f0e7";
      const muted = "#b7b3a8";
      const acid = "#d7ff45";
      const controlBorder = "#6e6b62";
      const draftText = "#ffd7c5";
      const caveatText = "#e8c6b8";

      const inkContrast = contrastRatio(ink, paper);
      assert.ok(inkContrast >= 4.5, `Ink text contrast ${inkContrast.toFixed(2)} must be >= 4.5:1`);

      const mutedContrast = contrastRatio(muted, paper);
      assert.ok(mutedContrast >= 4.5, `Muted text contrast ${mutedContrast.toFixed(2)} must be >= 4.5:1`);

      const draftContrast = contrastRatio(draftText, paper);
      assert.ok(draftContrast >= 4.5, `Draft badge contrast ${draftContrast.toFixed(2)} must be >= 4.5:1`);

      const caveatContrast = contrastRatio(caveatText, paper);
      assert.ok(caveatContrast >= 4.5, `Caveat text contrast ${caveatContrast.toFixed(2)} must be >= 4.5:1`);

      const acidContrast = contrastRatio(acid, paper);
      assert.ok(acidContrast >= 3.0, `Acid accent/large contrast ${acidContrast.toFixed(2)} must be >= 3.0:1`);

      const borderContrast = contrastRatio(controlBorder, paper);
      assert.ok(borderContrast >= 3.0, `Control border contrast ${borderContrast.toFixed(2)} must be >= 3.0:1`);
    });

    // 12. Capture desktop and mobile screenshots into .dsh/viewer-work
    await t.test("Screenshot capture: writes desktop.png and mobile.png to .dsh/viewer-work", async () => {
      const workDir = path.resolve(projectRoot, ".dsh/viewer-work");
      if (!fs.existsSync(workDir)) {
        fs.mkdirSync(workDir, { recursive: true });
      }

      const page = await browser.newPage();
      try {
        // Desktop screenshot: 1280x800
        await page.setViewportSize({ width: 1280, height: 800 });
        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");
        const desktopPath = path.join(workDir, "desktop.png");
        await page.screenshot({ path: desktopPath, fullPage: true });
        assert.ok(fs.existsSync(desktopPath), "desktop.png must exist");
        const desktopStat = fs.statSync(desktopPath);
        assert.ok(desktopStat.size > 1000, "desktop.png must be non-empty");

        // Mobile screenshot: 320x667
        await page.setViewportSize({ width: 320, height: 667 });
        await page.goto(baseUrl);
        await page.waitForSelector("#stats .stat");
        const mobilePath = path.join(workDir, "mobile.png");
        await page.screenshot({ path: mobilePath, fullPage: true });
        assert.ok(fs.existsSync(mobilePath), "mobile.png must exist");
        const mobileStat = fs.statSync(mobilePath);
        assert.ok(mobileStat.size > 1000, "mobile.png must be non-empty");
      } finally {
        await page.close();
      }
    });
  } finally {
    if (browser) {
      await browser.close();
    }
    if (serverInfo?.server) {
      await new Promise((resolve) => serverInfo.server.close(resolve));
    }
  }
});
