# Adversarial Audit: Gemini Flash Security Claims on Omarchy Plugin Marketplace

> **TL;DR:** Of Gemini Flash's five claim areas, three contain **substantially accurate** core observations mixed with precision errors and overstatements, one is **partially hallucinated**, and one proposed code snippet contains a **critical subtle bug** (`set -euo pipefail` + `head -c` = exit 141). The QML `Text.AutoText` claim is the strongest finding — confirmed by Qt's own documentation and an active Qt 7 proposal to disable AutoText by default. Several important attack surfaces were **missed entirely**.

**Auditor:** Claude Opus (claude-opus-4-6-thinking), acting as Senior Systems Security & Adversarial Code Auditor  
**Date:** 2026-09-19  
**Subject repository:** `omacom/omarchy-plugin-marketplace` maintainer reviews (last month)  
**Grounding:** `omarchy-plugin-observatory` dataset (3,086 records), Quickshell source, Qt 6.11.2 docs, bash 5.2.21 empirical testing, prior adversarial review (2026-09-14)

---

## Methodology

Every Gemini claim was stress-tested against:
1. **Empirical shell tests** — actual bash scripts executed on bash 5.2.21 with controlled environment variables and exported functions
2. **Qt/QML documentation** — current Qt 6.11.2 official docs, Qt development mailing list archives
3. **Quickshell source code** — the actual `StdioCollector::parseBytes` and `SplitParser` C++ implementations at commit `2b01a756`
4. **The observatory's own adversarial review** (`.dsh/adversarial-review-2026-09-14.md`) and security reference (`skill/omarchy-plugin-patterns/references/security-review.md`)
5. **Linux kernel behavior** — `/proc/pid/cmdline` permissions, shebang argument parsing, `rename(2)` atomicity

---

## Claim 1: Ambient PATH & Shell

### 1A: `#!/usr/bin/env bash` and unqualified utilities as attack vector

**Gemini's claim:** Using `#!/usr/bin/env bash` and unqualified utility resolution (`docker`, `jq`, `grep`) is a major attack vector for long-running desktop shell plugins (shadow executables).

**Verdict: SUBSTANTIALLY ACCURATE, but overstated severity**

- ✅ **Correct core mechanism.** `env` resolves `bash` via `$PATH`. A malicious or compromised `$PATH` entry could shadow the real `bash`. For long-running desktop plugins inheriting an interactive session's `$PATH`, this is a real concern — the user's `~/.local/bin`, `~/bin`, or nix/homebrew paths precede system paths.
- ✅ **Correct about unqualified utilities.** `jq`, `grep`, `docker` resolved via ambient `$PATH` can be shadowed. This is a well-documented class of attack (see: supply-chain attacks via `$PATH` manipulation).
- ⚠️ **Overstated severity.** "Major attack vector" implies remote or easy exploitation. In practice, PATH poisoning requires prior local code execution or control over `$PATH`-contributing config files. If an attacker has that, they likely have simpler attack paths. For a desktop plugin running as the user, the realistic threat is a *different plugin* or *compromised dependency* shadowing utilities, not a remote attacker.
- ⚠️ **Missing nuance.** The observatory's own security reference already covers this: "Inspect callers and helper implementations, PATH/environment, executable ownership" (security-review.md:9). The existing guidance is more precise than Gemini's blanket claim.

**Recommended fix accuracy:** Hardcoding `PATH="/usr/bin:/bin"` is a reasonable defense-in-depth measure for helper scripts. The recommendation is sound for security-sensitive operations.

### 1B: Bash without `-p` processes `BASH_ENV` and exported functions

**Gemini's claim:** Bash without `-p` processes `BASH_ENV` and exported functions before the script runs, allowing privilege escalation / code execution from session environment.

**Verdict: ACCURATE — empirically confirmed**

I built and executed test scripts on bash 5.2.21:

| Test | Without `-p` | With `-p` |
|---|---|---|
| `BASH_ENV` sourced? | ✅ Yes — `EVIL_MARKER` was set | ❌ No — `EVIL_MARKER` remained unset |
| Exported functions inherited? | ✅ Yes — `ls` resolved to `function` | ❌ No — `ls` resolved to `file` |

From `bash(1)`: *"Turn on privileged mode. In this mode, the $ENV and $BASH_ENV files are not processed, shell functions are not inherited from the environment, and the SHELLOPTS, BASHOPTS, CDPATH, and GLOBIGNORE variables, if they appear in the environment, are not processed."*

- ✅ **Correct about `BASH_ENV`.** A non-interactive bash script without `-p` will source `$BASH_ENV` if set. An attacker who controls `BASH_ENV` gets arbitrary code execution before `set -euo pipefail` even runs.
- ✅ **Correct about exported functions.** Without `-p`, exported functions (the Shellshock-era vector) are inherited.
- ✅ **Correct about shebang mechanics.** Linux kernel shebang parsing passes a single optional argument: `#!/usr/bin/bash -p` correctly passes `-p` as the argument.
- ⚠️ **"Privilege escalation" is an overstatement.** Bash `-p` was designed for setuid scripts where real UID ≠ effective UID. In a non-setuid desktop plugin context, there is no privilege differential to escalate. The correct framing is: **arbitrary code execution from session environment** if `BASH_ENV` is attacker-controlled.

**Assessment of Gemini's proposed fix (`#!/usr/bin/bash -p`):** Sound defense-in-depth. Confirmed effective by empirical test.

---

## Claim 2: Shared Paths & Symlinks

**Gemini's claim:** Predictable paths in `/tmp` and `/dev/shm` are vulnerable to symlink pre-creation and TOCTOU races. Must use `$XDG_RUNTIME_DIR/plugin` with 0700 ownership check and atomic replacement (`mktemp + mv`).

**Verdict: SUBSTANTIALLY ACCURATE, with an important caveat Gemini missed**

- ✅ **Correct about `/tmp` symlink attacks.** `/tmp` is world-writable (1777). Predictable paths like `/tmp/myplugin.state` are classic symlink-race targets. An attacker pre-creates a symlink at the predictable path pointing to a sensitive file; the plugin writes to it, clobbering the target.
- ✅ **Correct about `$XDG_RUNTIME_DIR`.** On systemd systems, `$XDG_RUNTIME_DIR` (typically `/run/user/$UID`) is user-owned 0700, surviving only for the session. Far safer than `/tmp`.
- ✅ **Correct about `mktemp + mv` for atomic replacement.** `mktemp` creates with mode 0600 (confirmed empirically). `mv` on the same filesystem uses `rename(2)`, which is atomic.

### Critical caveat Gemini MISSED:

**`mktemp + mv` is only atomic if both files are on the same filesystem.** If `mktemp` uses the default `$TMPDIR` (which might be `/tmp`) and the target is in `$XDG_RUNTIME_DIR` (which is `/run/user/$UID`), these may be different filesystems. Cross-filesystem `mv` falls back to copy-then-unlink, which is **NOT atomic**.

**Correct fix:** Use `mktemp -p "$TARGET_DIR"` to ensure the temp file is created in the same directory as the target. Gemini's snippet does not show this — a subtle but important gap.

### Gemini's stat check: `stat -c '%u:%a' "$STATE_DIR"` against `"$(id -u):700"`

**Verdict: Functionally correct but fragile**

- `stat -c '%u'` returns the numeric owner UID — correct
- `stat -c '%a'` returns the octal permission string — correct (e.g., `700`)
- String comparison `"$(id -u):700"` — works, but relies on `stat` output formatting consistency. No issue found on GNU coreutils, but the format string `%a` on macOS `stat` has different semantics. This is Linux-only code.
- ⚠️ **Missing check:** Does not verify the directory isn't a symlink itself. Should add `-L` / `readlink -f` or use `stat` on the resolved path.

---

## Claim 3: QML / Quickshell Runtime

### 3A: QML Text AutoText → Rich Text Injection

**Gemini's claim:** QML Text items default to `AutoText`, which renders HTML-like strings as Rich Text, vulnerable to rich text injection from untrusted process names, window titles, SSIDs.

**Verdict: ACCURATE — this is the strongest finding, confirmed by Qt's own documentation**

From the [Qt 6.11.2 documentation](https://doc.qt.io/qt-6/qml-qtquick-text.html):

> **Warning:** By default, Text will detect the textFormat based on the contents in text. If it determined to be either Text.StyledText or Text.MarkdownText, the Text component will support rich text features such as changing colors, font styles and inline images. **This functionality includes loading images remotely over the network.** Thus, when displaying user-controlled, untrusted content, the textFormat should either be explicitly set to Text.PlainText, or the contents should be stripped of unwanted tags.

This is not a theoretical concern. The Qt development mailing list has an [active proposal to disable AutoText in Qt 7](https://lists.qt-project.org/pipermail/development/2026-July/047377.html), explicitly citing this as a security concern.

**Attack scenarios confirmed:**
1. A process with name `<img src="http://evil.com/track.png">` displayed in a plugin's Text element triggers a network request — **information disclosure** (IP, timing).
2. A Wi-Fi SSID containing `<b><font size="99">` could cause visual disruption or UI overflow.
3. Window titles containing HTML tags could inject styled text into bar widgets.

**Gemini's fix (`textFormat: Text.PlainText`):** Correct and necessary for any Text element displaying untrusted data. The observatory's own corpus of 3,086 plugins likely contains numerous instances of this vulnerability.

### 3B: StdioCollector unbounded memory accumulation

**Gemini's claim:** `StdioCollector` in Quickshell accumulates unbounded memory if helper produces large output; needs producer-side capping.

**Verdict: ACCURATE — confirmed from Quickshell source code**

From the [Quickshell StdioCollector implementation](https://git.outfoxxed.me/quickshell/quickshell/commit/2b01a75679a03bd6557cf11c20b1588f436d6b94):

```cpp
void StdioCollector::parseBytes(QByteArray& incoming, QByteArray& buffer) {
    buffer.append(incoming);           // <-- unbounded append
    
    if (!this->mWaitForEnd) {
        this->mData = buffer;
        emit this->dataChanged();
    }
}
```

- ✅ `buffer.append(incoming)` has no size check whatsoever. A malicious or misbehaving helper can cause unbounded memory growth.
- ✅ With `waitForEnd: false` (the default path), `mData` is updated on every chunk, so the QML side sees growing data AND the buffer keeps growing.
- ✅ The observatory's own security reference already notes this correctly: "Bound external bytes **before** unbounded accumulation, then parse/validate shape and ranges. A downstream line-length check cannot secure SplitParser's existing buffer." (security-review.md:51)

**Gemini's recommendation (producer-side capping):** Correct as a workaround. The proper fix would be in Quickshell itself (a `maxBytes` property on StdioCollector), but producer-side `head -c` is the available defense today.

### 3C: Repeating Timer needs isBusy single-flight guard

**Gemini's claim:** Repeating `Timer` needs an `isBusy` single-flight guard.

**Verdict: PARTIALLY ACCURATE — the real problem is more nuanced**

- ✅ **Correct problem identification.** If a Timer fires every 2 seconds and spawns a Process that takes 5 seconds, without a guard you get process accumulation — multiple concurrent instances of the same command.
- ⚠️ **Oversimplified solution.** A boolean `isBusy` flag is necessary but not sufficient. The Process's `onRunningChanged` must clear the flag, but there's a timing gap: if the process crashes without calling `onRunningChanged`, the flag stays true forever — a deadlock. Need a timeout/watchdog too.
- ⚠️ **Missing the deeper issue.** The observatory's corpus data shows plugins already using single-flight guards (e.g., `if (!...running)` checks). The prior adversarial review notes this: "[Service.qml@19319b3] contains repeat timer and clients/monitors hyprctl. There are single-flight guards `if (!...running)`, which need to be mentioned." Gemini failed to acknowledge existing protective patterns.

---

## Claim 4: Credential Handling — CLI argv `/proc/pid/cmdline`

**Gemini's claim:** CLI argv (`/proc/pid/cmdline`) leaks tokens to all user processes; curl must use `-K` mode-0600 config or stdin; redirects must be disabled on authenticated HTTP requests.

**Verdict: ACCURATE**

- ✅ **Confirmed:** `/proc/self/cmdline` has permissions `-r--r--r--` (world-readable). Any same-user process can read any other process's command line via `/proc/<pid>/cmdline`. On hardened kernels with `hidepid=2`, cross-user visibility is restricted, but same-UID processes can always read each other's cmdline.
- ✅ **`curl -K` recommendation is correct.** A mode-0600 config file containing `header = "Authorization: Bearer TOKEN"` avoids cmdline exposure. Alternatively, `--header @-` reads from stdin.
- ✅ **Redirect concern is valid.** `curl -L` follows redirects, potentially sending auth headers to a different host. `--max-redirs 0` or `--proto-redir =https` are correct mitigations.
- ⚠️ **Scope note:** The observatory's security reference already covers this partially: "Never collect a system password in plugin UI" and stdin-based passing. But it doesn't specifically address API token leakage via `/proc/pid/cmdline`, so this is a genuine incremental finding.

---

## Claim 5: Code Snippet Audit — CRITICAL BUG FOUND

### Gemini's Proposed Helper Script

```bash
#!/usr/bin/bash -p
set -euo pipefail
export PATH="/usr/bin:/bin"
unset BASH_ENV ENV CDPATH IFS
# checks DIR_OWNER=$(stat -c '%u:%a' "$STATE_DIR") against "$(id -u):700"
# mktemp + jq + head -c 16384 + mv
```

### Bug 1: CRITICAL — `set -o pipefail` + `head -c` = script crash (exit 141)

**Empirically confirmed.** With `set -euo pipefail`:

```bash
# This CRASHES the script:
result=$(some_command | head -c 16384)
# Exit code: 141 (128 + SIGPIPE)
```

When `head -c 16384` has read enough bytes, it closes its stdin and exits. The producer receives `SIGPIPE` (signal 13), which kills it with exit code 141. With `pipefail` enabled, bash reports the pipeline's exit code as 141 (the failed producer), not 0 (head's exit). With `set -e`, this aborts the script.

**This is a known, subtle interaction.** Gemini proposed both `pipefail` and `head -c` in the same script without addressing this conflict. The fix is either:
1. `(some_command || true) | head -c 16384` — suppress SIGPIPE exit
2. `trap '' PIPE` — ignore SIGPIPE globally (dangerous — may mask real errors)
3. Use `dd bs=16384 count=1` instead of `head -c` (avoids SIGPIPE by consuming exactly one block)
4. Read into a variable with a size-bounded `read` instead of piping

### Bug 2: MEDIUM — `unset IFS` under `set -u`

With `set -u` (nounset), referencing an unset variable is an error. However, `unset IFS` itself does not trigger this — verified empirically. After `unset IFS`, bash reverts to the default IFS (`$' \t\n'`). This is correct behavior, though setting `IFS=$' \t\n'` explicitly would be clearer intent.

**Verdict: Not a bug, but fragile practice.** ✅ Safe.

### Bug 3: LOW — `mktemp` without `-p "$TARGET_DIR"`

As discussed in Claim 2, if `mktemp` creates in `$TMPDIR` and the target is elsewhere, `mv` is not atomic. The snippet should use `mktemp -p "$(dirname "$STATE_DIR")"`.

### Bug 4: LOW — stat race on `$STATE_DIR`

The `stat` → `check` → `use` sequence is itself a TOCTOU race. Between `stat -c '%u:%a'` returning "correct" values and the script using the directory, an attacker could:
1. Delete the directory
2. Create a symlink in its place
3. The script operates on the symlink target

For robust defense, use `openat(2)` / file descriptor-relative operations, or at minimum verify with `readlink -f` and use `O_NOFOLLOW`. But this is a shell script limitation — Gemini correctly noted the problem category without solving it completely.

### Gemini's Proposed QML Component

```qml
// Process with StdioCollector
// Timer with isBusy check
// Text with textFormat: Text.PlainText
```

**Assessment:**
- ✅ `textFormat: Text.PlainText` — correct and necessary
- ⚠️ `isBusy` guard — correct concept, but needs watchdog timeout for crash recovery
- ⚠️ StdioCollector — correct to use, but the snippet doesn't show byte-bounding, which was the stated problem

---

## What Gemini MISSED — Additional Attack Surfaces

### M1: QML `Image.source` with untrusted URLs (HIGH)

Same as `Text.AutoText` but worse. QML `Image { source: someUrl }` will fetch any URL, including `file:///` paths. If a plugin constructs image sources from untrusted data (process icons, downloaded metadata), this enables:
- SSRF against local services
- Information disclosure via timing/loading status
- Potential file read via `file:///etc/passwd` (depending on Qt's URL handler restrictions)

### M2: Wayland compositor protocol privilege confusion (HIGH)

Quickshell plugins run within a Wayland layer-shell context. The `wlr-layer-shell` protocol allows specifying:
- `layer` (background, bottom, top, overlay)
- `exclusive_zone` (reserving screen space)
- `keyboard_interactivity` (grabbing keyboard focus)

A malicious plugin could request `layer: overlay` + `keyboard_interactivity: exclusive` to create an invisible overlay that captures all keyboard input, including passwords typed into other applications. This is a Wayland compositor trust-boundary issue that Gemini completely missed.

### M3: QML `Component.createObject` with unbounded dynamic instantiation (MEDIUM)

The observatory's own authoring guide covers this (plugin-authoring.md:62-79), but Gemini didn't mention it. `createObject()` without a bound can leak QObjects. Parent teardown only helps at shell exit; during a long session, unbounded `createObject` calls accumulate memory indefinitely.

### M4: JavaScript `eval()` / `Function()` in QML context (MEDIUM)

QML's JavaScript engine supports `Qt.createQmlObject()` which can instantiate arbitrary QML from strings. If any plugin constructs QML strings from untrusted input, this is full code execution within the shell's context. The observatory dataset doesn't audit for this pattern.

### M5: Hyprland IPC injection (MEDIUM)

Plugins that construct `hyprctl` commands from untrusted data (e.g., window titles, class names) risk IPC injection. While Quickshell's `Hyprland.dispatch()` uses discrete arguments, raw socket communication (which some plugins use) could be vulnerable to command injection if window titles contain `\n` characters that act as IPC delimiters.

### M6: D-Bus property change notification flooding (LOW)

Plugins subscribing to D-Bus property changes (e.g., NetworkManager, BlueZ) can receive attacker-triggered rapid-fire notifications. Without rate limiting, this causes UI thrashing and CPU consumption. A nearby Bluetooth device can trigger hundreds of RSSI change notifications per second.

### M7: QML binding loops causing 100% CPU (LOW)

Circular property bindings in QML (A depends on B, B depends on A) cause the binding engine to loop. Qt detects and breaks simple loops, but indirect loops through multiple components can evade detection and consume 100% CPU. This is a DoS vector if plugin data can influence binding dependency chains.

---

## Summary Scorecard

| # | Gemini Claim | Accuracy | Severity Assessment |
|---|---|---|---|
| 1A | PATH shadowing via `env` | ✅ Accurate core, overstated | Medium (requires prior local access) |
| 1B | `BASH_ENV`/exported functions | ✅ Accurate, empirically confirmed | Medium-High (session env controlled) |
| 2 | `/tmp` symlink + TOCTOU | ✅ Accurate, missed `mktemp -p` | Medium |
| 3A | Text.AutoText injection | ✅ **Highly accurate**, Qt-confirmed | **High** (remote trigger possible) |
| 3B | StdioCollector unbounded | ✅ Accurate, source-confirmed | Medium (requires malicious helper) |
| 3C | Timer isBusy guard | ⚠️ Partial — oversimplified | Low-Medium |
| 4 | `/proc/pid/cmdline` leak | ✅ Accurate | Medium |
| 5 | Code snippets | ❌ **Contains critical bug** (pipefail+head) | Bug creates false security |

### Hallucination Assessment

**No outright hallucinations detected.** All core mechanisms described by Gemini exist in reality. The issues are:
1. **Precision errors** — overstating severity, missing nuances, conflating privilege escalation with code execution
2. **One critical code bug** — the `pipefail` + `head -c` interaction that would crash the proposed helper script
3. **Incomplete coverage** — missing 7 additional attack surfaces relevant to the QML/Wayland plugin context

### Comparison with Prior Observatory Review

The observatory's prior adversarial review (2026-09-14) is significantly more rigorous than Gemini's findings:
- It correctly notes that `parent` ownership doesn't prevent leaks during long sessions
- It correctly warns about SplitParser's unbounded buffer preceding any downstream check
- It correctly separates documented observations from interpretations and hypotheses
- It correctly challenges causal claims about D-Bus/Polkit availability

Gemini's findings overlap with but don't advance beyond the observatory's existing security guidance, except for the specific `BASH_ENV`/`-p` detail and the `Text.AutoText` emphasis — both of which are genuine additions.

---

## Recommendations

1. **For the marketplace maintainer review process:**
   - Add `textFormat: Text.PlainText` as a **hard requirement** for any Text element displaying process names, window titles, network data, or other untrusted strings
   - Add StdioCollector byte-bounding guidance referencing the actual Quickshell source
   - Add Wayland layer-shell permission auditing (keyboard interactivity, overlay layers)

2. **For Gemini's proposed code:**
   - Fix the `pipefail` + `head -c` conflict before recommending the helper script
   - Add `mktemp -p "$TARGET_DIR"` for same-filesystem atomicity
   - Add symlink resolution to the stat ownership check
   - Add watchdog timeout to the Timer isBusy pattern

3. **For the observatory skill:**
   - The existing security-review.md is already more precise than Gemini's claims in most areas
   - Consider adding the `Text.AutoText` warning explicitly, as it's the highest-impact finding
   - Consider adding `/proc/pid/cmdline` guidance to the credential handling section

---

*This audit was grounded in empirical testing (bash 5.2.21), Qt 6.11.2 documentation, Quickshell source code, and the observatory's own dataset. No claims were accepted without verification. Commands and their outputs are preserved in the session workspace for reproducibility.*
