# Performance: admission, completion, cancellation

[Entry](../SKILL.md) · [Reactive service and parsing](plugin-authoring.md) · [Security](security-review.md)

For each timer/process/request record owner, admission gate, maximum concurrency/size, completion, timeout and cancellation. Reject stale results after close/disable/sleep using request identity or generation tokens. Visibility is not a rate limit. Prefer A native service events; B is one persistent helper; C defines scheduling; D replaces file-reading subprocesses and can use C. These are configured-work policies, not measured savings.

## B — One streaming helper with delayed recovery

Integration fragment inside `Item { id: root }` with `import QtQuick` and `import Quickshell.Io`. Prerequisites: reviewed executable `helperPath`, host-wired `allowed` (enabled AND awake), `acceptFrame` validator and an owned lifecycle controller. The controller performs initial start, failed-start timeout and shutdown; this fragment supplies the crash-retry path, not an entire daemon implementation.

```qml
Process {
    id: helper
    command: [root.helperPath, "--json-lines"]
    stdinEnabled: true
    stdout: SplitParser {
        onRead: data => {
            if (root.allowed) root.acceptFrame(data);
        }
    }
    onExited: {
        if (root.allowed) retry.restart();
    }
}
Timer {
    id: retry
    interval: 2000
    repeat: false
    onTriggered: {
        if (root.allowed && !helper.running)
            helper.running = true;
    }
}
```

This fixed ≥2-second debounce backoff is the minimal recovery policy; exponential backoff may grow from 2000ms to a declared ceiling and reset only after sustained health. Never restart immediately from `onExited`/`onRunningChanged` or bind `running` continuously to enablement. Exactly one long-lived helper while healthy/enabled; zero while stopped/backing off. Do not add a second wrapper process just to satisfy this pattern.

**Controller obligations:** on disable/sleep stop retry, invalidate pending requests and request helper shutdown. Setting `running=false` sends SIGTERM; it is not proof of exit. Wait for actual termination before any new start, even across quick disable/enable. Bound graceful shutdown and handle an unresponsive *owned* helper according to the authorized policy; do not kill unrelated processes. Missing executables/start failure may not emit `exited`: use a bounded startup watchdog or visible manual-retry state, never install-on-failure. Destruction/config reload must not detach or orphan children. Test target-version stop/reaping behavior.

**Transport contract:** newline-delimited UTF-8 JSON, at most 65536 bytes per frame including delimiter, bounded rate/queues and stderr, flushed records, schema, request IDs and EOF/error handling. The reviewed producer must enforce the bound before emission; an untrusted producer needs a native bounded transport **before** SplitParser accumulates output. Post-parser `line.length` is neither a buffering limit nor UTF-8 byte accounting. If that guarantee is unavailable, this recipe is unsuitable. Validate and bound outgoing requests before `helper.write(JSON.stringify(request) + "\n")`, only while ready; `write()` is not backpressure or authorization.

## C — Separate detail polling from status cadence

QtQuick Timer fragments require application-owned opened/sleeping state and `busy`. `refresh()` must acquire busy synchronously, release on every terminal path, time out stalls and discard obsolete results. Do not queue missed polls.

```qml
Timer {
    interval: 2000
    repeat: true
    running: root.opened && !root.sleeping
    onTriggered: {
        if (root.opened && !root.sleeping && !root.busy)
            root.refresh();
    }
}
```

For **persistent panel status**, replace that schedule (do not run both) with `interval: root.opened ? 2000 : 20000` and `running: root.enabled && !root.sleeping`; recheck the same gate at dispatch. Active cadence 1–2s; justified background cadence 20–300s. Detail-only work stays off when closed. Unknown lifecycle state must deny admission.

Slider debounce:

```qml
Timer {
    id: debounce
    interval: 250
    repeat: false
    onTriggered: {
        if (root.opened && !root.sleeping)
            root.dispatchLatestIfIdle();
    }
}
```

User edits call `debounce.restart()`. Every subsecond slider debounce MUST be one-shot. `dispatchLatestIfIdle()` validates the latest value and coalesces one pending value when busy; completion dispatches it only if the gate still permits. Stop debounce/discard or explicitly retain pending state on gate closure. Repeated rearming still creates work. Active animations have distinct lifecycle requirements; do not classify every animation as polling or assume hidden animations stop automatically.

## D — FileView without telemetry CLI

QtQuick + Quickshell.Io fragment inside a root with opened/sleeping, `raw` string and `readError` boolean. FileView reads through native C++ file I/O, without `cat`, `free`, `top`, `awk` or fork/exec. Choose trusted small kernel files; FileView is not an arbitrary-input byte limiter.

```qml
FileView {
    id: telemetry
    path: root.opened && !root.sleeping ? "/proc/meminfo" : ""
    blockLoading: false
    blockAllReads: false
    onLoaded: {
        if (root.opened && !root.sleeping) {
            root.raw = telemetry.text();
            root.readError = false;
        }
    }
    onLoadFailed: { root.raw = ""; root.readError = true; }
}
Timer {
    interval: 2000
    repeat: true
    running: root.opened && !root.sleeping
    onTriggered: telemetry.reload()
}
```

Gate **path acquisition**, not just reload: default preloading otherwise reads while closed. Empty path unloads; clear or mark published data stale on close and ignore late callbacks. Confirm target-version reload serialization and completion semantics before selecting cadence; avoid overlapping native work. Procfs/sysfs may not notify changes, so watchChanges is not universal telemetry. Parse documented units after successful load; no direct-memory-mapping claim. Native I/O and synchronous parsing can still cost CPU or block UI.

## Measurement boundary and sources

Static evidence describes configured wake-up opportunities and fork/exec paths, never actual wake-up rate or physical energy. Use **[runtime-measurement-required]** for CPU/battery/energy outcomes. Authorized turbostat/powertop/RAPL measurements need hardware, power mode, workload, duration, baseline, repeated trials, counter scope and uncertainty; RAPL package counters do not isolate a plugin. No syntax-derived zero CPU or battery percentage.

Test open/close, sleep/wake, fast rearm, slow/missing/flapping helper, disable during backoff/shutdown, partial/oversized frames and long sessions in the existing authorized host. Recipes are not results of those tests.

API provenance: [Process](https://quickshell.org/docs/v0.2.1/types/Quickshell.Io/Process/), [FileView](https://quickshell.org/docs/v0.2.0/types/Quickshell.Io/FileView/). Versioned documentation is not proof of the user's installed runtime.
