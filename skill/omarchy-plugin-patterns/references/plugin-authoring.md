# Authoring: contracts before callbacks

[Entry](../SKILL.md) · [Lifecycle recipes](performance-review.md) · [Security](security-review.md) · [Translation hook](localization-review.md)

## Host and delivery checklist

- Verify the installed manifest schema, author namespace (not reserved `omarchy.*`), declared kinds/entryPoints, exact case-sensitive paths, packaged imports/assets/helpers, permissions and supported Qt/Quickshell versions. Do not invent a standalone panel kind or assume every host supplies `bar.shell`; use its documented integration point inside the existing shell.
- `root.opened`, `sleeping`, formatter, screen and theme adapters below are application contracts, not promised host APIs. Wire actual enable/suspend/disable events; unknown state must not authorize work. Render unavailable/loading/stale/error states through catalog keys.
- Prefer existing platform features. A is reactive service; B is one owned streaming helper; C is gated/dual-cadence polling; D replaces command-based file reads. D can combine with C. These are architecture policies, not corpus prevalence or CPU claims.

## A — Reactive PipeWire example

QML component body; QtQuick and the installed PipeWire service are prerequisites. Documented Quickshell v0.2.x member names below still require target-version checking.

```qml
import QtQuick
import Quickshell.Services.Pipewire
Item {
    id: root
    readonly property var sink: Pipewire.defaultAudioSink
    PwObjectTracker { objects: [root.sink] }
    readonly property var volume: root.sink && root.sink.audio
        ? root.sink.audio.volume : null
}
```

No plugin subprocess or polling timer. Null is unavailable, not muted/zero. The tracker binds node details; hotplug may temporarily remove the sink. For MPRIS use `Quickshell.Services.Mpris`; Hyprland uses **`Quickshell.Hyprland`**, not a guessed Services namespace. Read each actual service API. Do not copy a polling CLI fallback without explaining why the service cannot supply the feature.

## Parse, validate, preserve evidence

Pure JS functions for already byte-bounded, complete frames. Put inside the owning QML component or a local JS module. `null` explicitly means unknown/unusable.

```js
function evidenceBoolean(value) {
    return typeof value === "boolean" ? value : null;
}
function decodeFrame(text) {
    try {
        const x = JSON.parse(text);
        if (!x || typeof x !== "object" || Array.isArray(x)) return null;
        if (typeof x.value !== "number" || !isFinite(x.value)
                || x.value < 0 || x.value > 100) return null;
        return { value: x.value, enabled: evidenceBoolean(x.enabled) };
    } catch (_) { return null; }
}
```

Syntax guard is not schema validation; false and zero survive. Decide whether failure clears data or retains explicitly stale last-good state. Bound nesting, frame bytes, rate and stored history independently. Do not log secrets or unbounded invalid input. A finite one-shot `head -c 65536` limits bytes, but cannot by itself prove complete JSON or detect all truncation: use an upstream length/EOF contract or reject ambiguous completion. Preserve producer failure; never use this cap as a permanent streaming protocol.

## Ownership and hotplug

For every resource record **creator / owner / maximum / cancellation / late-result policy**. QObject parentage, visual parenting and JS references differ. C++ bridges need RAII, thread-affinity-safe queued delivery, cancellation and no dangling QObject callbacks; parentage does not prove thread safety.

Inside an `Item { id: root }`, with a ready Component containing no unbounded side effects:

```qml
property var rows: []
readonly property int maxItems: 64
function addRow(component, properties) {
    const object = component.createObject(root, properties);
    if (!object) return;
    const next = rows.slice();
    next.push(object);
    while (next.length > maxItems) next.shift().destroy();
    rows = next;
}
```

Only destroy exclusively owned dynamic objects, never shared services or Loader/Repeater-owned children. Eviction bounds ongoing sessions; root parentage only supplies teardown. Use a fixed positive cap and cap item payloads too; plain data uses splice/reassignment, not destroy. Reassign QML `var` collections when change notification is needed. Disconnect subscriptions and discard obsolete responses after lifecycle changes.

Screen example: `readonly property string screenName: targetScreen ? targetScreen.name : "default"`, where `targetScreen` is the actual declared nullable screen. A guard or `Variants` must cover that dereference and delegate removal, not merely exist nearby. Use verified host theme/spacing tokens (e.g. Color/Style only if supplied). Test hotplug, scaling, theme changes, repeated enable/disable and long-session eviction; ordinary JS errors do not establish native crashes.

## Integration checks and sources

Recipes are not complete plugins or executed Qt tests. Exercise malformed/oversized data, false/zero/unknown, dependency absence, sleep/wake, cancellation, stale replies and ownership. Any changed UI string triggers the local translation pipeline before completion.

API references: [Pipewire](https://quickshell.org/docs/v0.2.0/types/Quickshell.Services.Pipewire/Pipewire/), [PwObjectTracker](https://quickshell.org/docs/v0.2.1/types/Quickshell.Services.Pipewire/PwObjectTracker/), [Qt dynamic object creation](https://doc.qt.io/qt-6/qtqml-javascript-dynamicobjectcreation.html). These are optional provenance links, not required runtime downloads.
