import QtQuick
import Quickshell
import Quickshell.Io

// Compile target components without creating their instances or running helpers.
QtObject {
  property Process ownedProcessExit: Process {
    command: ["/usr/bin/kill", "-TERM", String(Quickshell.processId)]
  }
  Component.onCompleted: {
    const base = Quickshell.env("TTS_CHECK_ROOT")
    const paths = ["BarWidget.qml", "Panel.qml", "components/TtsController.qml",
      "components/ApiKeyDialog.qml", "components/FirstRunWizard.qml",
      "components/InlineAction.qml", "components/KeyRow.qml", "components/SettingToggle.qml"]
    let failed = 0
    for (const path of paths) {
      const component = Qt.createComponent("file://" + base + "/" + path, Component.PreferSynchronous)
      if (component.status !== Component.Ready) {
        console.error("TTS_COMPONENT_FAIL", path, component.errorString())
        failed++
      } else {
        console.log("TTS_COMPONENT_READY", path)
      }
      component.destroy()
    }
    console.log("TTS_COMPONENT_VERDICT", failed === 0 ? "PASS" : "FAIL", paths.length, failed)
    ownedProcessExit.running = true
  }
}
