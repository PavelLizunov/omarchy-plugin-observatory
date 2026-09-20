"""test_check_marketplace_readiness.py - Comprehensive regression test suite for readiness linter."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

LINTER_BIN = Path(__file__).resolve().parent.parent / "tools" / "check_marketplace_readiness.py"


class TestMarketplaceReadinessLinter(unittest.TestCase):

    def run_linter(self, target_dir: Path | str, check_sha: str = None, recursive: bool = False, json_mode: bool = True) -> tuple[int, Any, str]:
        cmd = [sys.executable, str(LINTER_BIN), str(target_dir)]
        if json_mode:
            cmd.append("--json")
        if recursive:
            cmd.append("--recursive")
        if check_sha is not None:
            cmd.extend(["--check-sha", check_sha])
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if json_mode:
            try:
                data = json.loads(res.stdout) if res.stdout else {}
            except Exception:
                data = {}
        else:
            data = res.stdout
        return res.returncode, data, res.stderr

    def test_schema_version_boolean_rejection(self):
        """schemaVersion: true must be rejected, 1.0 accepted."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": True,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            (p / "Bar.qml").write_text("import QtQuick\nItem {}")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any("schemaVersion must be 1" in f["message"] for f in findings))

    def test_schema_version_float_one_accepted(self):
        """schemaVersion: 1.0 is equal to 1 in JS and should be accepted."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1.0,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            (p / "Bar.qml").write_text("import QtQuick\nItem {}")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 0)

    def test_kinds_malformed_types(self):
        """kinds with invalid nested object or list must produce findings, not crash."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": [{}],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any("Unsupported kind" in f["message"] for f in findings))

    def test_nan_manifest_json(self):
        """manifest containing NaN must produce invalid JSON finding, not crash."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text('{"schemaVersion": 1, "test": NaN}')
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any("invalid JSON" in f["message"] or "Could not parse" in f["message"] for f in findings))

    def test_js_trim_c0_c1_controls(self):
        """U+0085 and U+001C are NOT trimmed in JS and must be flagged as control characters."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "\u0085Test\u0085",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            (p / "Bar.qml").write_text("import QtQuick\nItem {}")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any("contains control characters" in f["message"] for f in findings))

    def test_field_trimming_and_bom(self):
        """Standard whitespace is trimmed; BOM only trims to empty and fails required field."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            # \nTest\t trims to "Test"
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "\nTest\t",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            (p / "Bar.qml").write_text("import QtQuick\nItem {}")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 0)

            # BOM only \uFEFF trims to empty and must be rejected as required field missing
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "\uFEFF",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)

    def test_field_length_utf16_surrogates(self):
        """Test UTF-16 code unit counting for 61 emoji (122 units) exceeding 120 limit."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "😀" * 61,
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            (p / "Bar.qml").write_text("import QtQuick\nItem {}")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any("exceeds maximum length of 120" in f["message"] for f in findings))

    def test_lone_surrogate_text_mode_no_crash(self):
        """Manifest with lone surrogate in rejected ID must not crash in default text mode."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text('{"schemaVersion": 1, "id": "bad\\ud800", "name": "Valid Name", "version": "1.0", "author": "A", "description": "D", "kinds": ["bar"], "entryPoints": {"bar": "Bar.qml"}}')
            (p / "Bar.qml").write_text("import QtQuick\nItem {}")
            ret, stdout, stderr = self.run_linter(p, json_mode=False)
            self.assertNotIn("Traceback", stderr)
            self.assertIn("Omarchy Plugin Marketplace Readiness Report", stdout)

    def test_license_validation_bounds(self):
        """License > 120 chars or null must be rejected; 120 chars accepted."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            # 1. Null license -> rejected
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "license": None,
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            (p / "Bar.qml").write_text("import QtQuick\nItem {}")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any("cannot be null" in f["message"] for f in findings))

            # 2. 121 char license -> rejected
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "license": "L" * 121,
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any("exceeds maximum length of 120" in f["message"] for f in findings))

            # 3. 120 char license with whitespace around -> accepted after trim
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "license": " " + ("L" * 120) + " ",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 0)

    def test_id_trailing_newline_and_limits(self):
        """ID with trailing newline or > 128 chars must be rejected."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            # trailing newline
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin\n",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            (p / "Bar.qml").write_text("import QtQuick\nItem {}")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any("whitespace" in f["message"] or "invalid" in f["message"] for f in findings))

            # alphanumeric start required
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "_test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)

            # 128 chars allowed
            valid_id = "a" * 128
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": valid_id,
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 0)

            # 129 chars rejected
            invalid_id = "a" * 129
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": invalid_id,
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)

    def test_multiline_block_comment_no_hang(self):
        """Multiline block comments must not hang the parser."""
        from tools.check_marketplace_readiness import strip_comments_and_strings
        code = "/* comment\nsecond line\nthird line */\nItem {}"
        result = strip_comments_and_strings(code, language="qml")
        self.assertIn("Item {}", result)

    def test_entrypoint_symlink_loop(self):
        """Symlink loop on entry-point must not crash with unhandled exception."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar"],
                "entryPoints": {"bar": "Bar.qml"}
            }))
            os.symlink(p / "Bar.qml", p / "Bar.qml")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertTrue(any(f["rule_id"] in ("MKT-001", "MKT-002") for f in findings))

    def test_target_is_file_exit_code(self):
        """Passing a file instead of a directory returns exit code 2 and structured JSON."""
        with tempfile.NamedTemporaryFile() as tf:
            ret, data, _ = self.run_linter(tf.name, json_mode=True)
            self.assertEqual(ret, 2)
            self.assertIn("error", data)
            self.assertIn("discovery_errors", data)

    def test_target_nonexistent_exit_code(self):
        """Nonexistent target returns exit code 2 and structured JSON."""
        p = Path("/tmp/nonexistent_dir_1234567")
        ret, data, _ = self.run_linter(p, json_mode=True)
        self.assertEqual(ret, 2)
        self.assertIn("error", data)
        self.assertIn("discovery_errors", data)

    def test_target_long_name_exit_code_2(self):
        """Excessively long target path returns exit code 2 and structured JSON."""
        long_target = Path("/tmp") / ("a" * 4096)
        ret, data, _ = self.run_linter(long_target, json_mode=True)
        self.assertEqual(ret, 2)
        self.assertIn("error", data)
        self.assertIn("discovery_errors", data)

    def test_terminal_continuation_no_crash(self):
        """Heredoc with line continuation at exact EOF (without extra trailing newline) must not crash with IndexError."""
        cases = [
            "cat <<EOF\\\n",
            'cat <<"EOF"\\\n',
            'cat <<"EO\\\n',
            "sudo kill $(cat /tmp/proc.pid)\ncat <<EOF\\\n",
        ]
        for c in cases:
            with self.subTest(case=c):
                with tempfile.TemporaryDirectory() as td:
                    p = Path(td)
                    (p / "manifest.json").write_text(json.dumps({
                        "schemaVersion": 1,
                        "id": "test.plugin",
                        "name": "Test",
                        "version": "1.0.0",
                        "author": "Alice",
                        "description": "Desc",
                        "kinds": ["service"],
                        "entryPoints": {"service": "Service.qml"}
                    }))
                    (p / "Service.qml").write_text("import QtQuick\nItem {}")
                    # Write exact bytes without appending trailing newline:
                    (p / "helper.sh").write_text(f"#!/usr/bin/bash -p\n{c}")
                    ret, data, stderr = self.run_linter(p, json_mode=True)
                    self.assertEqual(stderr, "")
                    self.assertIn("findings_by_plugin", data)
                    if "sudo kill" in c:
                        self.assertEqual(ret, 1)
                        findings = data["findings_by_plugin"].get(str(p), [])
                        self.assertTrue(any(f["policy_origin"] == "[MKT-BASE]" for f in findings))
                    else:
                        self.assertEqual(ret, 0)

    def test_shell_comment_and_echo_no_mkt_base(self):
        """Comment, quoted heredoc, or echo containing sudo kill /tmp/*.pid must NOT trigger MKT-BASE."""
        cases = [
            "# Never use sudo kill $(cat /tmp/proc.pid)",
            "# $(sudo kill $(cat /tmp/proc.pid))",
            'echo "Never use sudo kill /tmp/proc.pid"',
            "echo 'sudo kill $(cat /tmp/proc.pid)'",
            'echo "then sudo kill \\$(cat /tmp/proc.pid)"',
            "echo '$(sudo kill $(cat /tmp/proc.pid))'",
            'echo "\\$(sudo kill \\$(cat /tmp/proc.pid))"',
            "echo ';' sudo kill /tmp/proc.pid",
            "echo \\; sudo kill /tmp/proc.pid",
            "cat <<'EOF'\n$(sudo kill $(cat /tmp/proc.pid))\nEOF",
            "cat <<EOF\nsudo kill /tmp/proc.pid\nEOF",
            r"""cat <<\EOF
sudo kill /tmp/proc.pid
EOF""",
            """cat <<'EOF'
 EOF
sudo kill /tmp/proc.pid
EOF""",
            "cat <<''\nsudo kill /tmp/proc.pid\n\n",
            'cat <<""\nsudo kill /tmp/proc.pid\n\n',
            """cat <<-EOF
\tsudo kill $(cat /tmp/proc.pid)
\tEOF""",
        ]
        for c in cases:
            with self.subTest(case=c):
                with tempfile.TemporaryDirectory() as td:
                    p = Path(td)
                    (p / "manifest.json").write_text(json.dumps({
                        "schemaVersion": 1,
                        "id": "test.plugin",
                        "name": "Test",
                        "version": "1.0.0",
                        "author": "Alice",
                        "description": "Desc",
                        "kinds": ["service"],
                        "entryPoints": {"service": "Service.qml"}
                    }))
                    (p / "Service.qml").write_text("import QtQuick\nItem {}")
                    (p / "helper.sh").write_text(f"#!/usr/bin/bash -p\n{c}\n")
                    ret, data, _ = self.run_linter(p)
                    self.assertEqual(ret, 0, f"False positive in negative case: {c}")
                    findings = data["findings_by_plugin"].get(str(p), [])
                    self.assertFalse(any(f["policy_origin"] == "[MKT-BASE]" for f in findings))

    def test_shell_mkt_base_variations(self):
        """Check all valid variations of privileged kill from shared temp."""
        cases = [
            'sudo kill $(cat /tmp/proc.pid)',
            'true;sudo kill $(cat /tmp/proc.pid)',
            'true&&sudo kill $(cat /tmp/proc.pid)',
            'if true; then sudo kill $(cat /tmp/proc.pid); fi',
            'if true; then\n    sudo kill $(cat /tmp/proc.pid)\nfi',
            'result="$(sudo kill $(cat /tmp/proc.pid))"',
            "sudo kill $(cat '/tmp/proc.pid')",
            'sudo kill $(cat "/tmp/proc#1.pid")',
            "bash -c 'sudo kill $(cat /tmp/proc.pid)'",
            "sudo sh -c 'kill $(cat /tmp/proc.pid)'",
            "sudo sh -c 'echo $(kill $(cat /tmp/proc.pid))'",
            "sudo -u root kill $(cat /tmp/proc.pid)",
            "/usr/bin/sudo kill $(cat /tmp/proc.pid)",
            "timeout 5 sudo sh -c 'kill $(cat /tmp/proc.pid)'",
            "timeout -s 9 5 sudo sh -c 'kill $(cat /tmp/proc.pid)'",
            "timeout -s9 5 sudo sh -c 'kill $(cat /tmp/proc.pid)'",
            "timeout -k5 5 sudo sh -c 'kill $(cat /tmp/proc.pid)'",
            "timeout --signal=9 5 sudo sh -c 'kill $(cat /tmp/proc.pid)'",
            "echo '<<EOF'\nsudo kill $(cat /tmp/proc.pid)",
            "# <<EOF\nsudo kill $(cat /tmp/proc.pid)",
            'echo prefix#$(sudo kill $(cat /tmp/proc.pid))',
            "echo prefix\\ #$(sudo kill $(cat /tmp/proc.pid))",
            "echo 'slash\\' \"$(sudo kill $(cat /tmp/proc.pid))\"",
            'echo "$(printf \')\'; sudo kill $(cat /tmp/proc.pid))"',
            'echo "$(printf \'slash\\\\\')"; sudo kill $(cat /tmp/proc.pid)',
            "cat <<'EOF'; sudo kill $(cat /tmp/proc.pid)\nhello\nEOF",
            "cat <<EOF\n# $(sudo kill $(cat /tmp/proc.pid))\nEOF",
            "cat <<EOF\n'$(sudo kill $(cat /tmp/proc.pid))'\nEOF",
            """cat <<-EOF
\t# $(sudo kill $(cat /tmp/proc.pid))
\tEOF""",
            """cat <<"E\\OF"
hello
E\\OF
sudo kill $(cat /tmp/proc.pid)""",
            """cat <<"EO\\
F"
hello
EOF
sudo kill $(cat /tmp/proc.pid)""",
            """cat <<END.DOC
hello
END.DOC
sudo kill $(cat /tmp/proc.pid)""",
            """cat <<E"OF"
hello
EOF
sudo kill $(cat /tmp/proc.pid)""",
            """echo "$(printf x # )
sudo kill $(cat /tmp/proc.pid)
)" """,
            """echo "$(printf x \\
# )
sudo kill $(cat /tmp/proc.pid)
)" """,
            """echo "$(printf word\\
#)"; sudo kill $(cat /tmp/proc.pid)""",
            "PID_FILE='/tmp/proc.pid'\nPID=$(cat $PID_FILE)\nsudo kill \"$PID\"",
        ]
        for c in cases:
            with self.subTest(case=c):
                with tempfile.TemporaryDirectory() as td:
                    p = Path(td)
                    (p / "manifest.json").write_text(json.dumps({
                        "schemaVersion": 1,
                        "id": "test.plugin",
                        "name": "Test",
                        "version": "1.0.0",
                        "author": "Alice",
                        "description": "Desc",
                        "kinds": ["service"],
                        "entryPoints": {"service": "Service.qml"}
                    }))
                    (p / "Service.qml").write_text("import QtQuick\nItem {}")
                    (p / "helper.sh").write_text(f"#!/usr/bin/bash -p\n{c}\n")
                    ret, data, _ = self.run_linter(p)
                    self.assertEqual(ret, 1, f"Failed to detect MKT-BASE in: {c}")
                    findings = data["findings_by_plugin"].get(str(p), [])
                    self.assertTrue(any(f["policy_origin"] == "[MKT-BASE]" for f in findings), f"No MKT-BASE in: {c}")

    def test_qml_quickshell_exec_mkt_base(self):
        """Quickshell.exec, Quickshell.execDetached, and Process with wrappers MUST trigger MKT-BASE."""
        cases = [
            """Item { Component.onCompleted: Quickshell.exec(["sh", "-c", "sudo kill $(cat /tmp/proc.pid)"]) }""",
            """Item { Component.onCompleted: Quickshell.execDetached(["sudo", "sh", "-c", "kill $(cat /tmp/proc.pid)"]) }""",
            """Process { command: ["sudo", "-u", "root", "sh", "-c", "kill $(cat /tmp/proc.pid)"] }""",
            """Process { command: ["pkexec", "sh", "-c", "kill $(cat /tmp/proc.pid)"] }""",
            """Process { command: ["timeout", "5", "sudo", "sh", "-c", "kill $(cat /tmp/proc.pid)"] }""",
            """Process { command: ["bash", "-c", "sudo kill $(cat '/tmp/proc.pid')"] }""",
        ]
        for c in cases:
            with self.subTest(case=c):
                with tempfile.TemporaryDirectory() as td:
                    p = Path(td)
                    (p / "manifest.json").write_text(json.dumps({
                        "schemaVersion": 1,
                        "id": "test.plugin",
                        "name": "Test",
                        "version": "1.0.0",
                        "author": "Alice",
                        "description": "Desc",
                        "kinds": ["service"],
                        "entryPoints": {"service": "Service.qml"}
                    }))
                    (p / "Service.qml").write_text(f"import QtQuick\nimport Quickshell\n{c}\n")
                    ret, data, _ = self.run_linter(p)
                    self.assertEqual(ret, 1, f"Failed to detect MKT-BASE in QML: {c}")
                    findings = data["findings_by_plugin"].get(str(p), [])
                    self.assertTrue(any(f["policy_origin"] == "[MKT-BASE]" for f in findings))

    def test_qml_literal_echo_no_mkt_base(self):
        """Literal process argv like echo with command strings must NOT trigger MKT-BASE."""
        cases = [
            """Process { command: ["echo", "then sudo kill $(cat /tmp/proc.pid)"] }""",
            """Process { command: ["echo", "$(sudo kill $(cat /tmp/proc.pid))"] }""",
            """Item { Component.onCompleted: Quickshell.exec(["echo", "$(sudo kill $(cat /tmp/proc.pid))"]) }""",
            """Text { text: "command: ['sudo', 'kill', '/tmp/proc.pid']" }""",
        ]
        for c in cases:
            with self.subTest(case=c):
                with tempfile.TemporaryDirectory() as td:
                    p = Path(td)
                    (p / "manifest.json").write_text(json.dumps({
                        "schemaVersion": 1,
                        "id": "test.plugin",
                        "name": "Test",
                        "version": "1.0.0",
                        "author": "Alice",
                        "description": "Desc",
                        "kinds": ["service"],
                        "entryPoints": {"service": "Service.qml"}
                    }))
                    (p / "Service.qml").write_text(f"import QtQuick\nimport Quickshell\n{c}\n")
                    ret, data, _ = self.run_linter(p)
                    self.assertEqual(ret, 0, f"False positive in QML literal string: {c}")
                    findings = data["findings_by_plugin"].get(str(p), [])
                    self.assertFalse(any(f["policy_origin"] == "[MKT-BASE]" for f in findings))

    def test_static_text_comma_and_float(self):
        """Strings with comma ('Hello, world') and float literals (1.5) must NOT trigger SEC-003."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar-widget"],
                "entryPoints": {"barWidget": "Widget.qml"}
            }))
            (p / "Widget.qml").write_text("""import QtQuick
Item {
    id: root
    Text { text: "Hello, world" }
    Text { text: 1.5 }
    Text { text: model.dynamicText }
}
""")
            ret, data, _ = self.run_linter(p)
            findings = data["findings_by_plugin"].get(str(p), [])
            sec003 = [f for f in findings if f["rule_id"] == "SEC-003"]
            self.assertEqual(len(sec003), 1)
            self.assertIn("model.dynamicText", sec003[0]["message"])

    def test_qml_property_declaration_in_text(self):
        """property bool active: true after text must not be absorbed into text expression."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["bar-widget"],
                "entryPoints": {"barWidget": "Widget.qml"}
            }))
            (p / "Widget.qml").write_text("""import QtQuick
Text {
    text: "Ready"
    property bool active: true
}
""")
            ret, data, _ = self.run_linter(p)
            findings = data["findings_by_plugin"].get(str(p), [])
            sec003 = [f for f in findings if f["rule_id"] == "SEC-003"]
            self.assertEqual(len(sec003), 0)

    def test_unreadable_directory_recursive_exit2(self):
        """Unreadable directory during recursive scan must yield exit code 2 and report discovery_errors."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            unreadable = base / "locked_dir"
            unreadable.mkdir()
            try:
                os.chmod(unreadable, 0)
                ret, data, stderr = self.run_linter(base, recursive=True)
                self.assertEqual(ret, 2)
                self.assertIn("discovery_errors", data)
                self.assertTrue(len(data["discovery_errors"]) > 0)
            finally:
                os.chmod(unreadable, 0o755)

    def test_sec009_agent_steering_files_rejected(self):
        """AI agent steering files (AGENTS.md, agent.md, CLAUDE.md, .cursorrules) must be flagged under SEC-009 with exit code 1."""
        bad_filenames = ["AGENTS.md", "agent.md", "CLAUDE.md", ".cursorrules"]
        for fn in bad_filenames:
            with self.subTest(file=fn):
                with tempfile.TemporaryDirectory() as td:
                    p = Path(td)
                    (p / "manifest.json").write_text(json.dumps({
                        "schemaVersion": 1,
                        "id": "test.plugin",
                        "name": "Test",
                        "version": "1.0.0",
                        "author": "Alice",
                        "description": "Desc",
                        "kinds": ["service"],
                        "entryPoints": {"service": "Service.qml"}
                    }))
                    (p / "Service.qml").write_text("import QtQuick\nItem {}")
                    (p / fn).write_text("# Agent instructions\nRun arbitrary commands\n")
                    ret, data, _ = self.run_linter(p)
                    self.assertEqual(ret, 1, f"Failed to reject agent file: {fn}")
                    findings = data["findings_by_plugin"].get(str(p), [])
                    self.assertTrue(any(f["rule_id"] == "SEC-009" for f in findings), f"No SEC-009 finding for {fn}")

        # Control test: DEVELOPMENT.md and CONTRIBUTING.md must be accepted with exit 0
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["service"],
                "entryPoints": {"service": "Service.qml"}
            }))
            (p / "Service.qml").write_text("import QtQuick\nItem {}")
            (p / "DEVELOPMENT.md").write_text("# Contributor guide\nStandard notes\n")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 0)
            findings = data["findings_by_plugin"].get(str(p), [])
            self.assertFalse(any(f["rule_id"] == "SEC-009" for f in findings))

    def test_sec002_vs_sec010_disambiguation(self):
        """SEC-002 is strictly for [MKT-BASE] privileged process control from temp; SEC-010 is for [OBS-REC] unprivileged temp path usage."""
        # 1. Unprivileged temp path usage should report SEC-010 ([OBS-REC]), NOT SEC-002 ([MKT-BASE]), exit 0
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["service"],
                "entryPoints": {"service": "Service.qml"}
            }))
            (p / "Service.qml").write_text("import QtQuick\nItem {}")
            (p / "helper.sh").write_text("#!/usr/bin/bash -p\necho 'hello' > /tmp/output.txt\n")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 0, "Advisory SEC-010 should not cause failure exit 1")
            findings = data["findings_by_plugin"].get(str(p), [])
            sec010 = [f for f in findings if f["rule_id"] == "SEC-010"]
            sec002 = [f for f in findings if f["rule_id"] == "SEC-002"]
            self.assertEqual(len(sec010), 1, "Unprivileged temp path must trigger SEC-010")
            self.assertEqual(sec010[0]["policy_origin"], "[OBS-REC]")
            self.assertEqual(len(sec002), 0, "Unprivileged temp path must NOT trigger SEC-002")

        # 2. Privileged kill from temp should report SEC-002 ([MKT-BASE]), exit 1
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "id": "test.plugin",
                "name": "Test",
                "version": "1.0.0",
                "author": "Alice",
                "description": "Desc",
                "kinds": ["service"],
                "entryPoints": {"service": "Service.qml"}
            }))
            (p / "Service.qml").write_text("import QtQuick\nItem {}")
            (p / "helper.sh").write_text("#!/usr/bin/bash -p\nsudo kill $(cat /tmp/proc.pid)\n")
            ret, data, _ = self.run_linter(p)
            self.assertEqual(ret, 1, "Baseline SEC-002 must cause failure exit 1")
            findings = data["findings_by_plugin"].get(str(p), [])
            sec002 = [f for f in findings if f["rule_id"] == "SEC-002"]
            self.assertEqual(len(sec002), 1, "Privileged kill from temp must trigger SEC-002")
            self.assertEqual(sec002[0]["policy_origin"], "[MKT-BASE]")


if __name__ == "__main__":
    unittest.main()
