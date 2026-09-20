#!/usr/bin/env python3
"""check_marketplace_readiness.py - Pre-flight validation for Omarchy Quattro plugins.

Validates community plugin repositories against:
- [MKT-COMPAT]: Marketplace compatibility rules (manifest, entry-points, symlinks).
- [MKT-BASE]: Automated Security Baseline checks (privileged process control from shared temp).
- [OBS-REC]: Observatory runtime, security, and lifecycle recommendations.

Reference: docs/rule-matrix-specification.md (v1.2)
Note: This is an advisory pre-flight tool. A clean verdict does not guarantee
upstream marketplace acceptance or safety certification.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

VERSION = "1.3.1"

SUPPORTED_KINDS = frozenset({
    "bar",
    "bar-widget",
    "menu",
    "overlay",
    "panel",
    "service",
})

DEFAULT_SECTIONS = frozenset({"left", "center", "right"})

# Precise ECMAScript whitespace definition
JS_WS_CHARS = "\t\n\x0b\x0c\r \xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
JS_TRIM_RE = re.compile(f"^[{re.escape(JS_WS_CHARS)}]+|[{re.escape(JS_WS_CHARS)}]+$")

ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}\Z")
CONTROL_CHARS_REGEX = re.compile(r"[\x00-\x1f\x7f-\x9f]")
SHA40_REGEX = re.compile(r"^[0-9a-fA-F]{40}\Z")
MAX_FILE_READ_BYTES = 1024 * 1024  # 1 MiB per-file read limit


def js_trim(s: str) -> str:
    """Trim whitespace and BOM matching JavaScript String.prototype.trim()."""
    return JS_TRIM_RE.sub("", s)


def js_utf16_length(s: str) -> int:
    """Calculate string length matching JavaScript's String.prototype.length (UTF-16 code units)."""
    return len(s.encode("utf-16-le", errors="surrogatepass")) // 2


def safe_str(s: str) -> str:
    """Format string safely for terminal output, escaping unencodable surrogates."""
    encoding = sys.stdout.encoding or "utf-8"
    return s.encode(encoding, errors="backslashreplace").decode(encoding, errors="replace")


def safe_print(text: str, file=sys.stdout) -> None:
    """Print text safely escaping unencodable characters."""
    encoding = file.encoding or "utf-8"
    clean_text = text.encode(encoding, errors="backslashreplace").decode(encoding, errors="replace")
    file.write(clean_text + "\n")


def unquote_str(s: str) -> str:
    """Unquote a token or string literal."""
    s = s.strip()
    if len(s) >= 2 and (s[0] == s[-1] and s[0] in ('"', "'", "`")):
        if s[0] == '"':
            try:
                return json.loads(s)
            except Exception:
                return s[1:-1]
        return s[1:-1].replace("\\'", "'")
    return s


@dataclass
class Finding:
    rule_id: str
    name: str
    policy_origin: str  # [MKT-COMPAT], [MKT-BASE], [OBS-REC]
    severity: str       # CRITICAL, HIGH, MEDIUM, INFO
    detection_mode: str # Deterministic, Heuristic
    file_path: str
    line: int
    message: str
    snippet: str = ""
    suggestion: str = ""


def strip_comments_and_strings(code: str, language: str = "js", strip_strings: bool = True) -> str:
    """Remove comments and optionally replace string contents with spaces."""
    result = []
    i = 0
    n = len(code)
    in_single_quote = False
    in_double_quote = False
    in_template = False
    in_line_comment = False
    in_block_comment = False

    while i < n:
        c = code[i]
        next_c = code[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if c == "\n":
                in_line_comment = False
                result.append("\n")
            else:
                result.append(" ")
            i += 1
            continue

        if in_block_comment:
            if c == "*" and next_c == "/":
                in_block_comment = False
                result.append("  ")
                i += 2
            elif c == "\n":
                result.append("\n")
                i += 1
            else:
                result.append(" ")
                i += 1
            continue

        if in_single_quote:
            if c == "\\" and i + 1 < n:
                result.append("  " if strip_strings else code[i:i + 2])
                i += 2
                continue
            if c == "'":
                in_single_quote = False
                result.append(" " if strip_strings else "'")
            else:
                result.append(" " if strip_strings else c)
            i += 1
            continue

        if in_double_quote:
            if c == "\\" and i + 1 < n:
                result.append("  " if strip_strings else code[i:i + 2])
                i += 2
                continue
            if c == '"':
                in_double_quote = False
                result.append(" " if strip_strings else '"')
            else:
                result.append(" " if strip_strings else c)
            i += 1
            continue

        if in_template:
            if c == "\\" and i + 1 < n:
                result.append("  " if strip_strings else code[i:i + 2])
                i += 2
                continue
            if c == "`":
                in_template = False
                result.append(" " if strip_strings else "`")
            else:
                result.append(" " if strip_strings else c)
            i += 1
            continue

        # Check comment start
        if language in ("js", "qml"):
            if c == "/" and next_c == "/":
                in_line_comment = True
                result.append("  ")
                i += 2
                continue
            if c == "/" and next_c == "*":
                in_block_comment = True
                result.append("  ")
                i += 2
                continue
        elif language == "sh":
            if c == "#":
                in_line_comment = True
                result.append(" ")
                i += 1
                continue

        # Check quote start
        if c == "'":
            in_single_quote = True
            result.append(" " if strip_strings else "'")
            i += 1
            continue
        if c == '"':
            in_double_quote = True
            result.append(" " if strip_strings else '"')
            i += 1
            continue
        if c == "`" and language in ("js", "qml"):
            in_template = True
            result.append(" " if strip_strings else "`")
            i += 1
            continue

        result.append(c)
        i += 1

    return "".join(result)


def tokenize_qml(code: str) -> List[Tuple[str, str, int]]:
    """Tokenize QML/JS code into a list of (kind, value, line_number) tuples."""
    token_spec = [
        ("LINE_COMMENT", r"//[^\n]*"),
        ("BLOCK_COMMENT", r"/\*[\s\S]*?\*/"),
        ("STRING", r"\"(?:\\.|[^\"\\])*\"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`"),
        ("NUMBER", r"\b\d+(?:\.\d+)?\b"),
        ("IDENT", r"[a-zA-Z_][a-zA-Z0-9_.]*"),
        ("PUNCT", r"[\{\}\(\)\[\]:,;?+\-*/=!<>|&]"),
        ("NEWLINE", r"\n"),
        ("SKIP", r"[ \t]+"),
        ("OTHER", r"."),
    ]
    tok_regex = "|".join(f"(?P<{name}>{pattern})" for name, pattern in token_spec)
    line_num = 1
    tokens = []
    for mo in re.finditer(tok_regex, code):
        kind = mo.lastgroup
        val = mo.group()
        if kind == "NEWLINE":
            line_num += 1
        elif kind in ("LINE_COMMENT", "BLOCK_COMMENT"):
            line_num += val.count("\n")
        elif kind != "SKIP" and kind is not None:
            tokens.append((kind, val, line_num))
            if kind == "STRING":
                line_num += val.count("\n")
    return tokens


def is_static_expr(tokens: List[Tuple[str, str]], depth_limit: int = 50) -> bool:
    """Check whether an expression AST token list is purely static."""
    if depth_limit <= 0 or not tokens:
        return False
    if len(tokens) == 1:
        k, v = tokens[0]
        if k == "STRING":
            return not (v.startswith("`") and "${" in v)
        if k == "NUMBER":
            return True
        if v in ("true", "false", "null", "undefined"):
            return True
        return False

    # Signed number: -1.5, +2
    if len(tokens) == 2 and tokens[0][1] in ("-", "+") and tokens[1][0] == "NUMBER":
        return True

    # Concatenation of static strings: "a" + "b"
    if all(
        (k == "STRING" and not (v.startswith("`") and "${" in v)) or (k == "PUNCT" and v == "+")
        for k, v in tokens
    ) and any(k == "STRING" for k, v in tokens):
        return True

    # Check for ternary: condition ? exprA : exprB
    depth = 0
    q_pos = -1
    c_pos = -1
    for idx, (k, v) in enumerate(tokens):
        if v in ("(", "{", "["):
            depth += 1
        elif v in (")", "}", "]"):
            depth -= 1
        elif v == "?" and depth == 0 and q_pos == -1:
            q_pos = idx
        elif v == ":" and depth == 0 and q_pos != -1:
            c_pos = idx
            break

    if q_pos != -1 and c_pos != -1:
        true_part = tokens[q_pos + 1 : c_pos]
        false_part = tokens[c_pos + 1 :]
        return is_static_expr(true_part, depth_limit - 1) and is_static_expr(false_part, depth_limit - 1)

    return False


def is_qml_type_name(ident: str) -> bool:
    """Return True if identifier represents a QML type (capitalized leaf)."""
    parts = ident.split(".")
    return bool(parts and parts[-1] and parts[-1][0].isupper())


def extract_sub_at(text: str, start_paren: int) -> Tuple[str, int]:
    """
    Extract substitution content starting at '(' in '$(', respecting:
    - single quotes ('...') where backslash does not escape closing quote
    - double quotes ("...") where backslash escapes
    - backslash escapes outside quotes
    - line continuation (backslash-newline) without altering word-boundary state
    - comments (# ... to end of line) starting at lexical word boundaries outside quotes
    - nested substitutions $(...) and ( ... )
    Returns (sub_content, end_idx) where end_idx is index of matching ')'
    """
    n = len(text)
    depth = 1
    j = start_paren + 1
    sub_chars: List[str] = []
    sub_in_sq = False
    sub_in_dq = False
    sub_in_comment = False
    sub_word_has_chars = False

    while j < n and depth > 0:
        sc = text[j]
        snc = text[j + 1] if j + 1 < n else ""

        if sub_in_comment:
            if sc == "\n":
                sub_in_comment = False
                sub_word_has_chars = False
            sub_chars.append(sc)
            j += 1
            continue

        if sub_in_sq:
            if sc == "'":
                sub_in_sq = False
            sub_chars.append(sc)
            sub_word_has_chars = True
            j += 1
            continue

        if sub_in_dq:
            if sc == "\\" and j + 1 < n:
                if snc == "\n":
                    # Line continuation inside double quotes
                    j += 2
                    continue
                if snc in ('$', '"', '\\', '`'):
                    sub_chars.append(sc)
                    sub_chars.append(snc)
                    sub_word_has_chars = True
                    j += 2
                    continue
                else:
                    sub_chars.append(sc)
                    sub_chars.append(snc)
                    sub_word_has_chars = True
                    j += 2
                    continue
            if sc == '"':
                sub_in_dq = False
            sub_chars.append(sc)
            sub_word_has_chars = True
            j += 1
            continue

        # Outside quotes
        if sc == "\\":
            if j + 1 < n:
                if snc == "\n":
                    # Line continuation outside quotes: preserves sub_word_has_chars state!
                    j += 2
                    continue
                sub_chars.append(sc)
                sub_chars.append(snc)
                sub_word_has_chars = True
                j += 2
                continue
            sub_chars.append(sc)
            j += 1
            continue

        if sc == "#" and not sub_word_has_chars:
            sub_in_comment = True
            sub_chars.append(sc)
            j += 1
            continue

        if sc == "'":
            sub_in_sq = True
            sub_chars.append(sc)
            sub_word_has_chars = True
            j += 1
            continue

        if sc == '"':
            sub_in_dq = True
            sub_chars.append(sc)
            sub_word_has_chars = True
            j += 1
            continue

        if sc in (" ", "\t", "\r", "\n"):
            sub_chars.append(sc)
            sub_word_has_chars = False
            j += 1
            continue

        if sc in (";", "&", "|", "<", ">"):
            sub_chars.append(sc)
            sub_word_has_chars = False
            j += 1
            continue

        if sc == "(":
            depth += 1
            sub_chars.append(sc)
            sub_word_has_chars = False
            j += 1
            continue
        elif sc == ")":
            depth -= 1
            if depth == 0:
                break
            sub_chars.append(sc)
            sub_word_has_chars = False
            j += 1
            continue

        sub_chars.append(sc)
        sub_word_has_chars = True
        j += 1

    return "".join(sub_chars), j


def extract_expansions_from_unquoted_text(text: str) -> List[str]:
    """Extract unescaped $(...) substitutions from text where quotes have no special meaning (e.g. unquoted heredoc body)."""
    subs: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "(":
            sub_content, end_idx = extract_sub_at(text, i + 1)
            subs.append(sub_content)
            i = end_idx + 1
            continue
        i += 1
    return subs


def parse_heredoc_delimiter_stream(lines: List[str], start_line_idx: int, start_char_idx: int) -> Tuple[str, bool, int, int, bool]:
    """
    Parse complete heredoc delimiter word starting at lines[start_line_idx][start_char_idx],
    advancing across line continuations (\\<newline>) if present.
    Returns (delim, is_quoted, end_line_idx, end_char_idx, found_token).
    """
    delim_chars: List[str] = []
    is_quoted = False
    in_sq = False
    in_dq = False
    found_any = False

    cur_line_idx = start_line_idx
    cur_char_idx = start_char_idx

    while cur_line_idx < len(lines):
        line = lines[cur_line_idx]
        advanced_line = False
        while cur_char_idx < len(line):
            c = line[cur_char_idx]

            if in_sq:
                if c == "'":
                    in_sq = False
                else:
                    delim_chars.append(c)
                cur_char_idx += 1
                continue

            if in_dq:
                if c == "\\" and cur_char_idx + 1 < len(line):
                    nc = line[cur_char_idx + 1]
                    if nc == "\n":
                        cur_line_idx += 1
                        cur_char_idx = 0
                        advanced_line = True
                        break
                    elif nc in ('$', '`', '"', '\\'):
                        delim_chars.append(nc)
                        cur_char_idx += 2
                        continue
                    else:
                        delim_chars.append(c)
                        delim_chars.append(nc)
                        cur_char_idx += 2
                        continue
                if c == '"':
                    in_dq = False
                    cur_char_idx += 1
                    continue
                else:
                    delim_chars.append(c)
                cur_char_idx += 1
                continue

            # Outside quotes
            if c == "\\":
                if cur_char_idx + 1 < len(line):
                    nc = line[cur_char_idx + 1]
                    if nc == "\n":
                        cur_line_idx += 1
                        cur_char_idx = 0
                        advanced_line = True
                        break
                    else:
                        is_quoted = True
                        found_any = True
                        delim_chars.append(nc)
                        cur_char_idx += 2
                        continue
                cur_char_idx += 1
                continue

            if c == "'":
                is_quoted = True
                found_any = True
                in_sq = True
                cur_char_idx += 1
                continue

            if c == '"':
                is_quoted = True
                found_any = True
                in_dq = True
                cur_char_idx += 1
                continue

            if c in " \t\r\n;|&<>()":
                return "".join(delim_chars), is_quoted, cur_line_idx, cur_char_idx, found_any

            found_any = True
            delim_chars.append(c)
            cur_char_idx += 1

        if not advanced_line:
            break

    return "".join(delim_chars), is_quoted, cur_line_idx, cur_char_idx, found_any


def parse_shell_code(text: str) -> Tuple[List[List[str]], List[str]]:
    """Parse shell text into command words and active $(...) substitutions."""
    lines = text.splitlines(keepends=True)
    clean_lines: List[str] = []
    unquoted_heredoc_lines: List[str] = []
    in_heredoc = False
    heredoc_delim = ""
    heredoc_quoted = False
    heredoc_strip_tabs = False

    line_idx = 0
    while line_idx < len(lines):
        line = lines[line_idx]
        if in_heredoc:
            term_line = line.rstrip("\r\n")
            if heredoc_strip_tabs:
                term_line = term_line.lstrip("\t")
            if term_line == heredoc_delim:
                in_heredoc = False
            elif not heredoc_quoted:
                unquoted_heredoc_lines.append(line)
            line_idx += 1
            continue

        in_s = False
        in_d = False
        idx = 0
        found_heredoc = False
        while idx < len(line):
            ch = line[idx]
            if in_s:
                if ch == "'":
                    in_s = False
                idx += 1
                continue
            if in_d:
                if ch == "\\" and idx + 1 < len(line):
                    idx += 2
                    continue
                if ch == '"':
                    in_d = False
                idx += 1
                continue

            if ch == "\\" and idx + 1 < len(line):
                idx += 2
                continue
            if ch == "'":
                in_s = True
                idx += 1
                continue
            if ch == '"':
                in_d = True
                idx += 1
                continue
            if ch == "#" and (idx == 0 or line[idx - 1] in " \t;|&()"):
                break
            if ch == "<" and idx + 1 < len(line) and line[idx + 1] == "<":
                start_heredoc = idx
                idx += 2
                strip_tabs = False
                if idx < len(line) and line[idx] == "-":
                    strip_tabs = True
                    idx += 1
                while idx < len(line) and line[idx] in " \t":
                    idx += 1
                delim, is_q, end_line_idx, end_char_idx, found_tok = parse_heredoc_delimiter_stream(lines, line_idx, idx)
                if found_tok:
                    in_heredoc = True
                    heredoc_delim = delim
                    heredoc_quoted = is_q
                    heredoc_strip_tabs = strip_tabs
                    found_heredoc = True
                    suffix = lines[end_line_idx][end_char_idx:] if end_line_idx < len(lines) else ""
                    clean_lines.append(line[:start_heredoc] + " " + suffix)
                    line_idx = end_line_idx + 1
                    break
            idx += 1
        if not found_heredoc:
            clean_lines.append(line)
            line_idx += 1

    code = "".join(clean_lines)

    commands: List[List[str]] = []
    active_subs: List[str] = []
    current_cmd: List[str] = []
    current_word: List[str] = []

    # Add substitutions from unquoted heredocs
    if unquoted_heredoc_lines:
        active_subs.extend(extract_expansions_from_unquoted_text("".join(unquoted_heredoc_lines)))

    i = 0
    n = len(code)
    in_sq = False
    in_dq = False
    in_comment = False
    word_has_chars = False

    def flush_word():
        nonlocal current_word, word_has_chars
        if current_word:
            current_cmd.append("".join(current_word))
            current_word = []
            word_has_chars = False

    def flush_cmd():
        nonlocal current_cmd
        flush_word()
        if current_cmd:
            commands.append(current_cmd)
            current_cmd = []

    while i < n:
        c = code[i]
        nc = code[i + 1] if i + 1 < n else ""

        if in_comment:
            if c == "\n":
                in_comment = False
                flush_cmd()
            i += 1
            continue

        if in_sq:
            if c == "'":
                in_sq = False
            current_word.append(c)
            word_has_chars = True
            i += 1
            continue

        if in_dq:
            if c == "\\" and i + 1 < n:
                if nc == "\n":
                    # line continuation inside double quotes
                    i += 2
                    continue
                if nc in ('$', '"', '\\', '`'):
                    current_word.append(nc)
                    word_has_chars = True
                    i += 2
                    continue
                else:
                    current_word.append(c)
                    current_word.append(nc)
                    word_has_chars = True
                    i += 2
                    continue
            if c == '"':
                in_dq = False
            current_word.append(c)
            word_has_chars = True
            if c == "$" and nc == "(":
                sub_content, end_idx = extract_sub_at(code, i + 1)
                active_subs.append(sub_content)
                current_word.append(f"$({sub_content})")
                i = end_idx + 1
                continue
            i += 1
            continue

        if c == "\\":
            if i + 1 < n:
                if nc == "\n":
                    # Line continuation outside quotes
                    i += 2
                    continue
                current_word.append(nc)
                word_has_chars = True
                i += 2
                continue
            i += 1
            continue

        # Comment starts with # only if word has no non-whitespace characters
        if c == "#" and not word_has_chars:
            in_comment = True
            i += 1
            continue

        if c == "'":
            in_sq = True
            current_word.append(c)
            word_has_chars = True
            i += 1
            continue

        if c == '"':
            in_dq = True
            current_word.append(c)
            word_has_chars = True
            i += 1
            continue

        if c == "$" and nc == "(":
            sub_content, end_idx = extract_sub_at(code, i + 1)
            active_subs.append(sub_content)
            current_word.append(f"$({sub_content})")
            word_has_chars = True
            i = end_idx + 1
            continue

        if c in (" ", "\t"):
            flush_word()
            i += 1
            continue

        if (c == "&" and nc == "&") or (c == "|" and nc == "|"):
            flush_cmd()
            i += 2
            continue

        if c in (";", "\n", "|", "&"):
            flush_cmd()
            i += 1
            continue

        current_word.append(c)
        word_has_chars = True
        i += 1

    flush_cmd()
    return commands, active_subs




def analyze_shell_command(cmd: List[str], pid_vars: Set[str], pid_files: Set[str], inherited_privilege: bool = False) -> bool:
    """Analyze a single logical shell command represented as a list of tokens."""
    if not cmd:
        return False

    cmd = list(cmd)
    while cmd and cmd[0] in ("then", "else", "do", "elif", "{", "("):
        cmd.pop(0)

    if not cmd:
        return False

    # Variable assignment: VAR=/tmp/foo.pid or VAR=$(cat /tmp/foo.pid)
    if len(cmd) == 1 and "=" in cmd[0]:
        var, _, val = cmd[0].partition("=")
        val_unquoted = unquote_str(val)
        if re.search(r"/(?:tmp|dev/shm)/[^\s;\"'`]*\.pid", val_unquoted):
            pid_files.add(var)
        m_read = re.match(r"^\$\(\s*(?:cat\s+|cat\s+--\s+|<\s*)(['\"]?)(.+?)\1\s*\)", val_unquoted)
        if m_read:
            src = m_read.group(2).strip("'\"").lstrip("$").strip("{}")
            if "/tmp/" in src or "/dev/shm/" in src or src in pid_files:
                pid_vars.add(var)
        return False

    idx = 0
    is_privileged = inherited_privilege

    # Strip env vars
    while idx < len(cmd) and re.match(r"^[A-Za-z_]\w*=.*", cmd[idx]):
        idx += 1

    # Process wrappers
    while idx < len(cmd):
        tok = unquote_str(cmd[idx]).split("/")[-1]
        if tok == "sudo":
            is_privileged = True
            idx += 1
            while idx < len(cmd) and cmd[idx].startswith("-"):
                opt = cmd[idx]
                if opt in (
                    "-u", "-g", "-p", "-h", "-C", "-D", "-R", "-r", "-T", "-t", "-U",
                    "--user", "--group", "--prompt", "--host", "--chdir", "--role", "--type"
                ):
                    idx += 2
                else:
                    idx += 1
            continue
        elif tok == "pkexec":
            is_privileged = True
            idx += 1
            while idx < len(cmd) and cmd[idx].startswith("-"):
                opt = cmd[idx]
                if opt in ("-u", "--user"):
                    idx += 2
                else:
                    idx += 1
            continue
        elif tok in ("nohup", "exec", "command"):
            idx += 1
            continue
        elif tok == "timeout":
            idx += 1
            while idx < len(cmd) and cmd[idx].startswith("-"):
                opt = cmd[idx]
                if opt in ("-k", "--kill-after", "-s", "--signal"):
                    idx += 2
                elif re.match(r"^-[ks]\S+", opt):
                    idx += 1
                elif opt.startswith("--kill-after=") or opt.startswith("--signal="):
                    idx += 1
                else:
                    idx += 1
            # Consume duration
            if idx < len(cmd):
                idx += 1
            continue
        elif tok == "env":
            idx += 1
            while idx < len(cmd) and (cmd[idx].startswith("-") or "=" in cmd[idx]):
                idx += 1
            continue
        break

    if idx >= len(cmd):
        return False

    exe = unquote_str(cmd[idx]).split("/")[-1]
    args = cmd[idx + 1:]

    # Subshell invocation: sh, bash, zsh with -c
    if exe in ("sh", "bash", "zsh") and "-c" in args:
        c_idx = args.index("-c")
        if c_idx + 1 < len(args):
            payload = unquote_str(args[c_idx + 1])
            if check_mkt_base_text(payload, inherited_privilege=is_privileged):
                return True

    # Check kill / pkill
    if is_privileged and exe in ("kill", "pkill"):
        arg_str = " ".join(args)
        if re.search(r"/(?:tmp|dev/shm)/[^\s;\"'`]*\.pid", arg_str):
            return True
        for pv in (pid_vars | pid_files):
            if re.search(rf"\$(?:\{{{pv}\}}|{pv}\b)", arg_str) or pv in args:
                return True

    return False


def check_mkt_base_text(text: str, inherited_privilege: bool = False) -> bool:
    """Analyze shell script text for privileged process control from shared temp."""
    commands, subs = parse_shell_code(text)

    # 1. Check all valid $(...) command substitutions with inherited privilege!
    for sub in subs:
        if check_mkt_base_text(sub, inherited_privilege=inherited_privilege):
            return True

    # 2. Analyze commands
    pid_files: Set[str] = set()
    pid_vars: Set[str] = set()

    for cmd in commands:
        if analyze_shell_command(cmd, pid_vars, pid_files, inherited_privilege=inherited_privilege):
            return True
    return False


class PluginValidator:
    def __init__(self, plugin_dir: Path, check_sha: Optional[str] = None):
        self.plugin_dir = plugin_dir.resolve()
        self.check_sha = check_sha
        self.findings: List[Finding] = []

    def report(
        self,
        rule_id: str,
        name: str,
        policy_origin: str,
        severity: str,
        detection_mode: str,
        file_path: Path | str,
        line: int,
        message: str,
        snippet: str = "",
        suggestion: str = "",
    ) -> None:
        rel_path = str(file_path)
        try:
            if isinstance(file_path, Path):
                rel_path = str(file_path.relative_to(self.plugin_dir))
            elif Path(file_path).is_absolute():
                rel_path = str(Path(file_path).relative_to(self.plugin_dir))
        except ValueError:
            rel_path = str(file_path)

        self.findings.append(
            Finding(
                rule_id=rule_id,
                name=name,
                policy_origin=policy_origin,
                severity=severity,
                detection_mode=detection_mode,
                file_path=rel_path,
                line=line,
                message=message,
                snippet=snippet.strip(),
                suggestion=suggestion.strip(),
            )
        )

    def validate_all(self) -> List[Finding]:
        if not self.plugin_dir.is_dir():
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                self.plugin_dir,
                0,
                f"Directory does not exist: {self.plugin_dir}",
            )
            return self.findings

        # 1. Symlink checks in plugin folder
        self._check_symlinks()

        # 2. Manifest checks
        self._check_manifest()

        # 3. Optional SHA check
        if self.check_sha is not None:
            self._check_commit_sha(self.check_sha)

        # 4. Source file scans
        self._scan_plugin_files()

        return self.findings

    def _check_symlinks(self) -> None:
        """MKT-002: Check for symbolic links within the plugin directory."""
        def on_walk_error(err: OSError):
            self.report(
                "MKT-002",
                "traversal-error",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                getattr(err, "filename", str(self.plugin_dir)) or self.plugin_dir,
                0,
                f"Unreadable directory or traversal error: {err}",
            )

        try:
            for root, dirs, files in os.walk(self.plugin_dir, followlinks=False, onerror=on_walk_error):
                for d in list(dirs):
                    full_path = Path(root) / d
                    if full_path.is_symlink():
                        self.report(
                            "MKT-002",
                            "symlink-in-plugin-tree",
                            "[MKT-COMPAT]",
                            "HIGH",
                            "Deterministic",
                            full_path,
                            0,
                            f"Directory symlink prohibited in plugin tree: {d}",
                            suggestion="Bundle actual regular directories instead of symbolic links.",
                        )
                for f in files:
                    full_path = Path(root) / f
                    if full_path.is_symlink():
                        self.report(
                            "MKT-002",
                            "symlink-in-plugin-tree",
                            "[MKT-COMPAT]",
                            "HIGH",
                            "Deterministic",
                            full_path,
                            0,
                            f"Symbolic link prohibited in plugin tree: {f}",
                            suggestion="Replace symlink with regular file or remove.",
                        )
        except OSError as e:
            self.report(
                "MKT-002",
                "symlink-in-plugin-tree",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                self.plugin_dir,
                0,
                f"Filesystem traversal error checking symlinks: {e}",
            )

    def _check_commit_sha(self, sha: str) -> None:
        """MKT-003: Check format of target commit SHA."""
        clean_sha = sha.strip()
        if not clean_sha or not SHA40_REGEX.match(clean_sha):
            self.report(
                "MKT-003",
                "update-commit-sha-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                "verification-request",
                0,
                f"Target commit SHA must be a 40-character hexadecimal string, got: {sha!r}",
                suggestion="Specify the complete 40-character commit SHA matching repository HEAD.",
            )

    def _check_manifest(self) -> None:
        """MKT-001: Validate manifest.json against marketplace rules."""
        manifest_path = self.plugin_dir / "manifest.json"
        if manifest_path.is_symlink():
            self.report(
                "MKT-002",
                "symlink-in-plugin-tree",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                "manifest.json",
                0,
                "manifest.json must not be a symbolic link.",
            )
            return

        if not manifest_path.is_file():
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                "manifest.json",
                0,
                "manifest.json not found in plugin root.",
                suggestion="Create a valid manifest.json in the repository root.",
            )
            return

        try:
            with open(manifest_path, "rb") as f:
                raw_bytes = f.read(MAX_FILE_READ_BYTES + 1)
            if len(raw_bytes) > MAX_FILE_READ_BYTES:
                self.report(
                    "MKT-001",
                    "manifest-schema-invalid",
                    "[MKT-COMPAT]",
                    "HIGH",
                    "Deterministic",
                    manifest_path,
                    0,
                    f"manifest.json exceeds size limit of {MAX_FILE_READ_BYTES} bytes.",
                )
                return

            content = raw_bytes.decode("utf-8", errors="replace")
            # Reject NaN, Infinity, -Infinity
            data = json.loads(content, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"Invalid constant: {c}")))
        except json.JSONDecodeError as e:
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                manifest_path,
                e.lineno,
                f"manifest.json contains invalid JSON: {e.msg}",
            )
            return
        except Exception as e:
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                manifest_path,
                0,
                f"Could not parse manifest.json: {e}",
            )
            return

        if not isinstance(data, dict):
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                manifest_path,
                1,
                "manifest.json root must be a JSON object.",
            )
            return

        # schemaVersion check (must be 1 in JS semantics, rejecting booleans)
        schema_version = data.get("schemaVersion")
        if isinstance(schema_version, bool) or not isinstance(schema_version, (int, float)) or schema_version != 1:
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                manifest_path,
                1,
                f"schemaVersion must be 1, got: {schema_version!r}",
                suggestion="Set \"schemaVersion\": 1",
            )

        # Field length limits per upstream build-catalog.mjs (UTF-16 code units)
        field_limits = {
            "id": 128,
            "name": 120,
            "version": 64,
            "author": 120,
            "description": 500,
            "license": 120,
        }

        # Required non-empty string fields
        for field in ("name", "version", "author", "description"):
            max_len = field_limits[field]
            if field not in data:
                self.report(
                    "MKT-001",
                    "manifest-schema-invalid",
                    "[MKT-COMPAT]",
                    "HIGH",
                    "Deterministic",
                    manifest_path,
                    1,
                    f"Required field '{field}' is missing.",
                    suggestion=f"Add non-empty \"{field}\": \"...\"",
                )
                continue

            val = data[field]
            if not isinstance(val, str) or not js_trim(val):
                self.report(
                    "MKT-001",
                    "manifest-schema-invalid",
                    "[MKT-COMPAT]",
                    "HIGH",
                    "Deterministic",
                    manifest_path,
                    1,
                    f"Required field '{field}' must be a non-empty string.",
                    suggestion=f"Set non-empty \"{field}\": \"...\"",
                )
            else:
                trimmed = js_trim(val)
                if js_utf16_length(trimmed) > max_len:
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Field '{field}' exceeds maximum length of {max_len} characters (length: {js_utf16_length(trimmed)}).",
                    )
                if CONTROL_CHARS_REGEX.search(trimmed):
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Field '{field}' contains control characters (C0/C1 codes).",
                    )

        # Optional license check (must be non-empty string <= 120 chars, not null)
        if "license" in data:
            lic = data["license"]
            if lic is None:
                self.report(
                    "MKT-001",
                    "manifest-schema-invalid",
                    "[MKT-COMPAT]",
                    "HIGH",
                    "Deterministic",
                    manifest_path,
                    1,
                    "Optional field 'license' cannot be null when present.",
                )
            elif not isinstance(lic, str) or not js_trim(lic):
                self.report(
                    "MKT-001",
                    "manifest-schema-invalid",
                    "[MKT-COMPAT]",
                    "HIGH",
                    "Deterministic",
                    manifest_path,
                    1,
                    "Optional field 'license' must be a non-empty string when provided.",
                )
            else:
                trimmed_lic = js_trim(lic)
                if js_utf16_length(trimmed_lic) > 120:
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Field 'license' exceeds maximum length of 120 characters (length: {js_utf16_length(trimmed_lic)}).",
                    )
                if CONTROL_CHARS_REGEX.search(trimmed_lic):
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        "Field 'license' contains control characters.",
                    )

        # Plugin ID specifics
        if "id" not in data:
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                manifest_path,
                1,
                "Required field 'id' is missing.",
            )
        else:
            plugin_id = data["id"]
            if not isinstance(plugin_id, str) or not js_trim(plugin_id):
                self.report(
                    "MKT-001",
                    "manifest-schema-invalid",
                    "[MKT-COMPAT]",
                    "HIGH",
                    "Deterministic",
                    manifest_path,
                    1,
                    "Required field 'id' must be a non-empty string.",
                )
            else:
                if plugin_id != js_trim(plugin_id):
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Plugin id '{plugin_id}' contains leading or trailing whitespace.",
                    )
                if plugin_id.startswith("omarchy."):
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Plugin id '{plugin_id}' uses reserved namespace 'omarchy.*'.",
                        suggestion="Rename ID to use custom namespace (e.g. 'io.github.user.plugin').",
                    )
                if ".." in plugin_id:
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Plugin id '{plugin_id}' must not contain '..'.",
                    )
                if not ID_REGEX.match(plugin_id):
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Plugin id '{plugin_id}' is invalid. Must match '^[a-z0-9][a-z0-9._-]{{0,127}}\\Z' (length 1-128, start with lowercase alphanumeric, no trailing newline).",
                    )

        # Kinds validation
        if "kinds" not in data:
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                manifest_path,
                1,
                "Required field 'kinds' is missing.",
            )
        else:
            kinds = data["kinds"]
            if not isinstance(kinds, list) or not kinds:
                self.report(
                    "MKT-001",
                    "manifest-schema-invalid",
                    "[MKT-COMPAT]",
                    "HIGH",
                    "Deterministic",
                    manifest_path,
                    1,
                    "Field 'kinds' must be a non-empty array of strings.",
                )
            else:
                for kind in kinds:
                    if not isinstance(kind, str) or kind not in SUPPORTED_KINDS:
                        self.report(
                            "MKT-001",
                            "manifest-schema-invalid",
                            "[MKT-COMPAT]",
                            "HIGH",
                            "Deterministic",
                            manifest_path,
                            1,
                            f"Unsupported kind {kind!r}. Supported kinds are: {sorted(SUPPORTED_KINDS)}",
                        )

        # entryPoints validation
        if "entryPoints" not in data:
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                manifest_path,
                1,
                "Required field 'entryPoints' is missing.",
            )
        elif not isinstance(data["entryPoints"], dict) or not data["entryPoints"]:
            self.report(
                "MKT-001",
                "manifest-schema-invalid",
                "[MKT-COMPAT]",
                "HIGH",
                "Deterministic",
                manifest_path,
                1,
                "Field 'entryPoints' must be a non-empty object mapping kinds to entry paths.",
            )
        else:
            entry_points = data["entryPoints"]
            kinds_val = data.get("kinds")
            if isinstance(kinds_val, list):
                for kind in kinds_val:
                    if isinstance(kind, str) and kind in SUPPORTED_KINDS:
                        expected_key = "barWidget" if kind == "bar-widget" else kind
                        if expected_key not in entry_points:
                            self.report(
                                "MKT-001",
                                "manifest-schema-invalid",
                                "[MKT-COMPAT]",
                                "HIGH",
                                "Deterministic",
                                manifest_path,
                                1,
                                f"Missing required entryPoint key '{expected_key}' for declared kind '{kind}'.",
                            )

            for ep_key, ep_path in entry_points.items():
                if not isinstance(ep_path, str) or not ep_path.strip():
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Entry point for '{ep_key}' must be a non-empty relative path string.",
                    )
                    continue

                if ep_path.startswith("/") or ep_path.startswith("./") or ".." in ep_path or "\\" in ep_path or ":" in ep_path or CONTROL_CHARS_REGEX.search(ep_path):
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Entry point path '{ep_path}' has invalid format. Must be a safe relative path without leading './', '/', '..', ':', '\\', or control characters.",
                    )
                    continue

                entry_raw_path = self.plugin_dir / ep_path

                # Check if leaf or any path component is a symlink before resolving
                is_symlink = False
                try:
                    curr = self.plugin_dir
                    for part in Path(ep_path).parts:
                        curr = curr / part
                        if curr.is_symlink():
                            is_symlink = True
                            break
                    if is_symlink:
                        self.report(
                            "MKT-002",
                            "symlink-in-plugin-tree",
                            "[MKT-COMPAT]",
                            "HIGH",
                            "Deterministic",
                            manifest_path,
                            1,
                            f"Entry point file '{ep_path}' is or traverses a symbolic link.",
                        )
                        continue
                except (RuntimeError, OSError) as e:
                    self.report(
                        "MKT-002",
                        "symlink-in-plugin-tree",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Entry point file '{ep_path}' cannot be safely inspected for symlinks: {e}",
                    )
                    continue

                try:
                    if not entry_raw_path.exists():
                        self.report(
                            "MKT-001",
                            "manifest-schema-invalid",
                            "[MKT-COMPAT]",
                            "HIGH",
                            "Deterministic",
                            manifest_path,
                            1,
                            f"Entry point file '{ep_path}' does not exist.",
                        )
                        continue
                    target_file = entry_raw_path.resolve(strict=True)
                    target_file.relative_to(self.plugin_dir)
                except (ValueError, RuntimeError, OSError) as e:
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Entry point file '{ep_path}' cannot be resolved safely: {e}",
                    )
                    continue

                if not target_file.is_file():
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"Entry point file '{ep_path}' does not exist as a regular file.",
                    )

        # barWidget.defaultSection check
        if "barWidget" in data and isinstance(data["barWidget"], dict):
            bw = data["barWidget"]
            if "defaultSection" in bw:
                sec = bw["defaultSection"]
                if not isinstance(sec, str) or sec not in DEFAULT_SECTIONS:
                    self.report(
                        "MKT-001",
                        "manifest-schema-invalid",
                        "[MKT-COMPAT]",
                        "HIGH",
                        "Deterministic",
                        manifest_path,
                        1,
                        f"barWidget.defaultSection must be one of {sorted(DEFAULT_SECTIONS)}, got {sec!r}.",
                    )

    def _safe_read_text(self, path: Path) -> Optional[str]:
        """Read file safely, rejecting symlinks and non-regular files with hard byte limit."""
        try:
            if path.is_symlink() or not path.is_file():
                return None
            try:
                if path.stat().st_size > MAX_FILE_READ_BYTES:
                    self.report(
                        "OBS-001",
                        "file-size-limit-exceeded",
                        "[OBS-REC]",
                        "HIGH",
                        "Deterministic",
                        path,
                        0,
                        f"File exceeds size limit of {MAX_FILE_READ_BYTES} bytes; skipping full analysis.",
                    )
                    return None
            except OSError:
                pass

            with open(path, "rb") as f:
                raw_bytes = f.read(MAX_FILE_READ_BYTES + 1)
            if len(raw_bytes) > MAX_FILE_READ_BYTES:
                self.report(
                    "OBS-001",
                    "file-size-limit-exceeded",
                    "[OBS-REC]",
                    "HIGH",
                    "Deterministic",
                    path,
                    0,
                    f"File exceeds size limit of {MAX_FILE_READ_BYTES} bytes ({len(raw_bytes)} bytes); skipping full analysis.",
                )
                return None
            return raw_bytes.decode("utf-8", errors="replace")
        except OSError as e:
            self.report(
                "OBS-002",
                "file-read-error",
                "[OBS-REC]",
                "HIGH",
                "Deterministic",
                path,
                0,
                f"I/O error reading file: {e}",
            )
            return None

    def _scan_plugin_files(self) -> None:
        """Scan scripts and QML files for security and hardening rules."""
        def on_walk_error(err: OSError):
            self.report(
                "OBS-003",
                "directory-walk-error",
                "[OBS-REC]",
                "HIGH",
                "Deterministic",
                getattr(err, "filename", str(self.plugin_dir)) or self.plugin_dir,
                0,
                f"Unreadable directory during scan: {err}",
            )

        try:
            for root, dirs, files in os.walk(self.plugin_dir, followlinks=False, onerror=on_walk_error):
                if ".git" in dirs:
                    dirs.remove(".git")

                for filename in files:
                    file_path = Path(root) / filename
                    if file_path.is_symlink():
                        continue

                    # SEC-009: AI agent steering file in distributable plugin tree
                    if filename.lower() in ("agents.md", "agent.md", "claude.md", ".cursorrules"):
                        self.report(
                            "SEC-009",
                            "agent-steering-directive-injection",
                            "[MKT-POLICY]",
                            "HIGH",
                            "Deterministic",
                            file_path,
                            1,
                            f"AI agent directive file '{filename}' found in plugin tree. Coding agents auto-ingest root/nested agent files, creating indirect prompt injection risk in user sessions.",
                            suggestion="Remove agent files from distributable checkout or rename contributor notes to 'DEVELOPMENT.md'.",
                        )

                    suffix = file_path.suffix.lower()
                    if suffix == ".qml":
                        self._scan_qml_file(file_path)
                    elif suffix in (".sh", ".bash") or (file_path.parent.name in ("bin", "scripts") and not suffix):
                        self._scan_shell_file(file_path)
                    elif suffix == ".js":
                        self._scan_js_file(file_path)
                    elif suffix == ".py":
                        self._scan_python_file(file_path)
        except OSError:
            pass

    def _scan_shell_file(self, path: Path) -> None:
        """Scan shell scripts for SEC-001, SEC-002, SEC-008."""
        raw_content = self._safe_read_text(path)
        if raw_content is None:
            return

        lines = raw_content.splitlines()

        # SEC-008: Ambient PATH shebang
        if lines and lines[0].startswith("#!"):
            shebang = lines[0]
            if "/usr/bin/env " in shebang and ("sh" in shebang or "bash" in shebang):
                self.report(
                    "SEC-008",
                    "ambient-path-daemon-exec",
                    "[OBS-REC]",
                    "MEDIUM",
                    "Heuristic",
                    path,
                    1,
                    f"Portable shebang '{shebang}' relies on ambient PATH resolution.",
                    snippet=shebang,
                    suggestion="Use explicit interpreter path with privileged mode: '#!/usr/bin/bash -p'",
                )

        # Baseline check: privileged process control from shared temp
        if check_mkt_base_text(raw_content):
            self.report(
                "SEC-002",
                "privileged-process-control-from-shared-temp",
                "[MKT-BASE]",
                "HIGH",
                "Heuristic",
                path,
                1,
                "Privileged process control trusting PID from predictable shared temporary state (/tmp or /dev/shm).",
                suggestion="Store PID files under verified $XDG_RUNTIME_DIR.",
            )

        clean_no_comments = strip_comments_and_strings(raw_content, language="sh", strip_strings=False)
        has_pipefail = bool(re.search(r"\bset\s+-[a-zA-Z]*o\s+pipefail\b", clean_no_comments))
        early_reader_regex = re.compile(r"\|\s*(head\b|grep\s+-[a-zA-Z]*q\b|grep\s+-[a-zA-Z]*m\s*\d+\b|sed\s+['\"][^'\"]*q['\"])")

        clean_lines = clean_no_comments.splitlines()
        for idx, clean_line in enumerate(clean_lines, 1):
            stripped = clean_line.strip()
            if not stripped:
                continue

            # SEC-001: pipefail + early reader
            if has_pipefail and early_reader_regex.search(stripped):
                if "141" not in stripped and "truncate" not in stripped:
                    self.report(
                        "SEC-001",
                        "pipefail-sigpipe-crash",
                        "[OBS-REC]",
                        "MEDIUM",
                        "Heuristic",
                        path,
                        idx,
                        "Pipeline to early-closing consumer (head/grep -q) under pipefail causes SIGPIPE (exit 141) crash.",
                        snippet=stripped,
                        suggestion="Capture output to temporary file and truncate conditionally: 'if [ size -gt 16384 ]; then truncate -s 16384 file; fi'",
                    )

            # SEC-010: General shared-temp path usage (OBS-REC)
            if re.search(r"/(?:tmp|dev/shm)/[a-zA-Z0-9_-]+", stripped):
                if "mktemp" not in stripped and "XDG_RUNTIME_DIR" not in stripped:
                    self.report(
                        "SEC-010",
                        "shared-temp-path-state",
                        "[OBS-REC]",
                        "HIGH",
                        "Heuristic",
                        path,
                        idx,
                        "Hardcoded file in shared directory (/tmp or /dev/shm) is vulnerable to TOCTOU and symlink attacks.",
                        snippet=stripped,
                        suggestion="Use a private user directory under $XDG_RUNTIME_DIR with mode 0700.",
                    )

    def _scan_python_file(self, path: Path) -> None:
        """Scan Python helpers for SEC-010."""
        raw_content = self._safe_read_text(path)
        if raw_content is None:
            return

        clean_content = strip_comments_and_strings(raw_content, language="sh", strip_strings=False)
        clean_lines = clean_content.splitlines()

        for idx, line in enumerate(clean_lines, 1):
            stripped = line.strip()
            if re.search(r"/(?:tmp|dev/shm)/[a-zA-Z0-9_-]+", stripped):
                if "NamedTemporaryFile" not in stripped and "mkstemp" not in stripped and "XDG_RUNTIME_DIR" not in stripped:
                    self.report(
                        "SEC-010",
                        "shared-temp-path-state",
                        "[OBS-REC]",
                        "HIGH",
                        "Heuristic",
                        path,
                        idx,
                        "Hardcoded file in shared directory (/tmp or /dev/shm) in Python helper.",
                        snippet=stripped,
                        suggestion="Resolve path via os.environ.get('XDG_RUNTIME_DIR') with mode 0700.",
                    )

    def _scan_js_file(self, path: Path) -> None:
        """Scan JavaScript files for SEC-006."""
        raw_content = self._safe_read_text(path)
        if raw_content is None:
            return

        tokens = tokenize_qml(raw_content)
        for i in range(len(tokens)):
            k1, v1, l1 = tokens[i]
            if v1 == "Qt.createQmlObject" and i + 1 < len(tokens) and tokens[i + 1][1] == "(":
                arg1_tokens = []
                depth = 0
                j = i + 2
                while j < len(tokens):
                    tk, tv, _ = tokens[j]
                    if tv in ("(", "{", "["):
                        depth += 1
                    elif tv in (")", "}", "]"):
                        if depth == 0:
                            break
                        depth -= 1
                    elif tv == "," and depth == 0:
                        break
                    arg1_tokens.append((tk, tv))
                    j += 1

                if not is_static_expr(arg1_tokens):
                    expr_snippet = " ".join(v for _, v in arg1_tokens)
                    self.report(
                        "SEC-006",
                        "dynamic-qml-eval-sink",
                        "[OBS-REC]",
                        "HIGH",
                        "Deterministic",
                        path,
                        l1,
                        f"Dynamic QML evaluation via Qt.createQmlObject with non-literal argument: {expr_snippet[:40]}",
                        snippet=f"Qt.createQmlObject({expr_snippet[:60]}...",
                        suggestion="Use Loader { source: '...' } with static component files.",
                    )

    def _scan_qml_file(self, path: Path) -> None:
        """Scan QML files for SEC-002, SEC-003, SEC-004, SEC-005, SEC-006, SEC-007."""
        raw_content = self._safe_read_text(path)
        if raw_content is None:
            return

        tokens = tokenize_qml(raw_content)

        # Baseline check: privileged process control from shared temp in QML
        for i in range(len(tokens)):
            v = tokens[i][1]
            line_no = tokens[i][2]
            is_cmd = False
            start_j = -1

            # Match command: [ ... ]
            if v == "command" and i + 2 < len(tokens) and tokens[i + 1][1] == ":" and tokens[i + 2][1] == "[":
                is_cmd = True
                start_j = i + 3
            # Match Quickshell.exec( [ ... ] ) or exec( [ ... ] )
            elif (
                v in ("Quickshell.exec", "Quickshell.execDetached", "exec", "execDetached")
                and i + 2 < len(tokens)
                and tokens[i + 1][1] == "("
                and tokens[i + 2][1] == "["
            ):
                is_cmd = True
                start_j = i + 3

            if is_cmd and start_j != -1:
                arr_tokens: List[str] = []
                depth = 1
                j = start_j
                while j < len(tokens) and depth > 0:
                    if tokens[j][1] == "[":
                        depth += 1
                    elif tokens[j][1] == "]":
                        depth -= 1
                        if depth == 0:
                            break
                    if tokens[j][0] == "STRING":
                        arr_tokens.append(unquote_str(tokens[j][1]))
                    j += 1

                if arr_tokens and analyze_shell_command(arr_tokens, set(), set(), inherited_privilege=False):
                    self.report(
                        "SEC-002",
                        "privileged-process-control-from-shared-temp",
                        "[MKT-BASE]",
                        "HIGH",
                        "Heuristic",
                        path,
                        line_no,
                        "Privileged process control trusting PID from predictable shared temporary state in QML command.",
                        suggestion="Store PID files under verified $XDG_RUNTIME_DIR.",
                    )

        for i in range(len(tokens) - 2):
            k1, v1, l1 = tokens[i]
            k2, v2, _ = tokens[i + 1]
            k3, v3, _ = tokens[i + 2]

            # SEC-007: WlrLayershell.keyboardFocus : WlrKeyboardFocus.Exclusive or 1
            if v1 in ("WlrLayershell.keyboardFocus", "keyboardFocus") and v2 == ":" and (v3 in ("WlrKeyboardFocus.Exclusive", "1")):
                self.report(
                    "SEC-007",
                    "layershell-exclusive-focus",
                    "[OBS-REC]",
                    "HIGH",
                    "Deterministic",
                    path,
                    l1,
                    "Exclusive keyboard focus requested on layer-shell surface (WlrKeyboardFocus.Exclusive / 1).",
                    snippet=f"{v1}: {v3}",
                    suggestion="Use 'WlrKeyboardFocus.None' (0) or 'WlrKeyboardFocus.OnDemand' (2).",
                )

            # SEC-006: Qt.createQmlObject( ... )
            if v1 == "Qt.createQmlObject" and v2 == "(":
                arg1_tokens = []
                depth = 0
                j = i + 2
                while j < len(tokens):
                    tk, tv, _ = tokens[j]
                    if tv in ("(", "{", "["):
                        depth += 1
                    elif tv in (")", "}", "]"):
                        if depth == 0:
                            break
                        depth -= 1
                    elif tv == "," and depth == 0:
                        break
                    arg1_tokens.append((tk, tv))
                    j += 1

                if not is_static_expr(arg1_tokens):
                    expr_snippet = " ".join(v for _, v in arg1_tokens)
                    self.report(
                        "SEC-006",
                        "dynamic-qml-eval-sink",
                        "[OBS-REC]",
                        "HIGH",
                        "Deterministic",
                        path,
                        l1,
                        f"Dynamic QML evaluation via Qt.createQmlObject with non-literal argument: {expr_snippet[:40]}",
                        snippet=f"Qt.createQmlObject({expr_snippet[:60]}...",
                        suggestion="Use Loader with static component files.",
                    )

        # Object-level scan for Text, Image, and Process
        self._analyze_qml_objects(path, tokens)

    def _analyze_qml_objects(self, path: Path, tokens: List[Tuple[str, str, int]]) -> None:
        """Parse QML object tree to evaluate properties in Text, Image, and Process items."""
        stack: List[Dict[str, Any]] = []

        file_has_timer = any(v == "Timer" for _, v, _ in tokens)
        file_has_cancel = any(v in ("running", "signal") for _, v, _ in tokens)

        i = 0
        while i < len(tokens):
            kind, val, line = tokens[i]

            # Only QML types start with an uppercase letter (Item, Text, Process, etc.)
            if kind == "IDENT" and is_qml_type_name(val) and i + 1 < len(tokens) and tokens[i + 1][1] == "{":
                obj = {"type": val, "line": line, "properties": {}, "sub_objects": [], "js_depth": 0}
                if stack:
                    stack[-1]["sub_objects"].append(obj)
                stack.append(obj)
                i += 2
                continue
            elif val == "{":
                if stack:
                    stack[-1]["js_depth"] += 1
                i += 1
                continue
            elif val == "}":
                if stack:
                    if stack[-1]["js_depth"] > 0:
                        stack[-1]["js_depth"] -= 1
                    else:
                        completed_obj = stack.pop()
                        self._evaluate_qml_object(path, completed_obj, file_has_timer and file_has_cancel)
                i += 1
                continue
            elif kind == "IDENT" and val in ("property", "readonly"):
                # Skip property keyword and type to colon
                while i < len(tokens) and tokens[i][1] != ":":
                    i += 1
                if i < len(tokens) and tokens[i][1] == ":":
                    prop_name = tokens[i - 1][1]
                    prop_line = tokens[i - 1][2]
                    i += 1
                    expr_tokens: List[Tuple[str, str]] = []
                    nested = 0
                    while i < len(tokens):
                        tk, tv, _ = tokens[i]
                        if tv in ("{", "(", "["):
                            nested += 1
                        elif tv in ("}", ")", "]"):
                            if nested == 0:
                                break
                            nested -= 1
                        elif tv == ";" and nested == 0:
                            i += 1
                            break
                        elif tk == "IDENT" and nested == 0:
                            if tv in ("property", "readonly", "function", "signal", "alias", "id"):
                                break
                            if i + 1 < len(tokens) and tokens[i + 1][1] in (":", "{"):
                                break
                        expr_tokens.append((tk, tv))
                        i += 1
                    if stack and stack[-1]["js_depth"] == 0:
                        stack[-1]["properties"][prop_name] = (expr_tokens, prop_line)
                continue
            elif kind == "IDENT" and i + 1 < len(tokens) and tokens[i + 1][1] == ":":
                prop_name = val
                prop_line = line
                i += 2
                expr_tokens: List[Tuple[str, str]] = []
                nested = 0
                while i < len(tokens):
                    tk, tv, _ = tokens[i]
                    if tv in ("{", "(", "["):
                        nested += 1
                    elif tv in ("}", ")", "]"):
                        if nested == 0:
                            break
                        nested -= 1
                    elif tv == ";" and nested == 0:
                        i += 1
                        break
                    elif tk == "IDENT" and nested == 0:
                        if tv in ("property", "readonly", "function", "signal", "alias", "id"):
                            break
                        if i + 1 < len(tokens) and tokens[i + 1][1] in (":", "{"):
                            break
                    expr_tokens.append((tk, tv))
                    i += 1
                if stack and stack[-1]["js_depth"] == 0:
                    stack[-1]["properties"][prop_name] = (expr_tokens, prop_line)
                continue
            i += 1

    def _evaluate_qml_object(self, path: Path, obj: Dict[str, Any], file_has_watchdog: bool) -> None:
        obj_type = obj["type"]
        props = obj["properties"]

        # SEC-003: Check Text elements
        if obj_type in ("Text", "Label") or obj_type.endswith(".Text") or obj_type.endswith(".Label"):
            if "text" in props:
                expr_tokens, line_no = props["text"]
                has_plain_text = False
                if "textFormat" in props:
                    tf_tokens, _ = props["textFormat"]
                    tf_val = "".join(v for _, v in tf_tokens).strip()
                    if tf_val in ("Text.PlainText", "PlainText", "0"):
                        has_plain_text = True

                if not has_plain_text and not is_static_expr(expr_tokens):
                    expr_str = " ".join(v for _, v in expr_tokens)
                    self.report(
                        "SEC-003",
                        "qml-untrusted-text-markup",
                        "[OBS-REC]",
                        "MEDIUM",
                        "Heuristic",
                        path,
                        line_no,
                        f"QML {obj_type} renders dynamic expression without explicit 'textFormat: Text.PlainText': {expr_str[:40]}",
                        snippet=f"text: {expr_str[:60]}",
                        suggestion="Add 'textFormat: Text.PlainText' to prevent rich-text / HTML injection.",
                    )

        # SEC-005: Check Image elements
        if obj_type in ("Image", "AsyncImage") or obj_type.endswith(".Image"):
            if "source" in props:
                expr_tokens, line_no = props["source"]
                expr_str = " ".join(v for _, v in expr_tokens)
                is_remote_http = "http://" in expr_str or "https://" in expr_str
                is_template_dynamic = any(
                    k == "STRING" and v.startswith("`") and "${" in v for k, v in expr_tokens
                )
                is_local_static = (
                    len(expr_tokens) == 1
                    and expr_tokens[0][0] == "STRING"
                    and not is_remote_http
                    and not is_template_dynamic
                )
                if is_remote_http:
                    self.report(
                        "SEC-005",
                        "image-unvalidated-remote-uri",
                        "[OBS-REC]",
                        "MEDIUM",
                        "Heuristic",
                        path,
                        line_no,
                        "Image element binds source directly to remote HTTP/HTTPS URL.",
                        snippet=f"source: {expr_str[:60]}",
                        suggestion="Cache remote assets locally via helper, or use local asset paths.",
                    )
                elif not is_local_static:
                    self.report(
                        "SEC-005",
                        "image-unvalidated-remote-uri",
                        "[OBS-REC]",
                        "MEDIUM",
                        "Heuristic",
                        path,
                        line_no,
                        "Image element binds source to dynamic or external expression without verified local protocol.",
                        snippet=f"source: {expr_str[:60]}",
                        suggestion="Ensure image source resolves to trusted local file:// or qrc: protocol.",
                    )

        # SEC-004: Check Process elements
        if obj_type in ("Process", "Subprocess") or obj_type.endswith(".Process"):
            if not file_has_watchdog:
                self.report(
                    "SEC-004",
                    "process-unbounded-lifecycle",
                    "[OBS-REC]",
                    "MEDIUM",
                    "Heuristic",
                    path,
                    obj["line"],
                    "Process element has no companion watchdog Timer or cancellation logic in component.",
                    snippet=f"Process {{ line {obj['line']} }}",
                    suggestion="Implement a 2-stage watchdog timer terminating unresponsive background helpers.",
                )


def format_text_report(findings: List[Finding], target_dir: Path) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(f"Omarchy Plugin Marketplace Readiness Report (v{VERSION})")
    lines.append(f"Target: {target_dir}")
    lines.append("=" * 72)
    lines.append("Note: Advisory pre-flight scan. 'No findings' does not guarantee upstream acceptance.\n")

    if not findings:
        lines.append("✅ PASS: No compatibility blockers or high-risk patterns detected.\n")
        return "\n".join(lines)

    compat_count = sum(1 for f in findings if f.policy_origin == "[MKT-COMPAT]")
    base_count = sum(1 for f in findings if f.policy_origin == "[MKT-BASE]")
    policy_count = sum(1 for f in findings if f.policy_origin == "[MKT-POLICY]")
    obs_count = sum(1 for f in findings if f.policy_origin == "[OBS-REC]")

    lines.append(f"Summary: {len(findings)} findings ({compat_count} Compat, {base_count} Baseline, {policy_count} Policy, {obs_count} Advisory)")
    lines.append("-" * 72)

    findings_by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        findings_by_file.setdefault(f.file_path, []).append(f)

    for file_path, file_findings in sorted(findings_by_file.items()):
        lines.append(f"\n📄 {file_path}")
        for f in file_findings:
            sev_marker = {
                "CRITICAL": "🛑 [CRITICAL]",
                "HIGH": "❌ [HIGH]",
                "MEDIUM": "⚠️  [MEDIUM]",
                "INFO": "ℹ️  [INFO]",
            }.get(f.severity, f"[{f.severity}]")

            lines.append(f"  Line {f.line:>4}: {sev_marker} {f.policy_origin} {f.rule_id} ({f.name})")
            lines.append(f"            {safe_str(f.message)}")
            if f.snippet:
                lines.append(f"            Snippet: {safe_str(f.snippet[:80])}")
            if f.suggestion:
                lines.append(f"            Fix:     {safe_str(f.suggestion)}")

    lines.append("\n" + "=" * 72)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pre-flight validation for Omarchy Quattro plugins prior to marketplace submission.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to plugin directory (or directory containing plugins if --recursive).",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Scan all subdirectories containing manifest.json.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output structured JSON results.",
    )
    parser.add_argument(
        "--check-sha",
        help="Validate a 40-character target commit SHA for plugin update.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    args = parser.parse_args()
    raw_target = Path(args.target)

    # Protect target inspection completely
    try:
        if not raw_target.exists():
            if args.json_output:
                safe_print(json.dumps({
                    "version": VERSION,
                    "error": f"Target path does not exist: {raw_target}",
                    "discovery_errors": [f"Target path does not exist: {raw_target}"]
                }, indent=2))
            else:
                safe_print(f"Error: Target path does not exist: {raw_target}", file=sys.stderr)
            return 2

        if not raw_target.is_dir():
            if args.json_output:
                safe_print(json.dumps({
                    "version": VERSION,
                    "error": f"Target path is not a directory: {raw_target}",
                    "discovery_errors": [f"Target path is not a directory: {raw_target}"]
                }, indent=2))
            else:
                safe_print(f"Error: Target path is not a directory: {raw_target}", file=sys.stderr)
            return 2

        target_path = raw_target.resolve(strict=True)
        if not target_path.is_dir():
            if args.json_output:
                safe_print(json.dumps({
                    "version": VERSION,
                    "error": f"Target path is not a directory: {target_path}",
                    "discovery_errors": [f"Target path is not a directory: {target_path}"]
                }, indent=2))
            else:
                safe_print(f"Error: Target path is not a directory: {target_path}", file=sys.stderr)
            return 2
    except (RuntimeError, OSError) as e:
        if args.json_output:
            safe_print(json.dumps({
                "version": VERSION,
                "error": f"Target path could not be accessed or resolved: {e}",
                "discovery_errors": [f"Target path could not be accessed or resolved: {e}"]
            }, indent=2))
        else:
            safe_print(f"Error: Target path could not be accessed or resolved: {e}", file=sys.stderr)
        return 2

    if args.check_sha is not None and not args.check_sha.strip():
        if args.json_output:
            safe_print(json.dumps({
                "version": VERSION,
                "error": "--check-sha requires a non-empty string",
                "discovery_errors": ["--check-sha requires a non-empty string"]
            }, indent=2))
        else:
            safe_print("Error: --check-sha requires a non-empty string", file=sys.stderr)
        return 2

    discovery_errors: List[str] = []
    targets_to_scan: List[Path] = []
    if args.recursive:
        def on_rec_error(err: OSError):
            msg = f"Cannot access {getattr(err, 'filename', str(target_path))}: {err}"
            discovery_errors.append(msg)
            safe_print(f"Error: {msg}", file=sys.stderr)

        for root, dirs, files in os.walk(target_path, followlinks=False, onerror=on_rec_error):
            if "manifest.json" in files:
                targets_to_scan.append(Path(root))
        if not targets_to_scan and not args.json_output and not discovery_errors:
            safe_print(f"Notice: No manifest.json found under {target_path}\n", file=sys.stderr)
    else:
        targets_to_scan.append(target_path)

    all_findings: Dict[str, List[Dict[str, Any]]] = {}
    total_compat_errors = 0
    total_baseline_errors = 0
    total_policy_errors = 0
    total_findings_count = 0

    for plugin_dir in sorted(targets_to_scan):
        validator = PluginValidator(plugin_dir, check_sha=args.check_sha)
        findings = validator.validate_all()
        total_findings_count += len(findings)
        total_compat_errors += sum(1 for f in findings if f.policy_origin == "[MKT-COMPAT]")
        total_baseline_errors += sum(1 for f in findings if f.policy_origin == "[MKT-BASE]")
        total_policy_errors += sum(1 for f in findings if f.policy_origin == "[MKT-POLICY]")

        if args.json_output:
            all_findings[str(plugin_dir)] = [asdict(f) for f in findings]
        else:
            safe_print(format_text_report(findings, plugin_dir))

    if args.json_output:
        summary = {
            "version": VERSION,
            "target": str(target_path),
            "plugins_scanned": len(targets_to_scan),
            "total_findings": total_findings_count,
            "total_compat_errors": total_compat_errors,
            "total_baseline_errors": total_baseline_errors,
            "total_policy_errors": total_policy_errors,
            "discovery_errors": discovery_errors,
            "findings_by_plugin": all_findings,
            "disclaimer": "Advisory pre-flight report. 'No findings' does not guarantee upstream marketplace acceptance.",
        }
        safe_print(json.dumps(summary, indent=2))

    if discovery_errors:
        return 2

    # Exit code contract:
    # 0 = clean or advisory only
    # 1 = compatibility errors, baseline blockers, or policy violations found
    if total_compat_errors > 0 or total_baseline_errors > 0 or total_policy_errors > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
