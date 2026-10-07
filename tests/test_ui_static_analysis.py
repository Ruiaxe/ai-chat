"""
tests/test_ui_static_analysis.py
Static analysis tests for HTML and JavaScript UI assets.
Verifies that:
1. /static/common.js is included and provides shared utilities (escapeHtml, escapeJs, formatRelativeTime, copyTextToClipboard).
2. All functions invoked in HTML event handlers (onclick, onchange, etc.) and in JS template literals are defined.
3. No bare function calls refer to undefined functions.
4. No variable assignments occur to undeclared variables (prevents regressions like missing 'let agentsCache = []').
"""

import os
os.environ["AICHAT_TESTING"] = "1"
import re
import unittest
from pathlib import Path
from bs4 import BeautifulSoup

from aichat.config import STATIC_DIR

STANDARD_GLOBALS = {
    # JS primitives & built-ins
    "Object", "Function", "Boolean", "Symbol", "Number", "BigInt", "Math", "Date", "String", "RegExp",
    "Array", "Int8Array", "Uint8Array", "Uint8ClampedArray", "Int16Array", "Uint16Array",
    "Int32Array", "Uint32Array", "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array",
    "Map", "Set", "WeakMap", "WeakSet", "ArrayBuffer", "DataView", "JSON", "Promise", "Reflect", "Proxy",
    "Intl", "WebAssembly",
    # Global functions
    "eval", "isFinite", "isNaN", "parseFloat", "parseInt", "decodeURI", "decodeURIComponent",
    "encodeURI", "encodeURIComponent", "escape", "unescape",
    # Browser globals
    "window", "self", "document", "navigator", "location", "history", "screen",
    "console", "fetch", "alert", "prompt", "confirm",
    "setTimeout", "clearTimeout", "setInterval", "clearInterval", "requestAnimationFrame", "cancelAnimationFrame",
    "localStorage", "sessionStorage", "indexedDB",
    "Event", "CustomEvent", "MouseEvent", "KeyboardEvent", "FocusEvent", "UIEvent",
    "WebSocket", "EventSource", "XMLHttpRequest", "FileReader", "FormData", "Blob", "File",
    "URL", "URLSearchParams", "Headers", "Request", "Response",
    "AbortController", "AbortSignal",
    "MutationObserver", "IntersectionObserver", "ResizeObserver",
    "AudioContext", "webkitAudioContext",
    "Node", "Element", "HTMLElement", "HTMLInputElement", "HTMLButtonElement", "HTMLSelectElement",
    "Image", "Audio", "Notification",
    "Error", "TypeError", "RangeError", "ReferenceError", "SyntaxError",
    "performance", "crypto", "atob", "btoa",
    # Third-party libraries loaded via CDN / local scripts
    "marked", "DOMPurify", "lucide",
    # Event parameter in inline handlers
    "event", "e", "this"
}

JS_KEYWORDS = {
    "if", "while", "for", "switch", "case", "catch", "function", "return", "throw",
    "typeof", "void", "delete", "import", "export", "super", "new", "await",
    "yield", "class", "constructor", "finally", "try", "with", "debugger",
    "async", "static", "get", "set", "true", "false", "null", "undefined"
}

CALLBACK_NAMES = {
    "onSuccess", "resolve", "reject", "cb", "callback", "fn", "handler", "done", "action"
}


def tokenize_js(code: str) -> str:
    """
    Parses JavaScript code and strips line/block comments, string literals, and literal
    template text, while preserving executable code inside ${...} expressions and properly
    skipping RegExp literals.
    """
    n = len(code)
    i = 0
    stack = ['NORMAL']
    brace_depth = [0]
    output = []
    last_token = ''

    regex_preceders = {
        '(', '[', '{', ';', ',', '=', ':', '!', '&', '|', '?', '+', '-', '*', '%', '~', '^',
        'return', 'case', 'typeof', 'void', 'delete', 'throw', 'yield', 'await', 'in'
    }

    while i < n:
        state = stack[-1]
        c = code[i]
        c2 = code[i:i+2] if i + 1 < n else ''

        if state == 'NORMAL':
            if c.isspace():
                output.append(c)
                i += 1
                continue

            if c2 == '//':
                end = code.find('\n', i)
                if end == -1: end = n
                output.append(' ')
                i = end
                continue
            elif c2 == '/*':
                end = code.find('*/', i + 2)
                if end == -1: end = n
                else: end += 2
                output.append(' ')
                i = end
                continue
            elif c == '"':
                output.append(' ')
                i += 1
                while i < n:
                    if code[i] == '\\': i += 2
                    elif code[i] == '"': i += 1; break
                    else: i += 1
                last_token = 'STRING'
                continue
            elif c == "'":
                output.append(' ')
                i += 1
                while i < n:
                    if code[i] == '\\': i += 2
                    elif code[i] == "'": i += 1; break
                    else: i += 1
                last_token = 'STRING'
                continue
            elif c == '/':
                if last_token in regex_preceders or not last_token:
                    # RegExp literal
                    output.append(' ')
                    i += 1
                    in_char_class = False
                    while i < n:
                        if code[i] == '\\':
                            i += 2
                        elif code[i] == '[':
                            in_char_class = True
                            i += 1
                        elif code[i] == ']' and in_char_class:
                            in_char_class = False
                            i += 1
                        elif code[i] == '/' and not in_char_class:
                            i += 1
                            while i < n and code[i].isalpha():
                                i += 1
                            break
                        else:
                            i += 1
                    last_token = 'REGEXP'
                    continue
                else:
                    output.append(c)
                    last_token = '/'
                    i += 1
                    continue
            elif c == '`':
                stack.append('TEMPLATE')
                brace_depth.append(0)
                output.append(' ')
                last_token = '`'
                i += 1
                continue
            elif c == '{':
                brace_depth[-1] += 1
                output.append(c)
                last_token = '{'
                i += 1
                continue
            elif c == '}':
                if len(stack) > 1 and brace_depth[-1] == 0:
                    stack.pop()
                    brace_depth.pop()
                    output.append(' ')
                    last_token = '}'
                    i += 1
                else:
                    if brace_depth[-1] > 0:
                        brace_depth[-1] -= 1
                    output.append(c)
                    last_token = '}'
                    i += 1
                continue
            elif c.isalnum() or c in '_$':
                start_id = i
                while i < n and (code[i].isalnum() or code[i] in '_$'):
                    output.append(code[i])
                    i += 1
                ident = code[start_id:i]
                last_token = ident
                continue
            else:
                output.append(c)
                last_token = c
                i += 1
        elif state == 'TEMPLATE':
            if c == '`':
                stack.pop()
                brace_depth.pop()
                output.append(' ')
                last_token = '`'
                i += 1
            elif c2 == '${':
                stack.append('NORMAL')
                brace_depth.append(0)
                output.append(' ')
                last_token = '${'
                i += 2
            elif c == '\\':
                i += 2
            else:
                output.append(' ')
                i += 1

    return "".join(output)


def extract_page_symbols_and_scripts(html_path: Path):
    """Parses HTML file, loads referenced local scripts, and extracts declared symbols."""
    content = html_path.read_text(encoding="utf-8")
    soup = BeautifulSoup(content, "html.parser")

    js_sources = []
    for script_tag in soup.find_all("script"):
        src = script_tag.get("src")
        if src and src.startswith("/static/"):
            rel_name = src.replace("/static/", "")
            local_file = STATIC_DIR / rel_name
            if local_file.exists():
                js_sources.append((local_file.name, local_file.read_text(encoding="utf-8")))
        elif script_tag.string:
            js_sources.append(("inline_script", script_tag.string))

    defined_symbols = set(STANDARD_GLOBALS)

    func_def_re = re.compile(r'\b(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(')
    class_def_re = re.compile(r'\bclass\s+([A-Za-z0-9_$]+)\b')
    var_decl_re = re.compile(r'\b(?:let|const|var)\s+([A-Za-z0-9_$]+)\b')
    window_assign_re = re.compile(r'\bwindow\.([A-Za-z0-9_$]+)\s*=')
    arrow_func_re = re.compile(r'\b(?:let|const|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\(')

    for name, code in js_sources:
        for m in func_def_re.finditer(code):
            defined_symbols.add(m.group(1))
        for m in class_def_re.finditer(code):
            defined_symbols.add(m.group(1))
        for m in var_decl_re.finditer(code):
            defined_symbols.add(m.group(1))
        for m in window_assign_re.finditer(code):
            defined_symbols.add(m.group(1))
        for m in arrow_func_re.finditer(code):
            defined_symbols.add(m.group(1))
        # Destructuring declarations: let { a, b } = ... or const [ a, b ] = ...
        for m in re.finditer(r'\b(?:let|const|var)\s+[\{\[]([^\}\]]+)[\}\]]', code):
            for part in m.group(1).split(','):
                part = part.strip().split(':')[0].strip().split('=')[0].strip()
                if part and part.isidentifier():
                    defined_symbols.add(part)

        tokenized = tokenize_js(code)
        # Function parameters: function(a, b)
        for m in re.finditer(r'\bfunction\s+(?:[A-Za-z0-9_$]+\s*)?\(([^)]*)\)', tokenized):
            for p in m.group(1).split(','):
                p = p.strip().split('=')[0].strip()
                if p and p.isidentifier():
                    defined_symbols.add(p)
        # Arrow function parameters: (a, b) =>
        for m in re.finditer(r'\(([^)]*)\)\s*=>', tokenized):
            for p in m.group(1).split(','):
                p = p.strip().split('=')[0].strip()
                if p and p.isidentifier():
                    defined_symbols.add(p)
        # Single arrow function parameter: a =>
        for m in re.finditer(r'\b([A-Za-z0-9_$]+)\s*=>', tokenized):
            defined_symbols.add(m.group(1))
        # Loop variables: for (let x of ...) or for (x of ...)
        for m in re.finditer(r'\bfor\s*\(\s*(?:let|const|var)?\s*([A-Za-z0-9_$]+)\s+(?:in|of)\b', tokenized):
            defined_symbols.add(m.group(1))

    return soup, js_sources, defined_symbols


def run_static_analysis(html_path: Path):
    """
    Performs full static analysis on an HTML file and its JavaScript dependencies.
    Returns:
        missing_calls: list of (location, function_name)
        undeclared_assignments: set of variable names assigned without declaration
    """
    soup, js_sources, defined_symbols = extract_page_symbols_and_scripts(html_path)

    call_re = re.compile(r'(?<![\.\w$])([A-Za-z0-9_$]+)\s*\(')
    missing_calls = []

    # 1. HTML event attributes (e.g. onclick="func(...)")
    event_attr_re = re.compile(r'^on[a-z]+$', re.I)
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if event_attr_re.match(attr) and isinstance(val, str):
                cleaned_val = tokenize_js(val)
                for cm in call_re.finditer(cleaned_val):
                    fn = cm.group(1)
                    if fn not in JS_KEYWORDS and fn not in defined_symbols and fn not in CALLBACK_NAMES:
                        missing_calls.append((f"<{tag.name} {attr}=\"...{fn}(...)\">", fn))

    # 2. Event handlers inside template literals in JS (e.g. onclick="func(...)")
    template_event_re = re.compile(r'''\bon[a-z]+\s*=\s*\\?["']([^"'\\]*\\?\([^\)]*\\?\)[^"'\\]*)\\?["']''', re.I)
    for name, code in js_sources:
        for tm in template_event_re.finditer(code):
            handler_str = tm.group(1)
            cleaned_handler = tokenize_js(handler_str)
            for cm in call_re.finditer(cleaned_handler):
                fn = cm.group(1)
                if fn not in JS_KEYWORDS and fn not in defined_symbols and fn not in CALLBACK_NAMES:
                    missing_calls.append((f"Template event in {name}: '{handler_str[:40]}'", fn))

    # 3. Bare function calls in executable JS code (including inside ${...} in templates)
    for name, code in js_sources:
        cleaned = tokenize_js(code)
        cleaned = re.sub(r'\b(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(', ' ', cleaned)
        cleaned = re.sub(r'\bcatch\s*\([^\)]*\)', ' ', cleaned)
        for cm in call_re.finditer(cleaned):
            fn = cm.group(1)
            if fn not in JS_KEYWORDS and fn not in defined_symbols and fn not in CALLBACK_NAMES:
                missing_calls.append((f"JS call in {name}", fn))

    # 4. Undeclared assignments: ident = ...
    assign_re = re.compile(r'(?<![\.\w$])([A-Za-z0-9_$]+)\s*=(?!=)')
    undeclared_assignments = set()
    for name, code in js_sources:
        cleaned = tokenize_js(code)
        cleaned = re.sub(r'\b(?:let|const|var)\s+[^;=]+[;=]', ' ', cleaned)
        for m in assign_re.finditer(cleaned):
            var_name = m.group(1)
            if var_name not in defined_symbols and var_name not in JS_KEYWORDS:
                undeclared_assignments.add(var_name)

    return missing_calls, undeclared_assignments


class TestUIStaticAnalysis(unittest.TestCase):
    """Unit tests verifying UI code integrity and static correctness."""

    def test_01_common_js_exists_and_loaded(self):
        """Verifies that common.js exists and is referenced in index.html and admin.html."""
        common_js = STATIC_DIR / "common.js"
        self.assertTrue(common_js.exists(), "aichat/static/common.js must exist")

        index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        admin_html = (STATIC_DIR / "admin.html").read_text(encoding="utf-8")

        self.assertIn('/static/common.js', index_html, "index.html must include /static/common.js")
        self.assertIn('/static/common.js', admin_html, "admin.html must include /static/common.js")

    def test_02_common_js_utilities_defined(self):
        """Verifies that all required shared utility functions are defined in common.js."""
        common_content = (STATIC_DIR / "common.js").read_text(encoding="utf-8")
        required_functions = [
            "escapeHtml",
            "escapeJs",
            "formatRelativeTime",
            "copyTextToClipboard",
            "fallbackCopyText",
        ]
        for fn in required_functions:
            self.assertRegex(
                common_content,
                rf"\bfunction\s+{fn}\b",
                f"common.js must define function '{fn}'"
            )

    def test_03_static_analysis_index_html(self):
        """Runs static analysis on index.html, asserting zero undefined function calls and undeclared assignments."""
        missing_calls, undeclared_assignments = run_static_analysis(STATIC_DIR / "index.html")
        self.assertEqual(
            missing_calls,
            [],
            f"index.html has undefined function calls: {missing_calls}"
        )
        self.assertEqual(
            undeclared_assignments,
            set(),
            f"index.html has undeclared variable assignments: {undeclared_assignments}"
        )

    def test_04_static_analysis_admin_html(self):
        """Runs static analysis on admin.html, asserting zero undefined function calls and undeclared assignments."""
        missing_calls, undeclared_assignments = run_static_analysis(STATIC_DIR / "admin.html")
        self.assertEqual(
            missing_calls,
            [],
            f"admin.html has undefined function calls: {missing_calls}"
        )
        self.assertEqual(
            undeclared_assignments,
            set(),
            f"admin.html has undeclared variable assignments: {undeclared_assignments}"
        )

    def test_05_analyzer_detects_missing_function_call(self):
        """Verifies that the static analyzer accurately flags an undefined function call."""
        admin_orig = (STATIC_DIR / "admin.html").read_text(encoding="utf-8")
        tmp_admin = STATIC_DIR / "_tmp_test_admin.html"
        try:
            # Inject a call to an undefined function
            mutated = admin_orig.replace("loadRoles()", "nonExistentTestFunction()", 1)
            tmp_admin.write_text(mutated, encoding="utf-8")

            missing, _ = run_static_analysis(tmp_admin)
            missing_names = [m[1] for m in missing]
            self.assertIn(
                "nonExistentTestFunction",
                missing_names,
                "Static analyzer must flag undefined function calls"
            )
        finally:
            if tmp_admin.exists():
                tmp_admin.unlink()

    def test_06_analyzer_detects_undeclared_variable_assignment(self):
        """Verifies that the static analyzer flags assignments to undeclared variables."""
        admin_orig = (STATIC_DIR / "admin.html").read_text(encoding="utf-8")
        tmp_admin = STATIC_DIR / "_tmp_test_admin.html"
        try:
            # Inject an assignment to an undeclared variable
            mutated = admin_orig.replace(
                "let agentsCache = [];",
                "// let agentsCache = [];\nundeclaredVariableTest = 123;",
                1
            )
            tmp_admin.write_text(mutated, encoding="utf-8")

            _, undeclared = run_static_analysis(tmp_admin)
            self.assertIn(
                "undeclaredVariableTest",
                undeclared,
                "Static analyzer must flag assignments to undeclared variables"
            )
        finally:
            if tmp_admin.exists():
                tmp_admin.unlink()


if __name__ == "__main__":
    unittest.main()
