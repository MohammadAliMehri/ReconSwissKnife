# -*- coding: utf-8 -*-
"""
Recon Swiss Knife Pro v3 - Semi-Active Security Recon & Method Fuzzer
================================================================================
Production-grade Burp Suite extension (Jython 2.7) for passive + semi-active
reconnaissance.  Extracts endpoints, parameters, JS files, risky HTTP methods,
missing security headers, and information disclosure (including Iranian-specific
patterns: National ID, mobile numbers) from HTTP history and live traffic.

Semi-active modules:
  * Automated JS deep-fetching with secondary regex extraction.
  * Safe OPTIONS/HEAD method probing.
  * Active cross-method fuzzing (PUT, DELETE, PATCH, DEBUG, TRACE).

UI features:
  * Professional dark-mode / light-mode auto-detected corporate dashboard.
  * No bottom split-pane - tables occupy full space.
  * Interactive JDialog popups with native Burp message editors on double-click.
  * Leak value auto-highlighting via ITextEditor search expression.
  * JS response beautifier for minified scripts.

Author : Generated for authorized penetration testing use only.
Load   : Burp -> Extender -> Extensions -> Add -> Python -> select this file.
Requires: Jython standalone JAR configured in Extender -> Options.
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IContextMenuFactory
from burp import IMessageEditorController
from burp import IExtensionStateListener

from javax.swing import (JPanel, JButton, JLabel, JTabbedPane, JTable,
                          JScrollPane, BoxLayout, JTextField, SwingUtilities,
                          BorderFactory, JOptionPane, RowFilter, JMenuItem,
                          JPopupMenu, JCheckBox, UIManager, JDialog, JSplitPane)
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing.event import DocumentListener
from java.awt import (BorderLayout, FlowLayout, GridLayout, Color, Font,
                       Toolkit, Dimension, Cursor)
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, MouseAdapter
from java.util import ArrayList
from java.util.concurrent import Executors
from java.lang import Runnable, Thread

import re
import threading


# ---------------------------------------------------------------------------
# Constants / Regex patterns  (compiled once at module load)
# ---------------------------------------------------------------------------

EXTENSION_NAME = "Recon Swiss Knife Pro v3"

BINARY_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.pdf', '.exe', '.dll',
    '.class', '.jar', '.swf'
)

BINARY_MIME_HINTS = (
    'image/', 'font/', 'video/', 'audio/', 'application/octet-stream',
    'application/zip', 'application/x-rar', 'application/pdf',
    'application/vnd.ms-fontobject', 'application/font'
)

SENSITIVE_METHODS = set(['PUT', 'DELETE', 'TRACE', 'PATCH', 'OPTIONS',
                         'DEBUG', 'CONNECT'])

FUZZ_METHODS = ['PUT', 'DELETE', 'PATCH', 'DEBUG', 'TRACE']

FUZZ_SUCCESS_CODES = set([200, 201, 204])

SECURITY_HEADERS = [
    'X-Frame-Options',
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-XSS-Protection'
]

# --- Leak detection ---
RE_IRAN_NATIONAL_ID   = re.compile(r'\b\d{10}\b')
RE_IRAN_MOBILE        = re.compile(r'(?:\+98|0098|0)?9\d{9}\b')
RE_EMAIL              = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
RE_AWS_KEY            = re.compile(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b')
RE_AWS_SECRET         = re.compile(r'(?i)aws(.{0,20})?(secret|key)[\'"\s:=]{1,4}[A-Za-z0-9/+=]{40}')
RE_BEARER             = re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_\.=]{10,}')
RE_JWT                = re.compile(r'\bey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b')
RE_GENERIC_APIKEY     = re.compile(r'(?i)(api[_\-]?key|apikey|access[_\-]?token|secret[_\-]?key)[\'"\s:=]{1,4}([A-Za-z0-9\-_]{16,64})')
RE_OPENAI_ANTHROPIC   = re.compile(r'\bsk-[A-Za-z0-9]{32,}\b')
RE_GCP_APIKEY         = re.compile(r'\bAIzaSy[A-Za-z0-9_\-]{33}\b')
RE_GITHUB_PAT         = re.compile(r'\bghp_[A-Za-z0-9]{36}\b')
RE_FIREBASE_URL       = re.compile(r'(?i)https?://[a-z0-9\-]+\.firebaseio\.com')

# --- Endpoint / param extraction ---
RE_JS_FILE     = re.compile(r'(?i)\.js(\?[^"\'\<\>\s]*)?$')
RE_QUERY_PARAM = re.compile(r'[?&]([A-Za-z0-9_\-\.\[\]]+)=([^&\s#]*)')
RE_POST_PARAM  = re.compile(r'([A-Za-z0-9_\-\.\[\]]+)=([^&\s]*)')

# --- JS deep-scan patterns ---
RE_JS_ABSOLUTE_ENDPOINT = re.compile(
    r'(?i)https?://[A-Za-z0-9\-\._~%]+(?::\d+)?(?:/[A-Za-z0-9_\-\./%\?=&#]*)?')
RE_JS_RELATIVE_PATH = re.compile(
    r'''(?i)["'](/(?:api|v[0-9]+|rest|graphql|internal|admin|auth|service)[A-Za-z0-9_\-/\.]*)["']''')
RE_S3_BUCKET = re.compile(
    r'(?i)[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|s3://[a-z0-9.\-]+')
RE_CLOUD_STORAGE = re.compile(
    r'(?i)(?:storage\.googleapis\.com/[a-z0-9._\-]+|'
    r'[a-z0-9\-]+\.blob\.core\.windows\.net|'
    r'[a-z0-9\-]+\.firebaseio\.com)')
RE_JS_FETCH_CALL = re.compile(
    r'''(?i)(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post|ajax))\s*\(\s*["']([^"']+)["']''')
RE_JS_SRC_ATTR = re.compile(
    r'''(?i)src\s*=\s*["']([^"']+\.js[^"']*)["']''')


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def is_valid_iranian_national_id(nid):
    """Basic Iranian National ID checksum validation."""
    try:
        if len(nid) != 10:
            return False
        if len(set(nid)) == 1:
            return False
        check = int(nid[9])
        s = 0
        for i in range(9):
            s += int(nid[i]) * (10 - i)
        r = s % 11
        if r < 2:
            return check == r
        else:
            return check == (11 - r)
    except Exception:
        return False


def copy_to_clipboard(text):
    """Copy a string to the system clipboard."""
    try:
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        selection = StringSelection(text)
        clipboard.setContents(selection, None)
    except Exception:
        pass


def _looks_like_plain_text(text):
    """Heuristic: return True if text has no regex metacharacters."""
    try:
        return not re.search(r'[\.\*\+\?\(\)\[\]\{\}\|\^\$\\]', text)
    except Exception:
        return True


def beautify_js(js_code):
    """Pure-Python lightweight JS beautifier compatible with Jython 2.7.
    Adds indentation around braces and semicolons for readability."""
    try:
        if not js_code:
            return ""
        indent_str = "    "
        indent_level = 0
        output = []
        in_string = False
        string_char = None
        in_single_comment = False
        in_multi_comment = False
        i = 0
        n = len(js_code)

        def match_at(idx, s):
            return js_code[idx:idx + len(s)] == s

        while i < n:
            ch = js_code[i]

            # --- Inside single-line comment ---
            if in_single_comment:
                output.append(ch)
                if ch == '\n':
                    in_single_comment = False
                    output.append(indent_str * indent_level)
                i += 1
                continue

            # --- Inside multi-line comment ---
            if in_multi_comment:
                output.append(ch)
                if match_at(i, "*/"):
                    output.append("/")
                    in_multi_comment = False
                    i += 2
                else:
                    i += 1
                continue

            # --- Inside string literal ---
            if in_string:
                output.append(ch)
                if ch == '\\':
                    if i + 1 < n:
                        output.append(js_code[i + 1])
                        i += 2
                    else:
                        i += 1
                elif ch == string_char:
                    in_string = False
                    i += 1
                else:
                    i += 1
                continue

            # --- String start ---
            if ch in ('"', "'", '`'):
                in_string = True
                string_char = ch
                output.append(ch)
                i += 1
                continue

            # --- Comment start ---
            if match_at(i, "//"):
                in_single_comment = True
                output.append("//")
                i += 2
                continue
            if match_at(i, "/*"):
                in_multi_comment = True
                output.append("/*")
                i += 2
                continue

            # --- Structural characters ---
            if ch == '{':
                if output and output[-1] not in ('\n', ' ', '\t'):
                    output.append(' ')
                output.append('{\n')
                indent_level += 1
                output.append(indent_str * indent_level)
            elif ch == '}':
                indent_level = max(0, indent_level - 1)
                if output and output[-1] != '\n' and not output[-1].isspace():
                    output.append('\n')
                while output and output[-1] in (' ', '\t'):
                    output.pop()
                if output and output[-1] != '\n':
                    output.append('\n')
                output.append(indent_str * indent_level)
                output.append('}\n')
                peek = i + 1
                while peek < n and js_code[peek] in (' ', '\t', '\r', '\n'):
                    peek += 1
                if peek < n and js_code[peek] != '}':
                    output.append(indent_str * indent_level)
            elif ch == ';':
                output.append(';\n')
                peek = i + 1
                while peek < n and js_code[peek] in (' ', '\t', '\r'):
                    peek += 1
                if peek < n and js_code[peek] != '\n':
                    output.append(indent_str * indent_level)
                i = peek - 1
            elif ch == ',':
                output.append(', ')
            elif ch in ('\r', '\n'):
                if output and output[-1] != '\n':
                    output.append('\n')
                    output.append(indent_str * indent_level)
            elif ch in (' ', '\t'):
                if output and output[-1] not in (' ', '\t', '\n'):
                    output.append(' ')
            else:
                output.append(ch)

            i += 1

        beautified = "".join(output)
        lines = beautified.split('\n')
        cleaned = []
        for line in lines:
            if line.strip():
                cleaned.append(line)
            else:
                if cleaned and cleaned[-1] != "":
                    cleaned.append("")
        return "\n".join(cleaned)
    except Exception:
        return js_code


def build_beautified_response(messageInfo, helpers):
    """Rebuild the HTTP response with a beautified JS body for display."""
    try:
        response_bytes = messageInfo.getResponse()
        if response_bytes is None:
            return None
        resp_info = helpers.analyzeResponse(response_bytes)
        body_offset = resp_info.getBodyOffset()
        resp_str = helpers.bytesToString(response_bytes)
        headers = list(resp_info.getHeaders())
        body = resp_str[body_offset:] if body_offset < len(resp_str) else ""
        if not body:
            return response_bytes
        beautified_body = beautify_js(body)
        beautified_bytes = helpers.stringToBytes(beautified_body)
        return helpers.buildHttpMessage(headers, beautified_bytes)
    except Exception:
        try:
            return messageInfo.getResponse()
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Scope filter - shared by passive and semi-active features
# ---------------------------------------------------------------------------

class ScopeFilter(object):
    """Thread-safe comma-separated domain/keyword scope matcher.
    Empty scope list => everything matches."""

    def __init__(self):
        self._lock = threading.Lock()
        self._terms = []

    def set_scope_text(self, text):
        with self._lock:
            self._terms = []
            if not text:
                return
            for part in text.split(','):
                p = part.strip().lower()
                if p:
                    self._terms.append(p)

    def get_terms(self):
        with self._lock:
            return list(self._terms)

    def in_scope(self, url_str):
        try:
            with self._lock:
                terms = list(self._terms)
            if not terms:
                return True
            u = url_str.lower()
            for t in terms:
                if t in u:
                    return True
            return False
        except Exception:
            return True


# ---------------------------------------------------------------------------
# Thread-safe data store  (messageInfo embedded in every finding)
# ---------------------------------------------------------------------------

class DataStore(object):
    """Central thread-safe data store.  Every finding retains its original
    IHttpRequestResponse object so double-click popups always have valid
    request/response bytes available."""

    def __init__(self):
        self.lock = threading.Lock()
        # url -> {"method":str, "params":set, "msg":IHttpRequestResponse}
        self.endpoints = {}
        # url -> IHttpRequestResponse
        self.js_files = {}
        # list of {"url", "method", "msg"}
        self.methods_findings = []
        # list of {"url", "issue", "msg"}
        self.header_findings = []
        # list of {"type", "value", "url", "msg"}
        self.leaks = []
        self.seen_leak_keys = set()
        self.processed_count = 0

        # --- Semi-active ---
        # list of {"type", "value", "source", "msg"}
        self.js_findings = []
        self.seen_js_finding_keys = set()
        # list of {"url", "allow", "status", "msg"}
        self.probe_results = []
        self.seen_probe_keys = set()
        self.probed_urls = set()
        self.fetched_js_urls = set()
        # list of {"url", "method", "status", "bypass", "msg"}
        self.fuzz_results = []

    def clear(self):
        with self.lock:
            self.endpoints.clear()
            self.js_files.clear()
            del self.methods_findings[:]
            del self.header_findings[:]
            del self.leaks[:]
            self.seen_leak_keys.clear()
            self.processed_count = 0
            del self.js_findings[:]
            self.seen_js_finding_keys.clear()
            del self.probe_results[:]
            self.seen_probe_keys.clear()
            self.probed_urls.clear()
            self.fetched_js_urls.clear()
            del self.fuzz_results[:]

    def add_endpoint(self, url, method, params, msg):
        with self.lock:
            if url not in self.endpoints:
                self.endpoints[url] = {"method": method, "params": set(),
                                       "msg": msg}
            self.endpoints[url]["params"].update(params)
            if self.endpoints[url].get("msg") is None and msg is not None:
                self.endpoints[url]["msg"] = msg

    def add_js(self, url, msg):
        with self.lock:
            if url not in self.js_files:
                self.js_files[url] = msg
            elif self.js_files[url] is None and msg is not None:
                self.js_files[url] = msg

    def update_js_msg(self, url, msg):
        with self.lock:
            self.js_files[url] = msg

    def add_method_finding(self, url, method, msg):
        with self.lock:
            self.methods_findings.append({"url": url, "method": method,
                                          "msg": msg})

    def add_header_finding(self, url, issue, msg):
        with self.lock:
            self.header_findings.append({"url": url, "issue": issue,
                                         "msg": msg})

    def add_leak(self, leak_type, value, url, msg):
        key = (leak_type, value, url)
        with self.lock:
            if key in self.seen_leak_keys:
                return
            self.seen_leak_keys.add(key)
            self.leaks.append({"type": leak_type, "value": value,
                               "url": url, "msg": msg})

    def incr_processed(self):
        with self.lock:
            self.processed_count += 1

    def snapshot_counts(self):
        with self.lock:
            return (len(self.endpoints), len(self.js_files),
                    len(self.methods_findings), len(self.header_findings),
                    len(self.leaks), self.processed_count,
                    len(self.js_findings), len(self.probe_results),
                    len(self.fuzz_results))

    # --- Semi-active store methods ---
    def add_js_finding(self, finding_type, value, source_url, msg):
        key = (finding_type, value, source_url)
        with self.lock:
            if key in self.seen_js_finding_keys:
                return
            self.seen_js_finding_keys.add(key)
            self.js_findings.append({"type": finding_type, "value": value,
                                     "source": source_url, "msg": msg})

    def add_probe_result(self, url, allow_header, status, msg):
        key = (url,)
        with self.lock:
            if key in self.seen_probe_keys:
                return
            self.seen_probe_keys.add(key)
            self.probe_results.append({"url": url, "allow": allow_header,
                                       "status": status, "msg": msg})

    def add_fuzz_result(self, url, method, status, bypass_str, msg):
        with self.lock:
            self.fuzz_results.append({"url": url, "method": method,
                                      "status": status, "bypass": bypass_str,
                                      "msg": msg})

    def try_claim_js_fetch(self, url):
        """Atomically claim a JS URL for deep-fetch.  Returns True on first
        claim, False if already in-flight or completed."""
        with self.lock:
            if url in self.fetched_js_urls:
                return False
            self.fetched_js_urls.add(url)
            return True

    def try_claim_probe(self, url):
        with self.lock:
            if url in self.probed_urls:
                return False
            self.probed_urls.add(url)
            return True


# ---------------------------------------------------------------------------
# Core analyzer - all parsing logic isolated & defensive
# ---------------------------------------------------------------------------

class ReconAnalyzer(object):
    def __init__(self, helpers, store, scope, on_js_discovered=None):
        self._helpers = helpers
        self._store = store
        self._scope = scope
        self._on_js_discovered = on_js_discovered

    def is_binary_response(self, headers_list, url_path):
        try:
            lower_path = url_path.lower().split('?')[0]
            for ext in BINARY_EXTENSIONS:
                if lower_path.endswith(ext):
                    return True
            for h in headers_list:
                if h.lower().startswith('content-type:'):
                    ct = h.split(':', 1)[1].strip().lower()
                    for hint in BINARY_MIME_HINTS:
                        if hint in ct:
                            return True
            return False
        except Exception:
            return False

    def analyze(self, url, method, request_bytes, response_bytes, msg):
        try:
            url_str = str(url)
            if not self._scope.in_scope(url_str):
                return

            self._store.incr_processed()

            # --- Sensitive method detection ---
            try:
                if method in SENSITIVE_METHODS:
                    self._store.add_method_finding(url_str, method, msg)
            except Exception:
                pass

            # --- Path extraction ---
            path = url_str
            try:
                if '://' in url_str:
                    path = url_str.split('://', 1)[1]
                    path = '/' + path.split('/', 1)[1] if '/' in path else '/'
            except Exception:
                path = url_str

            if RE_JS_FILE.search(path):
                self._register_js(url_str, msg)

            # --- Parameter extraction ---
            params = set()
            try:
                for m in RE_QUERY_PARAM.finditer(url_str):
                    params.add(m.group(1))
            except Exception:
                pass

            if request_bytes is not None:
                try:
                    req_info = self._helpers.analyzeRequest(request_bytes)
                    body_offset = req_info.getBodyOffset()
                    req_str = self._helpers.bytesToString(request_bytes)
                    body = req_str[body_offset:] if body_offset < len(req_str) else ""
                    ctype = ""
                    for h in req_info.getHeaders():
                        if h.lower().startswith('content-type:'):
                            ctype = h.lower()
                            break
                    if body and 'application/x-www-form-urlencoded' in ctype:
                        for m in RE_POST_PARAM.finditer(body):
                            params.add(m.group(1))
                    elif body and 'application/json' in ctype:
                        for m in re.finditer(r'"([A-Za-z0-9_\-\.]+)"\s*:', body):
                            params.add(m.group(1))
                except Exception:
                    pass

            self._store.add_endpoint(url_str, method, params, msg)

            # --- Response analysis (skip binary) ---
            if response_bytes is None:
                return

            try:
                resp_info = self._helpers.analyzeResponse(response_bytes)
                headers_list = list(resp_info.getHeaders())
            except Exception:
                return

            if self.is_binary_response(headers_list, path):
                return

            self._check_security_headers(url_str, headers_list, msg)
            self._check_cookies(url_str, headers_list, msg)

            try:
                body_offset = resp_info.getBodyOffset()
                resp_str = self._helpers.bytesToString(response_bytes)
                body = resp_str[body_offset:] if body_offset < len(resp_str) else ""
            except Exception:
                body = ""

            if body:
                if len(body) > 800000:
                    body = body[:800000]
                self._scan_leaks(url_str, body, msg)
                self._extract_js_from_body(url_str, body, msg)

        except Exception:
            pass

    def _register_js(self, js_url, msg):
        try:
            already_known = js_url in self._store.js_files
            self._store.add_js(js_url, msg)
            if not already_known and self._on_js_discovered is not None:
                if self._scope.in_scope(js_url):
                    try:
                        self._on_js_discovered(js_url)
                    except Exception:
                        pass
        except Exception:
            pass

    def _check_security_headers(self, url, headers_list, msg):
        try:
            present = {}
            for h in headers_list:
                if ':' in h:
                    name, val = h.split(':', 1)
                    present[name.strip().lower()] = val.strip()

            for hdr in SECURITY_HEADERS:
                key = hdr.lower()
                if key not in present:
                    self._store.add_header_finding(
                        url, "Missing header: %s" % hdr, msg)
                else:
                    val = present[key]
                    if (key == 'x-frame-options'
                            and val.upper() not in ('DENY', 'SAMEORIGIN')):
                        self._store.add_header_finding(
                            url, "Weak X-Frame-Options: %s" % val, msg)
                    if (key == 'strict-transport-security'
                            and 'max-age' not in val.lower()):
                        self._store.add_header_finding(
                            url, "Malformed HSTS header: %s" % val, msg)
                    if (key == 'x-content-type-options'
                            and val.lower() != 'nosniff'):
                        self._store.add_header_finding(
                            url, "Weak X-Content-Type-Options: %s" % val, msg)
        except Exception:
            pass

    def _check_cookies(self, url, headers_list, msg):
        try:
            for h in headers_list:
                if h.lower().startswith('set-cookie:'):
                    cookie_val = h.split(':', 1)[1]
                    issues = []
                    if 'secure' not in cookie_val.lower():
                        issues.append('missing Secure flag')
                    if 'httponly' not in cookie_val.lower():
                        issues.append('missing HttpOnly flag')
                    if issues:
                        cookie_name = cookie_val.strip().split('=')[0].strip()
                        self._store.add_header_finding(
                            url,
                            "Cookie '%s' %s" % (cookie_name, ", ".join(issues)),
                            msg)
        except Exception:
            pass

    def _scan_leaks(self, url, body, msg):
        """Scan response body for secrets, tokens, PII, and cloud keys."""
        scanners = [
            (RE_EMAIL,            "Email",                    False, None),
            (RE_IRAN_MOBILE,      "Iranian Mobile",           False, None),
            (RE_IRAN_NATIONAL_ID, "Iranian National ID",      False, is_valid_iranian_national_id),
            (RE_JWT,              "JWT Token",                True,  None),
            (RE_AWS_KEY,          "AWS Access Key",           False, None),
            (RE_AWS_SECRET,       "AWS Secret Key (possible)", True,  None),
            (RE_BEARER,           "Bearer Token",             True,  None),
            (RE_GENERIC_APIKEY,   "API Key / Secret",         True,  None),
            (RE_OPENAI_ANTHROPIC, "OpenAI/Anthropic Key",     False, None),
            (RE_GCP_APIKEY,       "Google Cloud/YouTube Key", False, None),
            (RE_GITHUB_PAT,       "GitHub PAT",               False, None),
            (RE_FIREBASE_URL,     "Firebase Database URL",    False, None),
        ]
        for pattern, label, truncate, validator in scanners:
            try:
                for m in pattern.finditer(body):
                    val = m.group(0)
                    if validator and not validator(val):
                        continue
                    display = val[:80] + "..." if truncate and len(val) > 80 else val
                    self._store.add_leak(label, display, url, msg)
            except Exception:
                pass

    def _extract_js_from_body(self, url, body, msg):
        try:
            for m in RE_JS_SRC_ATTR.finditer(body):
                js_url = m.group(1)
                self._register_js(js_url, msg)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# JS Deep-Scan analyzer  (Semi-Active Module 1 helper)
# ---------------------------------------------------------------------------

class JsDeepScanner(object):
    """Scans a fetched JS file body for hidden endpoints, cloud storage
    buckets, and relative API paths."""

    def __init__(self, store):
        self._store = store

    def scan(self, js_url, body, msg):
        if not body:
            return
        try:
            if len(body) > 1500000:
                body = body[:1500000]
        except Exception:
            pass

        scanners = [
            (RE_S3_BUCKET,            "S3 / Cloud Bucket"),
            (RE_CLOUD_STORAGE,        "Cloud Storage Endpoint"),
            (RE_JS_FETCH_CALL,        "Fetch/AJAX Call Target"),
            (RE_JS_RELATIVE_PATH,     "Relative API Path"),
        ]
        for pattern, label in scanners:
            try:
                for m in pattern.finditer(body):
                    val = m.group(1) if pattern.groups else m.group(0)
                    self._store.add_js_finding(label, val, js_url, msg)
            except Exception:
                pass

        # Absolute endpoints (capped at 500 to limit volume)
        try:
            count = 0
            for m in RE_JS_ABSOLUTE_ENDPOINT.finditer(body):
                if count > 500:
                    break
                self._store.add_js_finding(
                    "Absolute Endpoint", m.group(0), js_url, msg)
                count += 1
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Semi-active network engine: managed thread pool + de-duplication
# ---------------------------------------------------------------------------

class ActiveEngine(object):
    """Owns a bounded ExecutorService for all semi-active outbound requests."""

    POOL_SIZE = 6

    def __init__(self, callbacks, helpers, store, scope, js_scanner):
        self._callbacks = callbacks
        self._helpers = helpers
        self._store = store
        self._scope = scope
        self._js_scanner = js_scanner
        self._executor = Executors.newFixedThreadPool(self.POOL_SIZE)
        self._enabled = {"js_fetch": False, "method_probe": False}
        self._lock = threading.Lock()
        self._on_result_callback = None
        self._active_tasks = 0
        self._active_lock = threading.Lock()

    def set_result_callback(self, cb):
        self._on_result_callback = cb

    def set_module_enabled(self, module_name, enabled):
        with self._lock:
            self._enabled[module_name] = enabled

    def is_module_enabled(self, module_name):
        with self._lock:
            return self._enabled.get(module_name, False)

    def shutdown(self):
        try:
            self._executor.shutdownNow()
        except Exception:
            pass

    def _incr_active(self):
        with self._active_lock:
            self._active_tasks += 1
        self._notify()

    def _decr_active(self):
        with self._active_lock:
            self._active_tasks = max(0, self._active_tasks - 1)
        self._notify()

    def get_active_count(self):
        with self._active_lock:
            return self._active_tasks

    # ---- Module 1: JS deep-fetch ----
    def submit_js_fetch(self, js_url):
        try:
            if not self.is_module_enabled("js_fetch"):
                return
            if not self._scope.in_scope(js_url):
                return
            if not self._store.try_claim_js_fetch(js_url):
                return
            self._executor.submit(_JsFetchTask(self, js_url))
        except Exception:
            pass

    def _run_js_fetch(self, js_url):
        try:
            self._incr_active()
            svc = self._build_http_service(js_url)
            if svc is None:
                return
            http_service, req_bytes = svc

            resp = self._callbacks.makeHttpRequest(http_service, req_bytes)
            if resp is None:
                return
            try:
                persisted = self._callbacks.saveBuffersToTempFiles(resp)
                if persisted:
                    resp = persisted
            except Exception:
                pass
            self._store.update_js_msg(js_url, resp)

            response_bytes = resp.getResponse()
            if response_bytes is None:
                return
            resp_info = self._helpers.analyzeResponse(response_bytes)
            body_offset = resp_info.getBodyOffset()
            resp_str = self._helpers.bytesToString(response_bytes)
            body = resp_str[body_offset:] if body_offset < len(resp_str) else ""

            self._js_scanner.scan(js_url, body, resp)

            if self.is_module_enabled("method_probe"):
                self.submit_method_probe(js_url)
        except Exception:
            pass
        finally:
            self._decr_active()
            self._notify()

    # ---- Module 2: Safe HTTP method probing ----
    def submit_method_probe(self, url):
        try:
            if not self.is_module_enabled("method_probe"):
                return
            if not self._scope.in_scope(url):
                return
            if not self._store.try_claim_probe(url):
                return
            self._executor.submit(_MethodProbeTask(self, url))
        except Exception:
            pass

    def _run_method_probe(self, url):
        try:
            self._incr_active()
            svc = self._build_http_service(url, method="OPTIONS")
            if svc is None:
                return
            http_service, req_bytes = svc

            resp = self._callbacks.makeHttpRequest(http_service, req_bytes)
            allow_val = ""
            status = 0
            final_resp = resp
            if resp is not None and resp.getResponse() is not None:
                response_bytes = resp.getResponse()
                resp_info = self._helpers.analyzeResponse(response_bytes)
                status = resp_info.getStatusCode()
                for h in resp_info.getHeaders():
                    hl = h.lower()
                    if hl.startswith('allow:') or hl.startswith('public:'):
                        allow_val = h.split(':', 1)[1].strip()
                        break

            # Fallback HEAD probe
            if not allow_val:
                svc2 = self._build_http_service(url, method="HEAD")
                if svc2 is not None:
                    http_service2, req_bytes2 = svc2
                    resp2 = self._callbacks.makeHttpRequest(
                        http_service2, req_bytes2)
                    if resp2 is not None and resp2.getResponse() is not None:
                        final_resp = resp2
                        ri2 = self._helpers.analyzeResponse(resp2.getResponse())
                        if status == 0:
                            status = ri2.getStatusCode()

            if allow_val or status:
                try:
                    persisted = self._callbacks.saveBuffersToTempFiles(
                        final_resp)
                    if persisted:
                        final_resp = persisted
                except Exception:
                    pass
                self._store.add_probe_result(
                    url, allow_val if allow_val else "(none)",
                    status, final_resp)
        except Exception:
            pass
        finally:
            self._decr_active()
            self._notify()

    # ---- Module 3: Active cross-method fuzzing ----
    def submit_method_fuzz(self, url):
        try:
            if not self._scope.in_scope(url):
                return
            for method in FUZZ_METHODS:
                self._executor.submit(_MethodFuzzTask(self, url, method))
        except Exception:
            pass

    def _run_method_fuzz(self, url, method):
        try:
            self._incr_active()
            svc = self._build_http_service(url, method=method)
            if svc is None:
                return
            http_service, req_bytes = svc

            resp = self._callbacks.makeHttpRequest(http_service, req_bytes)
            if resp is not None and resp.getResponse() is not None:
                try:
                    persisted = self._callbacks.saveBuffersToTempFiles(resp)
                    if persisted:
                        resp = persisted
                except Exception:
                    pass
                response_bytes = resp.getResponse()
                resp_info = self._helpers.analyzeResponse(response_bytes)
                status = resp_info.getStatusCode()

                is_bypass = status in FUZZ_SUCCESS_CODES
                bypass_str = ("VULNERABLE (Bypass Confirmed)" if is_bypass
                              else "Blocked / No Bypass")
                self._store.add_fuzz_result(
                    url, method, status, bypass_str, resp)
        except Exception:
            pass
        finally:
            self._decr_active()
            self._notify()

    def _notify(self):
        if self._on_result_callback is not None:
            try:
                self._on_result_callback()
            except Exception:
                pass

    # ---- Shared request-building helper ----
    def _build_http_service(self, url_str, method="GET"):
        try:
            from java.net import URL
            j_url = URL(url_str)
            protocol = j_url.getProtocol()
            host = j_url.getHost()
            port = j_url.getPort()
            if port == -1:
                port = 443 if protocol == 'https' else 80
            use_https = (protocol == 'https')
            http_service = self._helpers.buildHttpService(
                host, port, use_https)
            path = j_url.getFile()
            if not path:
                path = "/"
            request_line = "%s %s HTTP/1.1" % (method, path)
            headers = ArrayList()
            headers.add(request_line)
            headers.add("Host: %s" % host)
            headers.add("User-Agent: Mozilla/5.0 (ReconSwissKnife/v3)")
            headers.add("Accept: */*")
            headers.add("Connection: Close")
            return (http_service, self._helpers.buildHttpMessage(headers, None))
        except Exception:
            return None


# --- Runnable wrappers for thread pool tasks ---

class _JsFetchTask(Runnable):
    def __init__(self, engine, js_url):
        self._engine = engine
        self._url = js_url

    def run(self):
        self._engine._run_js_fetch(self._url)


class _MethodProbeTask(Runnable):
    def __init__(self, engine, url):
        self._engine = engine
        self._url = url

    def run(self):
        self._engine._run_method_probe(self._url)


class _MethodFuzzTask(Runnable):
    def __init__(self, engine, url, method):
        self._engine = engine
        self._url = url
        self._method = method

    def run(self):
        self._engine._run_method_fuzz(self._url, self._method)


# ---------------------------------------------------------------------------
# Swing helpers
# ---------------------------------------------------------------------------

class _BtnListener(ActionListener):
    def __init__(self, callback):
        self._cb = callback

    def actionPerformed(self, event):
        try:
            self._cb(event)
        except Exception:
            pass


class _DocListener(DocumentListener):
    def __init__(self, callback):
        self._cb = callback

    def insertUpdate(self, e):
        self._safe()

    def removeUpdate(self, e):
        self._safe()

    def changedUpdate(self, e):
        self._safe()

    def _safe(self):
        try:
            self._cb()
        except Exception:
            pass


class _RefreshRunnable(Runnable):
    def __init__(self, ui):
        self._ui = ui

    def run(self):
        self._ui._do_refresh()


class _RescanRunnable(Runnable):
    def __init__(self, extender):
        self._ext = extender

    def run(self):
        self._ext._process_proxy_history()


# ---------------------------------------------------------------------------
# IMessageEditorController for popup message editors
# ---------------------------------------------------------------------------

class _EditorController(IMessageEditorController):
    def __init__(self):
        self._msg = None

    def set_message(self, msg):
        self._msg = msg

    def getHttpService(self):
        try:
            return self._msg.getHttpService() if self._msg else None
        except Exception:
            return None

    def getRequest(self):
        try:
            return self._msg.getRequest() if self._msg else None
        except Exception:
            return None

    def getResponse(self):
        try:
            return self._msg.getResponse() if self._msg else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Request / Response popup dialog  (JDialog with native Burp editors)
# ---------------------------------------------------------------------------

class RequestResponsePopup(object):
    """Independent JDialog displaying Burp's native IMessageEditors.
    Supports optional leak-value highlighting via ITextEditor and
    JS beautification for .js responses."""

    def __init__(self, callbacks, helpers, msg, title,
                 is_js=False, leak_value=None):
        self._callbacks = callbacks
        self._helpers = helpers
        self._msg = msg
        self._title = title
        self._is_js = is_js
        self._leak_value = leak_value

    def show(self):
        popup = self

        class _Show(Runnable):
            def run(self):
                popup._build_and_show()

        SwingUtilities.invokeLater(_Show())

    def _build_and_show(self):
        try:
            # Find Burp's main frame
            parent = None
            try:
                from java.awt import Frame
                for f in Frame.getFrames():
                    if f.isVisible() and f.getTitle() and "Burp" in f.getTitle():
                        parent = f
                        break
            except Exception:
                pass

            dialog = JDialog(parent, self._title, False)
            dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE)
            dialog.setPreferredSize(Dimension(1100, 720))
            dialog.setMinimumSize(Dimension(750, 480))

            controller = _EditorController()
            controller.set_message(self._msg)

            # --- Request editor ---
            req_editor = self._callbacks.createMessageEditor(controller, False)
            req_bytes = None
            try:
                req_bytes = self._msg.getRequest()
            except Exception:
                pass
            if req_bytes:
                req_editor.setMessage(req_bytes, True)
            else:
                req_editor.setMessage(
                    self._helpers.stringToBytes("(No request data)"), True)

            # --- Response editor ---
            resp_editor = self._callbacks.createMessageEditor(controller, False)
            resp_bytes = None
            try:
                resp_bytes = self._msg.getResponse()
            except Exception:
                pass
            if resp_bytes:
                displayed_resp = resp_bytes
                if self._is_js:
                    try:
                        beautified = build_beautified_response(
                            self._msg, self._helpers)
                        if beautified:
                            displayed_resp = beautified
                    except Exception:
                        pass
                resp_editor.setMessage(displayed_resp, False)
            else:
                resp_editor.setMessage(
                    self._helpers.stringToBytes("(No response data)"), False)

            # --- Labeled wrapper panels ---
            req_panel = JPanel(BorderLayout())
            req_lbl = JLabel("  \u25b6  Request")
            req_lbl.setFont(Font("SansSerif", Font.BOLD, 12))
            req_lbl.setBorder(BorderFactory.createEmptyBorder(6, 4, 6, 0))
            req_panel.add(req_lbl, BorderLayout.NORTH)
            req_panel.add(req_editor.getComponent(), BorderLayout.CENTER)

            resp_panel = JPanel(BorderLayout())
            resp_lbl = JLabel("  \u25c0  Response")
            resp_lbl.setFont(Font("SansSerif", Font.BOLD, 12))
            resp_lbl.setBorder(BorderFactory.createEmptyBorder(6, 4, 6, 0))
            resp_panel.add(resp_lbl, BorderLayout.NORTH)
            resp_panel.add(resp_editor.getComponent(), BorderLayout.CENTER)

            # --- Horizontal split: Request | Response ---
            h_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                 req_panel, resp_panel)
            h_split.setResizeWeight(0.45)
            h_split.setContinuousLayout(True)
            h_split.setDividerSize(5)

            main_content = h_split

            # --- Leak highlight panel (ITextEditor with search) ---
            if self._leak_value and resp_bytes:
                try:
                    text_editor = self._callbacks.createTextEditor()
                    text_editor.setEditable(False)
                    # Extract response body for the text editor
                    body_bytes = resp_bytes
                    try:
                        ri = self._helpers.analyzeResponse(resp_bytes)
                        bo = ri.getBodyOffset()
                        rs = self._helpers.bytesToString(resp_bytes)
                        body_text = rs[bo:] if bo < len(rs) else rs
                        body_bytes = self._helpers.stringToBytes(body_text)
                    except Exception:
                        pass
                    text_editor.setText(body_bytes)
                    try:
                        text_editor.setSearchExpression(self._leak_value)
                    except Exception:
                        pass

                    highlight_panel = JPanel(BorderLayout())
                    hl_lbl = JLabel(
                        "  \u26a0  Leak Highlight:  \"%s\"" % self._leak_value)
                    hl_lbl.setFont(Font("SansSerif", Font.BOLD, 11))
                    hl_lbl.setForeground(Color(255, 152, 0))
                    hl_lbl.setBorder(
                        BorderFactory.createEmptyBorder(4, 4, 4, 0))
                    highlight_panel.add(hl_lbl, BorderLayout.NORTH)
                    highlight_panel.add(
                        text_editor.getComponent(), BorderLayout.CENTER)

                    v_split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                                        h_split, highlight_panel)
                    v_split.setResizeWeight(0.6)
                    v_split.setContinuousLayout(True)
                    v_split.setDividerSize(5)
                    main_content = v_split
                except Exception:
                    pass

            dialog.getContentPane().setLayout(BorderLayout())
            dialog.getContentPane().add(main_content, BorderLayout.CENTER)

            # Status bar
            status_lbl = JLabel(
                "  Double-click any row to inspect  |  "
                "Right-click for actions  |  %s" % EXTENSION_NAME)
            status_lbl.setFont(Font("SansSerif", Font.PLAIN, 10))
            status_lbl.setForeground(Color(130, 130, 130))
            status_lbl.setBorder(
                BorderFactory.createEmptyBorder(3, 4, 3, 4))
            dialog.getContentPane().add(status_lbl, BorderLayout.SOUTH)

            dialog.pack()
            dialog.setLocationRelativeTo(parent)
            dialog.setVisible(True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Table mouse listener (double-click + right-click context menu)
# ---------------------------------------------------------------------------

class _TableMouseListener(MouseAdapter):
    """Handles double-click (popup viewer) and right-click (copy / fuzz)
    on all extension data tables."""

    def __init__(self, table, model, sorter, copy_actions, messages_list,
                 url_col=None, is_js=False, leak_col=None, ui=None):
        self._table = table
        self._model = model
        self._sorter = sorter
        self._copy_actions = copy_actions
        self._messages = messages_list  # mutable list ref, updated by refresh
        self._url_col = url_col
        self._is_js = is_js
        self._leak_col = leak_col
        self._ui = ui

    def mouseClicked(self, event):
        try:
            if event.getClickCount() != 2:
                return
            vr = self._table.rowAtPoint(event.getPoint())
            if vr < 0:
                return
            mr = self._table.convertRowIndexToModel(vr)
            msgs = self._messages  # snapshot ref
            if mr >= len(msgs):
                return
            msg = msgs[mr]
            if not msg or not self._ui:
                return

            url = self._extract_url(mr)
            leak_value = None
            if self._leak_col is not None:
                try:
                    leak_value = str(self._model.getValueAt(mr, self._leak_col))
                except Exception:
                    pass
            is_js = self._is_js or bool(
                re.search(r'\.js(?:$|\?)', url, re.I))
            self._ui.open_popup(msg, url, is_js, leak_value)
        except Exception:
            pass

    def mousePressed(self, event):
        self._ctx_menu(event)

    def mouseReleased(self, event):
        self._ctx_menu(event)

    def _ctx_menu(self, event):
        try:
            if not event.isPopupTrigger():
                return
            vr = self._table.rowAtPoint(event.getPoint())
            if vr < 0:
                return
            self._table.setRowSelectionInterval(vr, vr)
            mr = self._table.convertRowIndexToModel(vr)

            menu = JPopupMenu()

            # Copy actions
            for label, col in self._copy_actions:
                item = JMenuItem("Copy %s" % label)
                item.addActionListener(
                    _BtnListener(self._make_copy(mr, col)))
                menu.add(item)

            # Fuzz action
            if self._url_col is not None and self._ui is not None:
                menu.addSeparator()
                fuzz = JMenuItem("Test Risky Methods (Fuzz Endpoint)")
                fuzz.addActionListener(
                    _BtnListener(self._make_fuzz(mr)))
                menu.add(fuzz)

            # Show Request / Response action
            msgs = self._messages
            if self._ui is not None and mr < len(msgs) and msgs[mr]:
                menu.addSeparator()
                view = JMenuItem("Show Request / Response")
                view.addActionListener(
                    _BtnListener(self._make_view(mr)))
                menu.add(view)

            menu.show(event.getComponent(), event.getX(), event.getY())
        except Exception:
            pass

    def _extract_url(self, mr):
        url = ""
        if self._url_col is not None:
            try:
                url = str(self._model.getValueAt(mr, self._url_col))
            except Exception:
                pass
        if not url:
            try:
                msgs = self._messages
                if mr < len(msgs) and msgs[mr]:
                    u = msgs[mr].getUrl()
                    if u:
                        url = str(u)
            except Exception:
                pass
        return url

    def _make_copy(self, mr, col):
        def handler(evt):
            try:
                v = self._model.getValueAt(mr, col)
                copy_to_clipboard(str(v) if v is not None else "")
            except Exception:
                pass
        return handler

    def _make_fuzz(self, mr):
        def handler(evt):
            try:
                url = self._extract_url(mr)
                if url:
                    self._ui._extender.engine.submit_method_fuzz(url)
            except Exception:
                pass
        return handler

    def _make_view(self, mr):
        def handler(evt):
            try:
                msgs = self._messages
                if mr >= len(msgs):
                    return
                msg = msgs[mr]
                if not msg or not self._ui:
                    return
                url = self._extract_url(mr)
                leak_value = None
                if self._leak_col is not None:
                    try:
                        leak_value = str(
                            self._model.getValueAt(mr, self._leak_col))
                    except Exception:
                        pass
                is_js = self._is_js or bool(
                    re.search(r'\.js(?:$|\?)', url, re.I))
                self._ui.open_popup(msg, url, is_js, leak_value)
            except Exception:
                pass
        return handler


# ---------------------------------------------------------------------------
# Main UI panel
# ---------------------------------------------------------------------------

class ReconUI(object):
    """Builds and manages the entire Swing UI for the extension tab."""

    def __init__(self, extender):
        self._extender = extender
        self._store = extender.store
        self._scope = extender.scope

        # Parallel message lists (rebuilt atomically during EDT refresh)
        self.endpoints_msgs = []
        self.risk_msgs = []
        self.js_msgs = []
        self.leaks_msgs = []
        self.jsfind_msgs = []
        self.probe_msgs = []
        self.fuzz_msgs = []

        self._build_ui()

    # ---- Non-editable table model ----
    def _make_model(self, columns):
        class _NEM(DefaultTableModel):
            def isCellEditable(self, row, col):
                return False
        return _NEM(columns, 0)

    # ================================================================
    # UI Construction
    # ================================================================

    def _build_ui(self):
        self.panel = JPanel(BorderLayout())

        # --- Detect theme ---
        bg = UIManager.getColor("Panel.background")
        if bg is None:
            bg = JPanel().getBackground()
        brightness = (bg.getRed() * 299 + bg.getGreen() * 587
                      + bg.getBlue() * 114) / 1000.0
        self._dark = brightness < 128

        # --- Color palette ---
        if self._dark:
            self.c_card_bg      = Color(38, 38, 38)
            self.c_card_border  = Color(58, 58, 58)
            self.c_title        = Color(158, 158, 158)
            self.c_text         = Color(238, 238, 238)
            self.c_text_sec     = Color(130, 130, 130)
            self.c_btn_bg       = Color(55, 55, 55)
            self.c_btn_fg       = Color(220, 220, 220)
            self.c_accent       = Color(0, 188, 212)   # teal
            self.c_green        = Color(46, 125, 50)
            self.c_red          = Color(211, 47, 47)
            self.c_amber        = Color(255, 160, 0)
            self.c_row_even     = Color(42, 42, 42)
            self.c_row_odd      = Color(35, 35, 35)
            self.c_grid         = Color(58, 58, 58)
        else:
            self.c_card_bg      = Color(250, 250, 250)
            self.c_card_border  = Color(224, 224, 224)
            self.c_title        = Color(97, 97, 97)
            self.c_text         = Color(33, 33, 33)
            self.c_text_sec     = Color(117, 117, 117)
            self.c_btn_bg       = Color(238, 238, 238)
            self.c_btn_fg       = Color(50, 50, 50)
            self.c_accent       = Color(0, 137, 123)   # teal
            self.c_green        = Color(46, 125, 50)
            self.c_red          = Color(198, 40, 40)
            self.c_amber        = Color(245, 124, 0)
            self.c_row_even     = Color(255, 255, 255)
            self.c_row_odd      = Color(245, 245, 245)
            self.c_grid         = Color(224, 224, 224)

        # ---- Utility styling closures ----
        ui = self

        def style_btn(btn, bg_c, fg_c):
            btn.setBackground(bg_c)
            btn.setForeground(fg_c)
            btn.setFont(Font("SansSerif", Font.BOLD, 12))
            btn.setFocusPainted(False)
            btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(
                    bg_c.darker() if ui._dark else bg_c.brighter(), 1),
                BorderFactory.createEmptyBorder(6, 14, 6, 14)))
            btn.setOpaque(True)
            btn.setContentAreaFilled(True)
            btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))

        def style_cb(cb):
            cb.setFont(Font("SansSerif", Font.PLAIN, 12))
            cb.setForeground(ui.c_text)

        def style_tf(tf):
            tf.setFont(Font("Monospaced", Font.PLAIN, 12))
            tf.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(ui.c_card_border, 1),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)))
            tf.setBackground(ui.c_card_bg)
            tf.setForeground(ui.c_text)
            tf.setCaretColor(ui.c_text)

        # ================================================================
        # Top dashboard panel
        # ================================================================
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(BorderFactory.createEmptyBorder(14, 14, 10, 14))

        # --- Header row ---
        hdr = JPanel(BorderLayout())
        hdr.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0))

        # Title block
        title_box = JPanel()
        title_box.setLayout(BoxLayout(title_box, BoxLayout.Y_AXIS))

        title_lbl = JLabel("RECON SWISS KNIFE PRO")
        title_lbl.setFont(Font("SansSerif", Font.BOLD, 20))
        title_lbl.setForeground(self.c_accent)

        subtitle = JLabel("Semi-Active Security Recon & Method Fuzzer  \u2022  v3")
        subtitle.setFont(Font("SansSerif", Font.ITALIC, 11))
        subtitle.setForeground(self.c_text_sec)

        title_box.add(title_lbl)
        title_box.add(subtitle)
        hdr.add(title_box, BorderLayout.WEST)

        # Right side: status + toggle
        right_box = JPanel(FlowLayout(FlowLayout.RIGHT, 10, 4))

        self.lbl_status = JLabel("Status: Idle")
        self.lbl_status.setFont(Font("SansSerif", Font.BOLD, 12))
        self.lbl_status.setForeground(self.c_text_sec)
        right_box.add(self.lbl_status)

        self.toggle_btn = JButton("Passive Recon: OFF")
        style_btn(self.toggle_btn, self.c_red, Color.WHITE)
        self.toggle_btn.addActionListener(_BtnListener(self._on_toggle))
        right_box.add(self.toggle_btn)

        hdr.add(right_box, BorderLayout.EAST)
        top.add(hdr)

        # --- Actions row ---
        actions = JPanel(FlowLayout(FlowLayout.LEFT, 8, 3))

        self.clear_btn = JButton("Clear Data")
        style_btn(self.clear_btn, self.c_btn_bg, self.c_btn_fg)
        self.clear_btn.addActionListener(_BtnListener(self._on_clear))
        actions.add(self.clear_btn)

        self.rescan_btn = JButton("Rescan Proxy History")
        style_btn(self.rescan_btn, self.c_btn_bg, self.c_btn_fg)
        self.rescan_btn.addActionListener(_BtnListener(self._on_rescan))
        actions.add(self.rescan_btn)

        sep1 = JLabel("  \u2502  ")
        sep1.setForeground(self.c_card_border)
        actions.add(sep1)

        self.cb_js_fetch = JCheckBox("Auto Deep-Fetch JS")
        self.cb_js_fetch.setToolTipText(
            "Actively download newly-discovered in-scope .js files and scan "
            "them for hidden endpoints, cloud buckets, and API paths.")
        style_cb(self.cb_js_fetch)
        self.cb_js_fetch.addActionListener(
            _BtnListener(self._on_js_fetch_toggle))
        actions.add(self.cb_js_fetch)

        self.cb_method_probe = JCheckBox("Auto Method Probe (OPTIONS/HEAD)")
        self.cb_method_probe.setToolTipText(
            "Send a single low-overhead OPTIONS (fallback HEAD) request to "
            "newly-probed in-scope endpoints to verify accepted HTTP methods.")
        style_cb(self.cb_method_probe)
        self.cb_method_probe.addActionListener(
            _BtnListener(self._on_method_probe_toggle))
        actions.add(self.cb_method_probe)

        top.add(actions)

        # --- Filters row ---
        filters = JPanel(FlowLayout(FlowLayout.LEFT, 8, 3))

        scope_lbl = JLabel("Scope Filter (comma-separated):")
        scope_lbl.setFont(Font("SansSerif", Font.BOLD, 11))
        scope_lbl.setForeground(self.c_title)
        filters.add(scope_lbl)

        self.scope_field = JTextField(24)
        style_tf(self.scope_field)
        self.scope_field.getDocument().addDocumentListener(
            _DocListener(self._on_scope_changed))
        filters.add(self.scope_field)

        filters.add(JLabel("   "))

        search_lbl = JLabel("Search / Filter:")
        search_lbl.setFont(Font("SansSerif", Font.BOLD, 11))
        search_lbl.setForeground(self.c_title)
        filters.add(search_lbl)

        self.search_field = JTextField(24)
        style_tf(self.search_field)
        self.search_field.getDocument().addDocumentListener(
            _DocListener(self._on_search_changed))
        filters.add(self.search_field)

        top.add(filters)

        # --- Metric cards grid ---
        self._card_labels = {}

        def make_card(title, key):
            card = JPanel(BorderLayout(0, 2))
            card.setBackground(self.c_card_bg)
            card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(self.c_card_border, 1),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)))

            t = JLabel(title)
            t.setFont(Font("SansSerif", Font.PLAIN, 10))
            t.setForeground(self.c_title)

            v = JLabel("0")
            v.setFont(Font("SansSerif", Font.BOLD, 18))
            v.setForeground(self.c_text)

            card.add(t, BorderLayout.NORTH)
            card.add(v, BorderLayout.CENTER)
            self._card_labels[key] = v
            return card

        grid = JPanel(GridLayout(2, 4, 8, 8))
        grid.add(make_card("ENDPOINTS & PARAMS",    "endpoints"))
        grid.add(make_card("JS FILES DISCOVERED",   "js"))
        grid.add(make_card("METHOD / HEADER ISSUES", "findings"))
        grid.add(make_card("INFO LEAKS",             "leaks"))
        grid.add(make_card("PROCESSED ITEMS",        "processed"))
        grid.add(make_card("JS DEEP FINDINGS",       "js_findings"))
        grid.add(make_card("METHOD PROBES",          "probes"))
        grid.add(make_card("METHOD FUZZES",          "fuzzes"))

        grid_wrap = JPanel(BorderLayout())
        grid_wrap.setBorder(BorderFactory.createEmptyBorder(8, 0, 4, 0))
        grid_wrap.add(grid, BorderLayout.CENTER)
        top.add(grid_wrap)

        # ================================================================
        # Tabbed data tables
        # ================================================================
        self.tabs = JTabbedPane()

        # 0 - Endpoints
        self.ep_model = self._make_model(["URL", "Method", "Parameters"])
        self.ep_table = JTable(self.ep_model)
        self.ep_sorter = TableRowSorter(self.ep_model)
        self.ep_table.setRowSorter(self.ep_sorter)
        self.ep_table.addMouseListener(_TableMouseListener(
            self.ep_table, self.ep_model, self.ep_sorter,
            [("URL", 0), ("Parameters", 2)], self.endpoints_msgs,
            url_col=0, ui=self))
        self.tabs.addTab("Endpoints & Params (0)", JScrollPane(self.ep_table))

        # 1 - Methods & Headers
        self.risk_model = self._make_model(["URL", "Finding Type", "Detail"])
        self.risk_table = JTable(self.risk_model)
        self.risk_sorter = TableRowSorter(self.risk_model)
        self.risk_table.setRowSorter(self.risk_sorter)
        self.risk_table.addMouseListener(_TableMouseListener(
            self.risk_table, self.risk_model, self.risk_sorter,
            [("URL", 0), ("Detail", 2)], self.risk_msgs,
            url_col=0, ui=self))
        self.tabs.addTab("HTTP Methods & Headers (0)",
                         JScrollPane(self.risk_table))

        # 2 - JS Files
        self.js_model = self._make_model(
            ["JavaScript File URL", "Deep-Fetched?"])
        self.js_table = JTable(self.js_model)
        self.js_sorter = TableRowSorter(self.js_model)
        self.js_table.setRowSorter(self.js_sorter)
        self.js_table.addMouseListener(_TableMouseListener(
            self.js_table, self.js_model, self.js_sorter,
            [("URL", 0)], self.js_msgs,
            url_col=0, is_js=True, ui=self))
        self.tabs.addTab("JS Files (0)", JScrollPane(self.js_table))

        # 3 - Leaks
        self.leak_model = self._make_model(
            ["Type", "Match Value", "Source URL"])
        self.leak_table = JTable(self.leak_model)
        self.leak_sorter = TableRowSorter(self.leak_model)
        self.leak_table.setRowSorter(self.leak_sorter)
        self.leak_table.addMouseListener(_TableMouseListener(
            self.leak_table, self.leak_model, self.leak_sorter,
            [("Match Value", 1), ("Source URL", 2)], self.leaks_msgs,
            url_col=2, leak_col=1, ui=self))
        self.tabs.addTab("Leaks (0)", JScrollPane(self.leak_table))

        # 4 - JS Deep Findings
        self.jsfind_model = self._make_model(
            ["Type", "Value", "Source JS File"])
        self.jsfind_table = JTable(self.jsfind_model)
        self.jsfind_sorter = TableRowSorter(self.jsfind_model)
        self.jsfind_table.setRowSorter(self.jsfind_sorter)
        self.jsfind_table.addMouseListener(_TableMouseListener(
            self.jsfind_table, self.jsfind_model, self.jsfind_sorter,
            [("Value", 1), ("Source JS File", 2)], self.jsfind_msgs,
            url_col=2, ui=self))
        self.tabs.addTab("JS Deep Findings (0)",
                         JScrollPane(self.jsfind_table))

        # 5 - Method Probe Results
        self.probe_model = self._make_model(
            ["URL", "Allow / Public Header", "HTTP Status"])
        self.probe_table = JTable(self.probe_model)
        self.probe_sorter = TableRowSorter(self.probe_model)
        self.probe_table.setRowSorter(self.probe_sorter)
        self.probe_table.addMouseListener(_TableMouseListener(
            self.probe_table, self.probe_model, self.probe_sorter,
            [("URL", 0), ("Allow Header", 1)], self.probe_msgs,
            url_col=0, ui=self))
        self.tabs.addTab("Method Probe Results (0)",
                         JScrollPane(self.probe_table))

        # 6 - Method Fuzz Results
        self.fuzz_model = self._make_model(
            ["URL", "Method", "HTTP Status", "Bypass Status"])
        self.fuzz_table = JTable(self.fuzz_model)
        self.fuzz_sorter = TableRowSorter(self.fuzz_model)
        self.fuzz_table.setRowSorter(self.fuzz_sorter)
        self.fuzz_table.addMouseListener(_TableMouseListener(
            self.fuzz_table, self.fuzz_model, self.fuzz_sorter,
            [("URL", 0)], self.fuzz_msgs,
            url_col=0, ui=self))
        self.tabs.addTab("Method Fuzz Results (0)",
                         JScrollPane(self.fuzz_table))

        # ---- Style all tables ----
        all_tables = [
            self.ep_table, self.risk_table, self.js_table,
            self.leak_table, self.jsfind_table, self.probe_table,
            self.fuzz_table
        ]
        for t in all_tables:
            t.setRowHeight(26)
            t.setShowGrid(True)
            t.setGridColor(self.c_grid)
            t.setFont(Font("Monospaced", Font.PLAIN, 12))
            t.getTableHeader().setFont(Font("SansSerif", Font.BOLD, 11))
            t.setIntercellSpacing(Dimension(1, 1))

        # ---- All sorters list ----
        self._sorters = [
            self.ep_sorter, self.risk_sorter, self.js_sorter,
            self.leak_sorter, self.jsfind_sorter, self.probe_sorter,
            self.fuzz_sorter
        ]

        # ---- Assemble main panel (no bottom split) ----
        self.panel.add(top, BorderLayout.NORTH)
        self.panel.add(self.tabs, BorderLayout.CENTER)

    # ================================================================
    # Callbacks
    # ================================================================

    def _on_toggle(self, evt):
        self._extender.toggle_enabled()

    def _on_clear(self, evt):
        r = JOptionPane.showConfirmDialog(
            self.panel, "Clear all collected recon data?",
            "Confirm Clear", JOptionPane.YES_NO_OPTION)
        if r == JOptionPane.YES_OPTION:
            self._store.clear()
            self.refresh_all()

    def _on_rescan(self, evt):
        self._extender.rescan_proxy_history()

    def _on_js_fetch_toggle(self, evt):
        try:
            self._extender.engine.set_module_enabled(
                "js_fetch", self.cb_js_fetch.isSelected())
        except Exception:
            pass

    def _on_method_probe_toggle(self, evt):
        try:
            self._extender.engine.set_module_enabled(
                "method_probe", self.cb_method_probe.isSelected())
        except Exception:
            pass

    def _on_scope_changed(self):
        try:
            self._scope.set_scope_text(self.scope_field.getText())
        except Exception:
            pass

    def _on_search_changed(self):
        try:
            text = self.search_field.getText()
            if not text:
                rf = None
            else:
                escaped = re.escape(text) if _looks_like_plain_text(text) else text
                try:
                    rf = RowFilter.regexFilter("(?i)" + escaped)
                except Exception:
                    rf = RowFilter.regexFilter("(?i)" + re.escape(text))
            for s in self._sorters:
                try:
                    s.setRowFilter(rf)
                except Exception:
                    pass
        except Exception:
            pass

    def set_toggle_state(self, enabled):
        if enabled:
            self.toggle_btn.setText("Passive Recon: ON")
            self.toggle_btn.setBackground(self.c_green)
            self.toggle_btn.setForeground(Color.WHITE)
        else:
            self.toggle_btn.setText("Passive Recon: OFF")
            self.toggle_btn.setBackground(self.c_red)
            self.toggle_btn.setForeground(Color.WHITE)

    # ================================================================
    # Popup launcher (EDT safe)
    # ================================================================

    def open_popup(self, msg, url="", is_js=False, leak_value=None):
        if not msg:
            return
        title = EXTENSION_NAME
        if url:
            short = url if len(url) <= 80 else url[:77] + "..."
            title = "Request / Response  \u2014  %s" % short

        popup = RequestResponsePopup(
            self._extender._callbacks, self._extender._helpers,
            msg, title, is_js=is_js, leak_value=leak_value)
        popup.show()

    # ================================================================
    # Refresh (must run on EDT)
    # ================================================================

    def refresh_all(self):
        SwingUtilities.invokeLater(_RefreshRunnable(self))

    def _do_refresh(self):
        try:
            # ---- Take store snapshot under lock ----
            with self._store.lock:
                ep_snap = list(self._store.endpoints.items())
                js_snap = sorted(self._store.js_files.items())
                fetched_snap = set(self._store.fetched_js_urls)
                meth_snap = list(self._store.methods_findings)
                hdr_snap = list(self._store.header_findings)
                leak_snap = list(self._store.leaks)
                jsfind_snap = list(self._store.js_findings)
                probe_snap = list(self._store.probe_results)
                fuzz_snap = list(self._store.fuzz_results)

            # ---- Rebuild Endpoints table ----
            new_ep = []
            self.ep_model.setRowCount(0)
            for url, data in ep_snap:
                ps = ", ".join(sorted(data["params"])) if data["params"] else ""
                self.ep_model.addRow([url, data["method"], ps])
                new_ep.append(data.get("msg"))
            self.endpoints_msgs[:] = new_ep

            # ---- Rebuild Methods & Headers table ----
            new_risk = []
            self.risk_model.setRowCount(0)
            for f in meth_snap:
                self.risk_model.addRow(
                    [f["url"], "Sensitive Method", f["method"]])
                new_risk.append(f.get("msg"))
            for f in hdr_snap:
                self.risk_model.addRow(
                    [f["url"], "Header Issue", f["issue"]])
                new_risk.append(f.get("msg"))
            self.risk_msgs[:] = new_risk

            # ---- Rebuild JS Files table ----
            new_js = []
            self.js_model.setRowCount(0)
            for js_url, msg in js_snap:
                fetched = "Yes" if js_url in fetched_snap else "No"
                self.js_model.addRow([js_url, fetched])
                new_js.append(msg)
            self.js_msgs[:] = new_js

            # ---- Rebuild Leaks table ----
            new_leaks = []
            self.leak_model.setRowCount(0)
            for lk in leak_snap:
                self.leak_model.addRow(
                    [lk["type"], lk["value"], lk["url"]])
                new_leaks.append(lk.get("msg"))
            self.leaks_msgs[:] = new_leaks

            # ---- Rebuild JS Deep Findings table ----
            new_jsfind = []
            self.jsfind_model.setRowCount(0)
            for jf in jsfind_snap:
                self.jsfind_model.addRow(
                    [jf["type"], jf["value"], jf["source"]])
                new_jsfind.append(jf.get("msg"))
            self.jsfind_msgs[:] = new_jsfind

            # ---- Rebuild Probe Results table ----
            new_probe = []
            self.probe_model.setRowCount(0)
            for pr in probe_snap:
                self.probe_model.addRow(
                    [pr["url"], pr["allow"], str(pr["status"])])
                new_probe.append(pr.get("msg"))
            self.probe_msgs[:] = new_probe

            # ---- Rebuild Fuzz Results table ----
            new_fuzz = []
            self.fuzz_model.setRowCount(0)
            for fz in fuzz_snap:
                self.fuzz_model.addRow(
                    [fz["url"], fz["method"],
                     str(fz["status"]), fz["bypass"]])
                new_fuzz.append(fz.get("msg"))
            self.fuzz_msgs[:] = new_fuzz

            # ---- Update metric cards ----
            counts = self._store.snapshot_counts()
            n_ep      = counts[0]
            n_js      = counts[1]
            n_meth    = counts[2]
            n_hdr     = counts[3]
            n_leak    = counts[4]
            n_proc    = counts[5]
            n_jsfind  = counts[6]
            n_probe   = counts[7]
            n_fuzz    = counts[8]
            n_findings = n_meth + n_hdr

            self._card_labels["endpoints"].setText(str(n_ep))
            self._card_labels["js"].setText(str(n_js))
            self._card_labels["findings"].setText(str(n_findings))
            self._card_labels["leaks"].setText(str(n_leak))
            self._card_labels["processed"].setText(str(n_proc))
            self._card_labels["js_findings"].setText(str(n_jsfind))
            self._card_labels["probes"].setText(str(n_probe))
            self._card_labels["fuzzes"].setText(str(n_fuzz))

            # ---- Update tab titles with counts ----
            try:
                self.tabs.setTitleAt(0, "Endpoints & Params (%d)" % n_ep)
                self.tabs.setTitleAt(1, "HTTP Methods & Headers (%d)" % n_findings)
                self.tabs.setTitleAt(2, "JS Files (%d)" % n_js)
                self.tabs.setTitleAt(3, "Leaks (%d)" % n_leak)
                self.tabs.setTitleAt(4, "JS Deep Findings (%d)" % n_jsfind)
                self.tabs.setTitleAt(5, "Method Probe Results (%d)" % n_probe)
                self.tabs.setTitleAt(6, "Method Fuzz Results (%d)" % n_fuzz)
            except Exception:
                pass

            # ---- Update status indicator ----
            active = self._extender.engine.get_active_count()
            if active > 0:
                self.lbl_status.setText(
                    "Status: Scanning...  (%d active)" % active)
                self.lbl_status.setForeground(self.c_green)
            else:
                self.lbl_status.setText("Status: Idle")
                self.lbl_status.setForeground(self.c_text_sec)

            # Color leak card amber if leaks found
            if n_leak > 0:
                self._card_labels["leaks"].setForeground(self.c_amber)
            else:
                self._card_labels["leaks"].setForeground(self.c_text)

        except Exception:
            pass


# ---------------------------------------------------------------------------
# Context Menu Factory (right-click in Burp's built-in tools)
# ---------------------------------------------------------------------------

class _ContextMenuFactory(IContextMenuFactory):
    def __init__(self, extender):
        self._ext = extender

    def createMenuItems(self, invocation):
        items = ArrayList()
        try:
            item = JMenuItem("Send to %s" % EXTENSION_NAME)
            item.addActionListener(
                _BtnListener(self._make_handler(invocation)))
            items.add(item)
        except Exception:
            pass
        return items

    def _make_handler(self, invocation):
        def handler(evt):
            try:
                self._ext.handle_context_send(invocation)
            except Exception:
                pass
        return handler


# ---------------------------------------------------------------------------
# Main Extender
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IHttpListener, ITab,
                   IContextMenuFactory, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)

        self.store = DataStore()
        self.scope = ScopeFilter()
        self.analyzer = ReconAnalyzer(
            self._helpers, self.store, self.scope,
            on_js_discovered=self._on_js_discovered)
        self.js_scanner = JsDeepScanner(self.store)
        self.engine = ActiveEngine(
            self._callbacks, self._helpers, self.store,
            self.scope, self.js_scanner)

        self.enabled = False

        self._refresh_counter = 0
        self._refresh_lock = threading.Lock()
        self._refresh_threshold = 15

        self.ui = ReconUI(self)
        self.engine.set_result_callback(self.ui.refresh_all)

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        self._callbacks.printOutput(
            "%s loaded successfully." % EXTENSION_NAME)

    # ---- ITab ----
    def getTabCaption(self):
        return "Recon Swiss Knife"

    def getUiComponent(self):
        return self.ui.panel

    # ---- IContextMenuFactory ----
    def createMenuItems(self, invocation):
        factory = _ContextMenuFactory(self)
        return factory.createMenuItems(invocation)

    def handle_context_send(self, invocation):
        try:
            selected = invocation.getSelectedMessages()
            if selected is None:
                return
            for msg in selected:
                try:
                    self._process_message(msg, from_history=False, force=True)
                except Exception:
                    pass
            self.ui.refresh_all()
        except Exception:
            try:
                self._callbacks.printError("Context menu send failed.")
            except Exception:
                pass

    # ---- IHttpListener ----
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.enabled:
            return
        if messageIsRequest:
            return
        try:
            self._process_message(messageInfo, from_history=False)
            self._maybe_refresh()
        except Exception:
            pass

    # ---- IExtensionStateListener ----
    def extensionUnloaded(self):
        try:
            self.engine.shutdown()
        except Exception:
            pass

    # ---- Toggle ----
    def toggle_enabled(self):
        self.enabled = not self.enabled
        self.ui.set_toggle_state(self.enabled)
        if self.enabled:
            Thread(_RescanRunnable(self)).start()

    def rescan_proxy_history(self):
        Thread(_RescanRunnable(self)).start()

    def _process_proxy_history(self):
        try:
            history = self._callbacks.getProxyHistory()
            total = len(history)
            for i in range(total):
                if not self.enabled:
                    break
                self._process_message(history[i], from_history=True)
                if i % 25 == 0:
                    self.ui.refresh_all()
            self.ui.refresh_all()
        except Exception as e:
            try:
                self._callbacks.printError(
                    "Error scanning proxy history: %s" % str(e))
            except Exception:
                pass

    def _process_message(self, messageInfo, from_history=False, force=False):
        try:
            # Persist buffers so request/response survive GC
            try:
                persisted = self._callbacks.saveBuffersToTempFiles(messageInfo)
                if persisted:
                    messageInfo = persisted
            except Exception:
                pass

            request_bytes = messageInfo.getRequest()
            if request_bytes is None:
                return

            req_info = self._helpers.analyzeRequest(messageInfo)
            url = req_info.getUrl()
            method = req_info.getMethod()
            response_bytes = messageInfo.getResponse()

            self.analyzer.analyze(
                url, method, request_bytes, response_bytes, messageInfo)

            if force and self.engine.is_module_enabled("method_probe"):
                self.engine.submit_method_probe(str(url))
        except Exception:
            pass

    def _on_js_discovered(self, js_url):
        try:
            self.engine.submit_js_fetch(js_url)
        except Exception:
            pass

    def _maybe_refresh(self):
        do_it = False
        with self._refresh_lock:
            self._refresh_counter += 1
            if self._refresh_counter >= self._refresh_threshold:
                self._refresh_counter = 0
                do_it = True
        if do_it:
            self.ui.refresh_all()
