# -*- coding: utf-8 -*-
"""
Recon Swiss Knife Pro 3.1.0 - Semi-Active Security Recon & Method Fuzzer
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
                          JPopupMenu, JCheckBox, UIManager, JDialog, JSplitPane,
                          JTextArea, JPasswordField, ListSelectionModel)
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing.event import DocumentListener, ListSelectionListener, ChangeListener
from java.awt import (BorderLayout, FlowLayout, GridLayout, Color, Font,
                       Toolkit, Dimension, Cursor)
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, MouseAdapter
from java.util import ArrayList
from java.util.concurrent import (ThreadPoolExecutor, TimeUnit,
                                  ArrayBlockingQueue)
from java.lang import Runnable, Thread

import re
import threading
import json
import time
from urlparse import urlsplit, urljoin, urlunsplit
from recon.core.evidence import cookie_attributes, method_result_label, is_valid_iranian_national_id
from recon.core.redaction import redact_ai_text
from recon.core.urls import ai_endpoint
from recon.ai.protocol import AI_SYSTEM_PROMPT, validate_ai_findings
from recon.ai.context import format_ai_context


# ---------------------------------------------------------------------------
# Constants / Regex patterns  (compiled once at module load)
# ---------------------------------------------------------------------------

VERSION = "3.1.0"
EXTENSION_NAME = "Recon Swiss Knife Pro " + VERSION

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
RE_OPENAI_ANTHROPIC   = re.compile(r'\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{24,}')
RE_GCP_APIKEY         = re.compile(r'\bAIzaSy[A-Za-z0-9_\-]{33}\b')
RE_GITHUB_PAT         = re.compile(r'\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})\b')
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

# ---------------------------------------------------------------------------
# Evidence labels and AI protocol (compatible with Jython 2.7)
# ---------------------------------------------------------------------------













def build_ai_context(msg, helpers):
    """Extract a Burp response; delegate redaction and formatting to the pure core."""
    raw = msg.getResponse()
    if raw is None:
        raise ValueError('The selected message has no response.')
    info = helpers.analyzeRequest(msg)
    response = helpers.analyzeResponse(raw)
    body = helpers.bytesToString(raw)[response.getBodyOffset():][:200000]
    return format_ai_context(str(info.getMethod()), str(info.getUrl()),
                             response.getStatusCode(), response.getHeaders(), body)


class _UiCall(Runnable):
    def __init__(self, callback):
        self.callback = callback

    def run(self):
        self.callback()




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
    """Hostname filter for passive analysis; active requests also require Burp scope."""

    def __init__(self, callbacks=None):
        self._callbacks = callbacks
        self._lock = threading.Lock()
        self._terms = []

    def set_scope_text(self, text):
        with self._lock:
            self._terms = []
            if not text:
                return
            for part in text.split(','):
                p = part.strip().lower().lstrip('.').rstrip('.')
                if p:
                    self._terms.append(p)

    def get_terms(self):
        with self._lock:
            return list(self._terms)

    def in_scope(self, url_str):
        try:
            parsed = urlsplit(url_str)
            host = (parsed.hostname or "").lower().rstrip('.')
            if parsed.scheme not in ('http', 'https') or not host:
                return False
            with self._lock:
                terms = list(self._terms)
            if not terms:
                return True
            return any(host == t or host.endswith('.' + t) for t in terms)
        except Exception:
            return False

    def active_in_scope(self, url_str):
        if not self.in_scope(url_str):
            return False
        try:
            from java.net import URL
            return bool(self._callbacks.isInScope(URL(url_str)))
        except Exception:
            return False


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
        self.seen_method_keys = set()
        self.seen_header_keys = set()
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
            self.seen_method_keys.clear()
            self.seen_header_keys.clear()
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
            if msg is not None:
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
            key = (url, method)
            if key in self.seen_method_keys:
                return
            self.seen_method_keys.add(key)
            self.methods_findings.append({"url": url, "method": method,
                                          "msg": msg})

    def add_header_finding(self, url, issue, msg):
        with self.lock:
            key = (url, issue)
            if key in self.seen_header_keys:
                return
            self.seen_header_keys.add(key)
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

            ctype = present.get('content-type', '').lower()
            headers_to_check = ['X-Content-Type-Options']
            if 'text/html' in ctype:
                headers_to_check.append('Content-Security-Policy')
                if 'frame-ancestors' not in present.get('content-security-policy', '').lower():
                    headers_to_check.append('X-Frame-Options')
            if url.lower().startswith('https://'):
                headers_to_check.append('Strict-Transport-Security')
            for hdr in headers_to_check:
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
                    attrs = cookie_attributes(cookie_val)
                    if url.lower().startswith('https://') and 'secure' not in attrs:
                        issues.append('missing Secure flag')
                    if 'httponly' not in attrs:
                        issues.append('missing HttpOnly flag')
                    if 'samesite' not in attrs:
                        issues.append('no explicit SameSite attribute')
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
                js_url = urljoin(url, m.group(1))
                if urlsplit(js_url).scheme in ('http', 'https'):
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
        self._executor = ThreadPoolExecutor(
            self.POOL_SIZE, self.POOL_SIZE, 0, TimeUnit.SECONDS,
            ArrayBlockingQueue(64))
        self._request_lock = threading.Lock()
        self._last_request = 0.0
        self._enabled = {"js_fetch": False, "method_probe": False}
        self._lock = threading.Lock()
        self._on_result_callback = None
        self._active_tasks = 0
        self._active_lock = threading.Lock()

    def _report_error(self, operation, error):
        self._callbacks.printError("%s failed (%s). Check target connectivity, scope or queue capacity." %
                                   (operation, type(error).__name__))

    def _submit_task(self, task, claim=None, url=None):
        try:
            self._executor.submit(task)
        except Exception as e:
            with self._store.lock:
                if claim == "js":
                    self._store.fetched_js_urls.discard(url)
                elif claim == "probe":
                    self._store.probed_urls.discard(url)
            self._report_error("Queue submission", e)

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
            if not self._scope.active_in_scope(js_url):
                return
            if not self._store.try_claim_js_fetch(js_url):
                return
            self._submit_task(_JsFetchTask(self, js_url), "js", js_url)
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
        except Exception as e:
            self._report_error("_run_js_fetch", e)
        finally:
            self._decr_active()
            self._notify()

    # ---- Module 2: Safe HTTP method probing ----
    def submit_method_probe(self, url):
        try:
            if not self.is_module_enabled("method_probe"):
                return
            if not self._scope.active_in_scope(url):
                return
            if not self._store.try_claim_probe(url):
                return
            self._submit_task(_MethodProbeTask(self, url), "probe", url)
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
        except Exception as e:
            self._report_error("_run_method_probe", e)
        finally:
            self._decr_active()
            self._notify()

    # ---- Module 3: Active cross-method fuzzing ----
    def submit_method_fuzz(self, url):
        try:
            if not self._scope.active_in_scope(url):
                self._callbacks.printError("Fuzz cancelled: target is outside Burp scope.")
                return
            for method in FUZZ_METHODS:
                self._submit_task(_MethodFuzzTask(self, url, method))
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

                bypass_str = method_result_label(status)
                self._store.add_fuzz_result(
                    url, method, status, bypass_str, resp)
        except Exception as e:
            self._report_error("_run_method_fuzz", e)
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
            if not self._scope.active_in_scope(url_str):
                return None
            with self._request_lock:
                delay = 0.3 - (time.time() - self._last_request)
                if delay > 0:
                    time.sleep(delay)
                self._last_request = time.time()
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
            with self._store.lock:
                original = self._store.endpoints.get(url_str, {}).get("msg")
            if original is not None:
                raw = original.getRequest()
                info = self._helpers.analyzeRequest(raw)
                original_headers = list(info.getHeaders())
                original_headers[0] = request_line
                kept = ArrayList()
                for h in original_headers:
                    if h.lower().startswith(('content-length:', 'transfer-encoding:')):
                        continue
                    kept.add(h)
                body = None
                if method in ('PUT', 'PATCH'):
                    body = self._helpers.stringToBytes(
                        self._helpers.bytesToString(raw)[info.getBodyOffset():])
                return (http_service, self._helpers.buildHttpMessage(kept, body))
            headers = ArrayList()
            headers.add(request_line)
            headers.add("Host: %s" % (host if j_url.getPort() == -1 else "%s:%s" % (host, port)))
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
            req_lbl = JLabel("  >  Request")
            req_lbl.setFont(Font("SansSerif", Font.BOLD, 12))
            req_lbl.setBorder(BorderFactory.createEmptyBorder(6, 4, 6, 0))
            req_panel.add(req_lbl, BorderLayout.NORTH)
            req_panel.add(req_editor.getComponent(), BorderLayout.CENTER)

            resp_panel = JPanel(BorderLayout())
            resp_lbl = JLabel("  <  Response")
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
                        "  !  Leak Highlight:  \"%s\"" % self._leak_value)
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
                ai = JMenuItem("Prepare AI review (redacted preview)")
                ai.addActionListener(_BtnListener(lambda e: self._ui.prepare_ai(self._messages[mr])))
                menu.add(ai)
                repeater = JMenuItem("Send original request to Repeater")
                repeater.addActionListener(_BtnListener(lambda e: self._ui.send_repeater(self._messages[mr])))
                menu.add(repeater)

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
                    answer = JOptionPane.showConfirmDialog(
                        self._ui.panel,
                        "Send PUT, DELETE, PATCH, DEBUG and TRACE requests? "
                        "These can modify server data. Original authentication is retained.",
                        "Confirm active testing", JOptionPane.YES_NO_OPTION)
                    if answer == JOptionPane.YES_OPTION:
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

class _SelectionListener(ListSelectionListener):
    def __init__(self, callback):
        self.callback = callback

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.callback()


class _TabChangeListener(ChangeListener):
    def __init__(self, callback):
        self.callback = callback

    def stateChanged(self, event):
        self.callback()


def _table_scroll(table):
    scroll = JScrollPane(table)
    scroll.setColumnHeaderView(table.getTableHeader())
    return scroll


class _ReconTable(JTable):
    """Readable rows and a useful empty state in the actual table viewport."""
    def __init__(self, model):
        JTable.__init__(self, model)
        self.setFillsViewportHeight(True)
        self.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.setShowVerticalLines(False)

    def paintComponent(self, graphics):
        self.super__paintComponent(graphics)
        if self.getRowCount() == 0:
            text = 'No matching results. Start capture, import history, or reset your search.'
            graphics.setColor(self.getForeground())
            graphics.drawString(text, 16, 38)

    def getToolTipText(self, event=None):
        if event is not None:
            row = self.rowAtPoint(event.getPoint())
            col = self.columnAtPoint(event.getPoint())
            if row >= 0 and col >= 0:
                return unicode(self.getValueAt(row, col))
        return 'Select a row for details; double-click for the full request and response.'


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

        self._refresh_pending = False
        self._refresh_dirty = False
        self._ui_refresh_lock = threading.Lock()
        self._ai_generation = 0
        self._ai_connection = None
        self._ai_running = False
        self._ai_worker = None
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

        # Compact workflow header. Secondary controls and metrics are opt-in.
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(BorderFactory.createEmptyBorder(10, 12, 6, 12))
        hdr = JPanel(BorderLayout(12, 0))
        title = JLabel('Recon Swiss Knife Pro  /  ' + VERSION)
        title.setFont(Font('SansSerif', Font.BOLD, 18))
        title.setForeground(self.c_accent)
        hdr.add(title, BorderLayout.WEST)
        self.lbl_status = JLabel('Capture paused')
        hdr.add(self.lbl_status, BorderLayout.EAST)
        top.add(hdr)

        actions = JPanel(FlowLayout(FlowLayout.LEFT, 6, 6))
        self.toggle_btn = JButton('Start capture')
        style_btn(self.toggle_btn, self.c_accent, Color.WHITE)
        self.toggle_btn.addActionListener(_BtnListener(self._on_toggle))
        actions.add(self.toggle_btn)
        self.rescan_btn = JButton('Import proxy history')
        self.rescan_btn.addActionListener(_BtnListener(self._on_rescan))
        actions.add(self.rescan_btn)
        self.clear_btn = JButton('Clear workspace')
        self.clear_btn.addActionListener(_BtnListener(self._on_clear))
        actions.add(self.clear_btn)
        self.modules_toggle = JCheckBox('Active modules')
        actions.add(self.modules_toggle)
        self.metrics_toggle = JCheckBox('Show metrics')
        actions.add(self.metrics_toggle)
        top.add(actions)

        self.module_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 3))
        self.module_panel.setBorder(BorderFactory.createTitledBorder('Optional network activity - Burp scope required'))
        self.cb_js_fetch = JCheckBox('Fetch discovered JavaScript')
        self.cb_js_fetch.setToolTipText('Send GET requests for newly discovered in-scope JavaScript files.')
        self.cb_js_fetch.addActionListener(_BtnListener(self._on_js_fetch_toggle))
        self.module_panel.add(self.cb_js_fetch)
        self.cb_method_probe = JCheckBox('Probe OPTIONS / HEAD')
        self.cb_method_probe.setToolTipText('Send OPTIONS with HEAD fallback for new in-scope endpoints.')
        self.cb_method_probe.addActionListener(_BtnListener(self._on_method_probe_toggle))
        self.module_panel.add(self.cb_method_probe)
        self.module_panel.setVisible(False)
        top.add(self.module_panel)
        self.modules_toggle.addActionListener(_BtnListener(
            lambda e: self._show_section(self.module_panel, self.modules_toggle.isSelected())))

        filters = JPanel(BorderLayout(12, 0))
        host = JPanel(BorderLayout(6, 0))
        host.add(JLabel('Hosts'), BorderLayout.WEST)
        self.scope_field = JTextField(20)
        self.scope_field.setToolTipText('Exact hosts and subdomains, comma-separated. Empty means all passive traffic.')
        self.scope_field.getDocument().addDocumentListener(_DocListener(self._on_scope_changed))
        style_tf(self.scope_field)
        host.add(self.scope_field, BorderLayout.CENTER)
        filters.add(host, BorderLayout.WEST)
        search = JPanel(BorderLayout(6, 0))
        search.add(JLabel('Find in results'), BorderLayout.WEST)
        self.search_field = JTextField()
        self.search_field.setToolTipText('Literal text search across all result columns')
        self.search_field.getDocument().addDocumentListener(_DocListener(self._on_search_changed))
        style_tf(self.search_field)
        search.add(self.search_field, BorderLayout.CENTER)
        reset = JButton('Reset')
        reset.addActionListener(_BtnListener(lambda e: self.search_field.setText('')))
        search.add(reset, BorderLayout.EAST)
        filters.add(search, BorderLayout.CENTER)
        top.add(filters)
        self.summary_label = JLabel('No results yet. Start capture or import proxy history.')
        self.summary_label.setAlignmentX(0.0)
        self.summary_label.setBorder(BorderFactory.createEmptyBorder(6, 0, 4, 0))
        summary_row = JPanel(BorderLayout())
        summary_row.add(self.summary_label, BorderLayout.WEST)
        top.add(summary_row)

        self._card_labels = {}
        self.metric_panel = JPanel(GridLayout(1, 8, 6, 0))
        for label, name in [('Endpoints', 'endpoints'), ('Scripts', 'js'),
                            ('Observations', 'findings'), ('Leaks', 'leaks'),
                            ('Processed', 'processed'), ('JS findings', 'js_findings'),
                            ('Probes', 'probes'), ('Method tests', 'fuzzes')]:
            card = JPanel(BorderLayout())
            card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(self.c_card_border),
                BorderFactory.createEmptyBorder(5, 8, 5, 8)))
            card.add(JLabel(label), BorderLayout.NORTH)
            value = JLabel('0')
            value.setFont(Font('SansSerif', Font.BOLD, 16))
            self._card_labels[name] = value
            card.add(value, BorderLayout.CENTER)
            self.metric_panel.add(card)
        self.metric_panel.setVisible(False)
        top.add(self.metric_panel)
        self.metrics_toggle.addActionListener(_BtnListener(
            lambda e: self._show_section(self.metric_panel, self.metrics_toggle.isSelected())))

        # ================================================================
        # Tabbed data tables
        # ================================================================
        self.tabs = JTabbedPane(JTabbedPane.LEFT)

        # 0 - Endpoints
        self.ep_model = self._make_model(["URL", "Method", "Parameters"])
        self.ep_table = _ReconTable(self.ep_model)
        self.ep_sorter = TableRowSorter(self.ep_model)
        self.ep_table.setRowSorter(self.ep_sorter)
        self.ep_table.addMouseListener(_TableMouseListener(
            self.ep_table, self.ep_model, self.ep_sorter,
            [("URL", 0), ("Parameters", 2)], self.endpoints_msgs,
            url_col=0, ui=self))
        self.tabs.addTab("Endpoints & Params (0)", _table_scroll(self.ep_table))

        # 1 - Methods & Headers
        self.risk_model = self._make_model(["URL", "Finding Type", "Detail"])
        self.risk_table = _ReconTable(self.risk_model)
        self.risk_sorter = TableRowSorter(self.risk_model)
        self.risk_table.setRowSorter(self.risk_sorter)
        self.risk_table.addMouseListener(_TableMouseListener(
            self.risk_table, self.risk_model, self.risk_sorter,
            [("URL", 0), ("Detail", 2)], self.risk_msgs,
            url_col=0, ui=self))
        self.tabs.addTab("HTTP Methods & Headers (0)",
                         _table_scroll(self.risk_table))

        # 2 - JS Files
        self.js_model = self._make_model(
            ["JavaScript File URL", "Deep-Fetched?"])
        self.js_table = _ReconTable(self.js_model)
        self.js_sorter = TableRowSorter(self.js_model)
        self.js_table.setRowSorter(self.js_sorter)
        self.js_table.addMouseListener(_TableMouseListener(
            self.js_table, self.js_model, self.js_sorter,
            [("URL", 0)], self.js_msgs,
            url_col=0, is_js=True, ui=self))
        self.tabs.addTab("JS Files (0)", _table_scroll(self.js_table))

        # 3 - Leaks
        self.leak_model = self._make_model(
            ["Type", "Match Value", "Source URL"])
        self.leak_table = _ReconTable(self.leak_model)
        self.leak_sorter = TableRowSorter(self.leak_model)
        self.leak_table.setRowSorter(self.leak_sorter)
        self.leak_table.addMouseListener(_TableMouseListener(
            self.leak_table, self.leak_model, self.leak_sorter,
            [("Match Value", 1), ("Source URL", 2)], self.leaks_msgs,
            url_col=2, leak_col=1, ui=self))
        self.tabs.addTab("Leaks (0)", _table_scroll(self.leak_table))

        # 4 - JS Deep Findings
        self.jsfind_model = self._make_model(
            ["Type", "Value", "Source JS File"])
        self.jsfind_table = _ReconTable(self.jsfind_model)
        self.jsfind_sorter = TableRowSorter(self.jsfind_model)
        self.jsfind_table.setRowSorter(self.jsfind_sorter)
        self.jsfind_table.addMouseListener(_TableMouseListener(
            self.jsfind_table, self.jsfind_model, self.jsfind_sorter,
            [("Value", 1), ("Source JS File", 2)], self.jsfind_msgs,
            url_col=2, ui=self))
        self.tabs.addTab("JS Deep Findings (0)",
                         _table_scroll(self.jsfind_table))

        # 5 - Method Probe Results
        self.probe_model = self._make_model(
            ["URL", "Allow / Public Header", "HTTP Status"])
        self.probe_table = _ReconTable(self.probe_model)
        self.probe_sorter = TableRowSorter(self.probe_model)
        self.probe_table.setRowSorter(self.probe_sorter)
        self.probe_table.addMouseListener(_TableMouseListener(
            self.probe_table, self.probe_model, self.probe_sorter,
            [("URL", 0), ("Allow Header", 1)], self.probe_msgs,
            url_col=0, ui=self))
        self.tabs.addTab("Method Probe Results (0)",
                         _table_scroll(self.probe_table))

        # 6 - Method Fuzz Results
        self.fuzz_model = self._make_model(
            ["URL", "Method", "HTTP Status", "Observation (unverified)"])
        self.fuzz_table = _ReconTable(self.fuzz_model)
        self.fuzz_sorter = TableRowSorter(self.fuzz_model)
        self.fuzz_table.setRowSorter(self.fuzz_sorter)
        self.fuzz_table.addMouseListener(_TableMouseListener(
            self.fuzz_table, self.fuzz_model, self.fuzz_sorter,
            [("URL", 0)], self.fuzz_msgs,
            url_col=0, ui=self))
        self.tabs.addTab("Method Fuzz Results (0)",
                         _table_scroll(self.fuzz_table))

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

        self._table_specs = [
            (self.ep_table, self.ep_model, self.endpoints_msgs, 0, None),
            (self.risk_table, self.risk_model, self.risk_msgs, 0, None),
            (self.js_table, self.js_model, self.js_msgs, 0, None),
            (self.leak_table, self.leak_model, self.leaks_msgs, 2, 1),
            (self.jsfind_table, self.jsfind_model, self.jsfind_msgs, 2, None),
            (self.probe_table, self.probe_model, self.probe_msgs, 0, None),
            (self.fuzz_table, self.fuzz_model, self.fuzz_msgs, 0, None)]
        for table, model, messages, url_col, leak_col in self._table_specs:
            table.setFont(UIManager.getFont('Table.font'))
            table.setRowHeight(28)
            for col in range(model.getColumnCount()):
                column = table.getColumnModel().getColumn(col)
                column.setMinWidth(180 if col == url_col else 80)
                column.setPreferredWidth(660 if col == url_col else 150)
            table.getSelectionModel().addListSelectionListener(_SelectionListener(self._selection_changed))

        investigate = JPanel(BorderLayout(6, 6))
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 3))
        self.selection_buttons = []
        for label, action in [('Open evidence', 'evidence'), ('Prepare AI review', 'ai'), ('Send to Repeater', 'repeater')]:
            button = JButton(label)
            button.setEnabled(False)
            button.addActionListener(_BtnListener(lambda e, a=action: self._selected_action(a)))
            self.selection_buttons.append(button)
            toolbar.add(button)
        self.result_count = JLabel('0 shown / 0 total')
        toolbar.add(self.result_count)
        investigate.add(toolbar, BorderLayout.NORTH)
        self.inspector = JTextArea()
        self.inspector.setEditable(False)
        self.inspector.setLineWrap(True)
        self.inspector.setWrapStyleWord(True)
        self.inspector.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))
        details = JPanel(BorderLayout())
        details.setBorder(BorderFactory.createTitledBorder('Selection details'))
        details.add(JScrollPane(self.inspector), BorderLayout.CENTER)
        details.setMinimumSize(Dimension(200, 100))
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.tabs, details)
        split.setResizeWeight(0.78)
        split.setDividerLocation(1060)
        investigate.add(split, BorderLayout.CENTER)
        self.tabs.addChangeListener(_TabChangeListener(self._selection_changed))
        self.workspace_tabs = JTabbedPane()
        self.workspace_tabs.addTab('Investigate', investigate)
        self.workspace_tabs.addTab('AI review', self._build_ai_panel())
        self.panel.add(top, BorderLayout.NORTH)
        self.panel.add(self.workspace_tabs, BorderLayout.CENTER)
        self.help_label = JLabel('Passive capture starts paused. Active modules send requests only within Burp scope.')
        self.help_label.setBorder(BorderFactory.createEmptyBorder(5, 12, 5, 12))
        self.panel.add(self.help_label, BorderLayout.SOUTH)
        self._selection_changed()

    # ================================================================
    # Callbacks
    # ================================================================

    def _show_section(self, section, visible):
        section.setVisible(visible)
        self.panel.revalidate()
        self.panel.repaint()

    def _current_selection(self):
        index = self.tabs.getSelectedIndex()
        table, model, messages, url_col, leak_col = self._table_specs[index]
        row = table.getSelectedRow()
        if row < 0:
            return None
        row = table.convertRowIndexToModel(row)
        if row >= len(messages):
            return None
        return (messages[row], unicode(model.getValueAt(row, url_col)),
                unicode(model.getValueAt(row, leak_col)) if leak_col is not None else None,
                index == 2)

    def _selection_changed(self):
        if getattr(self, '_refreshing', False):
            return
        selected = self._current_selection()
        enabled = selected is not None and selected[0] is not None
        for button in self.selection_buttons:
            button.setEnabled(enabled)
        if selected is None:
            self.inspector.setText('Select a result to inspect its evidence.\n\nUse Open evidence for the native request/response viewer, or Prepare AI review to inspect redacted outbound context.')
        else:
            table, model, messages, url_col, leak_col = self._table_specs[self.tabs.getSelectedIndex()]
            row = table.convertRowIndexToModel(table.getSelectedRow())
            lines = ['SELECTED RESULT', '']
            for col in range(model.getColumnCount()):
                lines.append(unicode(model.getColumnName(col)) + ':\n' + unicode(model.getValueAt(row, col)) + '\n')
            lines.append('Observation only. Verify security impact before reporting.')
            self.inspector.setText('\n'.join(lines))
        self.inspector.setCaretPosition(0)
        self._update_result_count()

    def _update_result_count(self):
        table = self._table_specs[self.tabs.getSelectedIndex()][0]
        self.result_count.setText('%d shown / %d total' % (table.getRowCount(), table.getModel().getRowCount()))

    def _selected_action(self, action):
        selected = self._current_selection()
        if selected is None or selected[0] is None:
            return
        msg, url, leak, is_js = selected
        if action == 'evidence':
            self.open_popup(msg, url, is_js, leak)
        elif action == 'ai':
            self.prepare_ai(msg)
        elif action == 'repeater':
            self.send_repeater(msg)

    def _remember_selection(self):
        rows = []
        for table, model, messages, url_col, leak_col in self._table_specs:
            vr = table.getSelectedRow()
            if vr < 0:
                rows.append(None)
                continue
            row = table.convertRowIndexToModel(vr)
            rows.append(tuple(unicode(model.getValueAt(row, c)) for c in range(model.getColumnCount())))
        return rows

    def _restore_selection(self, selections):
        for spec, key in zip(self._table_specs, selections):
            if key is None:
                continue
            table, model = spec[:2]
            for row in range(model.getRowCount()):
                if tuple(unicode(model.getValueAt(row, c)) for c in range(model.getColumnCount())) == key:
                    vr = table.convertRowIndexToView(row)
                    if vr >= 0:
                        table.setRowSelectionInterval(vr, vr)
                    break

    def _build_ai_panel(self):
        panel = JPanel(BorderLayout(8, 8))
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))
        settings = JPanel(GridLayout(0, 1, 0, 6))
        settings.setBorder(BorderFactory.createTitledBorder('1. Configure provider'))
        self.ai_endpoint_field = JTextField('http://127.0.0.1:11434/v1/chat/completions')
        self.ai_model_field = JTextField('')
        self.ai_key_field = JPasswordField()
        for label, field in [('Chat completions endpoint', self.ai_endpoint_field),
                             ('Model name', self.ai_model_field),
                             ('API key (memory only; optional locally)', self.ai_key_field)]:
            row = JPanel(BorderLayout(8, 0))
            caption = JLabel(label)
            caption.setPreferredSize(Dimension(300, 28))
            row.add(caption, BorderLayout.WEST)
            row.add(field, BorderLayout.CENTER)
            settings.add(row)
            field.getDocument().addDocumentListener(_DocListener(self._reset_ai_consent))
        panel.add(settings, BorderLayout.NORTH)
        self.ai_context = JTextArea()
        self.ai_context.setLineWrap(True)
        self.ai_context.setWrapStyleWord(True)
        self.ai_context.getDocument().addDocumentListener(_DocListener(self._reset_ai_consent))
        self.ai_output = JTextArea()
        self.ai_output.setEditable(False)
        self.ai_output.setLineWrap(True)
        self.ai_output.setWrapStyleWord(True)
        preview = JPanel(BorderLayout())
        preview.setBorder(BorderFactory.createTitledBorder('2. Review outbound context (editable)'))
        preview.add(JScrollPane(self.ai_context), BorderLayout.CENTER)
        results = JPanel(BorderLayout())
        results.setBorder(BorderFactory.createTitledBorder('3. AI hypotheses (unverified)'))
        results.add(JScrollPane(self.ai_output), BorderLayout.CENTER)
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, preview, results)
        split.setDividerLocation(650)
        split.setResizeWeight(0.5)
        panel.add(split, BorderLayout.CENTER)
        bottom = JPanel(GridLayout(0, 1))
        self.ai_context_count = JLabel('0 / 24000 characters. Select a result, then choose Prepare AI review.')
        bottom.add(self.ai_context_count)
        self.ai_consent = JCheckBox('I reviewed this context and approve sending it to the configured endpoint')
        self.ai_consent.addActionListener(_BtnListener(lambda e: self._update_ai_state()))
        bottom.add(self.ai_consent)
        actions = JPanel(FlowLayout(FlowLayout.LEFT))
        self.ai_send = JButton('Analyze reviewed context')
        self.ai_send.setEnabled(False)
        self.ai_send.addActionListener(_BtnListener(self._send_ai))
        actions.add(self.ai_send)
        cancel = JButton('Cancel AI')
        cancel.addActionListener(_BtnListener(self._cancel_ai))
        actions.add(cancel)
        bottom.add(actions)
        panel.add(bottom, BorderLayout.SOUTH)
        self.ai_context.setText('')
        self.ai_output.setText('AI findings will appear here. No traffic is sent until you review the context and approve sending it.')
        return panel

    def _update_ai_state(self):
        if not hasattr(self, 'ai_send'):
            return
        count = len(unicode(self.ai_context.getText()))
        self.ai_context_count.setText('%d / 24000 characters. Review sensitive data before sending.' % count)
        self.ai_send.setEnabled(not self._ai_running and self.ai_consent.isSelected()
                                and 0 < count <= 24000 and bool(self.ai_model_field.getText().strip()))

    def _reset_ai_consent(self):
        if hasattr(self, 'ai_consent'):
            self.ai_consent.setSelected(False)
            self._update_ai_state()

    def send_repeater(self, msg):
        service = msg.getHttpService()
        self._extender._callbacks.sendToRepeater(service.getHost(), service.getPort(),
                                                service.getProtocol() == 'https',
                                                msg.getRequest(), 'Recon ' + VERSION)

    def prepare_ai(self, msg):
        self._cancel_ai(None)
        try:
            self.ai_context.setText(build_ai_context(msg, self._extender._helpers))
            self.ai_context.setCaretPosition(0)
            self.ai_output.setText('Review the exact outbound context above, then configure your model and approve sending. All results are unverified hypotheses.')
            self.workspace_tabs.setSelectedIndex(1)
        except Exception as e:
            self.ai_output.setText('Cannot prepare context: ' + str(e))

    def _cancel_ai(self, evt):
        self._ai_generation += 1
        self._reset_ai_consent()
        connection = self._ai_connection
        if connection is not None:
            # Disconnect off the EDT; some providers block while closing streams.
            worker = threading.Thread(target=connection.disconnect)
            worker.setDaemon(True)
            worker.start()
        if hasattr(self, 'ai_output'):
            self.ai_output.setText('AI cancelled / context reset. A running transport may take up to its timeout to close.')

    def _send_ai(self, evt):
        if self._ai_running:
            self.ai_output.setText('A review is still running or cancelling; wait for it to finish.')
            return
        if not self.ai_consent.isSelected():
            self.ai_output.setText('Review the context and approve sending first.')
            return
        try:
            endpoint = ai_endpoint(unicode(self.ai_endpoint_field.getText()))
            model = unicode(self.ai_model_field.getText()).strip()
            context = unicode(self.ai_context.getText())
            if not model or not context.strip() or len(context) > 24000:
                raise ValueError('Enter a model and 1-24000 characters of reviewed context.')
        except Exception as e:
            self.ai_output.setText(str(e))
            return
        password = self.ai_key_field.getPassword()
        key = ''.join(unicode(c) for c in password)
        for i in range(len(password)):
            password[i] = '\0'
        self._ai_generation += 1
        generation = self._ai_generation
        self._ai_running = True
        self.ai_send.setEnabled(False)
        self._reset_ai_consent()
        self.ai_output.setText('Analyzing reviewed context...')
        self._ai_worker = threading.Thread(target=self._ai_request,
                                           args=(endpoint, model, key, context, generation))
        self._ai_worker.setDaemon(True)
        self._ai_worker.start()

    def _ai_request(self, endpoint, model, key, context, generation):
        from java.net import URL
        from java.lang import String
        from java.io import ByteArrayOutputStream
        from jarray import zeros
        conn = None
        output = ''
        try:
            if generation != self._ai_generation:
                return
            conn = URL(endpoint).openConnection()
            self._ai_connection = conn
            conn.setConnectTimeout(10000)
            conn.setReadTimeout(45000)
            conn.setInstanceFollowRedirects(False)
            conn.setRequestMethod('POST')
            conn.setDoOutput(True)
            conn.setRequestProperty('Content-Type', 'application/json')
            if key:
                conn.setRequestProperty('Authorization', 'Bearer ' + key)
            payload = json.dumps({'model': model, 'temperature': 0, 'max_tokens': 1800,
                                  'messages': [{'role': 'system', 'content': AI_SYSTEM_PROMPT},
                                               {'role': 'user', 'content': context}]})
            data = String(payload).getBytes('UTF-8')
            conn.setFixedLengthStreamingMode(len(data))
            stream = conn.getOutputStream()
            try:
                stream.write(data)
            finally:
                stream.close()
            code = conn.getResponseCode()
            if code != 200:
                raise ValueError('Provider HTTP %s; check endpoint, model, credentials and limits.' % code)
            stream = conn.getInputStream()
            buffer = zeros(4096, 'b')
            content = ByteArrayOutputStream()
            deadline = time.time() + 60
            try:
                while True:
                    if generation != self._ai_generation:
                        return
                    if time.time() > deadline:
                        raise ValueError('Provider response exceeded the time limit.')
                    count = stream.read(buffer)
                    if count < 0:
                        break
                    if content.size() + count > 1000000:
                        raise ValueError('Provider response exceeds 1 MB.')
                    content.write(buffer, 0, count)
            finally:
                stream.close()
            decoded = json.loads(unicode(content.toString('UTF-8')))
            findings = validate_ai_findings(decoded['choices'][0]['message']['content'], context)
            blocks = ['AI HYPOTHESES - NOT VERIFIED VULNERABILITIES']
            if not findings:
                blocks.append('No supported hypotheses returned. This does not establish that the endpoint is secure.')
            for f in findings:
                blocks.append('%s\nCategory: %s | Confidence: %s\nEvidence: %s\n\n%s\n\nSuggested verification: %s' %
                              (f['title'], f['category'], f['confidence'], f['evidence'], f['explanation'], f['verification']))
            output = '\n\n---\n\n'.join(blocks)
        except ValueError as e:
            output = 'AI review failed: ' + str(e)
        except Exception as e:
            # Never echo provider bodies, request headers, or credentials.
            output = 'AI transport/protocol failed (%s). Check provider settings and connectivity.' % type(e).__name__
        finally:
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass
            self._ai_connection = None
            def finish():
                self._ai_running = False
                self._update_ai_state()
                if generation == self._ai_generation:
                    self.ai_output.setText(output)
                    self.ai_output.setCaretPosition(0)
            SwingUtilities.invokeLater(_UiCall(finish))

    def _on_toggle(self, evt):
        self._extender.toggle_enabled()

    def _on_clear(self, evt):
        r = JOptionPane.showConfirmDialog(
            self.panel, "Clear all collected recon data?",
            "Confirm Clear", JOptionPane.YES_NO_OPTION)
        if r == JOptionPane.YES_OPTION:
            self._cancel_ai(None)
            self._store.clear()
            self.refresh_all()

    def _on_rescan(self, evt):
        self._extender.rescan_proxy_history()

    def _on_js_fetch_toggle(self, evt):
        try:
            self._extender.engine.set_module_enabled(
                "js_fetch", self.cb_js_fetch.isSelected())
            self._update_module_hint()
        except Exception:
            pass

    def _on_method_probe_toggle(self, evt):
        try:
            self._extender.engine.set_module_enabled(
                "method_probe", self.cb_method_probe.isSelected())
            self._update_module_hint()
        except Exception:
            pass

    def _update_module_hint(self):
        enabled = []
        if self.cb_js_fetch.isSelected():
            enabled.append('JavaScript fetching')
        if self.cb_method_probe.isSelected():
            enabled.append('method probing')
        if enabled:
            self.help_label.setText('Active modules enabled: ' + ', '.join(enabled) + '. Requests require Burp scope.')
        else:
            self.help_label.setText('Active modules off. Select a result for evidence, Repeater or AI review.')

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
                escaped = re.escape(text)
                try:
                    rf = RowFilter.regexFilter("(?i)" + escaped)
                except Exception:
                    rf = RowFilter.regexFilter("(?i)" + re.escape(text))
            for s in self._sorters:
                try:
                    s.setRowFilter(rf)
                except Exception:
                    pass
            self._selection_changed()
        except Exception:
            pass

    def set_toggle_state(self, enabled):
        self.lbl_status.setText("Capture running" if enabled else "Capture paused")
        if enabled:
            self.toggle_btn.setText("Pause capture")
            self.toggle_btn.setBackground(self.c_green)
            self.toggle_btn.setForeground(Color.WHITE)
        else:
            self.toggle_btn.setText("Start capture")
            self.toggle_btn.setBackground(self.c_accent)
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
            title = "Request / Response  -  %s" % short

        popup = RequestResponsePopup(
            self._extender._callbacks, self._extender._helpers,
            msg, title, is_js=is_js, leak_value=leak_value)
        popup.show()

    # ================================================================
    # Refresh (must run on EDT)
    # ================================================================

    def refresh_all(self):
        with self._ui_refresh_lock:
            self._refresh_dirty = True
            if self._refresh_pending:
                return
            self._refresh_pending = True
        SwingUtilities.invokeLater(_RefreshRunnable(self))

    def _do_refresh(self):
        with self._ui_refresh_lock:
            self._refresh_dirty = False
        selections = self._remember_selection()
        self._refreshing = True
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

            self.summary_label.setText('%d endpoints  /  %d scripts  /  %d observations  /  %d leaks' %
                                       (n_ep, n_js, n_findings, n_leak))
            self._restore_selection(selections)
            # ---- Update status indicator ----
            active = self._extender.engine.get_active_count()
            if active > 0:
                self.lbl_status.setText(
                    "Status: Scanning...  (%d active)" % active)
                self.lbl_status.setForeground(self.c_green)
            else:
                self.lbl_status.setText("Capture running" if getattr(self._extender, "enabled", False) else "Capture paused")
                self.lbl_status.setForeground(self.c_text_sec)

            # Color leak card amber if leaks found
            if n_leak > 0:
                self._card_labels["leaks"].setForeground(self.c_amber)
            else:
                self._card_labels["leaks"].setForeground(self.c_text)

        except Exception as error:
            if hasattr(self._extender, "_callbacks"):
                self._extender._callbacks.printError("UI refresh failed: " + type(error).__name__)
        finally:
            self._refreshing = False
            self._selection_changed()
            with self._ui_refresh_lock:
                again = self._refresh_dirty
                if not again:
                    self._refresh_pending = False
            if again:
                SwingUtilities.invokeLater(_RefreshRunnable(self))


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
        self.scope = ScopeFilter(callbacks)
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

        created = []
        def create_ui():
            created.append(ReconUI(self))
        if SwingUtilities.isEventDispatchThread():
            create_ui()
        else:
            SwingUtilities.invokeAndWait(_UiCall(create_ui))
        self.ui = created[0]
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
            SwingUtilities.invokeLater(_UiCall(lambda: self.ui._cancel_ai(None)))
            self.engine.shutdown()
        except Exception:
            pass

    # ---- Toggle ----
    def toggle_enabled(self):
        self.enabled = not self.enabled
        self.ui.set_toggle_state(self.enabled)

    def rescan_proxy_history(self):
        Thread(_RescanRunnable(self)).start()

    def _process_proxy_history(self):
        try:
            history = self._callbacks.getProxyHistory()
            total = len(history)
            for i in range(total):
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

            if self.engine.is_module_enabled("method_probe"):
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
