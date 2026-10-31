# -*- coding: utf-8 -*-
"""
Recon Swiss Knife Pro 3.2.1 - Semi-Active Security Recon & Method Fuzzer
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
  * Burp-themed explicit category navigation, regex evidence and a PII view.
  * Scoped selected-GET scans and two-session access comparisons.
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
from burp import IBurpExtenderCallbacks
from burp import IHttpListener
from burp import ITab
from burp import IContextMenuFactory
from burp import IMessageEditorController
from burp import IExtensionStateListener

from javax.swing import (JPanel, JButton, JLabel, JTabbedPane, JTable,
                          JScrollPane, BoxLayout, JTextField, SwingUtilities,
                          BorderFactory, JOptionPane, RowFilter, JMenuItem,
                          JPopupMenu, JCheckBox, UIManager, JDialog, JSplitPane,
                          JTextArea, ListSelectionModel, JList, DefaultListModel)
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing.event import DocumentListener, ListSelectionListener, ChangeListener
from java.awt import (BorderLayout, FlowLayout, GridLayout, Color, Font,
                       Toolkit, Dimension, Cursor, CardLayout)
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, MouseAdapter
from java.util import ArrayList
from java.util.concurrent import (ThreadPoolExecutor, TimeUnit,
                                  ArrayBlockingQueue)
from java.lang import Runnable, Thread

import re
import threading
import time
import uuid
from urlparse import urlsplit, urljoin
from recon.core.evidence import cookie_attributes, method_result_label, is_valid_iranian_national_id, valid_luhn, valid_iranian_iban
from recon.core.iranian import scan_iranian, decode_web_text, PII_LABELS
from recon.core.extraction import extract_parameters, new_error_signatures, reflected_marker, parameter_focus, reflection_evidence


# ---------------------------------------------------------------------------
# Constants / Regex patterns  (compiled once at module load)
# ---------------------------------------------------------------------------

VERSION = "3.2.1"
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


# --- Leak detection ---
RE_PAYMENT_CARD = re.compile(r'(?<![A-Za-z0-9])(?:[0-9][ -]?){12,18}[0-9](?![A-Za-z0-9])')
RE_INTL_PHONE = re.compile(r'(?<![A-Za-z0-9])\+[1-9][0-9](?:[ -]?[0-9]){7,13}\b')
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
# Evidence labels and regex helpers (compatible with Jython 2.7)
# ---------------------------------------------------------------------------















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
        self.generation = 0
        self.parameters = []
        self.seen_parameter_keys = set()
        self.active_results = []
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
            self.generation += 1
            del self.parameters[:]
            self.seen_parameter_keys.clear()
            del self.active_results[:]
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

    def add_parameters(self, url, records, msg):
        with self.lock:
            for record in records:
                key = (url, record['name'], record['location'])
                if key in self.seen_parameter_keys or len(self.parameters) >= 10000:
                    continue
                self.seen_parameter_keys.add(key)
                row = dict(record)
                row.update(url=url, msg=msg)
                self.parameters.append(row)

    def add_active_result(self, url, parameter, test, status, evidence, msg, generation):
        with self.lock:
            if generation != self.generation:
                return
            self.active_results.append(dict(url=url, parameter=parameter, test=test,
                                            status=status, evidence=evidence, msg=msg))
            if len(self.active_results) > 2000:
                del self.active_results[0]

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

def decode_response_body(raw, helpers, info):
    """Bounded gzip/deflate decoding; unsupported encodings are never regex-scanned."""
    encoding = ''
    for header in info.getHeaders():
        if header.lower().startswith('content-encoding:'):
            encoding = header.split(':', 1)[1].strip().lower()
    if encoding in ('', 'identity'):
        return decode_web_text(helpers.bytesToString(raw)[info.getBodyOffset():][:800000], info.getHeaders())
    if encoding not in ('gzip', 'deflate'):
        return None
    from java.io import ByteArrayInputStream, ByteArrayOutputStream
    from java.util.zip import GZIPInputStream, InflaterInputStream
    from jarray import zeros
    stream = ByteArrayInputStream(raw[info.getBodyOffset():])
    stream = GZIPInputStream(stream) if encoding == 'gzip' else InflaterInputStream(stream)
    output = ByteArrayOutputStream()
    buf = zeros(4096, 'b')
    try:
        while output.size() < 800000:
            count = stream.read(buf, 0, min(4096, 800000 - output.size()))
            if count < 0:
                break
            output.write(buf, 0, count)
        return decode_web_text(unicode(output.toString('ISO-8859-1')), info.getHeaders())
    finally:
        stream.close()


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

            request_body, request_type = '', ''
            if request_bytes is not None:
                req_info = self._helpers.analyzeRequest(request_bytes)
                raw_request = self._helpers.bytesToString(request_bytes)
                request_body = decode_web_text(raw_request[req_info.getBodyOffset():][:800000], req_info.getHeaders())
                for header in req_info.getHeaders():
                    if header.lower().startswith('content-type:'):
                        request_type = header.split(':', 1)[1]
            records = extract_parameters(url_str, request_body, request_type)
            self._store.add_parameters(url_str, records, msg)
            self._store.add_endpoint(url_str, method, set(r['name'] for r in records if r['location'] in ('Query', 'Form body', 'JSON body', 'Multipart body')), msg)

            # --- Response analysis (skip binary) ---
            if response_bytes is None:
                return

            try:
                resp_info = self._helpers.analyzeResponse(response_bytes)
                headers_list = list(resp_info.getHeaders())
            except Exception:
                return

            self._check_cookies(url_str, headers_list, msg)
            self._scan_leaks(url_str, '\n'.join(unicode(h) for h in headers_list), msg)
            if self.is_binary_response(headers_list, path):
                return
            self._check_security_headers(url_str, headers_list, msg)
            body = decode_response_body(response_bytes, self._helpers, resp_info)
            if body is None:
                self._store.add_header_finding(url_str, 'Body scan skipped: unsupported content encoding. Use an uncompressed response for regex extraction.', msg)
                return
            response_type = ''
            for header in headers_list:
                if header.lower().startswith('content-type:'):
                    response_type = header.split(':', 1)[1]
            self._store.add_parameters(url_str, extract_parameters(url_str, response_body=body,
                                       response_type=response_type), msg)
            if body:
                self._scan_leaks(url_str, body, msg)
                self._extract_js_from_body(url_str, body, msg)
                if RE_JS_FILE.search(path) or 'javascript' in response_type.lower():
                    JsDeepScanner(self._store).scan(url_str, body, msg)

        except Exception as error:
            callbacks = getattr(self._scope, '_callbacks', None)
            if callbacks is not None:
                callbacks.printError('Response analysis failed: ' + type(error).__name__)

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
        iranian = scan_iranian(body)
        specific_values = set(f['value'] for f in iranian if f['type'] in ('Iranian Mobile', 'Iranian bank card (known BIN, Luhn)'))
        for finding in iranian:
            self._store.add_leak(finding['type'], finding['value'], url, msg)
        scanners = [
            (RE_PAYMENT_CARD, "Possible payment card (Luhn)", False, valid_luhn),
            (RE_INTL_PHONE, "International Phone", False, None),
            (RE_EMAIL,            "Email",                    False, None),
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
                    if pattern in (RE_PAYMENT_CARD, RE_INTL_PHONE) and val in specific_values:
                        continue
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
        self._last_status = 'Active requests require Burp Target scope. Select a GET request to scan.'
        self._scan_urls = set()
        self._closed = False
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
            return True
        except Exception as e:
            with self._store.lock:
                if claim == "js":
                    self._store.fetched_js_urls.discard(url)
                elif claim == "probe":
                    self._store.probed_urls.discard(url)
            self._report_error("Queue submission", e)
            return False

    def _access_pair(self, first, second):
        a = self._helpers.analyzeRequest(first)
        b = self._helpers.analyzeRequest(second)
        url = str(a.getUrl())
        if url != str(b.getUrl()) or str(a.getMethod()) != 'GET' or str(b.getMethod()) != 'GET':
            raise ValueError('Access comparison requires two GET requests for the exact same resource URL.')
        def credentials(info):
            fields = []
            for header in info.getHeaders():
                if ':' in header:
                    name, value = header.split(':', 1)
                    if name.lower().strip() in ('authorization', 'cookie', 'x-api-key'):
                        fields.append(name.lower().strip() + ':' + value.strip())
            return '\n'.join(sorted(fields))
        owner, other = credentials(a), credentials(b)
        if not owner or owner == other:
            raise ValueError('Set an authenticated owner baseline, then supply a request with different credentials or no credentials.')
        if not self._scope.active_in_scope(url):
            raise ValueError('Add the target to Burp Target > Scope before comparing access.')
        return url

    def submit_access_compare(self, first, second, expectation):
        try:
            url = self._access_pair(first, second)
        except ValueError as error:
            self._status(str(error))
            return False
        with self._lock:
            if url in self._scan_urls:
                self._last_status = 'A scan is already queued or running for this resource.'
                return False
            self._scan_urls.add(url)
        queued = self._submit_task(_AccessCompareTask(self, first, second, expectation, self._store.generation))
        if not queued:
            with self._lock:
                self._scan_urls.discard(url)
        return queued

    def _run_access_compare(self, first, second, expectation, generation):
        url = str(self._helpers.analyzeRequest(first).getUrl())
        try:
            self._incr_active()
            self._access_pair(first, second)
            replies = []
            for msg in (first, second):
                if generation != self._store.generation or self._closed:
                    return
                reply = self._send_scoped(url, msg.getHttpService(), msg.getRequest())
                if reply is None or reply.getResponse() is None:
                    return
                raw = reply.getResponse()
                info = self._helpers.analyzeResponse(raw)
                replies.append((reply, info.getStatusCode(), decode_response_body(raw, self._helpers, info)))
            if generation != self._store.generation:
                return
            first_reply, a_status, a_body = replies[0]
            second_reply, b_status, b_body = replies[1]
            same = a_body is not None and b_body is not None and a_body == b_body
            evidence = ('Owner HTTP %s; second session HTTP %s; bodies %s. Expected: %s. ' %
                        (a_status, b_status, 'identical' if same else 'different or undecodable', expectation[:300]))
            if 200 <= a_status < 300 and 200 <= b_status < 300:
                evidence += 'Potential access-control issue only if the second identity is unauthorized; public responses and soft errors must be excluded.'
            else:
                evidence += 'No access bypass established; inspect the actual protected data and permissions.'
            try:
                second_reply = self._callbacks.saveBuffersToTempFiles(second_reply) or second_reply
            except Exception:
                pass
            self._store.add_active_result(url, '-', 'IDOR / logic comparison', b_status, evidence, second_reply, generation)
            self._status('Access comparison complete. Inspect results and verify the expected authorization rule.')
        except Exception as error:
            self._report_error('Access comparison', error)
            self._status('Access comparison failed; check request selection, scope, and extension errors.')
        finally:
            with self._lock:
                self._scan_urls.discard(url)
            self._decr_active()
            self._notify()

    def status_text(self):
        with self._lock:
            return self._last_status

    def _status(self, text):
        with self._lock:
            self._last_status = text
        self._notify()

    def _pace(self):
        with self._request_lock:
            delay = 0.3 - (time.time() - self._last_request)
            if delay > 0:
                time.sleep(delay)
            self._last_request = time.time()

    def _identity_request(self, request):
        info = self._helpers.analyzeRequest(request)
        headers = ArrayList()
        for header in info.getHeaders():
            if not header.lower().startswith(('accept-encoding:', 'content-length:', 'transfer-encoding:')):
                headers.add(header)
        headers.add('Accept-Encoding: identity')
        text = self._helpers.bytesToString(request)
        body = self._helpers.stringToBytes(text[info.getBodyOffset():])
        return self._helpers.buildHttpMessage(headers, body)

    def _send_scoped(self, url, service, request):
        self._pace()
        if not self._scope.active_in_scope(url):
            self._status('Active request skipped: add this host to Burp Target > Scope.')
            return None
        return self._callbacks.makeHttpRequest(service, self._identity_request(request))

    def submit_active_scan(self, msg):
        info = self._helpers.analyzeRequest(msg)
        url = str(info.getUrl())
        if not self._scope.active_in_scope(url):
            self._status('Scan blocked: add the target to Burp Target > Scope and check Hosts.')
            return False
        if str(info.getMethod()) != 'GET':
            self._status('Scan skipped: selected-request checks currently support GET query parameters only.')
            return False
        with self._lock:
            if url in self._scan_urls:
                self._last_status = 'A scan is already queued or running for this URL.'
                return False
            self._scan_urls.add(url)
        generation = self._store.generation
        queued = self._submit_task(_ActiveScanTask(self, msg, generation))
        if not queued:
            with self._lock:
                self._scan_urls.discard(url)
        return queued

    def _run_active_scan(self, msg, generation):
        info = self._helpers.analyzeRequest(msg)
        url = str(info.getUrl())
        service = msg.getHttpService()
        original = msg.getRequest()
        def current():
            return generation == self._store.generation and not self._closed
        def send(request):
            if not current():
                return None
            response = self._send_scoped(url, service, request)
            if response is None or response.getResponse() is None:
                return None
            return response
        def body(response):
            raw = response.getResponse()
            ri = self._helpers.analyzeResponse(raw)
            return decode_response_body(raw, self._helpers, ri)
        def result(parameter, test, response, evidence):
            if not current():
                return
            status = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
            try:
                response = self._callbacks.saveBuffersToTempFiles(response) or response
            except Exception:
                pass
            self._store.add_active_result(url, parameter, test, status, evidence, response, generation)
        try:
            self._incr_active()
            baseline = send(original)
            if baseline is None:
                return
            baseline_body = body(baseline)
            if baseline_body is None:
                result('-', 'Skipped', baseline, 'Unsupported content encoding; no body checks performed.')
                return
            parameters = []
            seen = set()
            for parameter in info.getParameters():
                if parameter.getType() == 0 and parameter.getName() not in seen:
                    parameters.append(parameter)
                    seen.add(parameter.getName())
                if len(parameters) == 5:
                    break
            for parameter in parameters:
                for test, value in [('XSS reflection', 'reconswk_' + uuid.uuid4().hex[:16] + "<'\"&>"),
                                    ('Error differential', str(parameter.getValue()) + "'")]:
                    replacement = self._helpers.buildParameter(parameter.getName(), value, 0)
                    request = self._helpers.updateParameter(original, replacement)
                    response = send(request)
                    if response is None:
                        return
                    response_body = body(response)
                    if response_body is None:
                        result(parameter.getName(), test, response, 'Skipped: unsupported content encoding.')
                    elif test == 'XSS reflection':
                        response_type = ''
                        for header in self._helpers.analyzeResponse(response.getResponse()).getHeaders():
                            if header.lower().startswith('content-type:'):
                                response_type = header.split(':', 1)[1]
                        result(parameter.getName(), test, response,
                               reflection_evidence(value, response_body, response_type))
                    else:
                        errors = new_error_signatures(baseline_body, response_body)
                        evidence = ('New error signature: ' + '; '.join(label + ': ' + quote for label, quote in errors)
                                    if errors else 'No new known error signature versus fresh baseline.')
                        result(parameter.getName(), test, response, evidence)
            headers = ArrayList()
            for header in info.getHeaders():
                if not header.lower().startswith(('origin:', 'content-length:', 'transfer-encoding:')):
                    headers.add(header)
            origin = 'https://recon-scan.invalid'
            headers.add('Origin: ' + origin)
            raw_text = self._helpers.bytesToString(original)
            req_body = self._helpers.stringToBytes(raw_text[info.getBodyOffset():])
            response = send(self._helpers.buildHttpMessage(headers, req_body))
            if response is not None:
                ri = self._helpers.analyzeResponse(response.getResponse())
                values = {}
                for header in ri.getHeaders():
                    if ':' in header:
                        name, value = header.split(':', 1)
                        values[name.lower().strip()] = value.strip()
                evidence = 'No credentialed arbitrary-origin reflection observed.'
                if (values.get('access-control-allow-origin') == origin and
                        values.get('access-control-allow-credentials', '').lower() == 'true'):
                    evidence = 'Origin reflected with credentials=true; verify sensitive authenticated response access.'
                result('-', 'CORS origin', response, evidence)
            if current():
                self._status('Selected scan complete: %d query parameters checked; results are observations, not confirmed exploits.' % len(parameters))
        except Exception as error:
            self._report_error('Selected scan', error)
            self._status('Selected scan failed; see extension errors.')
        finally:
            with self._lock:
                self._scan_urls.discard(url)
            self._decr_active()
            self._notify()

    def set_result_callback(self, cb):
        self._on_result_callback = cb

    def set_module_enabled(self, module_name, enabled):
        with self._lock:
            self._enabled[module_name] = enabled

    def is_module_enabled(self, module_name):
        with self._lock:
            return self._enabled.get(module_name, False)

    def shutdown(self):
        self._closed = True
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
                self._status('JS fetch skipped: add this host to Burp Target > Scope.')
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

            resp = self._send_scoped(js_url, http_service, req_bytes)
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
            body = decode_response_body(response_bytes, self._helpers, resp_info)
            if body is None:
                self._status("JS scan skipped: unsupported response encoding.")
                return

            self._js_scanner.scan(js_url, body, resp)
            ReconAnalyzer(self._helpers, self._store, self._scope).analyze(
                js_url, "GET", resp.getRequest(), response_bytes, resp)

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
                self._status('Probe skipped: add this host to Burp Target > Scope.')
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

            resp = self._send_scoped(url, http_service, req_bytes)
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
                    resp2 = self._send_scoped(url, http_service2, req_bytes2)
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

            resp = self._send_scoped(url, http_service, req_bytes)
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

class _AccessCompareTask(Runnable):
    def __init__(self, engine, first, second, expectation, generation):
        self.args = (first, second, expectation, generation)
        self.engine = engine

    def run(self):
        self.engine._run_access_compare(*self.args)


class _ActiveScanTask(Runnable):
    def __init__(self, engine, msg, generation):
        self.engine, self.msg, self.generation = engine, msg, generation

    def run(self):
        self.engine._run_active_scan(self.msg, self.generation)


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
                scan = JMenuItem('Scan selected GET request')
                scan.addActionListener(_BtnListener(lambda e: self._ui._scan_selected(self._messages[mr])))
                menu.add(scan)
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


class _ResultNavigator(JPanel):
    """Explicit list + cards: independent of Burp's left-tab rendering delegate."""
    def __init__(self):
        JPanel.__init__(self, BorderLayout(8, 0))
        self.labels = DefaultListModel()
        self.nav = JList(self.labels)
        self.nav.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.nav.setFixedCellHeight(34)
        self.nav.setVisibleRowCount(9)
        self.nav.setFixedCellWidth(215)
        self.nav.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
        navigation = JScrollPane(self.nav)
        navigation.setPreferredSize(Dimension(230, 300))
        navigation.setMinimumSize(Dimension(190, 100))
        self.cards = JPanel(CardLayout())
        self.listeners = []
        self.add(navigation, BorderLayout.WEST)
        self.add(self.cards, BorderLayout.CENTER)
        self.nav.addListSelectionListener(_SelectionListener(self._changed))

    def _changed(self):
        index = self.getSelectedIndex()
        if index >= 0:
            self.cards.getLayout().show(self.cards, str(index))
            for listener in self.listeners:
                listener.stateChanged(None)

    def addTab(self, title, component):
        index = self.labels.size()
        self.cards.add(component, str(index))
        self.labels.addElement(title)
        if index == 0:
            self.nav.setSelectedIndex(0)

    def setTitleAt(self, index, title):
        self.labels.setElementAt(title, index)

    def setSelectedIndex(self, index):
        self.nav.setSelectedIndex(index)
        self.nav.ensureIndexIsVisible(index)

    def getSelectedIndex(self):
        return self.nav.getSelectedIndex()

    def getTabCount(self):
        return self.labels.size()

    def addChangeListener(self, listener):
        self.listeners.append(listener)


class _ResultFilter(RowFilter):
    def __init__(self, text, hide_static=False):
        self.text = unicode(text).lower()
        self.hide_static = hide_static

    def include(self, entry):
        if self.hide_static:
            path = urlsplit(unicode(entry.getStringValue(0))).path.lower()
            if path.endswith(BINARY_EXTENSIONS + ('.css',)):
                return False
        return not self.text or any(self.text in unicode(entry.getStringValue(i)).lower()
                                    for i in range(entry.getValueCount()))


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
        self.param_msgs = []
        self.active_msgs = []
        self.pii_msgs = []
        self.access_baseline = None

        self._refresh_pending = False
        self._refresh_dirty = False
        self._ui_refresh_lock = threading.Lock()
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
        self.show_leaks_btn = JButton('Leaks (0)')
        self.show_leaks_btn.addActionListener(_BtnListener(lambda e: self._show_category(3)))
        actions.add(self.show_leaks_btn)
        show_params = JButton('Parameters')
        show_params.addActionListener(_BtnListener(lambda e: self._show_category(7)))
        actions.add(show_params)
        pii = JButton('PII')
        pii.addActionListener(_BtnListener(lambda e: self._show_category(9)))
        actions.add(pii)
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
        self.hide_static = JCheckBox('Hide static assets', True)
        self.hide_static.addActionListener(_BtnListener(lambda e: self._on_search_changed()))
        extra = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
        extra.add(self.hide_static)
        extra.add(reset)
        search.add(extra, BorderLayout.EAST)
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
        self.tabs = _ResultNavigator()

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

        self.param_model = self._make_model(['Source URL', 'Name', 'Location', 'Review focus', 'Regex evidence'])
        self.param_table = _ReconTable(self.param_model)
        self.param_sorter = TableRowSorter(self.param_model)
        self.param_table.setRowSorter(self.param_sorter)
        self.param_table.addMouseListener(_TableMouseListener(
            self.param_table, self.param_model, self.param_sorter,
            [('Name', 1)], self.param_msgs, url_col=0, ui=self))
        self.tabs.addTab('Parameters (0)', _table_scroll(self.param_table))
        self.active_model = self._make_model(['URL', 'Parameter', 'Check', 'Status', 'Evidence / outcome'])
        self.active_table = _ReconTable(self.active_model)
        self.active_sorter = TableRowSorter(self.active_model)
        self.active_table.setRowSorter(self.active_sorter)
        self.active_table.addMouseListener(_TableMouseListener(
            self.active_table, self.active_model, self.active_sorter,
            [('Evidence', 4)], self.active_msgs, url_col=0, ui=self))
        self.tabs.addTab('Active scan (0)', _table_scroll(self.active_table))

        self.pii_model = self._make_model(['PII type', 'Match value', 'Source URL'])
        self.pii_table = _ReconTable(self.pii_model)
        self.pii_sorter = TableRowSorter(self.pii_model)
        self.pii_table.setRowSorter(self.pii_sorter)
        self.pii_table.addMouseListener(_TableMouseListener(
            self.pii_table, self.pii_model, self.pii_sorter, [('Value', 1)],
            self.pii_msgs, url_col=2, leak_col=1, ui=self))
        self.tabs.addTab('PII (0)', _table_scroll(self.pii_table))

        # ---- Style all tables ----
        all_tables = [
            self.ep_table, self.risk_table, self.js_table,
            self.leak_table, self.jsfind_table, self.probe_table,
            self.fuzz_table, self.param_table, self.active_table, self.pii_table
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
            self.fuzz_sorter, self.param_sorter, self.active_sorter, self.pii_sorter
        ]

        self._table_specs = [
            (self.ep_table, self.ep_model, self.endpoints_msgs, 0, None),
            (self.risk_table, self.risk_model, self.risk_msgs, 0, None),
            (self.js_table, self.js_model, self.js_msgs, 0, None),
            (self.leak_table, self.leak_model, self.leaks_msgs, 2, 1),
            (self.jsfind_table, self.jsfind_model, self.jsfind_msgs, 2, None),
            (self.probe_table, self.probe_model, self.probe_msgs, 0, None),
            (self.fuzz_table, self.fuzz_model, self.fuzz_msgs, 0, None),
            (self.param_table, self.param_model, self.param_msgs, 0, None),
            (self.active_table, self.active_model, self.active_msgs, 0, None),
            (self.pii_table, self.pii_model, self.pii_msgs, 2, 1)]
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
        for label, action in [('Open evidence', 'evidence'), ('Scan selected', 'scan'), ('Send to Repeater', 'repeater'), ('Set owner baseline', 'baseline'), ('Compare access', 'compare')]:
            button = JButton(label)
            button.setEnabled(False)
            button.addActionListener(_BtnListener(lambda e, a=action: self._selected_action(a)))
            self.selection_buttons.append(button)
            toolbar.add(button)
        cancel_scans = JButton('Cancel scans')
        cancel_scans.addActionListener(_BtnListener(self._cancel_scans))
        toolbar.add(cancel_scans)
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
        self.workspace_tabs.addTab('Regex extraction & active scan', investigate)
        self.panel.add(top, BorderLayout.NORTH)
        self.panel.add(self.workspace_tabs, BorderLayout.CENTER)
        self.help_label = JLabel('Passive capture starts paused. Active modules send requests only within Burp scope.')
        self.help_label.setBorder(BorderFactory.createEmptyBorder(5, 12, 5, 12))
        self.panel.add(self.help_label, BorderLayout.SOUTH)
        self._on_search_changed()
        self._selection_changed()

    # ================================================================
    # Callbacks
    # ================================================================

    def set_access_baseline(self, msg):
        info = self._extender._helpers.analyzeRequest(msg)
        if str(info.getMethod()) != 'GET':
            self.help_label.setText('Access baseline must be an authenticated GET request for the protected resource.')
            return
        self.access_baseline = msg
        self.help_label.setText('Owner baseline saved. Select the exact same resource with another session, then Compare access.')

    def compare_access(self, msg):
        if self.access_baseline is None:
            self.help_label.setText('First select an authenticated owner request and click Set owner baseline.')
            return
        try:
            self._extender.engine._access_pair(self.access_baseline, msg)
        except ValueError as error:
            self.help_label.setText(str(error))
            return
        expectation = JOptionPane.showInputDialog(self.panel,
            'Two fresh GET requests will be sent using the supplied sessions.\n'
            'Describe the expected access rule (for example: user B must be denied):',
            'Second session must not access this private resource')
        if expectation is not None and unicode(expectation).strip():
            self._extender.engine.submit_access_compare(self.access_baseline, msg, unicode(expectation).strip())
            self._show_category(8)

    def _show_category(self, index):
        self.search_field.setText('')
        self.tabs.setSelectedIndex(index)

    def _scan_selected(self, msg):
        info = self._extender._helpers.analyzeRequest(msg)
        if str(info.getMethod()) != 'GET':
            self.help_label.setText('Selected scan supports GET query parameters only. Use Repeater for other methods.')
            return
        if not self._scope.active_in_scope(str(info.getUrl())):
            self.help_label.setText('Scan blocked: add the target to Burp Target > Scope and check the Hosts filter.')
            return
        answer = JOptionPane.showConfirmDialog(self.panel,
            'Send up to 12 requests for this selected GET endpoint?\n'
            'Checks: fresh baseline, marker reflection, error differential, and CORS.\n'
            'Original authentication is retained. Results require manual verification.',
            'Run scoped active scan', JOptionPane.YES_NO_OPTION)
        if answer == JOptionPane.YES_OPTION:
            self._extender.engine.submit_active_scan(msg)
            self.help_label.setText(self._extender.engine.status_text())

    def _cancel_scans(self, evt):
        with self._store.lock:
            self._store.generation += 1
        self.help_label.setText('Selected scans cancelled. An in-flight request may finish; no further selected-scan requests will be sent.')

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
            self.inspector.setText('Select a result to inspect its evidence.\n\nUse Open evidence for the native request/response viewer, or Scan selected to run bounded active checks on an in-scope GET request.')
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
        elif action == 'scan':
            self._scan_selected(msg)
        elif action == 'repeater':
            self.send_repeater(msg)
        elif action == 'baseline':
            self.set_access_baseline(msg)
        elif action == 'compare':
            self.compare_access(msg)

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




    def send_repeater(self, msg):
        service = msg.getHttpService()
        self._extender._callbacks.sendToRepeater(service.getHost(), service.getPort(),
                                                service.getProtocol() == 'https',
                                                msg.getRequest(), 'Recon ' + VERSION)





    def _on_toggle(self, evt):
        self._extender.toggle_enabled()

    def _on_clear(self, evt):
        r = JOptionPane.showConfirmDialog(
            self.panel, "Clear all collected recon data?",
            "Confirm Clear", JOptionPane.YES_NO_OPTION)
        if r == JOptionPane.YES_OPTION:
            self.access_baseline = None
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
            self.help_label.setText('Active modules off. Select a result for evidence, Repeater or active scanning.')

    def _on_scope_changed(self):
        try:
            self._scope.set_scope_text(self.scope_field.getText())
        except Exception:
            pass

    def _on_search_changed(self):
        if not hasattr(self, '_sorters'):
            return
        text = unicode(self.search_field.getText())
        for sorter in self._sorters:
            sorter.setRowFilter(_ResultFilter(text, self.hide_static.isSelected() and sorter == self.ep_sorter))
        self._selection_changed()

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
                param_snap = list(self._store.parameters)
                active_snap = list(self._store.active_results)

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

            self.param_model.setRowCount(0)
            self.param_msgs[:] = []
            for row in param_snap:
                self.param_model.addRow([row['url'], row['name'], row['location'], ('IDOR / access control' if row['location'] == 'Path candidate' else parameter_focus(row['name'])), row['evidence']])
                self.param_msgs.append(row['msg'])
            self.active_model.setRowCount(0)
            self.active_msgs[:] = []
            for row in active_snap:
                self.active_model.addRow([row['url'], row['parameter'], row['test'], str(row['status']), row['evidence']])
                self.active_msgs.append(row['msg'])
            self.tabs.setTitleAt(7, 'Parameters (%d)' % len(param_snap))
            self.tabs.setTitleAt(8, 'Active scan (%d)' % len(active_snap))
            self.show_leaks_btn.setText('Leaks (%d)' % len(leak_snap))
            self.pii_model.setRowCount(0)
            self.pii_msgs[:] = []
            pii_types = set(['Email', 'Iranian Mobile', 'Iranian National ID', 'International Phone',
                             'Iranian IBAN', 'Possible payment card (Luhn)']) | PII_LABELS
            for row in leak_snap:
                if row['type'] in pii_types:
                    self.pii_model.addRow([row['type'], row['value'], row['url']])
                    self.pii_msgs.append(row['msg'])
            self.tabs.setTitleAt(9, 'PII (%d)' % len(self.pii_msgs))
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

            self.summary_label.setText('%d endpoints / %d parameters / %d scripts / %d observations / %d leaks' %
                                       (n_ep, len(param_snap), n_js, n_findings, n_leak))
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

            if hasattr(self._extender.engine, 'status_text'):
                self.help_label.setText(self._extender.engine.status_text())

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
            selected = invocation.getSelectedMessages()
            if selected is not None and len(selected) > 0:
                baseline = JMenuItem('Recon: set owner baseline')
                baseline.addActionListener(_BtnListener(lambda e: self._ext.ui.set_access_baseline(selected[0])))
                items.add(baseline)
                compare = JMenuItem('Recon: compare access with owner baseline')
                compare.addActionListener(_BtnListener(lambda e: self._ext.ui.compare_access(selected[0])))
                items.add(compare)
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
        # Avoid recursively probing traffic created by extension callbacks.
        if toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER:
            return
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
            if self._refresh_counter >= 1:
                self._refresh_counter = 0
                do_it = True
        if do_it:
            self.ui.refresh_all()
