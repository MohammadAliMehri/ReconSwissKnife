# Run with Jython 2.7 and burp-extender-api on the Java classpath.
import os
import sys
import json
import unittest
import threading
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.environ.get('RECON_TEST_TARGET') == 'source':
    from recon.burp import extension as r
else:
    import ReconSwissKnife_v3 as r
from java.net import URL
from javax.swing import SwingUtilities

class Callbacks(object):
    def isInScope(self, url): return url.getHost() == 'example.test'
    def printError(self, message): pass

class Helpers(object):
    def analyzeRequest(self, raw): return self
    def getHeaders(self): return ['POST /x HTTP/1.1', 'Host: example.test', 'Authorization: Bearer original', 'Content-Length: 3']
    def getBodyOffset(self): return 0
    def bytesToString(self, value): return value
    def stringToBytes(self, value): return value
    def buildHttpService(self, host, port, tls): return (host, port, tls)
    def buildHttpMessage(self, headers, body): return (list(headers), body)

class Message(object):
    def getRequest(self): return 'abc'

class ExtensionTests(unittest.TestCase):
    def test_host_scope(self):
        scope = r.ScopeFilter(Callbacks()); scope.set_scope_text('example.test')
        self.assertTrue(scope.in_scope('https://api.example.test/x'))
        self.assertFalse(scope.in_scope('https://evil.test/?next=example.test'))
        self.assertFalse(scope.in_scope('https://example.test.evil.test/'))
        self.assertFalse(scope.in_scope('not a URL'))
        self.assertTrue(scope.active_in_scope('https://example.test/'))
        self.assertFalse(scope.active_in_scope('https://api.example.test/'))

    def test_cookie_and_header_context(self):
        store = r.DataStore(); analyzer = r.ReconAnalyzer(None, store, r.ScopeFilter())
        analyzer._check_cookies('https://example.test', ['Set-Cookie: x=secure_httponly; Path=/'], None)
        self.assertIn('missing Secure flag', store.header_findings[0]['issue'])
        self.assertIn('missing HttpOnly flag', store.header_findings[0]['issue'])
        store.clear()
        analyzer._check_cookies('https://example.test', ['Set-Cookie: x=y; Secure; HttpOnly; SameSite=Lax'], None)
        self.assertEqual([], store.header_findings)
        analyzer._check_security_headers('http://example.test', ['Content-Type: application/json'], None)
        self.assertFalse(any('CSP' in f['issue'] or 'Content-Security' in f['issue'] or 'HSTS' in f['issue'] or 'Strict-Transport' in f['issue'] for f in store.header_findings))

    def test_relative_scripts(self):
        store = r.DataStore(); analyzer = r.ReconAnalyzer(None, store, r.ScopeFilter())
        analyzer._extract_js_from_body('https://example.test/app/page', '<script src="../a.js"></script>', None)
        self.assertIn('https://example.test/a.js', store.js_files)

    def test_success_is_unverified(self):
        for status in (200,201,204,403,500):
            self.assertNotIn('Confirmed', r.method_result_label(status))
        self.assertIn('unverified', r.method_result_label(200))

    def test_redaction(self):
        text = 'Authorization: Bearer abc\nCookie: sid=xyz\n{"password":"secret","api_key":"keyvalue"} user@example.test sk-proj-' + 'a'*32
        out = r.redact_ai_text(text)
        for secret in ('Bearer abc', 'sid=xyz', '"secret"', 'keyvalue', 'user@example.test', 'sk-proj-'):
            self.assertNotIn(secret, out)

    def test_context_excludes_credentials(self):
        class Info(object):
            def getUrl(self): return URL('https://user:pass@example.test/a?token=secret&name=alice#fragment')
            def getMethod(self): return 'GET'
            def getStatusCode(self): return 200
            def getHeaders(self): return ['Content-Type: text/plain', 'Set-Cookie: sid=private']
            def getBodyOffset(self): return 0
        class ContextHelpers(object):
            def analyzeRequest(self, msg): return Info()
            def analyzeResponse(self, raw): return Info()
            def bytesToString(self, raw): return raw
        class ResponseMessage(object):
            def getResponse(self): return 'email=user@example.test'
        context = r.build_ai_context(ResponseMessage(), ContextHelpers())
        self.assertIn('HTTP status: 200', context)
        for value in ('secret', 'alice', 'user:pass', 'fragment', 'sid=private', 'user@example.test'):
            self.assertNotIn(value, context)

    def test_ai_endpoints(self):
        self.assertEqual('http://127.0.0.1:11434/v1/chat/completions', r.ai_endpoint('http://127.0.0.1:11434/v1/chat/completions'))
        for url in ('http://remote.test/v1', 'https://user:key@remote.test/v1', 'https://remote.test/v1?key=abc'):
            self.assertRaises(ValueError, r.ai_endpoint, url)

    def test_ai_evidence(self):
        f = dict(title='Hypothesis', category='error', confidence='low', evidence='traceback', explanation='Inspect error', verification='Reproduce')
        payload = json.dumps({'findings':[f]})
        self.assertEqual(1, len(r.validate_ai_findings(payload, 'a traceback here')))
        self.assertRaises(ValueError, r.validate_ai_findings, payload, 'no supporting quote')
        self.assertRaises(ValueError, r.validate_ai_findings, '{"findings":[{}]}', '')
        self.assertEqual([], r.validate_ai_findings('{"findings":[]}', ''))

    def test_probe_preserves_auth(self):
        store = r.DataStore(); store.add_endpoint('https://example.test/x', 'POST', set(), Message())
        engine = r.ActiveEngine(Callbacks(), Helpers(), store, r.ScopeFilter(Callbacks()), None)
        try:
            service, (headers, body) = engine._build_http_service('https://example.test/x', 'OPTIONS')
            self.assertEqual('OPTIONS /x HTTP/1.1', headers[0])
            self.assertIn('Authorization: Bearer original', headers)
            self.assertFalse(any(h.lower().startswith('content-length:') for h in headers))
            self.assertIsNone(body)
            self.assertIsNone(engine._build_http_service('https://evil.test/x', 'OPTIONS'))
        finally: engine.shutdown()

    def test_real_swing_ai_panel(self):
        class Ext(object): pass
        ext = Ext(); ext.store = r.DataStore(); ext.scope = r.ScopeFilter()
        ui = []
        SwingUtilities.invokeAndWait(r._UiCall(lambda: ui.append(r.ReconUI(ext))))
        self.assertEqual(2, ui[0].workspace_tabs.getTabCount())
        self.assertEqual(7, ui[0].tabs.getTabCount())
        self.assertFalse(ui[0].ai_consent.isSelected())

    def make_ui(self):
        class Engine(object):
            def get_active_count(self): return 0
            def set_module_enabled(self, name, enabled): pass
        class Ext(object): pass
        ext = Ext(); ext.store = r.DataStore(); ext.scope = r.ScopeFilter()
        ext.engine = Engine(); ext.enabled = False; ext._callbacks = Callbacks()
        ui = []
        SwingUtilities.invokeAndWait(r._UiCall(lambda: ui.append(r.ReconUI(ext))))
        return ext, ui[0]

    def test_deduplicated_observations(self):
        store = r.DataStore()
        for i in range(5):
            store.add_header_finding('https://example.test/', 'Missing CSP', None)
            store.add_method_finding('https://example.test/', 'PUT', None)
        self.assertEqual(1, len(store.header_findings))
        self.assertEqual(1, len(store.methods_findings))
        store.clear(); store.add_header_finding('https://example.test/', 'Missing CSP', None)
        self.assertEqual(1, len(store.header_findings))

    def test_compact_controls(self):
        ext, ui = self.make_ui()
        def check():
            self.assertFalse(ui.metric_panel.isVisible())
            self.assertFalse(ui.module_panel.isVisible())
            self.assertFalse(ui.selection_buttons[0].isEnabled())
            ui.metrics_toggle.doClick()
            self.assertTrue(ui.metric_panel.isVisible())
            self.assertFalse(ui.cb_js_fetch.isSelected())
            self.assertFalse(ui.cb_method_probe.isSelected())
            ui.modules_toggle.doClick()
            self.assertTrue(ui.module_panel.isVisible())
            ui.cb_js_fetch.doClick()
            self.assertIn('JavaScript fetching', ui.help_label.getText())
            ui.modules_toggle.doClick()
            self.assertFalse(ui.module_panel.isVisible())
            self.assertTrue(ui.cb_js_fetch.isSelected())
        SwingUtilities.invokeAndWait(r._UiCall(check))

    def test_refresh_preserves_selection_and_literal_filter(self):
        ext, ui = self.make_ui()
        ext.store.add_endpoint('https://example.test/a[1]', 'GET', set(), Message())
        ext.store.add_endpoint('https://example.test/b', 'GET', set(), Message())
        def check():
            ui._do_refresh()
            ui.ep_sorter.toggleSortOrder(0)
            ui.ep_table.setRowSelectionInterval(0,0)
            selected = ui._current_selection()[1]
            self.assertTrue(ui.selection_buttons[0].isEnabled())
            ui._do_refresh()
            self.assertEqual(selected, ui._current_selection()[1])
            ui.search_field.setText('[1]')
            self.assertEqual(1, ui.ep_table.getRowCount())
            self.assertEqual('1 shown / 2 total', ui.result_count.getText())
            ui.search_field.setText('nothing-matches')
            self.assertEqual(0, ui.ep_table.getRowCount())
            self.assertFalse(ui.selection_buttons[0].isEnabled())
        SwingUtilities.invokeAndWait(r._UiCall(check))

    def test_refresh_requests_coalesce(self):
        ext, ui = self.make_ui()
        count = [0]; original = ui._do_refresh
        def counted():
            count[0] += 1
            original()
        ui._do_refresh = counted
        def request_many():
            for i in range(30): ui.refresh_all()
        SwingUtilities.invokeAndWait(r._UiCall(request_many))
        SwingUtilities.invokeAndWait(r._UiCall(lambda: None))
        self.assertEqual(1, count[0])

    def test_ai_send_requires_complete_review(self):
        ext, ui = self.make_ui()
        def check():
            self.assertFalse(ui.ai_send.isEnabled())
            ui.ai_model_field.setText('local-model')
            ui.ai_context.setText('reviewed response')
            ui.ai_consent.doClick()
            self.assertTrue(ui.ai_send.isEnabled())
            ui.ai_context.append(' changed')
            self.assertFalse(ui.ai_consent.isSelected())
            self.assertFalse(ui.ai_send.isEnabled())
        SwingUtilities.invokeAndWait(r._UiCall(check))

    def test_local_ai_transport(self):
        class Provider(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                self.server.received = payload
                body = json.dumps({'choices':[{'message':{'content':'{"findings":[]}'}}]})
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        server = HTTPServer(('127.0.0.1',0), Provider)
        worker = threading.Thread(target=server.serve_forever); worker.setDaemon(True); worker.start()
        class Ext(object): pass
        ext=Ext(); ext.store=r.DataStore(); ext.scope=r.ScopeFilter()
        holder=[]
        SwingUtilities.invokeAndWait(r._UiCall(lambda: holder.append(r.ReconUI(ext))))
        ui=holder[0]
        try:
            ui._ai_request('http://127.0.0.1:%d/v1/chat/completions' % server.server_port, 'local-model', '', 'reviewed context', ui._ai_generation)
            SwingUtilities.invokeAndWait(r._UiCall(lambda: None))
            self.assertIn('No supported hypotheses', ui.ai_output.getText())
            self.assertEqual('local-model', server.received['model'])
            self.assertEqual('reviewed context', server.received['messages'][1]['content'])
        finally: server.shutdown(); server.server_close()

if __name__ == '__main__': unittest.main()
