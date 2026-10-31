# -*- coding: utf-8 -*-
# Actual HTTP fixture for the bounded active scanner. Never contacts external targets.
import os, sys, threading, unittest
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from httplib import HTTPConnection
from urlparse import urlsplit, parse_qsl, urlunsplit
from urllib import urlencode
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.environ.get('RECON_TEST_TARGET') == 'source':
    from recon.burp import extension as r
else:
    import ReconSwissKnife_v3 as r
from java.lang import String
from java.net import URL

def text(raw): return unicode(String(raw, 'ISO-8859-1'))
def raw(value): return String(value).getBytes('ISO-8859-1')

class Service(object):
    def __init__(self, host, port, tls=False): self.host, self.port, self.tls = host, port, tls
    def getHost(self): return self.host
    def getPort(self): return self.port
    def getProtocol(self): return 'https' if self.tls else 'http'
class Message(object):
    def __init__(self, service, request, response=None): self.service, self.request, self.response = service, request, response
    def getRequest(self): return self.request
    def getResponse(self): return self.response
    def getHttpService(self): return self.service
class Parameter(object):
    def __init__(self, name, value, kind=0): self.name,self.value,self.kind=name,value,kind
    def getName(self): return self.name
    def getValue(self): return self.value
    def getType(self): return self.kind
class Info(object):
    def __init__(self, value): self.value=value; self.headers=value.split('\r\n\r\n',1)[0].split('\r\n')
    def getHeaders(self): return self.headers
    def getBodyOffset(self): return self.value.index('\r\n\r\n')+4
    def getStatusCode(self): return int(self.headers[0].split()[1])
    def getMethod(self): return self.headers[0].split()[0]
    def getUrl(self):
        host = next(h.split(':',1)[1].strip() for h in self.headers if h.lower().startswith('host:'))
        return URL('http://' + host + self.headers[0].split()[1])
    def getParameters(self): return [Parameter(k,v) for k,v in parse_qsl(urlsplit(str(self.getUrl())).query,keep_blank_values=True)]
class Helpers(object):
    def analyzeRequest(self, value): return Info(text(value.getRequest() if hasattr(value,'getRequest') else value))
    def analyzeResponse(self, value): return Info(text(value))
    def bytesToString(self, value): return text(value)
    def stringToBytes(self, value): return raw(value)
    def buildParameter(self, name, value, kind): return Parameter(name,value,kind)
    def updateParameter(self, value, parameter):
        info=Info(text(value)); method,path,protocol=info.headers[0].split()
        u=urlsplit(path); params=parse_qsl(u.query,keep_blank_values=True)
        params=[(k,parameter.getValue() if k==parameter.getName() else v) for k,v in params]
        info.headers[0]=' '.join((method,urlunsplit(('', '',u.path,urlencode(params),'')),protocol))
        return self.buildHttpMessage(info.headers, raw(info.value[info.getBodyOffset():]))
    def buildHttpMessage(self, headers, body): return raw('\r\n'.join(headers)+'\r\n\r\n'+(text(body) if body is not None else ''))
    def buildHttpService(self, host, port, tls): return Service(host,port,tls)
class Callbacks(object):
    def __init__(self, port): self.port=port; self.allowed=True; self.requests=0; self.errors=[]; self.after_send=None
    def isInScope(self, url): return self.allowed and url.getHost()=='127.0.0.1' and url.getPort()==self.port
    def printError(self, message): self.errors.append(message)
    def saveBuffersToTempFiles(self, msg): return msg
    def makeHttpRequest(self, service, value):
        info=Info(text(value)); method,path,protocol=info.headers[0].split(); headers=dict(h.split(':',1) for h in info.headers[1:])
        conn=HTTPConnection(service.getHost(),service.getPort(),timeout=3)
        try:
            conn.request(method,path,body=info.value[info.getBodyOffset():],headers={k:v.strip() for k,v in headers.items()})
            response=conn.getresponse(); body=response.read()
            encoded=raw('HTTP/1.1 %d OK\r\n'%response.status+'\r\n'.join(k+': '+v for k,v in response.getheaders())+'\r\n\r\n'+body)
        finally: conn.close()
        self.requests+=1
        if self.after_send: self.after_send()
        return Message(service,value,encoded)
class Target(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        query=dict(parse_qsl(urlsplit(self.path).query)); q=query.get('q','')
        body=('echo '+q if q.startswith('reconswk_') else ('SQLSTATE[42000]' if "'" in q else 'echo '+q))
        self.server.auth.append(self.headers.get('Authorization'))
        self.send_response(200); self.send_header('Content-Type','text/plain')
        if self.headers.get('Origin'):
            self.send_header('Access-Control-Allow-Origin',self.headers.get('Origin'))
            self.send_header('Access-Control-Allow-Credentials','true')
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)

class ActiveScanTests(unittest.TestCase):
    def setUp(self):
        self.server=HTTPServer(('127.0.0.1',0),Target); self.server.auth=[]
        t=threading.Thread(target=self.server.serve_forever); t.setDaemon(True); t.start()
        self.callbacks=Callbacks(self.server.server_port); self.helpers=Helpers(); self.store=r.DataStore()
        self.engine=r.ActiveEngine(self.callbacks,self.helpers,self.store,r.ScopeFilter(self.callbacks),r.JsDeepScanner(self.store))
        self.engine._pace=lambda:None
        self.service=Service('127.0.0.1',self.server.server_port)
        request=raw('GET /?q=hello HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nAuthorization: Bearer fixture-only\r\n\r\n'%self.server.server_port)
        self.msg=Message(self.service,request)
    def tearDown(self): self.engine.shutdown(); self.server.shutdown(); self.server.server_close()
    def test_full_scan_and_auth(self):
        self.engine._run_active_scan(self.msg,self.store.generation)
        self.assertEqual([],self.callbacks.errors)
        self.assertEqual(4,self.callbacks.requests)
        self.assertEqual(3,len(self.store.active_results))
        evidence=' '.join(row['evidence'] for row in self.store.active_results)
        self.assertIn('Marker reflected',evidence); self.assertIn('New error signature',evidence); self.assertIn('credentials=true',evidence)
        self.assertTrue(all(value=='Bearer fixture-only' for value in self.server.auth))
    def test_cross_session_access_comparison(self):
        second=Message(self.service,raw(text(self.msg.request).replace('Bearer fixture-only','Bearer second-user')))
        self.engine._run_access_compare(self.msg,second,'User B should be denied',self.store.generation)
        self.assertEqual([],self.callbacks.errors)
        self.assertEqual(2,self.callbacks.requests)
        self.assertEqual(1,len(self.store.active_results))
        self.assertIn('Potential access-control',self.store.active_results[0]['evidence'])
        self.assertIn('bodies identical',self.store.active_results[0]['evidence'])
        self.assertEqual(['Bearer fixture-only','Bearer second-user'],self.server.auth)
    def test_identical_session_rejected(self):
        self.assertFalse(self.engine.submit_access_compare(self.msg,self.msg,'Should be denied'))
        self.assertEqual(0,self.callbacks.requests)
    def test_header_case_does_not_create_a_new_identity(self):
        second=Message(self.service,raw(text(self.msg.request).replace('Authorization: Bearer','authorization:  Bearer')))
        self.assertFalse(self.engine.submit_access_compare(self.msg,second,'Should be denied'))
        self.assertEqual(0,self.callbacks.requests)
    def test_different_resource_rejected(self):
        second=Message(self.service,raw(text(self.msg.request).replace('/?q=hello','/other?q=hello').replace('Bearer fixture-only','Bearer second-user')))
        self.assertFalse(self.engine.submit_access_compare(self.msg,second,'Should be denied'))
        self.assertEqual(0,self.callbacks.requests)
    def test_pii_extraction_and_ui_visibility(self):
        body='Email: person@example.test; national: 1234567891; card: 4111 1111 1111 1111; phone: 09123456789'
        response=self.helpers.buildHttpMessage(['HTTP/1.1 200 OK','Content-Type: text/html'],raw(body))
        message=Message(self.service,self.msg.request,response)
        analyzer=r.ReconAnalyzer(self.helpers,self.store,r.ScopeFilter(self.callbacks))
        analyzer.analyze(str(self.helpers.analyzeRequest(message).getUrl()),'GET',message.getRequest(),response,message)
        kinds=set(row['type'] for row in self.store.leaks)
        self.assertIn('Email',kinds); self.assertIn('Iranian National ID',kinds)
        self.assertIn('Possible payment card (Luhn)',kinds); self.assertIn('Iranian Mobile',kinds)
        from javax.swing import SwingUtilities, JList
        class Ext(object): pass
        ext=Ext(); ext.store=self.store; ext.scope=r.ScopeFilter(self.callbacks); ext.engine=self.engine; ext._callbacks=self.callbacks; ext.enabled=False
        holder=[]
        def check():
            ui=r.ReconUI(ext); holder.append(ui); ui._do_refresh()
            self.assertIsInstance(ui.tabs.nav,JList)
            self.assertEqual(10,ui.tabs.labels.size())
            self.assertEqual(len(self.store.leaks),ui.leak_model.getRowCount())
            self.assertGreater(ui.pii_model.getRowCount(),0)
            ui.show_leaks_btn.doClick()
            self.assertEqual(3,ui.tabs.getSelectedIndex())
            self.assertEqual('Leaks (%d)'%len(self.store.leaks),ui.show_leaks_btn.getText())
            self.assertFalse(hasattr(ui,'ai_send'))
        SwingUtilities.invokeAndWait(r._UiCall(check))
    def test_persian_utf8_response_is_scanned(self):
        body=u'تلفن: ۰۹۱۲۱۲۳۴۵۶۷; کد پستی: ۱۲۳۴۵۶۷۸۹۰; کد ملی: ۱۲۳۴۵۶۷۸۹۱'
        response=self.helpers.buildHttpMessage(['HTTP/1.1 200 OK','Content-Type: text/html; charset=UTF-8'],String(body).getBytes('UTF-8'))
        message=Message(self.service,self.msg.request,response)
        analyzer=r.ReconAnalyzer(self.helpers,self.store,r.ScopeFilter(self.callbacks))
        analyzer.analyze(str(self.helpers.analyzeRequest(message).getUrl()),'GET',message.getRequest(),response,message)
        self.assertEqual([],self.callbacks.errors)
        records={row['type']:row['value'] for row in self.store.leaks}
        self.assertEqual(u'۰۹۱۲۱۲۳۴۵۶۷',records['Iranian Mobile'])
        self.assertEqual(u'۱۲۳۴۵۶۷۸۹۰',records['Iranian postal code (context)'])
        self.assertEqual(u'۱۲۳۴۵۶۷۸۹۱',records['Iranian National ID'])

    def test_compressed_response_is_scanned(self):
        from java.io import ByteArrayOutputStream
        from java.util.zip import GZIPOutputStream
        output=ByteArrayOutputStream(); gzip=GZIPOutputStream(output)
        gzip.write(String('person@example.test').getBytes('UTF-8')); gzip.close()
        response=self.helpers.buildHttpMessage(['HTTP/1.1 200 OK','Content-Type: text/plain','Content-Encoding: gzip'],output.toByteArray())
        message=Message(self.service,self.msg.request,response)
        analyzer=r.ReconAnalyzer(self.helpers,self.store,r.ScopeFilter(self.callbacks))
        analyzer.analyze(str(self.helpers.analyzeRequest(message).getUrl()),'GET',message.getRequest(),response,message)
        self.assertTrue(any(row['type']=='Email' for row in self.store.leaks))
    def test_unsupported_compression_is_visible(self):
        response=self.helpers.buildHttpMessage(['HTTP/1.1 200 OK','Content-Type: text/plain','Content-Encoding: br'],raw('compressed-fixture'))
        message=Message(self.service,self.msg.request,response)
        analyzer=r.ReconAnalyzer(self.helpers,self.store,r.ScopeFilter(self.callbacks))
        analyzer.analyze(str(self.helpers.analyzeRequest(message).getUrl()),'GET',message.getRequest(),response,message)
        self.assertTrue(any('unsupported content encoding' in row['issue'] for row in self.store.header_findings))
    def test_scope_block(self):
        self.callbacks.allowed=False
        self.assertFalse(self.engine.submit_active_scan(self.msg))
        self.assertEqual(0,self.callbacks.requests)
        self.assertIn('Scope',self.engine.status_text())
    def test_scope_changed_after_baseline(self):
        self.callbacks.after_send=lambda:setattr(self.callbacks,'allowed',False)
        self.engine._run_active_scan(self.msg,self.store.generation)
        self.assertEqual(1,self.callbacks.requests)
        self.assertEqual([],self.store.active_results)
    def test_clear_cancels_remaining_probes(self):
        self.callbacks.after_send=self.store.clear
        self.engine._run_active_scan(self.msg,self.store.generation)
        self.assertEqual(1,self.callbacks.requests)
        self.assertEqual([],self.store.active_results)
    def test_post_is_not_automatically_replayed(self):
        self.msg.request=raw(text(self.msg.request).replace('GET /','POST /',1))
        self.assertFalse(self.engine.submit_active_scan(self.msg))
        self.assertEqual(0,self.callbacks.requests)

if __name__=='__main__': unittest.main()
