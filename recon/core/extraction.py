# -*- coding: utf-8 -*-
"""Bounded regex extraction. Response-derived names are candidates, not proven inputs."""
import re
from recon.core.iranian import as_unicode, decode_web_text, persian_parameter_focus
try:
    from urlparse import urlsplit
    from urllib import unquote_plus
except ImportError:
    from urllib.parse import urlsplit, unquote_plus


def extract_parameters(url, request_body='', request_type='', response_body='', response_type=''):
    results = []
    seen = set()
    def add(name, location, evidence):
        name = decode_web_text(as_unicode(unquote_plus(name)), []).strip()
        key = (name, location)
        if not name or len(name) > 128 or key in seen or len(results) >= 500:
            return
        seen.add(key)
        results.append({'name': name, 'location': location, 'evidence': evidence[:160]})
    for index, segment in enumerate(urlsplit(url).path.split('/')):
        if re.match(r'^(?:[0-9]{1,20}|[a-fA-F0-9]{32}|[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12})$', segment):
            add('path_segment_%d' % index, 'Path candidate', segment)
    for match in re.finditer(r'(?:^|&)([^=&\s]+)(?:=[^&]*)?', urlsplit(url).query):
        add(match.group(1), 'Query', match.group(1))
    body = request_body[:800000]
    if 'application/x-www-form-urlencoded' in request_type.lower():
        for match in re.finditer(r'(?:^|&)([^=&\s]+)(?:=[^&]*)?', body):
            add(match.group(1), 'Form body', match.group(1))
    if 'json' in request_type.lower():
        for match in re.finditer(r'"([^"\\\r\n]{1,128})"\s*:', body):
            add(match.group(1), 'JSON body', match.group(0))
    if 'multipart/form-data' in request_type.lower():
        for match in re.finditer(r'(?im)^Content-Disposition:[^\r\n]*?;\s*name="([^"\r\n]{1,128})"', body):
            add(match.group(1), 'Multipart body', match.group(1))
    body = response_body[:800000]
    if 'html' in response_type.lower():
        for match in re.finditer(r'''(?i)<(?:input|select|textarea)\b[^>]{0,2000}?\bname\s*=\s*["']([^"']{1,128})["']''', body):
            add(match.group(1), 'HTML candidate', match.group(0))
    if any(kind in response_type.lower() for kind in ('html', 'javascript')):
        for match in re.finditer(r'''\.(?:get|set|append)\(\s*["']([^"'\r\n]{1,128})["']''', body):
            add(match.group(1), 'JS candidate', match.group(0))
    if 'json' in response_type.lower():
        for match in re.finditer(r'"([^"\\\r\n]{1,128})"\s*:', body):
            add(match.group(1), 'Response JSON candidate', match.group(0))
    return results


ERROR_SIGNATURES = (
    ('SQL error', re.compile(r'(?i)(SQLSTATE\[[A-Z0-9]+\]|you have an error in your SQL syntax|unclosed quotation mark after the character string|ORA-0[0-9]{4}|org\.postgresql\.util\.PSQLException|sqlite3?\.(?:Operational|Database)Error)')),
    ('Stack trace', re.compile(r'(Traceback \(most recent call last\)|java\.lang\.[A-Za-z]+Exception)')),
)


def new_error_signatures(baseline, mutated):
    return [(label, match.group(0)) for label, regex in ERROR_SIGNATURES
            for match in [regex.search(mutated[:800000])]
            if match is not None and not regex.search(baseline[:800000])]


def reflected_marker(marker, body):
    return marker if marker and marker in body[:800000] else None


def parameter_focus(name):
    normalized = re.sub(r'([a-z])([A-Z])', r'\1_\2', name).lower()
    parts = set(re.split(r'[^a-z0-9]+', normalized))
    focus = persian_parameter_focus(name)
    if parts.intersection(('id', 'uuid', 'guid', 'user', 'account', 'owner', 'tenant', 'project', 'order', 'invoice', 'document')):
        focus.append('IDOR / access control')
    if parts.intersection(('q', 'search', 'query', 'name', 'comment', 'message', 'description', 'html', 'content', 'redirect', 'url')):
        focus.append('XSS / output handling')
    if parts.intersection(('role', 'admin', 'price', 'amount', 'quantity', 'discount', 'coupon', 'balance', 'status', 'step', 'owner', 'tenant')):
        focus.append('Business logic')
    return ', '.join(item for i, item in enumerate(focus) if item not in focus[:i]) or 'Input review'


def reflection_evidence(value, body, content_type):
    token = value.split('<', 1)[0]
    if token not in body[:800000]:
        return 'No marker reflection observed.'
    if 'html' not in content_type.lower():
        return 'Marker reflected outside an HTML response; this alone is not XSS.'
    if value in body[:800000]:
        return 'Unescaped marker and delimiters reflected in HTML; inspect the sink and verify browser execution manually.'
    return 'Marker reflected with escaping or transformation; inspect its HTML/JavaScript context.'
