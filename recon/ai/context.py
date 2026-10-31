# -*- coding: utf-8 -*-
"""Format an immutable input snapshot for user-reviewed AI context."""
import re
from recon.core.compat import text_type
from recon.core.urls import urlsplit, urlunsplit
from recon.core.redaction import redact_ai_text


def format_ai_context(method, url, status, headers, body):
    parsed = urlsplit(url)
    host = parsed.hostname or ''
    if ':' in host:
        host = '[' + host + ']'
    if parsed.port:
        host += ':' + str(parsed.port)
    query = re.sub(r'=[^&]*', '=[REDACTED]', parsed.query)
    url = urlunsplit((parsed.scheme, host, parsed.path, query, ''))
    lines = [str(method) + ' ' + redact_ai_text(url),
             'HTTP status: ' + str(status)]
    allowed = set(['content-type', 'content-security-policy', 'x-frame-options',
                   'strict-transport-security', 'access-control-allow-origin',
                   'access-control-allow-credentials'])
    for header in headers:
        if ':' in header and header.split(':', 1)[0].lower() in allowed:
            lines.append(redact_ai_text(text_type(header)))
    body = text_type(body)[:200000]
    lines.append('\nResponse body (truncated):\n' + redact_ai_text(body)[:12000])
    return '\n'.join(lines)
