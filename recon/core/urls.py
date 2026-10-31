# -*- coding: utf-8 -*-
"""Provider endpoint validation; passive/active target scope stays in Burp."""
try:
    from urlparse import urlsplit, urlunsplit
except ImportError:
    from urllib.parse import urlsplit, urlunsplit

def ai_endpoint(raw):
    parsed = urlsplit(raw.strip())
    host = parsed.hostname
    local = host in ('localhost', '127.0.0.1', '::1')
    if (not host or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or not (parsed.scheme == 'https' or (parsed.scheme == 'http' and local))):
        raise ValueError("Use HTTPS, or local HTTP on localhost/127.0.0.1; no URL credentials, query or fragment.")
    # Validate port before initiating a request.
    parsed.port
    return raw.strip()
