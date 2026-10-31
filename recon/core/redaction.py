# -*- coding: utf-8 -*-
"""Best-effort redaction with no network, Burp or UI dependencies."""
import re

def redact_ai_text(text):
    text = re.sub(r'(?im)^(authorization|proxy-authorization|cookie|set-cookie):[^\r\n]*',
                  r'\1: [REDACTED]', text)
    text = re.sub(r'''(?i)(["']?(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&}]+)''',
                  r'\1"[REDACTED]"', text)
    text = re.sub(r'\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|(?:AKIA|ASIA)[A-Z0-9]{16})\b',
                  '[REDACTED_TOKEN]', text)
    text = re.sub(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED_JWT]', text)
    text = re.sub(r'(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]', text)
    text = re.sub(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', '[REDACTED_EMAIL]', text)
    text = re.sub(r'(?<!\d)(?:(?:\+98|0098|0)?9\d{9}|\d{10})(?!\d)', '[REDACTED_PII]', text)
    return text
