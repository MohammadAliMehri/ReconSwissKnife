# -*- coding: utf-8 -*-
"""Iranian PII patterns. Preserve original match text for Burp evidence highlighting."""
import re
from bisect import bisect_right
from recon.core.evidence import is_valid_iranian_national_id, valid_luhn, valid_iranian_iban

try:
    text_type = unicode
except NameError:
    text_type = str

_TRANSLATION = {}
for _index in range(10):
    _TRANSLATION[0x06f0 + _index] = text_type(_index)
    _TRANSLATION[0x0660 + _index] = text_type(_index)
for _code in (0x00a0, 0x200c, 0x200d, 0x200e, 0x200f, 0x061c, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069):
    _TRANSLATION[_code] = u' '
_TRANSLATION[0x064a] = u'ی'
_TRANSLATION[0x0643] = u'ک'
_ESCAPE = re.compile(r'\\u([0-9a-fA-F]{4})|&#(?:x([0-9a-fA-F]{1,6})|([0-9]{1,7}));', re.I)


def as_unicode(value):
    if isinstance(value, text_type):
        return value
    try:
        return value.decode('utf-8')
    except (AttributeError, UnicodeError):
        return text_type(value)


def decode_web_text(value, headers):
    """Burp bytesToString is byte-preserving, not a UTF-8 decoder."""
    value = as_unicode(value)
    charset = 'utf-8'
    for header in headers:
        if as_unicode(header).lower().startswith('content-type:'):
            match = re.search(r'''(?i)charset\s*=\s*["']?([A-Za-z0-9_-]+)''', as_unicode(header))
            if match:
                charset = match.group(1)
    try:
        return value.encode('latin-1').decode(charset)
    except (UnicodeError, LookupError):
        return value


def normalize_iranian(value):
    return as_unicode(value).translate(_TRANSLATION)


def _normalized_evidence(value):
    """Decode numeric/JSON escapes with sparse offsets, rather than per-character maps."""
    value = as_unicode(value)
    chunks, changes, starts = [], [], []
    original_end = normalized_end = 0
    for match in _ESCAPE.finditer(value):
        code = int(match.group(1) or match.group(2) or match.group(3), 10 if match.group(3) else 16)
        if not (0x0600 <= code <= 0x06ff or code in _TRANSLATION):
            continue
        chunks.append(value[original_end:match.start()])
        normalized_end += match.start() - original_end
        starts.append(normalized_end)
        try:
            char = unichr(code)
        except NameError:
            char = chr(code)
        chunks.append(char)
        changes.append((normalized_end, normalized_end + 1, match.start(), match.end()))
        normalized_end += 1
        original_end = match.end()
    chunks.append(value[original_end:])
    def original_offset(offset, end=False):
        index = bisect_right(starts, offset) - 1
        if index < 0:
            return offset
        begin, finish, old_begin, old_finish = changes[index]
        if offset == begin:
            return old_begin
        if offset < finish:
            return old_finish if end else old_begin
        return offset + old_finish - finish
    return normalize_iranian(u''.join(chunks)), original_offset


# Known Iranian card issuer prefixes: a heuristic catalog, not a complete/live registry.
_IRAN_BINS = set(('603799', '589210', '627648', '627961', '603770', '628023',
    '627760', '502908', '627412', '622106', '502229', '639347', '627488',
    '621986', '639346', '639607', '504706', '502806', '502938', '603769',
    '610433', '991975', '627353', '585983', '589463', '627381', '639599',
    '505785', '505416', '636214', '606373', '504172', '639370', '505801', '636949'))


def _digits(value):
    return re.sub(r'[^0-9]', '', value)


def _card(value):
    digits = _digits(value)
    return digits[:6] in _IRAN_BINS and valid_luhn(digits)


def _iban(value):
    return valid_iranian_iban(re.sub(r'[ -]', '', value))


def _postal(value):
    digits = _digits(value)
    return len(digits) == 10 and digits[0] != '0' and len(set(digits)) > 1


PII_LABELS = frozenset(('Iranian Mobile', 'Iranian National ID', 'Iranian IBAN',
    'Iranian landline (format)', 'Iranian postal code (context)', 'Iranian bank card (known BIN, Luhn)'))

_IRAN_RULES = (
    ('Iranian Mobile', re.compile(r'(?<![A-Za-z0-9])(?:(?:\+98|0098|0)[ -]?)?9[0-9]{2}[ -]?[0-9]{3}[ -]?[0-9]{4}(?![A-Za-z0-9])'), None, 0),
    ('Iranian National ID', re.compile(r'(?<![A-Za-z0-9])[0-9]{10}(?![A-Za-z0-9])'), is_valid_iranian_national_id, 0),
    ('Iranian IBAN', re.compile(r'(?<![A-Za-z0-9])IR[ -]?(?:[0-9][ -]?){23}[0-9](?![A-Za-z0-9])', re.I), _iban, 0),
    ('Iranian bank card (known BIN, Luhn)', re.compile(r'(?<![A-Za-z0-9])(?:[0-9]{4}[ -]?){3}[0-9]{4}(?![A-Za-z0-9])'), _card, 0),
    ('Iranian landline (format)', re.compile(r'(?<![A-Za-z0-9])(?:0|(?:\+98|0098)[ -]?)(?:11|13|17|21|23|24|25|26|28|31|34|35|38|41|44|45|51|54|56|58|61|66|71|74|76|77|81|83|84|86|87)[ -]?[1-9][0-9]{3}[ -]?[0-9]{4}(?![A-Za-z0-9])'), None, 0),
    ('Iranian postal code (context)', re.compile(u'''(?i)(?:کد[ _-]*پستی|postal[_ -]?code|zip[_ -]?code)[\\s"':=：<>-]{0,24}([1-9][0-9]{4}[ -]?[0-9]{5})(?![0-9])'''), _postal, 1),
)


def scan_iranian(value):
    """Return original values and offsets; normalized digits are used only for matching."""
    original = as_unicode(value)[:800000]
    normalized, offset = _normalized_evidence(original)
    findings = []
    seen = set()
    for label, pattern, validator, group in _IRAN_RULES:
        for match in pattern.finditer(normalized):
            candidate = match.group(group)
            if validator is not None and not validator(candidate):
                continue
            begin, end = offset(match.start(group)), offset(match.end(group), True)
            raw = original[begin:end]
            key = (label, raw)
            if key not in seen:
                seen.add(key)
                findings.append({'type': label, 'value': raw, 'normalized': candidate,
                                 'start': begin, 'end': end})
            if len(findings) >= 500:
                return findings
    return findings


def persian_parameter_focus(name):
    name = normalize_iranian(name).replace(' ', '').replace('_', '').replace('-', '')
    focus = []
    if any(term in name for term in (u'شناسه', u'کدملی', u'شمارهسفارش', u'شمارهفاکتور', u'حساب', u'کاربر')):
        focus.append('IDOR / access control')
    if any(term in name for term in (u'نام', u'جستجو', u'پیام', u'توضیح', u'نظر', u'محتوا', u'آدرس', u'عنوان')):
        focus.append('XSS / output handling')
    if any(term in name for term in (u'مبلغ', u'قیمت', u'تعداد', u'تخفیف', u'نقش', u'وضعیت', u'مرحله', u'اعتبار', u'موجودی')):
        focus.append('Business logic')
    if any(term in name for term in (u'کدملی', u'کدپستی', u'شمارهکارت', u'شبا', u'همراه', u'موبایل', u'تلفن', u'ایمیل', u'نامخانوادگی', u'آدرس')):
        focus.append('PII')
    return focus
