# -*- coding: utf-8 -*-
"""Pure cookie parsing, evidence labels and Iranian national-ID validation."""

def cookie_attributes(value):
    return set(part.strip().split('=', 1)[0].lower()
               for part in value.split(';')[1:])


def method_result_label(status):
    if status in (200, 201, 204):
        return "Method accepted - impact unverified"
    return "HTTP %s - no bypass established" % status


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


def valid_luhn(value):
    digits = ''.join(c for c in value if c.isdigit())
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, char in enumerate(reversed(digits)):
        number = int(char)
        if i % 2:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def valid_iranian_iban(value):
    value = value.replace(' ', '').upper()
    if len(value) != 26 or not value.startswith('IR') or not value[2:].isdigit():
        return False
    return int(value[4:] + '1827' + value[2:4]) % 97 == 1
