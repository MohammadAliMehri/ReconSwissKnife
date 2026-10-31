# -*- coding: utf-8 -*-
"""Synthetic Iranian/Persian fixtures; runnable under Python 3 and Jython 2.7."""
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon.core.iranian import scan_iranian, normalize_iranian, decode_web_text
from recon.core.extraction import extract_parameters, parameter_focus
from recon.core.evidence import valid_luhn


def localized(value, digits=u'۰۱۲۳۴۵۶۷۸۹'):
    return u''.join(digits[int(c)] if c in '0123456789' else c for c in value)


def values(body, label):
    return [row['value'] for row in scan_iranian(body) if row['type'] == label]


class IranianTests(unittest.TestCase):
    def test_digit_sets_and_direction_marks(self):
        self.assertEqual('0123456789', normalize_iranian(u'۰۱۲۳۴۵۶۷۸۹'))
        self.assertEqual('0123456789', normalize_iranian(u'٠١٢٣٤٥٦٧٨٩'))
        raw = u'\u200f+۹۸ ۹۱۲ ۱۲۳ ۴۵۶۷\u200e'
        self.assertEqual([raw[1:-1]], values(raw, 'Iranian Mobile'))

    def test_mobile_formats(self):
        for mobile in ('09121234567', '+98 912 123 4567', '0098-912-123-4567'):
            for candidate in (mobile, localized(mobile), localized(mobile, u'٠١٢٣٤٥٦٧٨٩')):
                self.assertEqual([candidate], values(candidate, 'Iranian Mobile'))
        self.assertEqual([], values('1091212345678', 'Iranian Mobile'))

    def test_validated_national_ids(self):
        self.assertEqual([u'۱۲۳۴۵۶۷۸۹۱'], values(u'کد ملی: ۱۲۳۴۵۶۷۸۹۱', 'Iranian National ID'))
        for invalid in (u'۱۲۳۴۵۶۷۸۹۲', u'۱۱۱۱۱۱۱۱۱۱', u'۰۰۰۰۰۰۰۰۰۰'):
            self.assertEqual([], values(invalid, 'Iranian National ID'))

    def test_grouped_shaba(self):
        iban = localized('IR062960000000100324200001')
        candidate = u' '.join(iban[i:i+4] for i in range(0,len(iban),4))
        self.assertEqual([candidate], values(candidate, 'Iranian IBAN'))
        self.assertEqual([], values(candidate[:-1]+u'۲', 'Iranian IBAN'))

    def test_known_bin_card(self):
        base = '603799123456789'
        card = next(base+str(i) for i in range(10) if valid_luhn(base+str(i)))
        candidate = localized('-'.join(card[i:i+4] for i in range(0,16,4)))
        self.assertEqual([candidate], values(candidate, 'Iranian bank card (known BIN, Luhn)'))
        self.assertEqual([], values('4111 1111 1111 1111', 'Iranian bank card (known BIN, Luhn)'))
        wrong = card[:-1] + str((int(card[-1])+1)%10)
        self.assertEqual([], values(wrong, 'Iranian bank card (known BIN, Luhn)'))

    def test_landline(self):
        self.assertEqual([u'۰۲۱-۸۸۷۷-۶۶۵۵'], values(u'تلفن: ۰۲۱-۸۸۷۷-۶۶۵۵', 'Iranian landline (format)'))
        self.assertEqual(['+98 21 8877 6655'], values('+98 21 8877 6655', 'Iranian landline (format)'))
        self.assertEqual([], values('099-8877-6655', 'Iranian landline (format)'))

    def test_postal_requires_context(self):
        code=u'۱۲۳۴۵۶۷۸۹۰'
        self.assertEqual([code], values(u'کد\u200cپستی: '+code, 'Iranian postal code (context)'))
        self.assertEqual([code], values(u'{"کدپستی":"'+code+u'"}', 'Iranian postal code (context)'))
        self.assertEqual([], values(code, 'Iranian postal code (context)'))
        self.assertEqual([], values(u'کد پستی: ۱۱۱۱۱۱۱۱۱۱', 'Iranian postal code (context)'))

    def test_encoded_values_preserve_evidence(self):
        mobile=u'۰۹۱۲۱۲۳۴۵۶۷'
        escaped=u''.join(u'\\u%04x'%ord(c) for c in mobile)
        entities=u''.join(u'&#%d;'%ord(c) for c in mobile)
        hex_entities=u''.join(u'&#x%x;'%ord(c) for c in mobile)
        for raw in (escaped,entities,hex_entities):
            body=u'prefix: '+raw+u'; after'
            rows=[r for r in scan_iranian(body) if r['type']=='Iranian Mobile']
            self.assertEqual(1,len(rows))
            self.assertEqual(raw,rows[0]['value'])
            self.assertEqual(raw,body[rows[0]['start']:rows[0]['end']])
        # Multiple escaped matches test cumulative original-offset correction.
        body=escaped+u' and '+entities
        self.assertEqual([escaped,entities], values(body,'Iranian Mobile'))

    def test_persian_parameter_focus(self):
        self.assertIn('IDOR', parameter_focus(u'شناسه_کاربر'))
        self.assertIn('Business logic', parameter_focus(u'مبلغ_تخفیف'))
        self.assertIn('XSS', parameter_focus(u'متن_پیام'))
        self.assertIn('PII', parameter_focus(u'کد\u200cملی'))
        self.assertIn('PII', parameter_focus(u'كد_ملي'))

    def test_persian_parameter_names(self):
        rows=extract_parameters('https://example.test/?%DA%A9%D8%AF%D9%85%D9%84%DB%8C=1')
        self.assertEqual(u'کدملی',rows[0]['name'])
        rows=extract_parameters('https://example.test',response_body=u'params.get("شناسه_کاربر")',response_type='application/javascript')
        self.assertEqual(u'شناسه_کاربر',rows[0]['name'])

    def test_burp_utf8_and_charset(self):
        text=u'تلفن: ۰۹۱۲۱۲۳۴۵۶۷'
        byte_preserving=text.encode('utf-8').decode('latin-1')
        self.assertEqual(text,decode_web_text(byte_preserving,['Content-Type: text/html; charset=UTF-8']))
        self.assertEqual(text,decode_web_text(text,[]))

    def test_output_bound(self):
        rows=scan_iranian(u' '.join(localized('0912%07d'%i) for i in range(600)))
        self.assertLessEqual(len(rows),500)

if __name__=='__main__': unittest.main()
