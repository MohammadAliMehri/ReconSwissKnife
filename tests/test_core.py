import json
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon.core import evidence, extraction

FUNCTIONS = {name: getattr(evidence, name) for name in ('cookie_attributes', 'method_result_label', 'is_valid_iranian_national_id')}

class CoreTests(unittest.TestCase):
    def test_retained_baseline(self):
        with open(os.path.join(os.path.dirname(__file__), 'fixtures', 'core_cases.json')) as fixture:
            cases = json.load(fixture)
        for case in cases:
            actual = FUNCTIONS[case['function']](*case['args'])
            if isinstance(actual, set): actual = sorted(actual)
            self.assertEqual(case['expected'], actual)
        self.assertEqual(14, len(cases))

    def test_request_parameters(self):
        rows = extraction.extract_parameters('https://example.test/?user%5Bid%5D=1&blank=&flag',
                'password=x&scope=read', 'application/x-www-form-urlencoded')
        self.assertEqual(set(['user[id]', 'blank', 'flag', 'password', 'scope']), set(r['name'] for r in rows))
        rows = extraction.extract_parameters('https://example.test', '{"user":{"id":1},"active":true}', 'application/json')
        self.assertEqual(set(['user','id','active']), set(r['name'] for r in rows))
        rows = extraction.extract_parameters('https://example.test', 'Content-Disposition: form-data; name="upload"; filename="x"', 'multipart/form-data')
        self.assertEqual('upload', rows[0]['name'])

    def test_response_candidates(self):
        rows = extraction.extract_parameters('https://example.test', response_body='<input name="csrf"><select name="role"></select><script>params.get("page")</script>', response_type='text/html')
        self.assertEqual(set(['csrf','role','page']), set(r['name'] for r in rows))
        self.assertTrue(all('candidate' in r['location'] for r in rows))
        self.assertEqual([], extraction.extract_parameters('https://example.test', response_body='<input name="bad">', response_type='image/png'))

    def test_bounded_and_deduplicated(self):
        rows = extraction.extract_parameters('https://example.test/?q=1&q=2', response_body='<input name="q">'*1000, response_type='text/html')
        self.assertEqual(2, len(rows))
        rows = extraction.extract_parameters('https://example.test/?' + '&'.join('q%d=1'%i for i in range(1000)))
        self.assertEqual(500, len(rows))

    def test_focus_and_xss_context(self):
        self.assertIn('IDOR', extraction.parameter_focus('userId'))
        self.assertIn('Business logic', extraction.parameter_focus('discount'))
        self.assertIn('XSS', extraction.parameter_focus('comment'))
        value = "marker<'\"&>"
        self.assertIn('Unescaped', extraction.reflection_evidence(value, value, 'text/html'))
        self.assertIn('escaping', extraction.reflection_evidence(value, 'marker&lt;', 'text/html'))
        self.assertIn('not XSS', extraction.reflection_evidence(value, value, 'application/json'))
        rows=extraction.extract_parameters('https://example.test/users/123/profile')
        self.assertEqual('Path candidate',rows[0]['location'])

    def test_pii_checksums(self):
        self.assertTrue(evidence.valid_luhn('4111 1111 1111 1111'))
        self.assertFalse(evidence.valid_luhn('4111 1111 1111 1112'))
        self.assertFalse(evidence.valid_luhn('0000000000000000'))
        self.assertTrue(evidence.valid_iranian_iban('IR062960000000100324200001'))
        self.assertFalse(evidence.valid_iranian_iban('IR062960000000100324200002'))

    def test_differential_errors(self):
        self.assertEqual([], extraction.new_error_signatures('SQLSTATE[42000]', 'SQLSTATE[42000]'))
        self.assertEqual('SQL error', extraction.new_error_signatures('OK', 'SQLSTATE[42000]')[0][0])
        self.assertEqual('marker', extraction.reflected_marker('marker', 'echo marker'))
        self.assertIsNone(extraction.reflected_marker('marker', 'no reflection'))

if __name__ == '__main__': unittest.main()
