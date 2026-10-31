# Pure development modules: runnable in CPython 3 and Jython 2.7 without Burp.
import json
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon.core import evidence, redaction, urls
from recon.ai import protocol, context

FUNCTIONS = {
    'cookie_attributes': evidence.cookie_attributes,
    'method_result_label': evidence.method_result_label,
    'is_valid_iranian_national_id': evidence.is_valid_iranian_national_id,
    'redact_ai_text': redaction.redact_ai_text,
    'ai_endpoint': urls.ai_endpoint,
    'validate_ai_findings': protocol.validate_ai_findings,
}

class CoreTests(unittest.TestCase):
    def test_pre_refactor_baseline(self):
        path = os.path.join(os.path.dirname(__file__), 'fixtures', 'core_cases.json')
        with open(path) as fixture:
            cases = json.load(fixture)
        for case in cases:
            fn = FUNCTIONS[case['function']]
            if 'error' in case:
                self.assertRaises(ValueError, fn, *case['args'])
            else:
                result = fn(*case['args'])
                if isinstance(result, set): result = sorted(result)
                self.assertEqual(case['expected'], result, case['function'])
        self.assertEqual(36, len(cases))

    def test_context_formatting(self):
        actual = context.format_ai_context('GET', 'https://u:p@example.test/a?token=fake#fragment', 200,
                    ['Content-Type: text/plain', 'Set-Cookie: secret=fake'], 'Contact user@example.test')
        self.assertEqual('GET https://example.test/a?token=[REDACTED]\nHTTP status: 200\nContent-Type: text/plain\n\nResponse body (truncated):\nContact [REDACTED_EMAIL]', actual)

    def test_body_limit_and_ipv6(self):
        actual = context.format_ai_context('GET', 'http://[::1]:8080/a', 200, [], 'a'*13000)
        self.assertTrue(actual.startswith('GET http://[::1]:8080/a'))
        self.assertEqual(12000, len(actual.split('Response body (truncated):\n')[1]))

if __name__ == '__main__': unittest.main()
