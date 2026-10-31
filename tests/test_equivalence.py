# Actual Jython module/artifact parity against pre-extraction fixtures.
import json
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ReconSwissKnife_v3 as bundled
from recon.burp import extension as source
from recon.ai.context import format_ai_context

class EquivalenceTests(unittest.TestCase):
    def test_baseline_on_both_entrypoints(self):
        with open(os.path.join(os.path.dirname(__file__), 'fixtures', 'core_cases.json')) as fixture:
            cases = json.load(fixture)
        for module in (source, bundled):
            for case in cases:
                fn = getattr(module, case['function'])
                if 'error' in case:
                    self.assertRaises(ValueError, fn, *case['args'])
                else:
                    actual = fn(*case['args'])
                    if isinstance(actual, set): actual = sorted(actual)
                    self.assertEqual(case['expected'], actual)
        self.assertEqual(source.VERSION, bundled.VERSION)

    def test_context_parity(self):
        args = ('GET', 'https://example.test/a?key=fake', 200, ['Content-Type: text/plain'], 'password=fake')
        self.assertEqual(format_ai_context(*args), bundled.format_ai_context(*args))
        self.assertEqual(source.AI_SYSTEM_PROMPT, bundled.AI_SYSTEM_PROMPT)

if __name__ == '__main__': unittest.main()
