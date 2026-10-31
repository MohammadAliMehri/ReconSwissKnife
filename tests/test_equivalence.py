# Actual Jython module/artifact parity against pre-extraction fixtures.
import json
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ReconSwissKnife_v3 as bundled
from recon.burp import extension as source
from recon.core.extraction import extract_parameters

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

    def test_regex_extraction_parity(self):
        args = ('https://example.test/?name=x', '{"id":1}', 'application/json')
        self.assertEqual(extract_parameters(*args), bundled.extract_parameters(*args))
        self.assertFalse(hasattr(bundled, 'AI_SYSTEM_PROMPT'))
        self.assertFalse(hasattr(source.ReconUI, 'prepare_ai'))

if __name__ == '__main__': unittest.main()
