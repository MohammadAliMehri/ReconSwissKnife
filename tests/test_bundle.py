"""Build-tool tests require Python 3; the artifact itself requires Jython."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bundle_tool', ROOT / 'tools/bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)

class BundleTests(unittest.TestCase):
    def test_deterministic_and_current(self):
        first = bundle.build()
        self.assertEqual(first, bundle.build())
        self.assertEqual(first.encode('utf-8'), bundle.ARTIFACT.read_bytes())
        self.assertNotIn('from recon.', first)

    def test_import_order_enforced(self):
        with self.assertRaises(ValueError):
            bundle.build(modules=tuple(reversed(bundle.MODULES)))

    def test_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'recon').mkdir()
            (root/'recon/a.py').write_text('value = 1\n')
            (root/'recon/b.py').write_text('from recon.a import value as alias\n')
            with self.assertRaises(ValueError):
                bundle.build(root, ('recon.a', 'recon.b'))

if __name__ == '__main__': unittest.main()
