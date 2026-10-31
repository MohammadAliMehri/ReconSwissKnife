#!/usr/bin/env python3
"""Verify modular sources, the generated bundle and isolated Burp installation."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, label, cwd=ROOT, env=None):
    print('\n' + label, flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jython', required=True, type=Path, help='Jython standalone 2.7.4 JAR')
    parser.add_argument('--burp-api', required=True, type=Path, help='Burp Extender API 2.3 JAR')
    parser.add_argument('--java', default='java')
    args = parser.parse_args()
    jython, burp = args.jython.resolve(), args.burp_api.resolve()
    for jar in (jython, burp):
        if not jar.is_file(): parser.error('Missing JAR: ' + str(jar))
    run([sys.executable, 'tools/bundle.py', '--check'], 'Check generated artifact')
    for name in ('test_core.py', 'test_bundle.py'):
        run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', name], 'Python 3: ' + name)
    with tempfile.TemporaryDirectory(prefix='recon-verify-') as temp:
        cache = Path(temp) / 'cache'
        java = [args.java, '-Djava.awt.headless=true', '-Dpython.cachedir=' + str(cache)]
        core = java + ['-cp', str(jython), 'org.python.util.jython', '-B']
        runtime = java + ['-cp', os.pathsep.join((str(jython), str(burp))), 'org.python.util.jython', '-B']
        env = os.environ.copy()
        env.pop('RECON_TEST_TARGET', None)
        run(core + ['tests/test_core.py'], 'Jython pure modules without Burp API', env=env)
        run(runtime + ['tests/test_equivalence.py'], 'Jython source/artifact equivalence', env=env)
        run(runtime + ['tests/test_extension.py'], 'Jython bundled extension regressions', env=env)
        env['RECON_TEST_TARGET'] = 'source'
        run(runtime + ['tests/test_extension.py'], 'Jython modular entry point regressions', env=env)
        standalone = Path(temp) / 'standalone'
        standalone.mkdir()
        shutil.copyfile(ROOT/'ReconSwissKnife_v3.py', standalone/'ReconSwissKnife_v3.py')
        script = '''
import os
import ReconSwissKnife_v3 as r
from javax.swing import SwingUtilities
assert not os.path.exists('recon')
try:
    import recon
except ImportError:
    pass
else:
    raise AssertionError('Development sources unexpectedly available')
assert r.method_result_label(200) == 'Method accepted - impact unverified'
class Ext(object): pass
ext = Ext(); ext.store = r.DataStore(); ext.scope = r.ScopeFilter()
ui = []
SwingUtilities.invokeAndWait(r._UiCall(lambda: ui.append(r.ReconUI(ext))))
assert ui[0].workspace_tabs.getTabCount() == 2
assert ui[0].tabs.getTabCount() == 7
print('Standalone artifact imports and builds Swing UI without the source package.')
'''
        env.pop('RECON_TEST_TARGET', None)
        env.pop('JYTHONPATH', None)
        env.pop('PYTHONPATH', None)
        run(runtime + ['-c', script], 'Isolated single-file installation smoke test', cwd=standalone, env=env)
    print('\nAll verification stages passed.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
