# Development

## Repository layout

```
ReconSwissKnife_v3.py     Generated, standalone Burp installation file
recon/core/              Pure extraction, evidence and Iranian locale rules
recon/burp/extension.py  Burp integration, tasks, store and Swing views
tools/                  Bundler, verification and cache cleanup commands
tests/                  Pure/Jython/Swing/loopback regression tests
tests/fixtures/         Synthetic baseline cases
docs/                   Pattern reference, roadmap and synthetic previews
```

Edit `recon/`, then run `python3 tools/bundle.py`. Commit source edits and the regenerated installation file together. Do not maintain separate logic in the generated file.

## Checks

```sh
python3 tools/bundle.py --check
python3 -m unittest discover -s tests -p test_core.py
python3 -m unittest discover -s tests -p test_iranian.py
python3 -m unittest discover -s tests -p test_bundle.py
python3 tools/verify.py --jython /path/to/jython-standalone-2.7.4.jar --burp-api /path/to/burp-extender-api-2.3.jar
```

Build tooling requires Python 3.8+; runtime source must remain Jython/Python 2.7 compatible. Full verification needs Java, Jython and the legacy Burp API JAR, plus loopback socket permission for disposable HTTP fixtures. It requires no real credentials and does not contact the target applications shown in user screenshots.

Add positive and negative synthetic fixtures for new regexes, including Persian/Arabic digit forms where relevant. Preserve scope checks, original authentication, evidence provenance and the distinction between observations and confirmed vulnerabilities.

## Previews and cleanup

`tests/render_ui.py` renders real Swing components using synthetic data into the system temporary directory. Copy reviewed previews to `docs/images/`; never use captured customer traffic in screenshots or fixtures.

```sh
python3 tools/clean.py          # List ignored cache files only
python3 tools/clean.py --apply  # Delete the listed generated caches
```

The cleaner preserves tracked files, development sources, JARs and local environments. For the remaining architectural work see [the roadmap](docs/refactoring.md).
