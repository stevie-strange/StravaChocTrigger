![coverage](https://codecov.io/gh/stevie-strange/StravaChocTrigger/branch/Add_test_suite_ai/graph/badge.svg)

# StravaChocTrigger

Azure function to trigger automatic CHOC calculation for rides (outdoor/virtual) on STRAVA.

## Tests

Lokale Ausführung der Tests:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest
pytest -q
```

Hinweis: Die Unit‑Tests in `tests/` verwenden lokale Shims und Mocks für `azure.*`-Pakete und externe HTTP‑Aufrufe, damit keine echten Azure‑Ressourcen oder Netzwerkanfragen notwendig sind.

## Developer setup (fast local lint/tests — empfohlen)

1. Dev-Abhängigkeiten installieren (einmalig):

```bash
make install-dev
```

2. pre-commit Hook installieren (führt Pylint bei jedem Commit aus):

```bash
make pre-commit-install
# oder
pre-commit install
```

3. Manuelle Checks vor dem Push:

```bash
make lint      # führt pylint über alle tracked .py Dateien aus
pytest -q      # führt die Tests lokal aus
```

Diese Schritte sorgen dafür, dass Lint-Fehler lokal erkannt werden (gleiche Pylint-Version wie CI), bevor ein PR erstellt wird.
