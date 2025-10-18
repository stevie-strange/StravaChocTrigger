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
# StravaChocTrigger
Azure function to trigger automatic CHOC calculation for rides (outdoor/virtual) on STRAVA.
