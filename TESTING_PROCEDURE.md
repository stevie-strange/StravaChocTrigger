# Test‑Prozedur für GitHub Copilot

Dieses Dokument beschreibt Schritt für Schritt, wie GitHub Copilot automatisiert eine Test‑Suite für das Projekt `StravaChocTrigger` erstellt, konfiguriert und in CI integriert. Die Anleitung ist in Deutsch verfasst und enthält konkrete Dateien, Beispielcode‑Strukturen, Akzeptanzkriterien und Befehle zum Ausführen.

## Ziel
- Automatisch erzeugte und lauffähige pytest‑Tests für die vorhandenen Azure Functions (`QueueTrigger1` und `StevieHttpTrigger`).
- CI (GitHub Actions) zum Installieren der Abhängigkeiten und Ausführen der Tests bei Push/PR.

## Vorbedingungen / Annahmen
- Repository enthält die Azure Functions wie in den Dateien `QueueTrigger1/__init__.py` und `StevieHttpTrigger/__init__.py`.
- `requirements.txt` listet die Produktionsabhängigkeiten. Für Tests wird `pytest` zusätzlich installiert (lokal oder in CI).
- Tests dürfen keine echten Azure‑Ressourcen oder externe HTTP‑Dienste ansprechen — alle externen Abhängigkeiten müssen gemockt werden.

## Akzeptanzkriterien
1. pytest kann lokal und in CI gestartet werden und führt die Tests aus.
2. Tests decken mindestens:
   - Happy Path und ein Fehler-/Edge‑Fall für jede Trigger‑Funktion;
   - Unit‑Tests für die rein funktionalen Helfer (z. B. `calc_cho`, `calculate_fat`).
3. GitHub Actions Workflow existiert unter `.github/workflows/tests.yml` und läuft auf Ubuntu + Python.
4. Tests verwenden Mocking für `azure.functions`, KeyVault, TableClient und externe `requests`-Aufrufe.

## Dateien, die erzeugt werden sollen
- `tests/conftest.py` — Fixtures und Mock‑Hilfen
- `tests/unit/test_stevie_http_trigger.py` — Tests für `StevieHttpTrigger`
- `tests/unit/test_queue_trigger.py` — Tests für `QueueTrigger1`
- `pytest.ini` — pytest Konfiguration
- `.github/workflows/tests.yml` — CI Workflow

## Schritt‑für‑Schritt Anleitung für Copilot (konkret und ausführbar)

1. Erzeuge Ordnerstruktur `tests/unit/` im Projekt.

2. Erstelle `pytest.ini` mit folgendem Minimalinhalt:

```ini
[pytest]
testpaths = tests
python_files = test_*.py
addopts = -q
```

3. Erstelle `tests/conftest.py` mit folgenden Inhalten und Fixtures:
- Fixture `env_vars` (autouse optional) zum Setzen/Zurücksetzen benötigter Umgebungsvariablen (z. B. `StravaVerifyToken`, `StravaKeyVault`).
- Hilfsklassen/Factory‑Funktionen für:
  - `DummyHttpRequest(method='GET'|'POST', params=dict, json_body=dict)` mit `get_json()` Methode und `params` Attribut.
  - `DummyQueueMessage(body: str)` mit `get_body()`.
  - `dummy_out()` — ein Mock‑Objekt mit `.set()` Methode (z. B. `unittest.mock.Mock()`).

4. Erstelle `tests/unit/test_stevie_http_trigger.py` mit Tests:
- Test GET webhook verification:
  - Setze `os.environ['StravaVerifyToken']` auf bekannten Wert.
  - Erzeuge `DummyHttpRequest(method='GET', params={'hub.mode':'subscribe', 'hub.verify_token': <value>, 'hub.challenge':'abc'})`.
  - Rufe `StevieHttpTrigger.main(req, dummy_out)` auf.
  - Prüfe, dass die Response status_code 200 ist und die JSON‑Antwort das Challenge‑Token enthält.

- Test POST happy path:
  - Patch `StevieHttpTrigger.init_key_vault` (oder `azure.keyvault.secrets.SecretClient`) so, dass `.get_secret('StravaConString').value` ein Dummy‑Connection‑String zurückgibt.
  - Patch `azure.data.tables.TableClient.from_connection_string` so, dass es ein Objekt mit `create_entity` Methode zurückgibt.
  - Simuliere `req.method='POST'` und `req.get_json()` liefert `{ 'aspect_type':'create', 'object_type':'activity', 'object_id': 12345 }`.
  - Übergib `msg = Mock()` (mit `msg.set` beobachtbar).
  - Rufe `StevieHttpTrigger.main(req, msg)` und assertiere `msg.set.assert_called_with('12345')` und dass die Funktion `HttpResponse` mit 200 zurückgibt.

- Test POST ResourceExistsError:
  - Lasse `create_entity` eine `azure.core.exceptions.ResourceExistsError` werfen.
  - Funktion sollte `HttpResponse` mit status 200 zurückgeben.

5. Erstelle `tests/unit/test_queue_trigger.py` mit Tests:
- Unit tests für `calc_cho` und `calculate_fat`:
  - Beispieldaten: `power = [100, 200, None, 50]` etc.
  - Prüfe numerische Ausgaben mit `pytest.approx()`.

- Test `main(msg)` happy path:
  - Patch `QueueTrigger1.get_access_token` um einen Dummy‑Token zurückzugeben.
  - Patch `requests.get` so, dass die erste Aufrufantwort (Activity metadata) `{'type':'Ride','elapsed_time':3600}` liefert und der zweite Aufruf (streams) liefert `'watts': {'data': [100, 200, None, 0]}`.
  - Patch `requests.put` und beobachte Aufrufe — prüfe, dass der PUT Request Body Strings enthält wie 'Total carbohydrates burned'.

- Test Nicht‑Ride activity:
  - Activity type != 'Ride' -> Funktion soll nichts updaten (PUT nicht aufgerufen).

6. Erzeuge `.github/workflows/tests.yml` mit folgendem Aufbau:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest
      - name: Run tests
        run: |
          pytest -q
```

7. README Ergänzung (kleiner Abschnitt `Tests`):

```markdown
## Tests

Lokale Ausführung:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest
pytest -q
```

Hinweis: Tests verwenden Mocks für externe Services (KeyVault, Table Storage, Strava API). Falls `azure.*` Module in der Testumgebung fehlen, sorgt `tests/conftest.py` für einfache Shims oder installiere die Pakete lokal.
```

## Taktische Hinweise für Copilot
- Generiere zuerst `conftest.py` und die Dummy‑Objekte, da Tests stark davon abhängen.
- Verwende `unittest.mock.patch` und `Mock()` breitflächig, statt echte SDK‑Instanzen zu konstruieren.
- Schreibe erst einfache, deterministische Tests (happy path), dann füge Edge‑Cases hinzu.

## Was nach Erstellung geprüft werden soll (Quality Gates)
1. Build / Lint: Nicht zwingend, aber pytest sollte importieren ohne ImportError.
2. Tests: `pytest -q` sollte mindestens die neuen Testdateien ausführen.
3. CI: GitHub Actions Workflow sollte die Tests beim nächsten Push ausführen.

## Beispiel Snippets für Copilot (zum Einfügen in Tests)

1) Dummy QueueMessage:

```python
class DummyQueueMessage:
    def __init__(self, body: str):
        self._body = body.encode('utf-8')
    def get_body(self):
        return self._body
```

2) Simple HttpRequest Shim:

```python
class DummyHttpRequest:
    def __init__(self, method='GET', params=None, json_body=None):
        self.method = method
        self.params = params or {}
        self._json = json_body
    def get_json(self):
        return self._json
```

3) Patch requests example:

```python
from unittest.mock import patch, Mock

mock_resp = Mock()
mock_resp.status_code = 200
mock_resp.json.return_value = {'type': 'Ride', 'elapsed_time': 3600}

with patch('requests.get', return_value=mock_resp):
    # call function
    pass
```

## Zusammenfassung
Dieses Dokument liefert eine vollständige, deutschsprachige Prozedur, die GitHub Copilot verwenden kann, um eine Test‑Suite (pytest) für das Projekt `StravaChocTrigger` zu erzeugen, inklusive Mocks, CI‑Workflow und README‑Hinweisen. Wenn du möchtest, kann ich die beschriebenen Dateien jetzt direkt im Repo erzeugen und die Tests lokal ausführen. Sage mir kurz, ob ich fortfahren soll.
