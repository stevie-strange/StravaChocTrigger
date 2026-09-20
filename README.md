![coverage](https://codecov.io/gh/stevie-strange/StravaChocTrigger/branch/Add_test_suite_ai/graph/badge.svg)

# StravaChocTrigger

Azure function to trigger automatic CHOC calculation for rides (outdoor/virtual) on STRAVA.

## CHO / fat model

`QueueTrigger1/__init__.py` estimates carbohydrate (CHO) and fat oxidation per second of a ride from the Strava power stream. The model is fitted to a spiroergometry test from **August 2026** (8 stages of ~30 s, 125–300 W in 25 W steps; see [issue #26](https://github.com/stevie-strange/StravaChocTrigger/issues/26)):

| Power (W) | 125 | 150 | 175 | 200 | 225 | 250 | 275 | 300 |
|---|---|---|---|---|---|---|---|---|
| CHO (g/h) | 101.2 | 127.3 | 140.9 | 161.6 | 199.2 | 244.9 | 261.2 | 275.5 |
| Fat (g/h) | 18.0 | 16.4 | 17.8 | 17.7 | 9.3 | 0.0 | 0.0 | 0.0 |
| EE (kcal/h) | 595 | 689 | 759 | 845 | 924 | 1029 | 1097 | 1157 |
| RER | 0.92 | 0.93 | 0.94 | 0.94 | 0.97 | 1.03 | 1.05 | 1.12 |

Both fits include a synthetic resting anchor at 0 W (24.48 g/h CHO, 9.92 g/h fat — the intercepts of the previous model) so that coasting seconds keep behaving as before.

- **CHO** — quadratic in power, capped at 100 % CHO of the test's energy expenditure line (`EE ≈ 192 + 3.27·P kcal/h`, divided by 4.184 kcal/g). CHO oxidation rises exponentially with relative intensity in principle (Brooks & Mercier 1994, *J Appl Physiol* 76:2253), but over a graded test it is close to linear and curvilinear models do not fit better (Brun et al. 2026, *Metabolites* 16:121). The quadratic keeps the mild upward curvature; the energy ceiling bounds extrapolation above 300 W and compensates the RER > 1 stages, where indirect calorimetry over-reads CHO.
- **Fat** — third-order polynomial (the conventional form for fat oxidation kinetics; Achten & Jeukendrup, Chenevière et al. 2009, *MSSE* 41:1615), fitted to the anchor and stages 1–6 and clamped at zero above Fatmin (~250 W).

Resulting curve (g/h):

| Power (W) | 0 | 50 | 100 | 150 | 200 | 250 | 300 | 350 | 400 | 500 |
|---|---|---|---|---|---|---|---|---|---|---|
| CHO | 23.2 | 49.8 | 83.4 | 124.0 | 171.6 | 226.1 | 280.4 | 319.4 | 358.5 | 436.7 |
| Fat | 10.0 | 9.2 | 14.1 | 18.4 | 15.8 | 0.1 | 0 | 0 | 0 | 0 |

**Updating after a new test:** edit the stage table in `scripts/fit_metabolic_model.py`, run it, paste the printed arrays into the constants block of `QueueTrigger1/__init__.py`, and update the expected values in `tests/unit/test_cho_model.py`.

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
