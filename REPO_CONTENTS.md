# Repository contents: StravaChocTrigger

This repository contains an Azure Functions (Python) app that reacts to Strava webhook events, enqueues activity IDs, and then processes those activities to calculate carbohydrate (CHO) and fat burn and update the activity description on Strava.

## Top-level files

- `host.json`
  - Azure Functions host configuration (queue extension tuning, AppInsights sampling, extension bundle).
- `requirements.txt`
  - Runtime dependencies for the Functions app (Azure Functions SDK + KeyVault/Identity/Table + NumPy), pinned to exact versions and kept current by Dependabot.
- `.python-version`
  - Python version (`3.12`) used by every GitHub workflow via `actions/setup-python`. 3.12 is the last version supported on the Linux Consumption plan.
- `requirements-dev.txt`
  - Developer dependencies (pylint, pre-commit, pytest, pytest-cov).
- `pytest.ini`
  - Pytest configuration (tests live under `tests/`, quiet output).
- `Makefile`
  - Convenience targets:
    - `make install-dev`
    - `make lint`
    - `make pre-commit-install`
- `LICENSE`
  - Project license.
- `README.md`
  - High-level description and local dev commands.
- `TESTING_PROCEDURE.md`
  - Detailed (German) procedure describing how the test suite/CI was set up.

## Function apps

Azure Functions are organized as folders where each folder is one function.

### `StevieHttpTrigger/`

HTTP-triggered function that receives Strava webhook calls.

- `StevieHttpTrigger/__init__.py`
  - Main handler.
  - GET: Strava webhook verification (`hub.mode`, `hub.verify_token`, `hub.challenge`).
  - POST: on new activity creation, writes a row to Azure Table Storage and enqueues the activity ID.
- `StevieHttpTrigger/function.json`
  - Bindings:
    - HTTP trigger (anonymous, GET/POST)
    - Queue output binding to queue `processing` via `MyStorageConnectionAppSetting`
    - HTTP response output

### `QueueTrigger1/`

Queue-triggered function that processes the activity ID from the queue and updates Strava.

- `QueueTrigger1/__init__.py`
  - Main handler.
  - Reads Strava tokens from Azure Key Vault (and refreshes them when expired).
  - Pulls Strava activity metadata and power stream (`watts`).
  - Computes CHO and fat consumption and updates the activity description via the Strava API.
- `QueueTrigger1/function.json`
  - Binding: queueTrigger on queue `processing` via `MyStorageConnectionAppSetting`.
- `QueueTrigger1/readme.md`
  - Placeholder/template documentation (currently contains a TODO).

## Tests

- `tests/`
  - `conftest.py`: test fixtures and local shims/mocks for Azure SDK modules.
  - `unit/`: unit tests for triggers and helper behavior.

Run tests:

```bash
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -m pip install -r requirements-dev.txt
./.venv/bin/python -m pytest -q
```

## Scripts and tooling

- `scripts/run_pylint.sh`
  - Runs pylint over all tracked Python files.
- `.github/workflows/`
  - `tests.yml` (pytest + pre-commit), `pylint.yml`, `codeql-analysis.yml`, and `main_steviehttptrigger.yml` (build + deploy to Azure). All read the Python version from `.python-version`.
- `.github/dependabot.yml`
  - Weekly grouped update PRs for GitHub Actions and pip dependencies.

Run lint:

```bash
make install-dev
make lint
```

## Configuration (environment variables / secrets)

The functions rely on environment variables and secrets stored in Azure Key Vault.

Common inputs referenced by the code include:

- `StravaKeyVault` (env var)
  - Name of the Key Vault used to fetch secrets.
- `StravaVerifyToken` (env var)
  - Verification token used for Strava webhook validation.
- `StravaClientID` / `StravaClientSecret` (env vars)
  - Used when refreshing Strava OAuth tokens.
- Key Vault secrets used by the code:
  - `StravaAccessToken`, `StravaRefreshToken`, `StravaTokenExpires`
  - `StravaConString` (Azure Storage connection string for Table Storage usage)
- `MyStorageConnectionAppSetting`
  - Azure Functions app setting name used by queue bindings.

## Running locally (Azure Functions)

If you have Azure Functions Core Tools installed:

```bash
# from repo root
func host start
```

(You’ll also need the appropriate local settings / environment variables for the bindings and Key Vault access.)
