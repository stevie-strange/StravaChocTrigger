#!/usr/bin/env bash
set -euo pipefail

# Run pylint on all python files tracked by git
# Exits non-zero if pylint finds issues (so pre-commit will fail)
PY_FILES=$(git ls-files '*.py' | tr '\n' ' ')
if [ -z "$PY_FILES" ]; then
  echo "No python files to lint"
  exit 0
fi

# Allow passing extra args via environment variable PYLINT_ARGS

# Prefer calling the pylint binary when available, otherwise fall back to
# running it as a module with the active interpreter.
if command -v pylint >/dev/null 2>&1; then
  pylint ${PYLINT_ARGS:-} $PY_FILES
elif [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ]; then
  "${VIRTUAL_ENV}/bin/python" -m pylint ${PYLINT_ARGS:-} $PY_FILES
elif [ -x "./.venv/bin/python" ]; then
  ./.venv/bin/python -m pylint ${PYLINT_ARGS:-} $PY_FILES
else
  python -m pylint ${PYLINT_ARGS:-} $PY_FILES
fi
