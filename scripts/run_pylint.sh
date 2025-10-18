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
pylint ${PYLINT_ARGS:-} $PY_FILES
