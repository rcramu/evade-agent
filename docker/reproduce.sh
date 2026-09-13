#!/bin/sh
# Full laboratory reproduce: tests, campaign, figures.
set -eu
cd /app

pytest -q -o cache_dir=/tmp/pytest-cache

python evaluation/run.py \
  --repeats "${EVADEAGENT_REPEATS:-200}" \
  --seed "${EVADEAGENT_SEED:-20260911}"
python evaluation/make_figures.py
EVADE_DUMP_ROOT=/tmp/evade-dumps python evaluation/run_kernel_pilot.py
