"""Diagnostic attribution of one cohort; not unmodified package qualification."""
import json
from pathlib import Path
import sys
import observe
from support import save
original_timed = observe.timed
def traced(smoke, arguments):
    smoke.commands.environment['SE_OBSERVE_PHASES'] = '1'
    try:
        return original_timed(smoke, arguments)
    finally:
        smoke.commands.environment.pop('SE_OBSERVE_PHASES', None)
observe.timed = traced
output = Path(sys.argv[1]).resolve()
image = json.loads((output/'image.json').read_text())
observations = output/'observations'
observations.mkdir()
row = observe.condition(observations, image, 'codex', True, 1)
result = dict(result='OBSERVED' if row['exit']==0 else 'FAIL', exit=row['exit'],
              image=image, cohorts=[row], scope='Diagnostic clocks; one codex/dirty/one-agent cohort; no shipping performance qualification')
save(output/'result.json',result)
print(json.dumps(result),flush=True)
raise SystemExit(row['exit'])
