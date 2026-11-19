"""Run the maintained idle check from the probe workflow."""
from pathlib import Path
import runpy
import sys

judges = Path(__file__).resolve().parent.parent / "crates/se/tests/judges"
sys.path.insert(0, str(judges))
runpy.run_path(str(judges / "idle_budget.py"), run_name="__main__")
