"""Keep all provider configuration under the directory owned by a test."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))
from harness_matrix.io import prepare_provider_home
from harness_matrix.io import verify_provider_home as verify

KEYS = ("HOME", "USERPROFILE", "CODEX_HOME", "CLAUDE_CONFIG_DIR")


def isolate(environment, fixture, home, *, codex=None, claude=None):
    home = Path(home)
    environment.update(HOME=str(home), USERPROFILE=str(home),
                       CODEX_HOME=str(codex or home / ".codex"),
                       CLAUDE_CONFIG_DIR=str(claude or home / ".claude"))
    prepare_provider_home(environment, fixture)
