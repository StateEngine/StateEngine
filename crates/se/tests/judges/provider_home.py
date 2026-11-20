"""Keep all provider configuration under the directory owned by a test."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))
from harness_matrix.io import (
    PROVIDER_HOME_FILES, prepare_provider_home, provider_home_environment, run_provider_command,
)
from harness_matrix.io import verify_provider_home as verify

KEYS = tuple(PROVIDER_HOME_FILES)


def isolate(environment, fixture, home, *, codex=None, claude=None):
    environment.update(provider_home_environment(home, codex=codex, claude=claude))
    prepare_provider_home(environment, fixture)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("words", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    words = args.words[1:] if args.words[:1] == ["--"] else args.words
    if not words:
        parser.error("a candidate executable is required")
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith(("CODEX_", "CLAUDE", "ANTHROPIC_", "OPENAI_"))}
    isolate(environment, args.fixture, args.home)
    return run_provider_command(subprocess.call, words, environment, args.fixture)


if __name__ == "__main__":
    sys.exit(main())
