"""Run harness=false binaries from the archive once, outside nextest's libtest protocol."""
import argparse
import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def custom_targets():
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
    targets = {}
    for member in workspace["workspace"]["members"]:
        manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text())
        for target in manifest.get("test", []):
            if target.get("harness") is False:
                targets[f"{manifest['package']['name']}::{target['name']}"] = ROOT / member
    return targets


def filterset():
    terms = [f"(package(={key.split('::')[0]}) & binary(={key.split('::')[1]}))"
             for key in custom_targets()]
    return "not (" + " or ".join(terms) + ")" if terms else "all()"


def run():
    metadata = json.loads((ROOT / "target/nextest/binaries-metadata.json").read_text())
    # Existing tests bake CARGO_BIN_EXE and CARGO_MANIFEST_DIR into their executables.
    # Checkout/extract in the same runner path; refuse if that invariant changes.
    if Path(metadata["rust-build-meta"]["target-directory"]).resolve() != ROOT / "target":
        raise RuntimeError("archive target path differs; compile-time fixture paths cannot be remapped")
    failures = 0
    for key, cwd in custom_targets().items():
        binary = Path(metadata["rust-binaries"][key]["binary-path"])
        if not binary.is_relative_to(ROOT / "target") or not binary.is_file():
            raise RuntimeError(f"missing or foreign archived custom executable: {key}")
        print(f"Custom harness: {key}", flush=True)
        result = subprocess.run([str(binary)], cwd=cwd, timeout=120)
        print(f"Custom harness: {key}: exit {result.returncode}", flush=True)
        failures += result.returncode != 0
    print(f"Custom harnesses: {len(custom_targets()) - failures} passed, {failures} failed")
    return int(failures != 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["filter", "run"])
    args = parser.parse_args()
    if args.action == "filter":
        print(filterset())
    else:
        raise SystemExit(run())
