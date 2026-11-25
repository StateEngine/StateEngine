"""Test drivers must use the provider-home boundary before launching setup."""
import ast
from pathlib import Path
import re
import shlex
import unittest

ROOT = Path(__file__).resolve().parents[2]
SETUP = re.compile(r"""["'](?:init|--adopt)["']|["']mcp["']\s*,\s*["']add["']""")
EXEC = r"\.(?:output|spawn|status)(?:_executable)?\s*\("
RUST_FUNCTION = re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+\s*\(")
RUST_COMMAND = re.compile(r"(?:std::process::)?Command\s*::\s*new\s*\(")


def rust_bypasses(source):
    for body in RUST_FUNCTION.split(source):
        argv = re.findall(r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*\[([^;]+)\];", body)
        guarded_words = [re.escape(name) for name, words in argv if SETUP.search(words)]
        aliases = re.compile(r"\.args\s*\(\s*(?:" + "|".join(guarded_words) + r")\s*\)") if guarded_words else None

        def uses_setup(text):
            return SETUP.search(text) or (aliases and aliases.search(text))

        for command in RUST_COMMAND.finditer(body):
            start = command.start()
            if re.match(r"""\s*["']git(?:\.exe)?["']\s*\)""", body[command.end():]):
                continue
            statement = body[start:].partition(";")[0]
            if uses_setup(statement) and re.search(EXEC, statement):
                yield statement.splitlines()[0]
                continue
            binding = re.search(r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*$", body[:start])
            if binding is None:
                continue
            name = re.escape(binding[1])
            tail = body[start + len(statement):]
            split = re.split(rf"\blet\s+(?:mut\s+)?{name}\b", tail, maxsplit=1)[0]
            # Builder mutation and launch may be separate statements, but the
            # check must apply to the same named command before it can run.
            sites = [(part.start(), part[0]) for part in re.finditer(
                rf"\b{name}\s*\.(?:arg|args)\s*\([^;]*", split) if uses_setup(part[0])]
            if uses_setup(statement):
                sites.insert(0, (0, statement))
            for offset, part in sites:
                launch = re.search(EXEC, part) or re.search(rf"\b{name}\s*{EXEC}", split[offset:])
                if launch is None:
                    continue
                before = split[:offset + launch.start()]
                checks = list(re.finditer(
                    rf"\bprovider_home::(?:for_state|isolate|isolate_at)\(\s*&mut\s+{name}\b", before))
                later = before[checks[-1].end():] if checks else ""
                if not checks or re.search(rf"\b{name}\s*\.env_clear\s*\(", later):
                    yield part.splitlines()[0]
                break


def python_bypasses(source):
    for call in ast.walk(ast.parse(source)):
        if not isinstance(call, ast.Call):
            continue
        function = ast.unparse(call.func)
        if function not in {"subprocess.run", "subprocess.call", "subprocess.Popen",
                            "subprocess.check_call", "subprocess.check_output",
                            "asyncio.create_subprocess_exec"}:
            continue
        if function == "asyncio.create_subprocess_exec":
            argv = call.args
        elif call.args:
            argv = call.args[0]
        else:
            argv = next((keyword.value for keyword in call.keywords if keyword.arg == "args"), None)
            if argv is None:
                continue
        if isinstance(argv, ast.Constant) and isinstance(argv.value, str):
            try:
                words = shlex.split(argv.value)
            except ValueError:
                continue
            if words and Path(words[0]).name not in {"git", "git.exe"} and (
                "init" in words[1:] or "mcp add" in " ".join(words[1:])
            ):
                yield f"line {call.lineno}"
            continue
        if isinstance(argv, (tuple, list, ast.Tuple, ast.List)):
            values = argv if isinstance(argv, (tuple, list)) else argv.elts
            if not values:
                continue
            if isinstance(values[0], ast.Constant) and values[0].value in {"git", "git.exe"}:
                continue
            argv = "[" + ", ".join(map(ast.unparse, values)) + "]"
        else:
            argv = ast.unparse(argv)
        if SETUP.search(argv):
            yield f"line {call.lineno}"


def powershell_bypasses(source):
    for lineno, line in enumerate(source.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        direct = r"^\s*(?:\$[\w:]+\s*=\s*)?(?:se|codex|claude)(?:\.exe)?\s+"
        if re.search(r"(?i)\b(?:Start-Process|Invoke-Expression)\b|&\s*[^({\s]+", line) or re.match(direct, line, re.I):
            if re.search(r"(?i)\b(?:init|--adopt)\b|\bmcp\s+add\b", line):
                if not re.search(r"(?i)\bgit(?:\.exe)?\s+init\b", line):
                    yield f"line {lineno}"


class GuardedInitTests(unittest.TestCase):
    def test_detects_direct_spawns_even_with_an_unrelated_guard(self):
        found = list(rust_bypasses('''
fn init() {
    provider_home::isolate(&mut other, root);
    Command::new(image).args(["--home", "fixture", "init"]).output()?;
}
fn named() {
    let mut command = Command::new(image);
    command.args(["init", "--repo", "example"]);
    command.status()?;
}
fn detached() {
    let args = ["--json", "init"];
    Command::new(image).args(args).output()?;
}
fn builder() {
    let command = Command::new(image).arg("init");
    command.output()?;
}
fn guarded() {
    let mut command = Command::new(image);
    command.arg("init");
    provider_home::isolate(&mut command, root);
    command.output()?;
}
fn git() {
    Command::new("git").arg("init").output()?;
}
'''))
        self.assertEqual(len(found), 4, found)
        self.assertEqual(list(python_bypasses("""
subprocess.run([image, "--json", "init"])
subprocess.Popen([codex, "mcp", "add", "test"])
subprocess.run(["git", "init"])
subprocess.run(args=[image, "init"])
run_provider_command(subprocess.run, [image, "init"], env, root)
""")), ["line 2", "line 3", "line 5"])
        self.assertEqual(list(powershell_bypasses("""
& $script:Binary --home $root init
Start-Process $binary -ArgumentList @('init')
$initialized = se.exe --home $root init
Invoke-ProviderFixture -Words @('init')
""")), ["line 2", "line 3", "line 4"])

    def test_repository_has_no_direct_unchecked_init_spawn(self):
        candidates = [*ROOT.glob("crates/*/tests"), ROOT / "scripts/ci",
                      ROOT / "scripts/harness_matrix", ROOT / "scripts/windows_journeys",
                      ROOT / "journeys"]
        scanners = {".rs": rust_bypasses, ".py": python_bypasses, ".ps1": powershell_bypasses}
        failures = []
        for directory in candidates:
            for path in directory.rglob("*"):
                if path.suffix in scanners:
                    source = path.read_text(encoding="utf-8-sig")
                    if "init" not in source and "mcp" not in source and "--adopt" not in source:
                        continue
                    for failure in scanners[path.suffix](source):
                        failures.append(f"{path.relative_to(ROOT)} {failure}")
        self.assertEqual(failures, [], "Use the guarded provider command before init or registration")
