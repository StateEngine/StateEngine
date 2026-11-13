"""Validate native smoke inputs without converting missing prerequisites to passes."""
import os
from pathlib import Path
import re
import shutil
import sys
import tomllib

from .io import digest, require

DRIVERS = {'acp-stdio': 'acp', 'claude-stream-json': 'claude', 'codex-app-server': 'codex',
           'secode-native': 'secode'}
RESULTS = ('PASS', 'FAIL', 'ABSENT', 'SKIPPED', 'UNREADABLE', 'NOT RUN')


class Unavailable(RuntimeError):
    def __init__(self, state, reason):
        super().__init__(reason)
        self.state = state


def name(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value)


def environment_names(values):
    require(isinstance(values, list) and len(values) <= 128, 'Environment names must be a bounded list')
    for value in values:
        require(isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', value),
                'Invalid environment variable name')
        require(value.upper() != 'SE_SESSION' and not value.upper().startswith(('STATEENGINE_', 'SECODE_')),
                'Environment name carries runtime or machine authority')


def plain_file(value, label):
    path = Path(value)
    require(path.is_absolute() and not path.is_symlink(), label + ' must be an absolute plain file')
    if not path.exists():
        raise Unavailable('ABSENT', label + ' is absent')
    require(path.is_file(), label + ' is not a file')
    return path


def preflight(entry):
    if entry.get('skip'):
        require(isinstance(entry['skip'], str), 'A skip requires a reason')
        raise Unavailable('SKIPPED', entry['skip'])
    if entry.get('driver') not in DRIVERS:
        raise Unavailable('SKIPPED', 'Selected adapter driver has no smoke implementation')
    settings = entry.get('platforms', {}).get(sys.platform)
    if settings is None:
        raise Unavailable('ABSENT', 'No native inputs for this platform')
    require(isinstance(settings, dict), 'Native settings must be an object')
    if settings.get('absent'):
        require(isinstance(settings['absent'], str), 'Absent native inputs require a reason')
        raise Unavailable('ABSENT', settings['absent'])
    settings = {**settings, 'provider': DRIVERS[entry['driver']]}
    seconds = settings.get('task_seconds', 240)
    require(type(seconds) is int and 1 <= seconds <= 1800, 'Task deadline must be 1..1800 seconds')
    names, required, homes = (settings.get(key, default) for key, default in
                              [('environment', []), ('required_environment', []), ('home_environment', {})])
    environment_names(names)
    environment_names(required)
    require(isinstance(homes, dict), 'Native private home bindings must be an object')
    environment_names(list(homes))
    require(all(isinstance(value, str) and not Path(value).is_absolute()
                and '..' not in Path(value).parts for value in homes.values()),
            'Native home bindings must remain inside the private fixture')
    require(set(required).issubset(names), 'Required credentials must be explicitly inherited by name')
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise Unavailable('ABSENT', 'Missing required native environment: ' + ', '.join(missing))
    configuration = settings.get('configuration', {})
    path = plain_file(configuration.get('path', ''), 'Selected configuration')
    require(path.stat().st_size <= 1024 * 1024, 'Selected configuration exceeds one MiB')
    require(digest(path) == configuration.get('sha256'), 'Selected configuration digest differs')
    value = tomllib.loads(path.read_text(encoding='utf-8'))
    provider = settings['provider']
    selected = value.get('providers', {}).get(provider, {})
    if provider == 'acp':
        require(name(settings.get('harness')), 'Saved harness name is invalid')
        descriptor = value.get('harnesses', {}).get(settings['harness'])
        require(isinstance(descriptor, dict) and descriptor.get('driver') == entry['driver'],
                'Selected descriptor does not use the expected adapter driver')
    else:
        descriptor = selected
    expected = settings.get('permission_profile')
    require(isinstance(expected, dict) and set(expected) == {'name', 'sandbox', 'approval', 'network', 'bypass'},
            'An explicit native launch permission profile is required')
    profile = value.get('profiles', {}).get(expected['name'], {})
    require({key: profile.get(key) for key in ('sandbox', 'approval', 'network', 'bypass')}
            == {key: expected[key] for key in ('sandbox', 'approval', 'network', 'bypass')},
            'Declared permission choice differs from the selected configuration')
    require(selected.get('profile') == expected['name'], 'Selected native launch profile differs')
    if provider == 'acp':
        require(expected['name'] in descriptor.get('permissions', {}),
                'Descriptor has no native permission mapping')
    seed_files = None
    if provider == 'secode':
        seed = settings.get('seed_profile', {})
        root = Path(seed.get('path', ''))
        require(root.is_absolute() and not root.is_symlink() and root.is_dir()
                and str(root) == selected.get('seed_profile'), 'Selected private seed profile differs')
        seed_files = seed.get('files')
        require(isinstance(seed_files, dict)
                and set(seed_files) == {'secode.jsonc', 'provider.credential', 'account-models.json'},
                'Exact private seed file identities are required')
        for name, expected_digest in seed_files.items():
            path = plain_file(str(root / name), 'Private seed input')
            require(path.stat().st_size <= 16 * 1024**2 and digest(path) == expected_digest,
                    'Private seed input digest or size differs')
    images = settings.get('images')
    require(isinstance(images, list) and 1 <= len(images) <= 16, 'Exact native image identities are required')
    pinned = {}
    for image in images:
        image_path = plain_file(image['path'], 'Required native image')
        actual = digest(image_path)
        require(actual == image['sha256'], 'Required native image digest differs')
        pinned[str(image_path.resolve())] = actual
    executable = descriptor.get('command', provider if provider != 'acp' else '')
    resolved = executable if Path(executable).is_absolute() else shutil.which(executable)
    if not resolved:
        raise Unavailable('ABSENT', 'Selected native command is absent')
    require(str(Path(resolved).resolve()) in pinned, 'Selected command is not a pinned native image')
    version = settings.get('version_command')
    require(isinstance(version, list) and 1 <= len(version) <= 32
            and all(isinstance(arg, str) and '\0' not in arg for arg in version), 'Invalid version command')
    require(str(Path(version[0]).resolve()) in pinned and isinstance(settings.get('version_stdout'), str),
            'Native version probe is not bound to the selected image')
    if sys.platform == 'win32' and not settings.get('terminal_prefix'):
        raise Unavailable('ABSENT', 'Native Windows terminal driver is absent')
    return settings, dict(configuration_sha256=configuration['sha256'], images=pinned,
                          seed_files_sha256=seed_files,
                          environment={key: 'present-unverified' if os.environ.get(key) else 'absent'
                                       for key in names})
