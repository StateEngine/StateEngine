"""Obtain scheduler GitHub authority without persisting it."""
import os
from pathlib import Path
import subprocess


def environment(settings):
    command = settings.get('github_token_command')
    if (not isinstance(command, list) or not command or len(command) > 16
            or any(not isinstance(value, str) or not value or '\0' in value for value in command)
            or not Path(command[0]).is_absolute()):
        raise ValueError('an absolute GitHub App token command is required')
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('GitHub App token command failed') from error
    try:
        token = result.stdout.decode('utf-8').strip()
    except UnicodeDecodeError as error:
        raise ValueError('GitHub App token command returned unreadable output') from error
    if not token or len(token) > 16384 or any(char in token for char in '\r\n\0'):
        raise ValueError('GitHub App token command returned an invalid value')
    env = {key: value for key, value in os.environ.items() if key not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    env['GH_TOKEN'] = token
    return env
