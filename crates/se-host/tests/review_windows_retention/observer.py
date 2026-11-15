"""Hold a native Windows process birth across the public worker cancellation."""
import json
from pathlib import Path
import sys
from windows_process import Process

pid, image = int(sys.argv[1]), Path(sys.argv[2])
process = Process(pid, image, '--stateengine-private-atlas-cold')
try:
    print(json.dumps({'ready': process.initial}), flush=True)
    assert sys.stdin.readline().strip() == 'check'
    assert process.exited(), 'Cancellation returned before the retained native process exited'
    print(json.dumps({'pid': pid, 'creation_filetime': process.initial['creation_filetime'],
                      'native_handle_signalled': True}), flush=True)
finally:
    process.close()
