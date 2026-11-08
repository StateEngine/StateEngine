"""Native settings probe plus the retained-stream capture fixture."""
import json
import sys

import soak_capture_provider


if __name__ == '__main__':
    if '--safe-mode' in sys.argv:
        request = json.loads(sys.stdin.readline())
        assert request['request']['subtype'] == 'get_settings'
        print(json.dumps({'type': 'control_response', 'response': {
            'request_id': request['request_id'], 'subtype': 'success',
            'response': {'effective': {}, 'sources': [], 'errors': []}}}), flush=True)
    else:
        soak_capture_provider.main()
