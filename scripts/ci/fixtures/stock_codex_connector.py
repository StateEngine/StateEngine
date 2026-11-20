"""An independent stdio MCP connector that occupies a managed-name candidate."""

import json
import sys


for line in sys.stdin:
    request = json.loads(line)
    if "id" not in request:
        continue
    reply = {"jsonrpc": "2.0", "id": request["id"]}
    method = request["method"]
    if method == "initialize":
        reply["result"] = {"protocolVersion": request["params"]["protocolVersion"],
                           "capabilities": {"tools": {}},
                           "serverInfo": {"name": "fixture-connector", "version": "1"}}
    elif method == "tools/list":
        reply["result"] = {"tools": [{"name": "fixture_status", "description": "Read fixture status",
                                      "inputSchema": {"type": "object"}}]}
    elif method == "tools/call" and request["params"]["name"] == "fixture_status":
        reply["result"] = {"content": [{"type": "text", "text": "fixture available"}]}
    else:
        reply["error"] = {"code": -32601, "message": "Unknown fixture method"}
    print(json.dumps(reply), flush=True)
