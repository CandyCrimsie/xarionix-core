"""Fixed local bridge. Body bytes use hijacked stdin, never exec Cmd/env or disk."""

import json
import re
import socket
import struct
import time
from pathlib import Path
from typing import Any

# This source is constant: no interpolation, shell, user URL or filesystem path.
# Alarm also bounds a disconnected client that never finishes its stdin frame.
BRIDGE = r"""import sys,os,json,struct,signal,http.client,re,datetime
signal.signal(signal.SIGALRM, lambda *a: sys.exit(1))
signal.alarm(16)
try:
 h=sys.stdin.buffer.read(4)
 assert len(h)==4
 n=struct.unpack('!I',h)[0]
 assert 1<=n<=72000
 raw=sys.stdin.buffer.read(n)
 assert len(raw)==n
 frame=json.loads(raw)
 ctx=frame['context']
 op=ctx['operation_id']
 assert re.fullmatch('[a-z][a-z0-9-]{0,62}',op)
 seconds=(datetime.datetime.fromisoformat(ctx['deadline'].replace('Z','+00:00'))-datetime.datetime.now(datetime.timezone.utc)).total_seconds()
 assert 0<seconds<=15
 body=json.dumps({'context':ctx,'body':frame['body']},ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
 c=http.client.HTTPConnection('127.0.0.1',8080,timeout=max(.1,seconds))
 c.request('POST','/_xarionix/api/v1/'+op,body,{'Content-Type':'application/json'})
 r=c.getresponse()
 assert r.status==200 and r.getheader('Content-Type','').split(';')[0]=='application/json'
 limit=min(1048576,frame['response_max_bytes'])
 out=r.read(limit+1)
 assert len(out)<=limit
 value=json.loads(out)
 assert isinstance(value,dict)
 print(json.dumps({'body':value},ensure_ascii=False,separators=(',',':'),allow_nan=False),flush=True)
 c.close()
except Exception:
 print('{"error":"module_response_invalid"}',flush=True)
"""


def exchange(path: Path, exec_id: str, frame: bytes, timeout: float, maximum: int) -> dict[str, Any]:
    """Engine API hijack (not a generic tunnel). Exact fixed exec ID, one bounded frame."""
    if not re.fullmatch(r"[0-9a-f]{64}", exec_id) or len(frame) > 72000:
        raise ValueError("ipc_binding_invalid")
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:

        def receive(count: int) -> bytes:
            output = bytearray()
            while len(output) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("ipc_deadline")
                connection.settimeout(remaining)
                data = connection.recv(count - len(output))
                if not data:
                    if output:
                        raise ValueError("ipc_truncated")
                    return b""
                output.extend(data)
            return bytes(output)

        connection.settimeout(timeout)
        connection.connect(str(path))
        start = b'{"Detach":false,"Tty":false}'
        connection.sendall(
            (
                f"POST /v1.52/exec/{exec_id}/start HTTP/1.1\r\nHost: deployment-engine\r\n"
                f"Connection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: {len(start)}\r\n\r\n"
            ).encode()
            + start
        )
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            byte = receive(1)
            if not byte or len(header) >= 8192:
                raise ValueError("ipc_upgrade_invalid")
            header.extend(byte)
        if bytes(header).split(b"\r\n", 1)[0] != b"HTTP/1.1 101 UPGRADED":
            raise ValueError("ipc_upgrade_required")
        connection.sendall(struct.pack("!I", len(frame)) + frame)
        connection.shutdown(socket.SHUT_WR)
        output = bytearray()
        while block := receive(8):
            stream, size = block[0], int.from_bytes(block[4:], "big")
            if stream != 1 or block[1:4] != b"\0\0\0" or size > maximum + 1024 - len(output):
                raise ValueError("ipc_response_limit")
            data = receive(size)
            if len(data) != size:
                raise ValueError("ipc_truncated")
            output.extend(data)
        value = json.loads(output)
        if not isinstance(value, dict) or set(value) not in ({"body"}, {"error"}):
            raise ValueError("ipc_response_invalid")
        return value
