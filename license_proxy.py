#!/usr/bin/env python3
"""
Widevine license proxy — a plain, stateless license server.i

Usage:
    python3 license_proxy.py          # listens on localhost:8081
    python3 license_proxy.py 9090     # custom port
"""

import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

LICENSE_URL = 'https://proxy.uat.widevine.com/proxy?provider=widevine_test'


def decode_varint(data, pos):
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def proto_fields(data):
    """Walk a protobuf and yield (field_number, wire_type, raw_value)."""
    pos = 0
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            val, pos = decode_varint(data, pos)
            yield field, wire, val
        elif wire == 2:
            length, pos = decode_varint(data, pos)
            yield field, wire, bytes(data[pos:pos + length])
            pos += length
        else:
            break  # unknown wire type


def extract_key_ids(license_response):
    """Parse SignedMessage -> License -> KeyContainer.id (key_ids in plaintext).
    These come straight out of the license the server just issued."""
    key_ids = []
    try:
        for fn, wt, val in proto_fields(license_response):       # SignedMessage
            if fn == 2 and wt == 2:                              # field 2 = License
                for fn2, wt2, val2 in proto_fields(val):
                    if fn2 == 3 and wt2 == 2:                    # field 3 = KeyContainer
                        for fn3, wt3, val3 in proto_fields(val2):
                            if fn3 == 1 and wt3 == 2:            # field 1 = id
                                key_ids.append(val3.hex())
    except Exception as e:
        print(f'[proxy] key_id decode error: {e}', file=sys.stderr)
    return key_ids


class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        print(f'[proxy] forwarding {n}-byte license request to Widevine UAT',
              file=sys.stderr)
        try:
            req = urllib.request.Request(
                LICENSE_URL, data=body, method='POST',
                headers={'Content-Type': 'application/octet-stream'})
            with urllib.request.urlopen(req, timeout=15) as r:
                resp = r.read()
            key_ids = extract_key_ids(resp)
            print(f'[proxy] got {len(resp)}-byte license response; '
                  f'key IDs: {key_ids}', file=sys.stderr)
            self.send_response(200)
            self._cors()
            if key_ids:
                self.send_header('X-Widevine-Key-IDs', ','.join(key_ids))
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        except Exception as e:
            print(f'[proxy] error: {e}', file=sys.stderr)
            msg = str(e).encode()
            self.send_response(502)
            self._cors()
            self.send_header('Content-Length', str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def do_GET(self):
        # A license server only answers license POSTs. Nothing to GET.
        self.send_response(404)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Expose-Headers', 'X-Widevine-Key-IDs')

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    print(f'Widevine license proxy -> {LICENSE_URL}', file=sys.stderr)
    print(f'Listening on http://localhost:{port}', file=sys.stderr)
    HTTPServer(('localhost', port), Handler).serve_forever()
