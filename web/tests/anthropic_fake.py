"""A fake Anthropic Messages API on loopback for tests: no network, no key. It answers POST /v1/messages from a script (a list of response
bodies, the last one repeating) and records every request body. The shapes are the ones Anthropic documents for current models: a ``thinking``
block comes before the ``text`` block when a model reasons, ``max_tokens`` can end a reply before any text, ``refusal`` is a stop reason with an
empty or partial content, and ``tool_use`` ends a turn that asked for a tool."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

USAGE = {'input_tokens': 321, 'output_tokens': 2048}


def message(content, stop_reason='end_turn', usage=None):
    return {'id': 'msg_test', 'type': 'message', 'role': 'assistant', 'model': 'claude-haiku-5-5', 'content': content,
            'stop_reason': stop_reason, 'stop_sequence': None, 'usage': usage or USAGE}


def text(answer):
    return {'type': 'text', 'text': answer}


THINKING = {'type': 'thinking', 'thinking': 'private reasoning', 'signature': 'sig'}

SHAPES = {
    'text_only': lambda answer='{}': message([text(answer)]),
    'thinking_then_text': lambda answer='{}': message([THINKING, text(answer)]),
    'two_text_blocks': lambda answer='{}': message([text(answer[:1]), text(answer[1:])]),
    'thinking_only_max_tokens': lambda answer='{}': message([THINKING], 'max_tokens'),
    'thinking_only_end_turn': lambda answer='{}': message([THINKING], 'end_turn'),
    'refusal': lambda answer='{}': message([], 'refusal'),
    'empty_content': lambda answer='{}': message([], 'end_turn', {'input_tokens': 321, 'output_tokens': 0}),
    'tool_use': lambda answer='{}': message([{'type': 'tool_use', 'id': 'toolu_1', 'name': 'x', 'input': {}}], 'tool_use'),
}


class FakeAnthropic:
    def __init__(self, script):
        self.script, self.requests = list(script), []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or b'{}')
                outer.requests.append(body)
                reply = outer.script[min(len(outer.requests), len(outer.script)) - 1]
                data = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        return False

    @property
    def limits(self):
        return [r.get('max_tokens') for r in self.requests]
