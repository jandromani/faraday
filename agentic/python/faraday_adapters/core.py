"""FARADAY metadata-only instrumentation. No model or framework dependency."""
from __future__ import annotations

import functools
import hashlib
import inspect
import json
import os
import stat
import threading
import time
from pathlib import Path

FRAMEWORKS = frozenset({'langgraph', 'crewai', 'openai-agents'})
KINDS = frozenset({'tool_call', 'node_call', 'agent_start', 'agent_end'})
STATUSES = frozenset({'started', 'ok', 'error', 'denied', 'unverified'})


def identity(name: object, salt: str = '') -> str:
    """Stable opaque identifier for one configured salt; never serialize raw names."""
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ValueError('Expected a nonempty bounded identifier')
    digest = hashlib.sha256((salt + '\0' + name).encode('utf-8')).hexdigest()[:24]
    return 'id-' + digest


class Recorder:
    def __init__(self, path: str | Path | None = None, *, salt: str = '',
                 on_error: str = 'raise'):
        if on_error not in ('raise', 'drop'):
            raise ValueError('on_error must be raise or drop')
        self.path = Path(path) if path is not None else None
        self.salt = salt
        self.on_error = on_error
        self.events: list[dict] = []
        self._lock = threading.Lock()

    def record(self, framework: str, agent: str, tool: str, kind: str,
               status: str, elapsed_ms: int = 0) -> dict:
        if framework not in FRAMEWORKS or kind not in KINDS or status not in STATUSES:
            raise ValueError('Invalid metadata enum')
        if not isinstance(elapsed_ms, int) or not (0 <= elapsed_ms <= 3600000):
            raise ValueError('Invalid duration')
        event = {'version': 1, 'framework': framework,
                 'agent': identity(agent, self.salt),
                 'tool': identity(tool, self.salt),
                 'kind': kind, 'status': status, 'elapsed_ms': elapsed_ms}
        try:
            with self._lock:
                if self.path is None:
                    self.events.append(event)
                else:
                    # O_NOFOLLOW prevents symlink substitution of a private trace.
                    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
                    if hasattr(os, 'O_NOFOLLOW'):
                        flags |= os.O_NOFOLLOW
                    fd = os.open(self.path, flags, 0o600)
                    try:
                        mode = os.fstat(fd).st_mode
                        if not stat.S_ISREG(mode):
                            raise ValueError('Refusing non-regular event log')
                        if os.name != 'nt' and (mode & 0o077):
                            raise ValueError('Event log must not be group/world accessible')
                        with os.fdopen(fd, 'a', encoding='utf-8') as fp:
                            fd = -1
                            fp.write(json.dumps(event, separators=(',', ':')) + '\n')
                    finally:
                        if fd != -1:
                            os.close(fd)
        except (OSError, ValueError):
            if self.on_error == 'raise':
                raise
        return event


def instrument(fn, *, recorder: Recorder, framework: str, agent: str,
               tool: str, kind: str = 'tool_call', allowed_tools: set[str] | None = None):
    """Explicitly instrument a node/tool; enforce the optional *local* allowlist.

    Not a mandatory gateway, and not a replacement for Authority capabilities.
    """
    if not callable(fn):
        raise TypeError('fn must be callable')
    if kind not in ('tool_call', 'node_call'):
        raise ValueError('invalid function kind')

    def check():
        if allowed_tools is not None and tool not in allowed_tools:
            recorder.record(framework, agent, tool, kind, 'denied')
            raise PermissionError('FARADAY: tool denied by explicit local policy')

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            check()
            start = time.monotonic_ns()
            try:
                outcome = await fn(*args, **kwargs)
            except BaseException:
                recorder.record(framework, agent, tool, kind, 'error', min(3600000, (time.monotonic_ns()-start)//1000000))
                raise
            recorder.record(framework, agent, tool, kind, 'ok', min(3600000, (time.monotonic_ns()-start)//1000000))
            return outcome
        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        check()
        start = time.monotonic_ns()
        try:
            outcome = fn(*args, **kwargs)
        except BaseException:
            recorder.record(framework, agent, tool, kind, 'error', min(3600000, (time.monotonic_ns()-start)//1000000))
            raise
        recorder.record(framework, agent, tool, kind, 'ok', min(3600000, (time.monotonic_ns()-start)//1000000))
        return outcome
    return wrapper
