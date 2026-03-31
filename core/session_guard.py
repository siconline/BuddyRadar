from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from secrets import token_urlsafe
from threading import Lock
from time import monotonic


@dataclass(frozen=True)
class SessionRecord:
    token: str
    client_ip: str
    user_id: str
    username: str
    username_key: str
    group_hash: str
    code: str
    created_at_monotonic: float
    expires_at_monotonic: float


class SessionManager:
    def __init__(self, *, ttl_seconds: int, refresh_on_use: bool = True, bind_to_ip: bool = True, cleanup_interval_seconds: int = 300) -> None:
        self.ttl_seconds = max(60, int(ttl_seconds))
        self.refresh_on_use = bool(refresh_on_use)
        self.bind_to_ip = bool(bind_to_ip)
        self.cleanup_interval_seconds = max(30, int(cleanup_interval_seconds))
        self._lock = Lock()
        self._sessions: dict[str, SessionRecord] = {}
        self._user_index: dict[tuple[str, str, str], str] = {}
        self._last_cleanup = 0.0

    def issue_session(self, *, client_ip: str, user_id: str, username: str, username_key: str, group_hash: str, code: str) -> SessionRecord:
        now = monotonic()
        with self._lock:
            self._cleanup_locked(now)
            binding = (client_ip if self.bind_to_ip else '', user_id, group_hash)
            old_token = self._user_index.pop(binding, None)
            if old_token:
                self._sessions.pop(old_token, None)
            token = token_urlsafe(32)
            record = SessionRecord(token, client_ip, user_id, username, username_key, group_hash, code, now, now + float(self.ttl_seconds))
            self._sessions[token] = record
            self._user_index[binding] = token
            return record

    def validate_session(self, token: str, *, client_ip: str, user_id: str | None = None, touch: bool = True) -> SessionRecord | None:
        if not token:
            return None
        now = monotonic()
        with self._lock:
            self._cleanup_locked(now)
            record = self._sessions.get(token)
            if record is None:
                return None
            if record.expires_at_monotonic <= now:
                self._remove_locked(token)
                return None
            if self.bind_to_ip and record.client_ip != client_ip:
                return None
            if user_id is not None and record.user_id != user_id:
                return None
            if touch and self.refresh_on_use:
                refreshed = SessionRecord(record.token, record.client_ip, record.user_id, record.username, record.username_key, record.group_hash, record.code, record.created_at_monotonic, now + float(self.ttl_seconds))
                self._sessions[token] = refreshed
                return refreshed
            return record

    def revoke_session(self, token: str) -> None:
        if not token:
            return
        with self._lock:
            self._remove_locked(token)

    def retry_after_seconds(self, token: str) -> int:
        now = monotonic()
        with self._lock:
            self._cleanup_locked(now)
            record = self._sessions.get(token)
            if record is None:
                return 0
            if record.expires_at_monotonic <= now:
                self._remove_locked(token)
                return 0
            return max(1, ceil(record.expires_at_monotonic - now))

    def _remove_locked(self, token: str) -> None:
        record = self._sessions.pop(token, None)
        if record is None:
            return
        binding = (record.client_ip if self.bind_to_ip else '', record.user_id, record.group_hash)
        indexed_token = self._user_index.get(binding)
        if indexed_token == token:
            self._user_index.pop(binding, None)

    def _cleanup_locked(self, now: float) -> None:
        if now - self._last_cleanup < self.cleanup_interval_seconds:
            return
        self._last_cleanup = now
        expired_tokens = [token for token, record in self._sessions.items() if record.expires_at_monotonic <= now]
        for token in expired_tokens:
            self._remove_locked(token)
