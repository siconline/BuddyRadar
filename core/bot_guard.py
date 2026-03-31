from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from math import ceil
from threading import Lock
from time import monotonic
from typing import DefaultDict

from fastapi import Request


@dataclass(frozen=True)
class RateLimitRule:
    window_seconds: int
    max_requests: int
    block_seconds: int = 0


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    retry_after_seconds: int = 0
    reason: str = ''


class BotGuard:
    def __init__(
        self,
        *,
        enabled: bool,
        trust_proxy_headers: bool,
        proxy_header: str,
        rules: dict[str, RateLimitRule],
        cleanup_interval_seconds: int = 120,
        escalation_enabled: bool = True,
        escalation_window_seconds: int = 1800,
        escalation_steps: tuple[int, ...] = (1, 2, 4, 8),
        escalation_max_block_seconds: int = 1800,
        strikes_for_session: int = 2,
        strikes_for_challenge: int = 3,
        strikes_for_pow: int = 5,
    ) -> None:
        self.enabled = enabled
        self.trust_proxy_headers = trust_proxy_headers
        self.proxy_header = proxy_header.lower().strip() or 'x-forwarded-for'
        self.rules = dict(rules)
        self.cleanup_interval_seconds = max(30, int(cleanup_interval_seconds))
        self.escalation_enabled = escalation_enabled
        self.escalation_window_seconds = max(60, int(escalation_window_seconds))
        self.escalation_steps = tuple(max(1, int(step)) for step in escalation_steps) or (1,)
        self.escalation_max_block_seconds = max(1, int(escalation_max_block_seconds))
        self.strikes_for_session = max(1, int(strikes_for_session))
        self.strikes_for_challenge = max(1, int(strikes_for_challenge))
        self.strikes_for_pow = max(1, int(strikes_for_pow))
        self._lock = Lock()
        self._events: DefaultDict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}
        self._client_flags: dict[str, dict[str, bool]] = {}
        self._strikes: DefaultDict[str, deque[float]] = defaultdict(deque)
        self._last_cleanup = 0.0

    def resolve_client_ip(self, request: Request | None) -> str:
        if request is None:
            return 'unknown'
        if self.trust_proxy_headers:
            forwarded = str(request.headers.get(self.proxy_header, '') or '').strip()
            if forwarded:
                first = forwarded.split(',')[0].strip()
                if first:
                    return first[:128]
        client = getattr(request, 'client', None)
        host = getattr(client, 'host', '') if client else ''
        host = str(host or '').strip()
        return host[:128] if host else 'unknown'

    def client_flags(self, client_ip: str) -> dict[str, bool]:
        with self._lock:
            flags = self._client_flags.setdefault(
                client_ip,
                {
                    'challenge_required': False,
                    'session_token_required': False,
                    'pow_required': False,
                },
            )
            return dict(flags)

    def consume(self, client_ip: str, action: str) -> GuardDecision:
        if not self.enabled:
            return GuardDecision(True)
        rule = self.rules.get(action)
        if rule is None:
            return GuardDecision(True)
        now = monotonic()
        with self._lock:
            self._cleanup_locked(now)
            blocked_until = float(self._blocked_until.get(client_ip, 0.0))
            if blocked_until > now:
                return GuardDecision(False, retry_after_seconds=max(1, ceil(blocked_until - now)), reason='blocked')
            if blocked_until:
                self._blocked_until.pop(client_ip, None)
            bucket = self._events[(client_ip, action)]
            window_start = now - float(rule.window_seconds)
            while bucket and bucket[0] <= window_start:
                bucket.popleft()
            if len(bucket) >= int(rule.max_requests):
                retry_after = self._apply_block_locked(client_ip, now, rule, bucket)
                return GuardDecision(False, retry_after_seconds=retry_after, reason='rate_limited')
            bucket.append(now)
            self._client_flags.setdefault(
                client_ip,
                {
                    'challenge_required': False,
                    'session_token_required': False,
                    'pow_required': False,
                },
            )
            return GuardDecision(True)

    def _apply_block_locked(self, client_ip: str, now: float, rule: RateLimitRule, bucket: deque[float]) -> int:
        base_seconds = self._base_block_seconds(now, rule, bucket)
        effective_seconds = base_seconds
        strike_count = 0
        if self.escalation_enabled:
            strike_count = self._register_strike_locked(client_ip, now)
            multiplier = self._multiplier_for_strike_count(strike_count)
            effective_seconds = min(self.escalation_max_block_seconds, base_seconds * multiplier)
        blocked_until = now + float(effective_seconds)
        self._blocked_until[client_ip] = blocked_until
        self._update_flags_locked(client_ip, strike_count)
        return max(1, int(effective_seconds))

    def _base_block_seconds(self, now: float, rule: RateLimitRule, bucket: deque[float]) -> int:
        if rule.block_seconds > 0:
            return max(1, int(rule.block_seconds))
        oldest = bucket[0] if bucket else now
        return max(1, ceil((oldest + float(rule.window_seconds)) - now))

    def _register_strike_locked(self, client_ip: str, now: float) -> int:
        strike_bucket = self._strikes[client_ip]
        threshold = now - float(self.escalation_window_seconds)
        while strike_bucket and strike_bucket[0] <= threshold:
            strike_bucket.popleft()
        strike_bucket.append(now)
        return len(strike_bucket)

    def _multiplier_for_strike_count(self, strike_count: int) -> int:
        if strike_count <= 0:
            return 1
        index = min(strike_count - 1, len(self.escalation_steps) - 1)
        return max(1, int(self.escalation_steps[index]))

    def _update_flags_locked(self, client_ip: str, strike_count: int) -> None:
        flags = self._client_flags.setdefault(
            client_ip,
            {
                'challenge_required': False,
                'session_token_required': False,
                'pow_required': False,
            },
        )
        if strike_count >= self.strikes_for_session:
            flags['session_token_required'] = True
        if strike_count >= self.strikes_for_challenge:
            flags['challenge_required'] = True
        if strike_count >= self.strikes_for_pow:
            flags['pow_required'] = True

    def _cleanup_locked(self, now: float) -> None:
        if now - self._last_cleanup < self.cleanup_interval_seconds:
            return
        self._last_cleanup = now
        self._blocked_until = {client_ip: until_ts for client_ip, until_ts in self._blocked_until.items() if until_ts > now}
        fresh_events: DefaultDict[tuple[str, str], deque[float]] = defaultdict(deque)
        for key, bucket in self._events.items():
            _, action = key
            rule = self.rules.get(action)
            if rule is None:
                continue
            window_start = now - float(rule.window_seconds)
            fresh_bucket = deque(ts for ts in bucket if ts > window_start)
            if fresh_bucket:
                fresh_events[key] = fresh_bucket
        self._events = fresh_events

        fresh_strikes: DefaultDict[str, deque[float]] = defaultdict(deque)
        strike_threshold = now - float(self.escalation_window_seconds)
        for client_ip, bucket in self._strikes.items():
            fresh_bucket = deque(ts for ts in bucket if ts > strike_threshold)
            if fresh_bucket:
                fresh_strikes[client_ip] = fresh_bucket
        self._strikes = fresh_strikes

        active_clients = set(self._blocked_until.keys())
        active_clients.update(client_ip for client_ip, _ in self._events.keys())
        active_clients.update(self._strikes.keys())
        self._client_flags = {
            client_ip: flags
            for client_ip, flags in self._client_flags.items()
            if client_ip in active_clients
        }


def default_rules_from_config(config_module) -> dict[str, RateLimitRule]:
    return {
        'ui_connect': RateLimitRule(config_module.RATE_LIMIT_UI_CONNECT_WINDOW_SECONDS, config_module.RATE_LIMIT_UI_CONNECT_MAX_REQUESTS, config_module.RATE_LIMIT_UI_CONNECT_BLOCK_SECONDS),
        'ui_update': RateLimitRule(config_module.RATE_LIMIT_UI_UPDATE_WINDOW_SECONDS, config_module.RATE_LIMIT_UI_UPDATE_MAX_REQUESTS, config_module.RATE_LIMIT_UI_UPDATE_BLOCK_SECONDS),
        'ui_visible_users': RateLimitRule(config_module.RATE_LIMIT_UI_VISIBLE_USERS_WINDOW_SECONDS, config_module.RATE_LIMIT_UI_VISIBLE_USERS_MAX_REQUESTS, config_module.RATE_LIMIT_UI_VISIBLE_USERS_BLOCK_SECONDS),
        'ui_disconnect': RateLimitRule(config_module.RATE_LIMIT_UI_DISCONNECT_WINDOW_SECONDS, config_module.RATE_LIMIT_UI_DISCONNECT_MAX_REQUESTS, config_module.RATE_LIMIT_UI_DISCONNECT_BLOCK_SECONDS),
        'api_connect': RateLimitRule(config_module.RATE_LIMIT_API_CONNECT_WINDOW_SECONDS, config_module.RATE_LIMIT_API_CONNECT_MAX_REQUESTS, config_module.RATE_LIMIT_API_CONNECT_BLOCK_SECONDS),
        'api_update_location': RateLimitRule(config_module.RATE_LIMIT_API_UPDATE_LOCATION_WINDOW_SECONDS, config_module.RATE_LIMIT_API_UPDATE_LOCATION_MAX_REQUESTS, config_module.RATE_LIMIT_API_UPDATE_LOCATION_BLOCK_SECONDS),
        'api_visible_users': RateLimitRule(config_module.RATE_LIMIT_API_VISIBLE_USERS_WINDOW_SECONDS, config_module.RATE_LIMIT_API_VISIBLE_USERS_MAX_REQUESTS, config_module.RATE_LIMIT_API_VISIBLE_USERS_BLOCK_SECONDS),
        'api_disconnect': RateLimitRule(config_module.RATE_LIMIT_API_DISCONNECT_WINDOW_SECONDS, config_module.RATE_LIMIT_API_DISCONNECT_MAX_REQUESTS, config_module.RATE_LIMIT_API_DISCONNECT_BLOCK_SECONDS),
        'api_disconnect_beacon': RateLimitRule(config_module.RATE_LIMIT_API_DISCONNECT_BEACON_WINDOW_SECONDS, config_module.RATE_LIMIT_API_DISCONNECT_BEACON_MAX_REQUESTS, config_module.RATE_LIMIT_API_DISCONNECT_BEACON_BLOCK_SECONDS),
        'api_health': RateLimitRule(config_module.RATE_LIMIT_API_HEALTH_WINDOW_SECONDS, config_module.RATE_LIMIT_API_HEALTH_MAX_REQUESTS, config_module.RATE_LIMIT_API_HEALTH_BLOCK_SECONDS),
    }
