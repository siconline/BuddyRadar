
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from time import monotonic
from uuid import uuid4

from fastapi import HTTPException, Request
from nicegui import app, events, ui
from pydantic import BaseModel, Field

from config import (
    ACTIVE_USER_SECONDS,
    APP_NAME,
    APP_VERSION,
    CODE_MAX_LENGTH,
    CODE_MIN_LENGTH,
    GPS_UPDATE_SECONDS,
    MAP_CHANGE_POLL_SECONDS,
    MAP_REFRESH_SECONDS,
    MAP_THROTTLED_REFRESH_SECONDS,
    MARKER_MESSAGE_MAX_LENGTH,
    MAX_ACCURACY_METERS,
    MAX_DEVICE_TIME_LENGTH,
    OFFLINE_RETENTION_HOURS,
    SESSION_TOKEN_MAX_LENGTH,
    UPDATE_STORM_THRESHOLD,
    UPDATE_STORM_WINDOW_SECONDS,
    UI_PRIMARY,
    USERNAME_MAX_LENGTH,
    USERNAME_MIN_LENGTH,
    USER_ID_MAX_LENGTH,
)
from core.bot_guard import BotGuard
from core.security import SecurityManager
from core.session_guard import SessionManager, SessionRecord
from core.storage import Storage


MARKER_ID_MAX_LENGTH = 80


class ConnectRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=USER_ID_MAX_LENGTH)
    username: str = Field(min_length=USERNAME_MIN_LENGTH, max_length=USERNAME_MAX_LENGTH)
    code: str = Field(min_length=CODE_MIN_LENGTH, max_length=CODE_MAX_LENGTH)
    latitude: float = Field(ge=-90.0, le=90.0)
    longitude: float = Field(ge=-180.0, le=180.0)
    accuracy: float | None = Field(default=None, ge=0.0, le=MAX_ACCURACY_METERS)
    device_time: str | None = Field(default=None, max_length=MAX_DEVICE_TIME_LENGTH)


class UpdateLocationRequest(BaseModel):
    session_token: str = Field(min_length=16, max_length=SESSION_TOKEN_MAX_LENGTH)
    latitude: float = Field(ge=-90.0, le=90.0)
    longitude: float = Field(ge=-180.0, le=180.0)
    accuracy: float | None = Field(default=None, ge=0.0, le=MAX_ACCURACY_METERS)
    device_time: str | None = Field(default=None, max_length=MAX_DEVICE_TIME_LENGTH)


class DisconnectRequest(BaseModel):
    session_token: str = Field(min_length=16, max_length=SESSION_TOKEN_MAX_LENGTH)


class MarkerUpsertRequest(BaseModel):
    session_token: str = Field(min_length=16, max_length=SESSION_TOKEN_MAX_LENGTH)
    latitude: float = Field(ge=-90.0, le=90.0)
    longitude: float = Field(ge=-180.0, le=180.0)
    message: str = Field(default='', max_length=MARKER_MESSAGE_MAX_LENGTH)
    marker_id: str | None = Field(default=None, min_length=1, max_length=MARKER_ID_MAX_LENGTH)


class MarkerDeleteRequest(BaseModel):
    session_token: str = Field(min_length=16, max_length=SESSION_TOKEN_MAX_LENGTH)
    marker_id: str = Field(min_length=1, max_length=MARKER_ID_MAX_LENGTH)


security: SecurityManager | None = None
storage: Storage | None = None
bot_guard: BotGuard | None = None
session_manager: SessionManager | None = None
_routes_registered = False
_page_registered = False


def setup(
    storage_instance: Storage,
    security_instance: SecurityManager,
    bot_guard_instance: BotGuard,
    session_manager_instance: SessionManager,
) -> None:
    global storage, security, bot_guard, session_manager
    storage = storage_instance
    security = security_instance
    bot_guard = bot_guard_instance
    session_manager = session_manager_instance
    _register_api_routes()
    _register_page()


def _resolve_effective_user_id(requested_user_id: str, username: str, code: str) -> tuple[str, str]:
    assert storage is not None
    assert security is not None

    username_key = security.username_key(username)
    existing = storage.find_by_username_key(username_key)
    if existing:
        return str(existing['user_id']), username_key

    group_hash = security.visibility_hash(code)
    normalized_username = Storage.normalize_username(username)
    for row in storage.list_group_records_for_reclaim(group_hash):
        if row['username_key']:
            continue
        try:
            plain = security.decrypt_text(row['payload_encrypted'], code)
            payload = Storage.loads_payload(plain)
        except Exception:
            continue
        if Storage.normalize_username(str(payload.get('username') or '')) == normalized_username:
            return str(row['user_id']), username_key

    return requested_user_id, username_key


async def _persist_presence(
    *,
    user_id: str,
    username: str,
    code: str,
    latitude: float,
    longitude: float,
    accuracy: float | None,
    device_time: str | None,
) -> dict:
    assert storage is not None
    assert security is not None

    received_at = datetime.now(timezone.utc).isoformat()
    group_hash = security.visibility_hash(code)
    effective_user_id, username_key = _resolve_effective_user_id(user_id, username, code)
    encrypted = security.encrypt_text(
        Storage.dumps_payload(
            {
                'user_id': effective_user_id,
                'username': username,
                'latitude': latitude,
                'longitude': longitude,
                'accuracy': accuracy,
                'device_time': device_time,
                'received_at': received_at,
            }
        ),
        code,
    )
    change_version, persisted_user_id = storage.upsert_presence(
        effective_user_id,
        username_key,
        group_hash,
        encrypted,
        received_at,
        active_seconds=ACTIVE_USER_SECONDS,
        offline_retention_hours=OFFLINE_RETENTION_HOURS,
    )
    return {
        'ok': True,
        'updated_at': received_at,
        'change_version': change_version,
        'user_id': persisted_user_id,
        'group_hash': group_hash,
        'username_key': username_key,
    }


def _extract_session_token(
    request: Request | None,
    *,
    payload_token: str | None = None,
    query_token: str | None = None,
) -> str:
    for candidate in (payload_token, query_token):
        value = str(candidate or '').strip()
        if value:
            return value

    if request is None:
        return ''

    header_token = str(request.headers.get('x-buddy-session-token', '') or '').strip()
    if header_token:
        return header_token

    auth_header = str(request.headers.get('authorization', '') or '').strip()
    if auth_header.lower().startswith('bearer '):
        bearer_token = auth_header[7:].strip()
        if bearer_token:
            return bearer_token
    return ''


def _validate_session_token(
    session_token: str,
    *,
    client_ip: str,
    user_id: str | None = None,
    touch: bool = True,
) -> SessionRecord:
    assert session_manager is not None
    token = str(session_token or '').strip()
    if not token:
        raise RuntimeError('Sitzung fehlt. Bitte neu verbinden.')
    session = session_manager.validate_session(token, client_ip=client_ip, user_id=user_id, touch=touch)
    if session is None:
        raise RuntimeError('Sitzung ungültig oder abgelaufen. Bitte neu verbinden.')
    return session


def _require_session_http(
    request: Request,
    *,
    payload_token: str | None = None,
    query_token: str | None = None,
    user_id: str | None = None,
    touch: bool = True,
) -> SessionRecord:
    assert bot_guard is not None
    session_token = _extract_session_token(request, payload_token=payload_token, query_token=query_token)
    client_ip = bot_guard.resolve_client_ip(request)
    try:
        return _validate_session_token(session_token, client_ip=client_ip, user_id=user_id, touch=touch)
    except RuntimeError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


async def _connect_user(payload: ConnectRequest, *, client_ip: str) -> dict:
    assert session_manager is not None

    result = await _persist_presence(
        user_id=payload.user_id,
        username=payload.username,
        code=payload.code,
        latitude=payload.latitude,
        longitude=payload.longitude,
        accuracy=payload.accuracy,
        device_time=payload.device_time,
    )
    session = session_manager.issue_session(
        client_ip=client_ip,
        user_id=str(result['user_id']),
        username=payload.username,
        username_key=str(result['username_key']),
        group_hash=str(result['group_hash']),
        code=payload.code,
    )
    return {
        'ok': True,
        'updated_at': result['updated_at'],
        'change_version': result['change_version'],
        'user_id': result['user_id'],
        'session_token': session.token,
        'session_expires_in': session_manager.ttl_seconds,
    }


async def _store_location_for_session(payload: UpdateLocationRequest, *, client_ip: str) -> dict:
    session = _validate_session_token(payload.session_token, client_ip=client_ip)
    result = await _persist_presence(
        user_id=session.user_id,
        username=session.username,
        code=session.code,
        latitude=payload.latitude,
        longitude=payload.longitude,
        accuracy=payload.accuracy,
        device_time=payload.device_time,
    )
    return {
        'ok': True,
        'updated_at': result['updated_at'],
        'change_version': result['change_version'],
        'user_id': result['user_id'],
    }



def _normalize_marker_message(message: str | None) -> str:
    return str(message or '').strip()[:MARKER_MESSAGE_MAX_LENGTH]


async def _upsert_marker_for_session(payload: MarkerUpsertRequest, *, client_ip: str) -> dict:
    assert storage is not None
    assert security is not None

    session = _validate_session_token(payload.session_token, client_ip=client_ip)
    changed_at = datetime.now(timezone.utc).isoformat()
    marker_id = str(payload.marker_id or uuid4().hex).strip()[:MARKER_ID_MAX_LENGTH]
    message = _normalize_marker_message(payload.message)

    owner_user_id = session.user_id
    owner_username = session.username
    existing_marker = storage.get_group_marker(marker_id, session.group_hash) if payload.marker_id else None
    if existing_marker:
        owner_user_id = str(existing_marker.get('owner_user_id') or '').strip() or owner_user_id
        owner_username = str(existing_marker.get('owner_username') or '').strip() or owner_username
        if not existing_marker.get('owner_user_id'):
            try:
                existing_plain = security.decrypt_text(str(existing_marker['payload_encrypted']), session.code)
                existing_payload = Storage.loads_payload(existing_plain)
                owner_user_id = str(existing_payload.get('owner_user_id') or existing_payload.get('updated_by_user_id') or owner_user_id)
                owner_username = str(existing_payload.get('owner_username') or existing_payload.get('updated_by_username') or owner_username)
            except Exception:
                pass

    for row in storage.list_group_markers(session.group_hash):
        other_marker_id = str(row.get('marker_id') or '').strip()
        if not other_marker_id or other_marker_id == marker_id:
            continue
        row_owner_user_id = str(row.get('owner_user_id') or '').strip()
        if not row_owner_user_id:
            try:
                row_plain = security.decrypt_text(str(row['payload_encrypted']), session.code)
                row_payload = Storage.loads_payload(row_plain)
                row_owner_user_id = str(row_payload.get('owner_user_id') or row_payload.get('updated_by_user_id') or '').strip()
            except Exception:
                row_owner_user_id = ''
        if row_owner_user_id == owner_user_id:
            storage.delete_group_marker(other_marker_id, session.group_hash, changed_at)

    encrypted = security.encrypt_text(
        Storage.dumps_payload(
            {
                'marker_id': marker_id,
                'owner_user_id': owner_user_id,
                'owner_username': owner_username,
                'latitude': payload.latitude,
                'longitude': payload.longitude,
                'message': message,
                'updated_by_user_id': session.user_id,
                'updated_by_username': session.username,
                'updated_at': changed_at,
            }
        ),
        session.code,
    )
    change_version, stored_marker_id = storage.upsert_group_marker(
        marker_id,
        session.group_hash,
        owner_user_id,
        owner_username,
        encrypted,
        changed_at,
    )
    return {
        'ok': True,
        'marker_id': stored_marker_id,
        'updated_at': changed_at,
        'change_version': change_version,
    }


async def _delete_marker_for_session(payload: MarkerDeleteRequest, *, client_ip: str) -> dict:
    assert storage is not None

    session = _validate_session_token(payload.session_token, client_ip=client_ip, touch=False)
    changed_at = datetime.now(timezone.utc).isoformat()
    change_version = storage.delete_group_marker(payload.marker_id, session.group_hash, changed_at)
    return {
        'ok': change_version is not None,
        'updated_at': changed_at,
        'change_version': change_version or 0,
    }


async def _fetch_visible_users_for_group(*, group_hash: str, code: str) -> list[dict]:
    assert storage is not None
    assert security is not None

    rows = storage.list_visible_group_records(group_hash, ACTIVE_USER_SECONDS, OFFLINE_RETENTION_HOURS)
    users: list[dict] = []
    for row in rows:
        try:
            plain = security.decrypt_text(row['payload_encrypted'], code)
            item = Storage.loads_payload(plain)
            item['updated_at'] = row['updated_at']
            item['status'] = row['status'] or 'online'
            item['disconnected_at'] = row['disconnected_at']
            users.append(item)
        except Exception:
            continue
    return users


async def _fetch_visible_users_for_session(session_token: str, *, client_ip: str) -> list[dict]:
    session = _validate_session_token(session_token, client_ip=client_ip)
    return await _fetch_visible_users_for_group(group_hash=session.group_hash, code=session.code)


async def _fetch_visible_markers_for_group(*, group_hash: str, code: str) -> list[dict]:
    assert storage is not None
    assert security is not None

    markers: list[dict] = []
    for row in storage.list_group_markers(group_hash):
        try:
            plain = security.decrypt_text(row['payload_encrypted'], code)
            item = Storage.loads_payload(plain)
            item['marker_id'] = row['marker_id']
            item['owner_user_id'] = row.get('owner_user_id') or item.get('owner_user_id') or item.get('updated_by_user_id')
            item['owner_username'] = row.get('owner_username') or item.get('owner_username') or item.get('updated_by_username')
            item['created_at'] = row['created_at']
            item['updated_at'] = row['updated_at']
            markers.append(item)
        except Exception:
            continue
    return markers


async def _fetch_visible_markers_for_session(session_token: str, *, client_ip: str) -> list[dict]:
    session = _validate_session_token(session_token, client_ip=client_ip)
    markers = await _fetch_visible_markers_for_group(group_hash=session.group_hash, code=session.code)
    for marker in markers:
        marker['is_self'] = str(marker.get('owner_user_id') or '').strip() == str(session.user_id or '').strip()
    return markers


def _get_change_state_for_session(session_token: str, *, client_ip: str) -> dict:
    assert storage is not None
    session = _validate_session_token(session_token, client_ip=client_ip)
    return storage.get_change_state(session.group_hash, UPDATE_STORM_WINDOW_SECONDS)


async def _disconnect_session(session_token: str, *, client_ip: str, revoke_session: bool = True) -> dict:
    assert storage is not None
    assert session_manager is not None

    session = _validate_session_token(session_token, client_ip=client_ip, touch=False)
    changed_at = datetime.now(timezone.utc).isoformat()
    change_version = storage.set_presence_offline(session.user_id, session.group_hash, changed_at)
    users = await _fetch_visible_users_for_group(group_hash=session.group_hash, code=session.code)
    if revoke_session:
        session_manager.revoke_session(session.token)
    return {
        'ok': change_version is not None,
        'updated_at': changed_at,
        'change_version': change_version or 0,
        'users': users,
    }


def _check_rate_limit(action: str, request: Request | None) -> tuple[bool, int, str]:
    assert bot_guard is not None
    client_ip = bot_guard.resolve_client_ip(request)
    decision = bot_guard.consume(client_ip, action)
    return decision.allowed, int(decision.retry_after_seconds or 0), client_ip


def _raise_rate_limit_http(action: str, request: Request) -> str:
    allowed, retry_after, client_ip = _check_rate_limit(action, request)
    if allowed:
        return client_ip
    wait_for = max(1, int(retry_after or 1))
    raise HTTPException(
        status_code=429,
        detail=f'Zu viele Anfragen von dieser Verbindung. Bitte in {wait_for} Sekunden erneut versuchen.',
        headers={'Retry-After': str(wait_for)},
    )


def _register_api_routes() -> None:
    global _routes_registered
    if _routes_registered:
        return
    _routes_registered = True

    @app.post('/api/connect')
    async def connect_user(payload: ConnectRequest, request: Request):
        client_ip = _raise_rate_limit_http('api_connect', request)
        if len(payload.code.strip()) < CODE_MIN_LENGTH:
            raise HTTPException(status_code=400, detail=f'Code muss mindestens {CODE_MIN_LENGTH} Zeichen lang sein.')
        username = payload.username.strip()
        if len(username) < USERNAME_MIN_LENGTH:
            raise HTTPException(
                status_code=400,
                detail=f'Benutzername muss mindestens {USERNAME_MIN_LENGTH} Zeichen lang sein.',
            )
        return await _connect_user(payload, client_ip=client_ip)

    @app.post('/api/update-location')
    async def update_location(payload: UpdateLocationRequest, request: Request):
        client_ip = _raise_rate_limit_http('api_update_location', request)
        _require_session_http(request, payload_token=payload.session_token)
        return await _store_location_for_session(payload, client_ip=client_ip)

    @app.post('/api/disconnect')
    async def disconnect_user(payload: DisconnectRequest, request: Request):
        client_ip = _raise_rate_limit_http('api_disconnect', request)
        _require_session_http(request, payload_token=payload.session_token, touch=False)
        return await _disconnect_session(payload.session_token, client_ip=client_ip)

    @app.post('/api/disconnect-beacon')
    async def disconnect_beacon(request: Request):
        client_ip = _raise_rate_limit_http('api_disconnect_beacon', request)
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        session_token = str(payload.get('session_token') or '').strip()
        if not session_token:
            return {'ok': False, 'reason': 'missing_session_token'}
        try:
            _require_session_http(request, payload_token=session_token, touch=False)
            return await _disconnect_session(session_token, client_ip=client_ip, revoke_session=False)
        except HTTPException:
            return {'ok': False, 'reason': 'invalid_or_expired_session'}



    @app.post('/api/marker-upsert')
    async def marker_upsert(payload: MarkerUpsertRequest, request: Request):
        client_ip = _raise_rate_limit_http('api_update_location', request)
        _require_session_http(request, payload_token=payload.session_token)
        return await _upsert_marker_for_session(payload, client_ip=client_ip)

    @app.post('/api/marker-delete')
    async def marker_delete(payload: MarkerDeleteRequest, request: Request):
        client_ip = _raise_rate_limit_http('api_update_location', request)
        _require_session_http(request, payload_token=payload.session_token, touch=False)
        return await _delete_marker_for_session(payload, client_ip=client_ip)

    @app.get('/api/visible-users')
    async def visible_users(request: Request, session_token: str | None = None):
        client_ip = _raise_rate_limit_http('api_visible_users', request)
        session = _require_session_http(request, query_token=session_token)
        return {'users': await _fetch_visible_users_for_session(session.token, client_ip=client_ip)}

    @app.get('/api/health')
    async def health(request: Request):
        _raise_rate_limit_http('api_health', request)
        return {'ok': True, 'name': APP_NAME, 'version': APP_VERSION}


def _register_page() -> None:
    global _page_registered
    if _page_registered:
        return
    _page_registered = True

    @ui.page('/')
    async def index_page(request: Request) -> None:
        ui.colors(primary=UI_PRIMARY)
        ui.add_head_html(
            '''
            <style>
                html, body {
                    margin: 0;
                    padding: 0;
                    width: 100%;
                    min-height: 100%;
                }
                body {
                    background: #f3f4f6;
                    color: #111827;
                }
                body.buddy-dark {
                    background: #0f172a;
                    color: #e5e7eb;
                }
                .buddy-header {
                    background: #2563eb;
                    color: white;
                }
                body.buddy-dark .buddy-header {
                    background: #0b1220;
                    color: #f9fafb;
                    border-bottom: 1px solid rgba(148, 163, 184, 0.18);
                }
                .nicegui-content {
                    margin: 0 !important;
                    padding: 0 !important;
                    gap: 0 !important;
                    width: 100% !important;
                    max-width: none !important;
                }
                .q-page {
                    padding: 0 !important;
                }
                .buddy-app-bg {
                    background: transparent;
                }
                .buddy-main-full {
                    width: 100%;
                    height: calc(100dvh - 64px);
                    min-height: calc(100dvh - 64px);
                    margin: 0;
                    padding: 0;
                    overflow: hidden;
                }
                .buddy-map-card-full {
                    width: 100%;
                    height: 100%;
                    margin: 0 !important;
                    padding: 0 !important;
                    background: transparent !important;
                    border: 0 !important;
                    box-shadow: none !important;
                    border-radius: 0 !important;
                    overflow: hidden !important;
                }
                .buddy-map-full {
                    width: 100%;
                    height: 100%;
                    margin: 0 !important;
                    border: 0 !important;
                    border-radius: 0 !important;
                    display: block !important;
                }
                .buddy-surface {
                    background: #ffffff;
                    color: #111827;
                    border: 1px solid #e5e7eb;
                }
                body.buddy-dark .buddy-surface {
                    background: #111827;
                    color: #f9fafb;
                    border: 1px solid #334155;
                }
                .buddy-drawer-surface {
                    background: #ffffff;
                    color: #111827;
                }
                body.buddy-dark .buddy-drawer-surface {
                    background: #0f172a;
                    color: #f9fafb;
                }
                .buddy-section-separator {
                    border-color: #e5e7eb;
                }
                body.buddy-dark .buddy-section-separator {
                    border-color: #334155;
                }
                .buddy-text-primary {
                    color: #111827;
                }
                .buddy-text-secondary {
                    color: #374151;
                }
                .buddy-text-muted {
                    color: #6b7280;
                }
                body.buddy-dark .buddy-text-primary {
                    color: #f9fafb;
                }
                body.buddy-dark .buddy-text-secondary {
                    color: #cbd5e1;
                }
                body.buddy-dark .buddy-text-muted {
                    color: #94a3b8;
                }
                .buddy-status-self {
                    color: #1d4ed8;
                }
                .buddy-status-other {
                    color: #c2410c;
                }
                .buddy-status-offline {
                    color: #4b5563;
                }
                body.buddy-dark .buddy-status-self {
                    color: #93c5fd;
                }
                body.buddy-dark .buddy-status-other {
                    color: #fdba74;
                }
                body.buddy-dark .buddy-status-offline {
                    color: #94a3b8;
                }
                .buddy-marker-icon {
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    width: 42px;
                    height: 34px;
                    border-radius: 999px;
                    color: white;
                    font-weight: 800;
                    font-size: 12px;
                    letter-spacing: 0.04em;
                    line-height: 1;
                    border: 2px solid white;
                    box-shadow: 0 4px 12px rgba(0,0,0,.28);
                    font-family: Arial, sans-serif;
                }
                .buddy-marker-self {
                    background: linear-gradient(135deg, #2563eb, #1d4ed8);
                }
                .buddy-marker-other {
                    background: linear-gradient(135deg, #f97316, #ea580c);
                }
                .buddy-marker-offline {
                    background: linear-gradient(135deg, #9ca3af, #6b7280);
                }
                .buddy-number-badge {
                    min-width: 2.35rem;
                    height: 1.85rem;
                    padding: 0 0.45rem;
                    font-size: 0.78rem;
                    letter-spacing: 0.04em;
                    border-radius: 999px;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    font-weight: 700;
                    color: white;
                    background: linear-gradient(135deg, #f97316, #ea580c);
                    box-shadow: 0 2px 8px rgba(0,0,0,.18);
                }
                .buddy-number-badge-self {
                    background: linear-gradient(135deg, #2563eb, #1d4ed8);
                }
                .buddy-number-badge-offline {
                    background: linear-gradient(135deg, #9ca3af, #6b7280);
                }
                .buddy-note-marker {
                    width: 28px;
                    height: 28px;
                    border-radius: 10px 10px 10px 2px;
                    transform: rotate(-45deg);
                    border: 2px solid white;
                    box-shadow: 0 4px 12px rgba(0,0,0,.25);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .buddy-note-marker-self {
                    background: linear-gradient(135deg, #2563eb, #1d4ed8);
                }
                .buddy-note-marker-other {
                    background: linear-gradient(135deg, #f97316, #ea580c);
                }
                .buddy-note-marker > span {
                    transform: rotate(45deg);
                    color: white;
                    font-size: 13px;
                    font-weight: 700;
                    line-height: 1;
                }
                .buddy-marker-popup {
                    min-width: 240px;
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                    color: #111827;
                }
                .leaflet-popup-content-wrapper {
                    border-radius: 14px;
                }
                .leaflet-popup-content {
                    margin: 12px 14px;
                }
                .buddy-marker-popup-top {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    gap: 8px;
                }
                .buddy-marker-popup-title {
                    font-weight: 700;
                    color: #111827;
                }
                .buddy-marker-popup-meta {
                    font-size: 12px;
                    color: #6b7280;
                }
                .buddy-marker-popup-textarea {
                    width: 100%;
                    min-height: 88px;
                    resize: vertical;
                    padding: 8px 10px;
                    border-radius: 10px;
                    border: 1px solid #d1d5db;
                    outline: none;
                    font: inherit;
                    color: #111827;
                    background: #ffffff;
                }
                .buddy-marker-popup-actions {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    gap: 10px;
                }
                .buddy-marker-popup-save,
                .buddy-marker-popup-delete {
                    border: 0;
                    cursor: pointer;
                }
                .buddy-marker-popup-save {
                    padding: 7px 12px;
                    border-radius: 999px;
                    color: white;
                    font-weight: 600;
                    background: #2563eb;
                }
                .buddy-marker-popup-delete {
                    width: 28px;
                    height: 28px;
                    border-radius: 999px;
                    color: white;
                    font-size: 16px;
                    line-height: 1;
                    background: #dc2626;
                }
                body.buddy-dark .buddy-marker-popup {
                    color: #f9fafb;
                }
                body.buddy-dark .buddy-marker-popup-title {
                    color: #f9fafb;
                }
                body.buddy-dark .buddy-marker-popup-meta {
                    color: #94a3b8;
                }
                body.buddy-dark .buddy-marker-popup-textarea {
                    background: #111827;
                    color: #f9fafb;
                    border-color: #334155;
                }
                body.buddy-dark .leaflet-popup-content-wrapper {
                    background: #0f172a;
                    color: #f9fafb;
                    border: 1px solid #334155;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
                }
                body.buddy-dark .leaflet-popup-content {
                    color: #f9fafb;
                }
                body.buddy-dark .leaflet-popup-tip {
                    background: #0f172a;
                    border: 1px solid #334155;
                    box-shadow: none;
                }
                body.buddy-dark .leaflet-container a.leaflet-popup-close-button {
                    color: #cbd5e1;
                }
                body.buddy-dark .leaflet-container a.leaflet-popup-close-button:hover {
                    color: #ffffff;
                }
                .buddy-user-card-self {
                    background: #eff6ff;
                    border: 1px solid #bfdbfe;
                }
                body.buddy-dark .buddy-user-card-self {
                    background: #172033;
                    border: 1px solid #2f4b78;
                }
                .buddy-user-card-offline {
                    background: #f3f4f6;
                    border: 1px solid #d1d5db;
                }
                body.buddy-dark .buddy-user-card-offline {
                    background: #1e293b;
                    border: 1px solid #475569;
                }
                body.buddy-dark .q-field__control {
                    background: #111827;
                    color: #f9fafb;
                }
                body.buddy-dark .q-field__native,
                body.buddy-dark .q-field__input,
                body.buddy-dark .q-field__label,
                body.buddy-dark .q-field__marginal,
                body.buddy-dark .q-field input {
                    color: #f9fafb !important;
                }
                body.buddy-dark .q-drawer {
                    background: #0f172a;
                    color: #f9fafb;
                }
            </style>
            <script>
                (() => {
                    const applyTheme = (theme, persist = false) => {
                        const normalized = String(theme || 'light').toLowerCase() === 'dark' ? 'dark' : 'light';
                        const apply = () => {
                            if (document.body) {
                                document.body.classList.toggle('buddy-dark', normalized === 'dark');
                            }
                        };
                        apply();
                        if (!document.body) {
                            window.addEventListener('DOMContentLoaded', apply, {once: true});
                        }
                        if (persist) {
                            localStorage.setItem('buddy_radar_theme', normalized);
                        }
                        return normalized;
                    };
                    window.__buddyRadarApplyTheme = applyTheme;
                    window.__buddyRadarGetTheme = () => localStorage.getItem('buddy_radar_theme') || 'light';
                    window.__buddyRadarMarkerSessionToken = () => {
                        try {
                            const raw = sessionStorage.getItem('buddy_radar_session_state');
                            if (!raw) {
                                return '';
                            }
                            const data = JSON.parse(raw);
                            return String(data?.session_token || '');
                        } catch (error) {
                            return '';
                        }
                    };
                    window.__buddyRadarMarkerNotify = (message, isError = false) => {
                        if (!message) return;
                        try {
                            if (window.Quasar && window.Quasar.Notify) {
                                window.Quasar.Notify.create({message, type: isError ? 'negative' : 'positive', position: 'top'});
                                return;
                            }
                        } catch (error) {
                        }
                        if (isError) {
                            alert(message);
                        }
                    };
                    window.__buddyRadarMarkerUpsert = async (markerId, latitude, longitude, textareaId) => {
                        const sessionToken = window.__buddyRadarMarkerSessionToken();
                        const textarea = document.getElementById(textareaId);
                        const message = textarea ? textarea.value : '';
                        if (!sessionToken) {
                            window.__buddyRadarMarkerNotify('Sitzung fehlt. Bitte neu verbinden.', true);
                            return false;
                        }
                        const response = await fetch('/api/marker-upsert', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                session_token: sessionToken,
                                marker_id: markerId,
                                latitude,
                                longitude,
                                message,
                            }),
                        });
                        if (!response.ok) {
                            let detail = 'Marker konnte nicht gespeichert werden.';
                            try {
                                const data = await response.json();
                                if (data && data.detail) {
                                    detail = String(data.detail);
                                }
                            } catch (error) {
                            }
                            window.__buddyRadarMarkerNotify(detail, true);
                            return false;
                        }
                        const closeButton = document.querySelector('.leaflet-popup-close-button');
                        if (closeButton) {
                            closeButton.click();
                        }
                        window.__buddyRadarMarkerNotify('Marker gespeichert');
                        return true;
                    };
                    window.__buddyRadarMarkerDelete = async (markerId) => {
                        const sessionToken = window.__buddyRadarMarkerSessionToken();
                        if (!sessionToken) {
                            window.__buddyRadarMarkerNotify('Sitzung fehlt. Bitte neu verbinden.', true);
                            return false;
                        }
                        if (!confirm('Marker wirklich löschen?')) {
                            return false;
                        }
                        const response = await fetch('/api/marker-delete', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                session_token: sessionToken,
                                marker_id: markerId,
                            }),
                        });
                        if (!response.ok) {
                            let detail = 'Marker konnte nicht gelöscht werden.';
                            try {
                                const data = await response.json();
                                if (data && data.detail) {
                                    detail = String(data.detail);
                                }
                            } catch (error) {
                            }
                            window.__buddyRadarMarkerNotify(detail, true);
                            return false;
                        }
                        const closeButton = document.querySelector('.leaflet-popup-close-button');
                        if (closeButton) {
                            closeButton.click();
                        }
                        window.__buddyRadarMarkerNotify('Marker gelöscht');
                        return true;
                    };
                    applyTheme(window.__buddyRadarGetTheme(), false);
                })();
            </script>
            '''
        )
        state: dict = {
            'connected': False,
            'user_id': None,
            'username': '',
            'code': '',
            'self_lat': None,
            'self_lon': None,
            'last_rendered_change_version': -1,
            'last_render_ts': 0.0,
            'throttled_until_ts': 0.0,
            'current_refresh_mode': 'normal',
            'session_epoch': 0,
            'map_view_initialized': False,
            'theme': 'light',
            'session_token': '',
            'marker_mode': False,
            'pending_marker_lat': None,
            'pending_marker_lon': None,
        }

        client_ip = bot_guard.resolve_client_ip(request) if bot_guard is not None else 'unknown'

        def ui_rate_limited(action: str, label: str) -> tuple[bool, int]:
            allowed, retry_after, _ = _check_rate_limit(action, request)
            if allowed:
                return False, 0
            wait_for = max(1, int(retry_after or 1))
            text = f'{label} gedrosselt · bitte {wait_for} s warten'
            status_label.text = text
            ui.notify(text, type='warning')
            return True, wait_for

        async def get_or_create_browser_user_id() -> str:
            user_id = await ui.run_javascript(
                '''
                (() => {
                    let sessionUid = sessionStorage.getItem('buddy_radar_session_user_id');
                    if (sessionUid) {
                        return sessionUid;
                    }

                    let deviceUid = localStorage.getItem('buddy_radar_device_id');
                    if (!deviceUid) {
                        deviceUid = (self.crypto && self.crypto.randomUUID)
                            ? self.crypto.randomUUID()
                            : 'device-' + Math.random().toString(36).slice(2);
                        localStorage.setItem('buddy_radar_device_id', deviceUid);
                    }

                    const sessionPart = (self.crypto && self.crypto.randomUUID)
                        ? self.crypto.randomUUID()
                        : 'session-' + Math.random().toString(36).slice(2);
                    sessionUid = `${deviceUid}:${sessionPart}`;
                    sessionStorage.setItem('buddy_radar_session_user_id', sessionUid);
                    return sessionUid;
                })()
                ''',
                timeout=5.0,
            )
            return str(user_id or uuid4())


        async def load_resume_session_state() -> dict:
            result = await ui.run_javascript(
                '''
                (() => {
                    try {
                        const raw = sessionStorage.getItem('buddy_radar_session_state');
                        return raw ? JSON.parse(raw) : null;
                    } catch (error) {
                        return null;
                    }
                })()
                ''',
                timeout=3.0,
            )
            return result if isinstance(result, dict) else {}

        async def save_resume_session_state() -> None:
            payload = {
                'session_token': str(state.get('session_token') or ''),
                'user_id': str(state.get('user_id') or ''),
                'username': str(state.get('username') or ''),
                'self_lat': state.get('self_lat'),
                'self_lon': state.get('self_lon'),
            }
            payload_json = json.dumps(payload, ensure_ascii=False)
            await ui.run_javascript(
                f'''
                (() => {{
                    sessionStorage.setItem('buddy_radar_session_state', {payload_json!r});
                    return true;
                }})()
                ''',
                timeout=3.0,
            )

        async def clear_resume_session_state() -> None:
            await ui.run_javascript(
                '''
                (() => {
                    sessionStorage.removeItem('buddy_radar_session_state');
                    return true;
                })()
                ''',
                timeout=3.0,
            )


        async def set_disconnect_beacon(enabled: bool) -> None:
            session_token = str(state.get('session_token') or '')
            if not enabled or not session_token:
                await ui.run_javascript(
                    '''
                    (() => {
                        window.__buddyRadarDisconnectPayload = null;
                        return true;
                    })()
                    ''',
                    timeout=3.0,
                )
                return
            await ui.run_javascript(
                f'''
                (() => {{
                    window.__buddyRadarDisconnectPayload = {{
                        session_token: {session_token!r},
                    }};
                    return true;
                }})()
                ''',
                timeout=3.0,
            )

        async def install_disconnect_beacon() -> None:
            await ui.run_javascript(
                '''
                (() => {
                    if (window.__buddyRadarDisconnectHandlerInstalled) {
                        return true;
                    }

                    const sendOffline = () => {
                        const payload = window.__buddyRadarDisconnectPayload;
                        if (!payload || !payload.session_token) {
                            return;
                        }
                        const body = JSON.stringify({
                            session_token: payload.session_token,
                        });
                        try {
                            if (navigator.sendBeacon) {
                                const blob = new Blob([body], {type: 'application/json'});
                                navigator.sendBeacon('/api/disconnect-beacon', blob);
                                return;
                            }
                        } catch (error) {
                        }
                        try {
                            fetch('/api/disconnect-beacon', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body,
                                keepalive: true,
                            });
                        } catch (error) {
                        }
                    };

                    window.addEventListener('pagehide', sendOffline);
                    window.addEventListener('beforeunload', sendOffline);
                    window.__buddyRadarDisconnectHandlerInstalled = true;
                    return true;
                })()
                ''',
                timeout=5.0,
            )

        async def apply_theme(theme: str, persist: bool = True) -> None:
            normalized_theme = 'dark' if str(theme).strip().lower() == 'dark' else 'light'
            state['theme'] = normalized_theme
            theme_button.icon = 'light_mode' if normalized_theme == 'dark' else 'dark_mode'
            try:
                await ui.run_javascript(
                    f'''
                    (() => {{
                        if (window.__buddyRadarApplyTheme) {{
                            return window.__buddyRadarApplyTheme({normalized_theme!r}, {str(persist).lower()});
                        }}
                        return {normalized_theme!r};
                    }})()
                    ''',
                    timeout=1.5,
                )
            except Exception:
                pass

        async def load_theme() -> None:
            try:
                stored_theme = await ui.run_javascript(
                    '''
                    (() => window.__buddyRadarGetTheme ? window.__buddyRadarGetTheme() : 'light')()
                    ''',
                    timeout=1.5,
                )
                normalized_theme = 'dark' if str(stored_theme or 'light').strip().lower() == 'dark' else 'light'
            except Exception:
                normalized_theme = 'light'
            state['theme'] = normalized_theme
            theme_button.icon = 'light_mode' if normalized_theme == 'dark' else 'dark_mode'
            try:
                await ui.run_javascript(
                    f'''
                    (() => {{
                        if (window.__buddyRadarApplyTheme) {{
                            return window.__buddyRadarApplyTheme({normalized_theme!r}, false);
                        }}
                        return {normalized_theme!r};
                    }})()
                    ''',
                    timeout=1.5,
                )
            except Exception:
                pass

        async def toggle_theme() -> None:
            next_theme = 'dark' if state.get('theme') != 'dark' else 'light'
            await apply_theme(next_theme, persist=True)

        async def get_geolocation() -> dict:
            result = await ui.run_javascript(
                '''
                return await new Promise(async (resolve) => {
                    try {
                        if (!window.isSecureContext) {
                            resolve({ok: false, error: 'Standortzugriff benötigt HTTPS oder localhost.'});
                            return;
                        }
                        if (!navigator.geolocation) {
                            resolve({ok: false, error: 'Geolocation wird vom Browser nicht unterstützt.'});
                            return;
                        }

                        const readPosition = (options) => new Promise((resolvePosition) => {
                            navigator.geolocation.getCurrentPosition(
                                pos => resolvePosition({
                                    ok: true,
                                    latitude: pos.coords.latitude,
                                    longitude: pos.coords.longitude,
                                    accuracy: pos.coords.accuracy,
                                    device_time: new Date(pos.timestamp).toISOString(),
                                }),
                                err => resolvePosition({
                                    ok: false,
                                    code: err.code,
                                    error: err.message || 'Standort konnte nicht gelesen werden.',
                                }),
                                options,
                            );
                        });

                        const fastTry = await readPosition({
                            enableHighAccuracy: false,
                            timeout: 8000,
                            maximumAge: 60000,
                        });
                        if (fastTry.ok) {
                            resolve(fastTry);
                            return;
                        }

                        if (fastTry.code !== 2 && fastTry.code !== 3) {
                            const codeMap = {
                                1: 'Standortfreigabe verweigert.',
                                2: 'Standort momentan nicht verfügbar.',
                                3: 'Standortabfrage hat zu lange gedauert.',
                            };
                            resolve({ok: false, error: codeMap[fastTry.code] || fastTry.error});
                            return;
                        }

                        const preciseTry = await readPosition({
                            enableHighAccuracy: true,
                            timeout: 25000,
                            maximumAge: 0,
                        });
                        if (preciseTry.ok) {
                            resolve(preciseTry);
                            return;
                        }

                        const codeMap = {
                            1: 'Standortfreigabe verweigert.',
                            2: 'Standort momentan nicht verfügbar. Bitte Standortdienste/GPS prüfen.',
                            3: 'Standortabfrage hat zu lange gedauert.',
                        };
                        resolve({ok: false, error: codeMap[preciseTry.code] || preciseTry.error});
                    } catch (error) {
                        resolve({ok: false, error: String(error)});
                    }
                })
                ''',
                timeout=40.0,
            )
            if not isinstance(result, dict):
                raise RuntimeError('Ungültige Geolokationsdaten empfangen.')
            if not result.get('ok'):
                raise RuntimeError(str(result.get('error') or 'Standort konnte nicht gelesen werden.'))
            return result

        def sorted_visible_users(entries: list[dict]) -> list[dict]:
            def rank(entry: dict) -> tuple[int, str, str]:
                is_self = entry.get('user_id') == state['user_id']
                status = str(entry.get('status') or 'online')
                return (
                    0 if is_self else 1 if status == 'online' else 2,
                    str(entry.get('username') or '').casefold(),
                    str(entry.get('user_id') or ''),
                )

            return sorted(entries, key=rank)

        def username_short_label(username: str) -> str:
            compact = ''.join(str(username or '').strip().split())
            if not compact:
                compact = '???'
            return compact[:3].upper()

        def labeled_visible_users(entries: list[dict]) -> list[dict]:
            labeled_entries: list[dict] = []
            for entry in sorted_visible_users(entries):
                enriched = dict(entry)
                enriched['status'] = str(enriched.get('status') or 'online')
                enriched['is_offline'] = enriched['status'] == 'offline'
                enriched['is_self'] = enriched.get('user_id') == state['user_id']
                enriched['display_label'] = username_short_label(str(enriched.get('username') or ''))
                labeled_entries.append(enriched)
            return labeled_entries

        def icon_js(label: str, variant: str) -> str:
            safe_label = escape(label)
            return (
                'L.divIcon({'
                'className: "",'
                f'html: "<div class=\\"buddy-marker-icon buddy-marker-{variant}\\">{safe_label}</div>",'
                'iconSize: [42, 34],'
                'iconAnchor: [21, 17],'
                'popupAnchor: [0, -18]'
                '})'
            )

        def marker_variant(entry: dict) -> str:
            if entry.get('status') == 'offline':
                return 'offline'
            if entry.get('user_id') == state['user_id']:
                return 'self'
            return 'other'

        def shared_marker_icon_js(marker: dict) -> str:
            marker_owner_user_id = str(marker.get('owner_user_id') or marker.get('updated_by_user_id') or '').strip()
            current_user_id = str(state.get('user_id') or '').strip()
            is_self_marker = bool(marker_owner_user_id and current_user_id and marker_owner_user_id == current_user_id)
            marker_class = 'buddy-note-marker-self' if is_self_marker else 'buddy-note-marker-other'
            return (
                'L.divIcon({'
                'className: "",'
                f"html: '<div class=\"buddy-note-marker {marker_class}\"><span>✎</span></div>',"
                'iconSize: [28, 28],'
                'iconAnchor: [14, 28],'
                'popupAnchor: [0, -24]'
                '})'
            )

        def marker_popup_html(marker: dict) -> str:
            marker_id = str(marker.get('marker_id') or '')
            textarea_suffix = ''.join(ch for ch in marker_id if ch.isalnum())[:24] or uuid4().hex[:8]
            textarea_id = f'buddy_marker_message_{textarea_suffix}'
            owner_username = str(marker.get('owner_username') or marker.get('updated_by_username') or 'Unbekannt')
            updated_by = str(marker.get('updated_by_username') or owner_username or 'Unbekannt')
            updated_at = str(marker.get('updated_at') or '-')
            message = str(marker.get('message') or '')
            latitude = float(marker.get('latitude') or 0.0)
            longitude = float(marker.get('longitude') or 0.0)
            delete_js = f"window.__buddyRadarMarkerDelete({json.dumps(marker_id)}); return false;"
            save_js = (
                f"window.__buddyRadarMarkerUpsert({json.dumps(marker_id)}, "
                f"{json.dumps(latitude)}, {json.dumps(longitude)}, {json.dumps(textarea_id)}); return false;"
            )
            return ''.join(
                [
                    '<div class="buddy-marker-popup">',
                    '<div class="buddy-marker-popup-top">',
                    f'<div class="buddy-marker-popup-title">Marker · {escape(owner_username)}</div>',
                    '</div>',
                    f'<div class="buddy-marker-popup-meta">Zuletzt geändert von {escape(updated_by)} · {escape(updated_at)}</div>',
                    (
                        f'<textarea id="{textarea_id}" class="buddy-marker-popup-textarea" '
                        f'maxlength="{MARKER_MESSAGE_MAX_LENGTH}" placeholder="Nachricht am Marker">'
                        f'{escape(message)}</textarea>'
                    ),
                    '<div class="buddy-marker-popup-actions">',
                    (
                        f'<button class="buddy-marker-popup-delete" title="Marker löschen" '
                        f'onclick="{escape(delete_js, quote=True)}">×</button>'
                    ),
                    (
                        f'<button class="buddy-marker-popup-save" '
                        f'onclick="{escape(save_js, quote=True)}">Speichern</button>'
                    ),
                    '</div>',
                    '</div>',
                ]
            )

        async def focus_user_on_map(entry: dict) -> None:
            try:
                target_lat = float(entry['latitude'])
                target_lon = float(entry['longitude'])
            except Exception:
                return
            state['map_view_initialized'] = True
            radar_map.set_zoom(14)
            radar_map.set_center((target_lat, target_lon))

        async def copy_coordinates(entry: dict) -> None:
            try:
                lat = float(entry['latitude'])
                lon = float(entry['longitude'])
            except Exception:
                ui.notify('Koordinaten konnten nicht kopiert werden.', type='warning')
                return

            coords_text = f'{lat:.6f}, {lon:.6f}'

            copied = await ui.run_javascript(
                f'''
                (() => {{
                    const text = {coords_text!r};

                    const fallbackCopy = () => {{
                        const el = document.createElement('textarea');
                        el.value = text;
                        el.setAttribute('readonly', '');
                        el.style.position = 'fixed';
                        el.style.opacity = '0';
                        document.body.appendChild(el);
                        el.select();
                        let ok = false;
                        try {{
                            ok = document.execCommand('copy');
                        }} catch (e) {{}}
                        document.body.removeChild(el);
                        return ok;
                    }};

                    try {{
                        if (navigator.clipboard && window.isSecureContext) {{
                            return navigator.clipboard.writeText(text).then(() => true).catch(() => fallbackCopy());
                        }}
                        return fallbackCopy();
                    }} catch (e) {{
                        return fallbackCopy();
                    }}
                }})()
                ''',
                timeout=3.0,
            )

            if copied:
                ui.notify(f'Koordinaten kopiert: {coords_text}', type='positive')
            else:
                ui.notify('Kopieren fehlgeschlagen.', type='warning')

        def render_map(entries: list[dict], markers: list[dict] | None = None) -> None:
            labeled_entries = labeled_visible_users(entries)
            radar_map.clear_layers()
            radar_map.tile_layer(
                url_template='https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
                options={'maxZoom': 19, 'attribution': '© OpenStreetMap'},
            )
            if state['connected'] and state['self_lat'] is not None and state['self_lon'] is not None:
                self_marker = radar_map.marker(latlng=(state['self_lat'], state['self_lon']))
                self_label = username_short_label(state['username'])
                self_marker.run_method(':setIcon', icon_js(self_label, 'self'))
                radar_map.run_layer_method(
                    self_marker.id,
                    'bindPopup',
                    f"{escape(self_label)} · {escape(state['username'])}<br>Status: Eigener Standort",
                )
                if not state['map_view_initialized']:
                    radar_map.set_center((state['self_lat'], state['self_lon']))
                    state['map_view_initialized'] = True
            for entry in labeled_entries:
                if state['connected'] and entry['user_id'] == state['user_id']:
                    continue
                marker = radar_map.marker(latlng=(entry['latitude'], entry['longitude']))
                label = str(entry['display_label'])
                marker.run_method(':setIcon', icon_js(label, marker_variant(entry)))
                status_text = 'Offline' if entry.get('status') == 'offline' else 'Online'
                time_text = entry.get('disconnected_at') if entry.get('status') == 'offline' else entry.get('device_time') or entry.get('updated_at', '-')
                popup_html = (
                    f"{escape(label)} · {escape(str(entry['username']))}"
                    f"<br>Status: {escape(status_text)}"
                    f"<br>{escape(str(time_text or '-'))}"
                )
                radar_map.run_layer_method(marker.id, 'bindPopup', popup_html)
            for shared_marker in markers or []:
                try:
                    marker_lat = float(shared_marker['latitude'])
                    marker_lon = float(shared_marker['longitude'])
                except Exception:
                    continue
                note_marker = radar_map.marker(latlng=(marker_lat, marker_lon))
                note_marker.run_method(':setIcon', shared_marker_icon_js(shared_marker))
                radar_map.run_layer_method(note_marker.id, 'bindPopup', marker_popup_html(shared_marker))

        @ui.refreshable
        def visible_users_view(entries: list[dict]) -> None:
            labeled_entries = labeled_visible_users(entries)
            if not labeled_entries:
                ui.label('Keine Nutzer sichtbar.').classes('buddy-text-muted')
                return
            for entry in labeled_entries:
                card_classes = 'buddy-surface w-full rounded-xl shadow-sm cursor-pointer hover:shadow-md transition-shadow'
                if entry['is_self']:
                    card_classes += ' buddy-user-card-self'
                if entry['is_offline']:
                    card_classes += ' buddy-user-card-offline'
                with ui.card().classes(card_classes).on('click', lambda e=None, item=entry: focus_user_on_map(item)):
                    with ui.row().classes('w-full items-center gap-3'):
                        badge_classes = 'buddy-number-badge'
                        badge_text = str(entry['display_label'])
                        if entry['is_offline']:
                            badge_classes += ' buddy-number-badge-offline'
                        elif entry['is_self']:
                            badge_classes += ' buddy-number-badge-self'
                        ui.label(badge_text).classes(badge_classes)
                        with ui.column().classes('gap-0'):
                            ui.label(entry['username']).classes('text-base font-medium buddy-text-primary')
                            if entry['is_offline']:
                                ui.label('Getrennt').classes('text-xs buddy-status-offline')
                            elif entry['is_self']:
                                ui.label('Eigener Standort').classes('text-xs buddy-status-self')
                            else:
                                ui.label('Verbunden').classes('text-xs buddy-status-other')
                    coords_label = ui.label(
                        f"Lat: {entry['latitude']:.5f}, Lon: {entry['longitude']:.5f}"
                    ).classes('text-sm buddy-text-secondary cursor-pointer')
                    coords_label.on('click', lambda e=None, item=entry: copy_coordinates(item))
                    time_label = 'Offline seit' if entry['is_offline'] else 'Letztes Update'
                    time_value = entry.get('disconnected_at') if entry['is_offline'] else entry.get('device_time') or entry.get('updated_at', '-')
                    ui.label(f'{time_label}: {time_value}').classes('text-xs buddy-text-muted')

        async def update_ui_from_server(force: bool = False, expected_change_version: int | None = None) -> bool:
            if not state['connected'] or not state.get('session_token'):
                return False

            limited, wait_for = ui_rate_limited('ui_visible_users', 'Abruf')
            if limited and not force:
                return False
            if limited and force:
                status_label.text = f'Abruf gedrosselt · bitte {wait_for} s warten'
                return False

            try:
                change_state = _get_change_state_for_session(state['session_token'], client_ip=client_ip)
            except RuntimeError as exc:
                state['connected'] = False
                state['session_token'] = ''
                await clear_resume_session_state()
                await set_disconnect_beacon(False)
                status_label.text = str(exc)
                return False

            change_version = int(change_state.get('change_version') or 0)
            recent_changes = int(change_state.get('recent_changes') or 0)
            now_ts = monotonic()
            throttled = recent_changes > UPDATE_STORM_THRESHOLD
            periodic_refresh_due = (now_ts - state['last_render_ts']) >= MAP_REFRESH_SECONDS

            if throttled:
                state['current_refresh_mode'] = 'throttled'
                if now_ts < state['throttled_until_ts'] and not force and not periodic_refresh_due:
                    return False
                state['throttled_until_ts'] = now_ts + MAP_THROTTLED_REFRESH_SECONDS
            else:
                state['current_refresh_mode'] = 'normal'
                state['throttled_until_ts'] = 0.0

            if expected_change_version is not None and expected_change_version > change_version:
                change_version = expected_change_version

            if not force and not periodic_refresh_due and change_version == state['last_rendered_change_version']:
                return False

            try:
                users = await _fetch_visible_users_for_session(state['session_token'], client_ip=client_ip)
                markers = await _fetch_visible_markers_for_session(state['session_token'], client_ip=client_ip)
            except RuntimeError as exc:
                state['connected'] = False
                state['session_token'] = ''
                await clear_resume_session_state()
                await set_disconnect_beacon(False)
                status_label.text = str(exc)
                return False

            render_map(users, markers)
            visible_users_view.refresh(users)
            state['last_rendered_change_version'] = change_version
            state['last_render_ts'] = now_ts
            if throttled:
                status_label.text = (
                    f'Verbunden · viele Änderungen erkannt · Kartenupdate max. alle '
                    f'{MAP_THROTTLED_REFRESH_SECONDS} s'
                )
            return True


        async def send_location_once(*, expected_epoch: int | None = None, skip_rate_limit: bool = False) -> None:
            epoch = int(expected_epoch if expected_epoch is not None else state['session_epoch'])
            if not state['connected'] or not state.get('session_token'):
                return
            if not skip_rate_limit:
                limited, _ = ui_rate_limited('ui_update', 'Standortupdate')
                if limited:
                    return
            try:
                geo = await get_geolocation()
                if epoch != state['session_epoch']:
                    return
                payload = UpdateLocationRequest(
                    session_token=str(state['session_token']),
                    latitude=float(geo['latitude']),
                    longitude=float(geo['longitude']),
                    accuracy=float(geo.get('accuracy') or 0.0),
                    device_time=geo.get('device_time'),
                )
                result = await _store_location_for_session(payload, client_ip=client_ip)
                if epoch != state['session_epoch']:
                    return
                state['self_lat'] = float(payload.latitude)
                state['self_lon'] = float(payload.longitude)
                state['user_id'] = str(result.get('user_id') or state['user_id'])
                await save_resume_session_state()
                status_label.text = f"Verbunden · letztes Senden: {result['updated_at']}"
                await update_ui_from_server(force=True, expected_change_version=int(result['change_version']))
            except RuntimeError as exc:
                if epoch != state['session_epoch']:
                    return
                state['connected'] = False
                state['session_token'] = ''
                await clear_resume_session_state()
                await set_disconnect_beacon(False)
                status_label.text = str(exc)
            except Exception as exc:
                if epoch != state['session_epoch']:
                    return
                status_label.text = f'Standortfehler: {exc}'

        async def refresh_visible_users() -> None:
            if not state['connected'] or not state.get('session_token'):
                return
            try:
                refreshed = await update_ui_from_server()
                if not refreshed and state['current_refresh_mode'] == 'normal':
                    status_label.text = 'Verbunden'
            except Exception as exc:
                status_label.text = f'Abruffehler: {exc}'

        def close_new_marker_dialog() -> None:
            state['pending_marker_lat'] = None
            state['pending_marker_lon'] = None
            new_marker_message.value = ''
            new_marker_dialog.close()

        async def arm_marker_mode() -> None:
            if not state['connected'] or not state.get('session_token'):
                ui.notify('Bitte zuerst verbinden.', type='warning')
                return
            state['marker_mode'] = True
            status_label.text = 'Marker-Modus aktiv · auf die Karte klicken'
            ui.notify('Marker-Modus aktiv · auf die Karte klicken', type='positive')

        def handle_map_click(e: events.GenericEventArguments) -> None:
            if not state.get('marker_mode'):
                return
            if not state['connected'] or not state.get('session_token'):
                state['marker_mode'] = False
                return
            latlng = e.args.get('latlng') or {}
            try:
                state['pending_marker_lat'] = float(latlng.get('lat'))
                state['pending_marker_lon'] = float(latlng.get('lng'))
            except Exception:
                state['marker_mode'] = False
                ui.notify('Marker-Koordinaten konnten nicht gelesen werden.', type='warning')
                return
            state['marker_mode'] = False
            marker_position_label.text = f"Lat: {state['pending_marker_lat']:.5f}, Lon: {state['pending_marker_lon']:.5f}"
            new_marker_message.value = ''
            new_marker_dialog.open()

        async def save_new_marker() -> None:
            if not state['connected'] or not state.get('session_token'):
                ui.notify('Bitte zuerst verbinden.', type='warning')
                return
            if state['pending_marker_lat'] is None or state['pending_marker_lon'] is None:
                ui.notify('Kein Markerpunkt ausgewählt.', type='warning')
                return
            limited, _ = ui_rate_limited('ui_update', 'Marker speichern')
            if limited:
                return
            try:
                payload = MarkerUpsertRequest(
                    session_token=str(state['session_token']),
                    latitude=float(state['pending_marker_lat']),
                    longitude=float(state['pending_marker_lon']),
                    message=str(new_marker_message.value or ''),
                )
                result = await _upsert_marker_for_session(payload, client_ip=client_ip)
                close_new_marker_dialog()
                status_label.text = f"Marker gespeichert · {result['updated_at']}"
                await update_ui_from_server(force=True, expected_change_version=int(result['change_version']))
            except RuntimeError as exc:
                status_label.text = str(exc)
            except Exception as exc:
                status_label.text = f'Markerfehler: {exc}'


        async def connect() -> None:
            username = username_input.value.strip()
            code = code_input.value.strip()
            if len(username) < USERNAME_MIN_LENGTH:
                ui.notify(
                    f'Benutzername muss mindestens {USERNAME_MIN_LENGTH} Zeichen lang sein.',
                    type='warning',
                )
                return
            if len(code) < CODE_MIN_LENGTH:
                ui.notify(f'Der Code muss mindestens {CODE_MIN_LENGTH} Zeichen lang sein.', type='warning')
                return
            limited, _ = ui_rate_limited('ui_connect', 'Verbindungsversuch')
            if limited:
                return
            state['session_epoch'] += 1
            connect_epoch = state['session_epoch']
            state['user_id'] = await get_or_create_browser_user_id()
            state['username'] = username
            state['code'] = code
            state['session_token'] = ''
            state['connected'] = False
            state['self_lat'] = None
            state['self_lon'] = None
            state['last_rendered_change_version'] = -1
            state['last_render_ts'] = 0.0
            state['throttled_until_ts'] = 0.0
            state['current_refresh_mode'] = 'normal'
            state['map_view_initialized'] = False
            state['marker_mode'] = False
            state['pending_marker_lat'] = None
            state['pending_marker_lon'] = None
            await clear_resume_session_state()
            await set_disconnect_beacon(False)
            status_label.text = 'Verbinde …'
            try:
                geo = await get_geolocation()
                if connect_epoch != state['session_epoch']:
                    return
                payload = ConnectRequest(
                    user_id=str(state['user_id']),
                    username=state['username'],
                    code=state['code'],
                    latitude=float(geo['latitude']),
                    longitude=float(geo['longitude']),
                    accuracy=float(geo.get('accuracy') or 0.0),
                    device_time=geo.get('device_time'),
                )
                result = await _connect_user(payload, client_ip=client_ip)
                if connect_epoch != state['session_epoch']:
                    return
                state['self_lat'] = float(payload.latitude)
                state['self_lon'] = float(payload.longitude)
                state['user_id'] = str(result.get('user_id') or state['user_id'])
                state['session_token'] = str(result.get('session_token') or '')
                state['connected'] = True
                await save_resume_session_state()
                await set_disconnect_beacon(True)
                status_label.text = f"Verbunden · letztes Senden: {result['updated_at']}"
                await update_ui_from_server(force=True, expected_change_version=int(result['change_version']))
            except RuntimeError as exc:
                if connect_epoch != state['session_epoch']:
                    return
                state['connected'] = False
                state['session_token'] = ''
                await clear_resume_session_state()
                await set_disconnect_beacon(False)
                status_label.text = str(exc)
            except Exception as exc:
                if connect_epoch != state['session_epoch']:
                    return
                state['connected'] = False
                state['session_token'] = ''
                await clear_resume_session_state()
                await set_disconnect_beacon(False)
                status_label.text = f'Verbindungsfehler: {exc}'


        async def disconnect() -> None:
            limited, _ = ui_rate_limited('ui_disconnect', 'Trennen')
            if limited:
                return
            current_session_token = str(state.get('session_token') or '')
            state['session_epoch'] += 1
            state['connected'] = False
            await set_disconnect_beacon(False)

            users: list[dict] = []
            if current_session_token:
                try:
                    result = await _disconnect_session(current_session_token, client_ip=client_ip)
                    users = list(result.get('users') or [])
                except RuntimeError as exc:
                    status_label.text = str(exc)
                    state['session_token'] = ''
                    await clear_resume_session_state()
                    return
                except Exception as exc:
                    status_label.text = f'Trennfehler: {exc}'
                    state['session_token'] = ''
                    await clear_resume_session_state()
                    return

            state['session_token'] = ''
            await clear_resume_session_state()
            state['self_lat'] = None
            state['self_lon'] = None
            state['last_rendered_change_version'] = -1
            state['last_render_ts'] = 0.0
            state['throttled_until_ts'] = 0.0
            state['current_refresh_mode'] = 'normal'
            state['map_view_initialized'] = False
            state['marker_mode'] = False
            state['pending_marker_lat'] = None
            state['pending_marker_lon'] = None
            status_label.text = 'Getrennt'
            render_map(users, [])
            visible_users_view.refresh(users)

        async def resume_session_from_storage() -> None:
            saved_state = await load_resume_session_state()
            session_token = str(saved_state.get('session_token') or '').strip()
            if not session_token:
                return

            state['session_epoch'] += 1
            resume_epoch = state['session_epoch']
            stored_user_id = str(saved_state.get('user_id') or '').strip()

            try:
                session = _validate_session_token(
                    session_token,
                    client_ip=client_ip,
                    user_id=stored_user_id or None,
                )
            except RuntimeError:
                await clear_resume_session_state()
                await set_disconnect_beacon(False)
                status_label.text = 'Sitzung abgelaufen. Bitte neu verbinden.'
                return

            state['connected'] = True
            state['session_token'] = session.token
            state['user_id'] = session.user_id
            state['username'] = session.username
            state['code'] = ''
            state['last_rendered_change_version'] = -1
            state['last_render_ts'] = 0.0
            state['throttled_until_ts'] = 0.0
            state['current_refresh_mode'] = 'normal'
            state['map_view_initialized'] = False

            try:
                state['self_lat'] = float(saved_state.get('self_lat')) if saved_state.get('self_lat') is not None else None
            except Exception:
                state['self_lat'] = None
            try:
                state['self_lon'] = float(saved_state.get('self_lon')) if saved_state.get('self_lon') is not None else None
            except Exception:
                state['self_lon'] = None

            username_input.value = session.username
            code_input.value = ''

            await save_resume_session_state()
            await set_disconnect_beacon(True)
            status_label.text = 'Sitzung wiederhergestellt …'

            await send_location_once(expected_epoch=resume_epoch, skip_rate_limit=True)
            if state['connected'] and state['last_rendered_change_version'] < 0:
                await update_ui_from_server(force=True)

        with ui.left_drawer(value=False).props('overlay bordered').classes('buddy-drawer-surface w-96 max-w-full p-0 overflow-hidden') as connection_drawer:
            with ui.column().classes('w-full h-full gap-0 no-wrap'):
                with ui.column().classes('w-full p-4 gap-4'):
                    ui.label('Verbindung').classes('text-lg font-semibold buddy-text-primary')
                    username_input = ui.input('Benutzername').props(
                        f'outlined maxlength={USERNAME_MAX_LENGTH} counter'
                    ).classes('w-full')
                    code_input = ui.input('Code').props('outlined type=password').classes('w-full')
                    with ui.row().classes('w-full gap-2'):
                        ui.button('Verbinden', on_click=connect).props('unelevated').classes('flex-1')
                        ui.button('Trennen', on_click=disconnect).props('flat').classes('flex-1')
                    ui.button('Marker setzen', on_click=arm_marker_mode).props('outline').classes('w-full')
                    status_label = ui.label('Nicht verbunden').classes('text-sm buddy-text-secondary')
                ui.separator().classes('buddy-section-separator')
                with ui.column().classes('w-full flex-1 min-h-0 p-4 gap-3 overflow-auto').style('max-height: calc(100vh - 220px);'):
                    ui.label('Bro Nutzer').classes('text-lg font-semibold buddy-text-primary')
                    visible_users_view([])

        with ui.dialog() as new_marker_dialog, ui.card().classes('buddy-surface w-[30rem] max-w-full rounded-2xl shadow-lg p-4 gap-3'):
            ui.label('Marker setzen').classes('text-lg font-semibold buddy-text-primary')
            marker_position_label = ui.label('Bitte Punkt auf der Karte wählen.').classes('text-sm buddy-text-secondary')
            new_marker_message = ui.textarea('Nachricht').props(f'outlined maxlength={MARKER_MESSAGE_MAX_LENGTH} counter').classes('w-full')
            with ui.row().classes('w-full justify-end gap-2'):
                ui.button('Abbrechen', on_click=close_new_marker_dialog).props('flat')
                ui.button('Speichern', on_click=save_new_marker).props('unelevated')

        with ui.header().classes('buddy-header items-center justify-between px-4 py-3'):
            ui.button(icon='menu', on_click=connection_drawer.toggle).props('flat round color=white')
            ui.label(f'{APP_NAME} v{APP_VERSION}').classes('text-lg font-semibold')
            ui.space()
            theme_button = ui.button(icon='dark_mode', on_click=toggle_theme).props('flat round color=white')

        with ui.column().classes('buddy-app-bg buddy-main-full'):
            with ui.card().classes('buddy-map-card-full'):
                radar_map = ui.leaflet(center=(48.137154, 11.576124), zoom=6).classes(
                    'buddy-map-full'
                )
                radar_map.on('map-click', handle_map_click)

        await radar_map.initialized()
        render_map([], [])

        await install_disconnect_beacon()
        ui.timer(0.2, load_theme, once=True)
        ui.timer(0.35, resume_session_from_storage, once=True)

        ui.timer(GPS_UPDATE_SECONDS, send_location_once)
        ui.timer(MAP_CHANGE_POLL_SECONDS, refresh_visible_users)
