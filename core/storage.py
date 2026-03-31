from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @contextmanager
    def connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA busy_timeout = 10000')
            conn.execute('PRAGMA foreign_keys = ON')
            if write:
                conn.execute('BEGIN IMMEDIATE')
            yield conn
            if write:
                conn.commit()
        except Exception:
            if write:
                conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        with self.connection(write=True) as conn:
            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS presence (
                    user_id TEXT PRIMARY KEY,
                    username_key TEXT,
                    group_hash TEXT NOT NULL,
                    payload_encrypted TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'online',
                    disconnected_at TEXT
                )
                '''
            )
            columns = {row['name'] for row in conn.execute('PRAGMA table_info(presence)').fetchall()}
            if 'username_key' not in columns:
                conn.execute('ALTER TABLE presence ADD COLUMN username_key TEXT')
            if 'status' not in columns:
                conn.execute("ALTER TABLE presence ADD COLUMN status TEXT NOT NULL DEFAULT 'online'")
            if 'disconnected_at' not in columns:
                conn.execute('ALTER TABLE presence ADD COLUMN disconnected_at TEXT')

            conn.execute(
                'CREATE INDEX IF NOT EXISTS idx_presence_group_updated ON presence(group_hash, updated_at)'
            )
            conn.execute(
                'CREATE INDEX IF NOT EXISTS idx_presence_group_status ON presence(group_hash, status, updated_at)'
            )
            conn.execute(
                'CREATE UNIQUE INDEX IF NOT EXISTS idx_presence_username_key_unique '
                'ON presence(username_key) WHERE username_key IS NOT NULL'
            )

            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS group_meta (
                    group_hash TEXT PRIMARY KEY,
                    change_version INTEGER NOT NULL DEFAULT 0,
                    last_change_at TEXT NOT NULL DEFAULT '',
                    last_maintenance_at TEXT NOT NULL DEFAULT ''
                )
                '''
            )
            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS change_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_hash TEXT NOT NULL DEFAULT '',
                    changed_at TEXT NOT NULL
                )
                '''
            )
            change_log_columns = {row['name'] for row in conn.execute('PRAGMA table_info(change_log)').fetchall()}
            if 'group_hash' not in change_log_columns:
                conn.execute("ALTER TABLE change_log ADD COLUMN group_hash TEXT NOT NULL DEFAULT ''")
            conn.execute(
                'CREATE INDEX IF NOT EXISTS idx_change_log_group_changed_at ON change_log(group_hash, changed_at)'
            )
            conn.execute(
                '''
                INSERT INTO group_meta (group_hash, change_version, last_change_at, last_maintenance_at)
                VALUES ('__maintenance__', 0, '', '')
                ON CONFLICT(group_hash) DO NOTHING
                '''
            )

            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS group_markers (
                    marker_id TEXT PRIMARY KEY,
                    group_hash TEXT NOT NULL,
                    owner_user_id TEXT,
                    owner_username TEXT,
                    payload_encrypted TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                '''
            )
            marker_columns = {row['name'] for row in conn.execute('PRAGMA table_info(group_markers)').fetchall()}
            if 'owner_user_id' not in marker_columns:
                conn.execute('ALTER TABLE group_markers ADD COLUMN owner_user_id TEXT')
            if 'owner_username' not in marker_columns:
                conn.execute('ALTER TABLE group_markers ADD COLUMN owner_username TEXT')
            conn.execute(
                'CREATE INDEX IF NOT EXISTS idx_group_markers_group_updated ON group_markers(group_hash, updated_at)'
            )
            conn.execute(
                'CREATE UNIQUE INDEX IF NOT EXISTS idx_group_markers_group_owner_unique '
                'ON group_markers(group_hash, owner_user_id) WHERE owner_user_id IS NOT NULL AND owner_user_id != ""'
            )

    def _ensure_group_meta_row(self, conn: sqlite3.Connection, group_hash: str) -> None:
        conn.execute(
            '''
            INSERT INTO group_meta (group_hash, change_version, last_change_at, last_maintenance_at)
            VALUES (?, 0, '', '')
            ON CONFLICT(group_hash) DO NOTHING
            ''',
            (group_hash,),
        )

    def _bump_change_version(self, conn: sqlite3.Connection, group_hash: str, changed_at: str) -> int:
        self._ensure_group_meta_row(conn, group_hash)
        current_version = int(
            conn.execute(
                'SELECT change_version FROM group_meta WHERE group_hash = ?',
                (group_hash,),
            ).fetchone()['change_version']
        )
        next_version = current_version + 1
        conn.execute(
            '''
            UPDATE group_meta
            SET change_version = ?,
                last_change_at = ?
            WHERE group_hash = ?
            ''',
            (next_version, changed_at, group_hash),
        )
        conn.execute(
            'INSERT INTO change_log (group_hash, changed_at) VALUES (?, ?)',
            (group_hash, changed_at),
        )
        prune_threshold = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn.execute('DELETE FROM change_log WHERE changed_at < ?', (prune_threshold,))
        return next_version

    @staticmethod
    def normalize_username(username: str) -> str:
        return ' '.join(username.strip().split()).casefold()

    def find_by_username_key(self, username_key: str) -> sqlite3.Row | None:
        with self.connection() as conn:
            return conn.execute(
                '''
                SELECT user_id, username_key, group_hash, payload_encrypted, updated_at, status, disconnected_at
                FROM presence
                WHERE username_key = ?
                LIMIT 1
                ''',
                (username_key,),
            ).fetchone()

    def list_group_records_for_reclaim(self, group_hash: str) -> list[sqlite3.Row]:
        with self.connection() as conn:
            rows = conn.execute(
                '''
                SELECT user_id, username_key, group_hash, payload_encrypted, updated_at, status, disconnected_at
                FROM presence
                WHERE group_hash = ?
                ORDER BY updated_at DESC
                ''',
                (group_hash,),
            ).fetchall()
        return list(rows)

    def _maintenance_locked(
        self,
        conn: sqlite3.Connection,
        *,
        active_seconds: int,
        offline_retention_hours: int,
        maintenance_interval_seconds: int = 15,
    ) -> int:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        meta_row = conn.execute(
            '''
            SELECT last_maintenance_at
            FROM group_meta
            WHERE group_hash = '__maintenance__'
            LIMIT 1
            '''
        ).fetchone()
        last_maintenance_at = str(meta_row['last_maintenance_at'] or '') if meta_row else ''
        if last_maintenance_at:
            try:
                last_dt = datetime.fromisoformat(last_maintenance_at)
                if (now - last_dt).total_seconds() < maintenance_interval_seconds:
                    return 0
            except ValueError:
                pass

        stale_threshold = (now - timedelta(seconds=active_seconds)).isoformat()
        stale_rows = conn.execute(
            '''
            SELECT user_id, group_hash
            FROM presence
            WHERE status = 'online' AND updated_at < ?
            ''',
            (stale_threshold,),
        ).fetchall()
        offline_changed_groups = {str(row['group_hash']) for row in stale_rows}
        if stale_rows:
            conn.execute(
                '''
                UPDATE presence
                SET status = 'offline',
                    disconnected_at = ?,
                    updated_at = ?
                WHERE status = 'online' AND updated_at < ?
                ''',
                (now_iso, now_iso, stale_threshold),
            )

        purge_threshold = (now - timedelta(hours=offline_retention_hours)).isoformat()
        conn.execute(
            '''
            DELETE FROM presence
            WHERE status = 'offline' AND disconnected_at IS NOT NULL AND disconnected_at < ?
            ''',
            (purge_threshold,),
        )

        for group_hash in offline_changed_groups:
            self._bump_change_version(conn, group_hash, now_iso)

        conn.execute(
            '''
            INSERT INTO group_meta (group_hash, change_version, last_change_at, last_maintenance_at)
            VALUES ('__maintenance__', 0, '', ?)
            ON CONFLICT(group_hash) DO UPDATE SET last_maintenance_at = excluded.last_maintenance_at
            ''',
            (now_iso,),
        )
        return len(offline_changed_groups)

    def upsert_presence(
        self,
        user_id: str,
        username_key: str,
        group_hash: str,
        payload_encrypted: str,
        updated_at: str,
        *,
        active_seconds: int,
        offline_retention_hours: int,
    ) -> tuple[int, str]:
        with self.connection(write=True) as conn:
            self._maintenance_locked(
                conn,
                active_seconds=active_seconds,
                offline_retention_hours=offline_retention_hours,
            )
            existing = conn.execute(
                'SELECT user_id FROM presence WHERE username_key = ? LIMIT 1',
                (username_key,),
            ).fetchone()
            effective_user_id = str(existing['user_id']) if existing else user_id
            conn.execute(
                '''
                INSERT INTO presence (
                    user_id,
                    username_key,
                    group_hash,
                    payload_encrypted,
                    updated_at,
                    status,
                    disconnected_at
                )
                VALUES (?, ?, ?, ?, ?, 'online', NULL)
                ON CONFLICT(user_id) DO UPDATE SET
                    username_key = excluded.username_key,
                    group_hash = excluded.group_hash,
                    payload_encrypted = excluded.payload_encrypted,
                    updated_at = excluded.updated_at,
                    status = 'online',
                    disconnected_at = NULL
                ''',
                (effective_user_id, username_key, group_hash, payload_encrypted, updated_at),
            )
            return self._bump_change_version(conn, group_hash, updated_at), effective_user_id

    def set_presence_offline(self, user_id: str, group_hash: str, changed_at: str) -> int | None:
        with self.connection(write=True) as conn:
            row = conn.execute(
                '''
                SELECT user_id
                FROM presence
                WHERE user_id = ? AND group_hash = ?
                LIMIT 1
                ''',
                (user_id, group_hash),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                '''
                UPDATE presence
                SET status = 'offline',
                    disconnected_at = ?,
                    updated_at = ?
                WHERE user_id = ? AND group_hash = ?
                ''',
                (changed_at, changed_at, user_id, group_hash),
            )
            return self._bump_change_version(conn, group_hash, changed_at)

    def list_visible_group_records(
        self,
        group_hash: str,
        active_seconds: int,
        offline_retention_hours: int,
    ) -> list[dict]:
        online_threshold = (datetime.now(timezone.utc) - timedelta(seconds=active_seconds)).isoformat()
        offline_threshold = (datetime.now(timezone.utc) - timedelta(hours=offline_retention_hours)).isoformat()
        with self.connection() as conn:
            rows = conn.execute(
                '''
                SELECT user_id, username_key, payload_encrypted, updated_at, status, disconnected_at
                FROM presence
                WHERE group_hash = ?
                  AND (
                      (status = 'online' AND updated_at >= ?)
                      OR
                      (status = 'offline' AND disconnected_at IS NOT NULL AND disconnected_at >= ?)
                      OR
                      (status = 'online' AND updated_at < ?)
                  )
                ORDER BY CASE WHEN status = 'online' AND updated_at >= ? THEN 0 ELSE 1 END, updated_at DESC
                ''',
                (group_hash, online_threshold, offline_threshold, online_threshold, online_threshold),
            ).fetchall()

        visible_rows: list[dict] = []
        for row in rows:
            item = dict(row)
            if item['status'] == 'online' and str(item['updated_at']) < online_threshold:
                item['status'] = 'offline'
                item['disconnected_at'] = item['updated_at']
            if item['status'] == 'offline' and item['disconnected_at'] and str(item['disconnected_at']) < offline_threshold:
                continue
            visible_rows.append(item)
        return visible_rows



    def get_group_marker(self, marker_id: str, group_hash: str) -> dict | None:
        with self.connection() as conn:
            row = conn.execute(
                '''
                SELECT marker_id, group_hash, owner_user_id, owner_username, payload_encrypted, created_at, updated_at
                FROM group_markers
                WHERE marker_id = ? AND group_hash = ?
                LIMIT 1
                ''',
                (marker_id, group_hash),
            ).fetchone()
        return dict(row) if row else None

    def upsert_group_marker(
        self,
        marker_id: str,
        group_hash: str,
        owner_user_id: str,
        owner_username: str,
        payload_encrypted: str,
        changed_at: str,
    ) -> tuple[int, str]:
        with self.connection(write=True) as conn:
            if owner_user_id:
                conn.execute(
                    '''
                    DELETE FROM group_markers
                    WHERE group_hash = ?
                      AND owner_user_id = ?
                      AND marker_id != ?
                    ''',
                    (group_hash, owner_user_id, marker_id),
                )
            conn.execute(
                '''
                INSERT INTO group_markers (
                    marker_id,
                    group_hash,
                    owner_user_id,
                    owner_username,
                    payload_encrypted,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(marker_id) DO UPDATE SET
                    group_hash = excluded.group_hash,
                    owner_user_id = excluded.owner_user_id,
                    owner_username = excluded.owner_username,
                    payload_encrypted = excluded.payload_encrypted,
                    updated_at = excluded.updated_at
                ''',
                (marker_id, group_hash, owner_user_id, owner_username, payload_encrypted, changed_at, changed_at),
            )
            return self._bump_change_version(conn, group_hash, changed_at), marker_id

    def delete_group_marker(self, marker_id: str, group_hash: str, changed_at: str) -> int | None:
        with self.connection(write=True) as conn:
            deleted = conn.execute(
                'DELETE FROM group_markers WHERE marker_id = ? AND group_hash = ?',
                (marker_id, group_hash),
            ).rowcount
            if not deleted:
                return None
            return self._bump_change_version(conn, group_hash, changed_at)

    def list_group_markers(self, group_hash: str) -> list[dict]:
        with self.connection() as conn:
            rows = conn.execute(
                '''
                SELECT marker_id, owner_user_id, owner_username, payload_encrypted, created_at, updated_at
                FROM group_markers
                WHERE group_hash = ?
                ORDER BY updated_at DESC
                ''',
                (group_hash,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_change_state(self, group_hash: str, window_seconds: int) -> dict:
        recent_threshold = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
        with self.connection() as conn:
            group_row = conn.execute(
                '''
                SELECT change_version, last_change_at
                FROM group_meta
                WHERE group_hash = ?
                LIMIT 1
                ''',
                (group_hash,),
            ).fetchone()
            recent_count = conn.execute(
                'SELECT COUNT(*) AS count FROM change_log WHERE group_hash = ? AND changed_at >= ?',
                (group_hash, recent_threshold),
            ).fetchone()['count']
        return {
            'change_version': int(group_row['change_version']) if group_row else 0,
            'last_change_at': str(group_row['last_change_at']) if group_row else '',
            'recent_changes': int(recent_count or 0),
        }

    @staticmethod
    def dumps_payload(payload: dict) -> str:
        return json.dumps(payload, ensure_ascii=False, separators=(',', ':'))

    @staticmethod
    def loads_payload(payload_text: str) -> dict:
        return json.loads(payload_text)
