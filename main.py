from __future__ import annotations

import asyncio
import sys


def _configure_windows_runtime() -> None:
    """Apply Windows asyncio workarounds before importing NiceGUI/Uvicorn."""
    if not sys.platform.startswith('win'):
        return

    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass

    try:
        import asyncio.proactor_events as proactor_events
    except Exception:
        return

    original = getattr(proactor_events._ProactorBasePipeTransport, '_call_connection_lost', None)
    if original is None or getattr(original, '__buddy_radar_patched__', False):
        return

    def _safe_call_connection_lost(self, exc):
        try:
            return original(self, exc)
        except ConnectionResetError:
            return None
        except OSError as error:
            if getattr(error, 'winerror', None) == 10054:
                return None
            raise

    _safe_call_connection_lost.__buddy_radar_patched__ = True
    proactor_events._ProactorBasePipeTransport._call_connection_lost = _safe_call_connection_lost


def main() -> None:
    _configure_windows_runtime()

    from nicegui import ui

    import config
    from core.bot_guard import BotGuard, default_rules_from_config
    from core.dev_cert import ensure_dev_certificate
    from core.security import SecurityManager
    from core.session_guard import SessionManager
    from core.storage import Storage
    from gui.buddy_gui import setup

    storage = Storage(config.DB_PATH)
    security = SecurityManager(config.SALT_PATH)
    guard = BotGuard(
        enabled=config.BOT_GUARD_ENABLED,
        trust_proxy_headers=config.BOT_GUARD_TRUST_PROXY_HEADERS,
        proxy_header=config.BOT_GUARD_PROXY_HEADER,
        rules=default_rules_from_config(config),
        cleanup_interval_seconds=config.BOT_GUARD_CLEANUP_INTERVAL_SECONDS,
        escalation_enabled=config.BOT_GUARD_ESCALATION_ENABLED,
        escalation_window_seconds=config.BOT_GUARD_ESCALATION_WINDOW_SECONDS,
        escalation_steps=config.BOT_GUARD_ESCALATION_STEPS,
        escalation_max_block_seconds=config.BOT_GUARD_ESCALATION_MAX_BLOCK_SECONDS,
        strikes_for_session=config.BOT_GUARD_ESCALATION_STRIKES_FOR_SESSION,
        strikes_for_challenge=config.BOT_GUARD_ESCALATION_STRIKES_FOR_CHALLENGE,
        strikes_for_pow=config.BOT_GUARD_ESCALATION_STRIKES_FOR_POW,
    )
    sessions = SessionManager(
        ttl_seconds=config.SESSION_TOKEN_TTL_SECONDS,
        refresh_on_use=config.SESSION_TOKEN_REFRESH_ON_USE,
        bind_to_ip=config.SESSION_TOKEN_BIND_TO_IP,
        cleanup_interval_seconds=config.SESSION_TOKEN_CLEANUP_INTERVAL_SECONDS,
    )
    setup(storage, security, guard, sessions)

    run_kwargs: dict = {
        'host': config.HOST,
        'port': config.PORT,
        'title': f'{config.APP_NAME} v{config.APP_VERSION}',
        'reload': False,
        'favicon': '📍',
    }

    if config.USE_HTTPS:
        if config.AUTO_GENERATE_DEV_CERT:
            cert_path, key_path = ensure_dev_certificate(config.SSL_CERTFILE, config.SSL_KEYFILE)
        else:
            cert_path, key_path = config.SSL_CERTFILE, config.SSL_KEYFILE
        if cert_path.exists() and key_path.exists():
            run_kwargs['ssl_certfile'] = str(cert_path)
            run_kwargs['ssl_keyfile'] = str(key_path)
        else:
            print('WARNUNG: HTTPS ist aktiviert, aber Zertifikat/Key fehlen. Starte ohne HTTPS.')

    ui.run(**run_kwargs)


if __name__ in {'__main__', '__mp_main__'}:
    main()
