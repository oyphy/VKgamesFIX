from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .diagnose import diagnose, format_diagnosis
from .frame_proxy import DEFAULT_PORT, FrameBypassProxy, run_proxy_forever
from .game_navigator import GameNavigator
from .launcher import MODERN_USER_AGENT, launch
from .paths import require_install_dir
from .repair import repair, stop_vkapp
from .ua_patch import patch_libcef, restore_libcef


def _print_lines(lines: list[str]) -> None:
    for line in lines:
        print(line, flush=True)


def cmd_diagnose(args: argparse.Namespace) -> int:
    install = require_install_dir(args.path)
    report = diagnose(install)
    print(format_diagnosis(report))
    critical = report.has_badbrowser or any(f.severity == "critical" for f in report.findings)
    return 1 if critical else 0


def cmd_repair(args: argparse.Namespace) -> int:
    install = require_install_dir(args.path)
    _print_lines(repair(install))
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    install = require_install_dir(args.path)
    report = diagnose(install)
    print(format_diagnosis(report))
    print()

    print("--- repair ---")
    _print_lines(repair(install))
    print()

    ua = args.user_agent or MODERN_USER_AGENT
    proxy_port = None if args.no_proxy else args.proxy_port

    proxy = None
    navigator = None
    if proxy_port is not None:
        print("--- proxy ---")
        proxy = FrameBypassProxy(port=proxy_port, user_agent=ua)
        try:
            proxy.start()
        except OSError as exc:
            print(f"Не удалось запустить прокси на порту {proxy_port}: {exc}")
            print("Закройте старый процесс или укажите --proxy-port другой.")
            return 1
        time.sleep(0.3)
        debug_html = (
            Path(__file__).resolve().parent.parent
            / "data"
            / "debug-last-embed.html"
        )
        navigator = GameNavigator(debug_html)
        navigator.start()
        print()

    print("--- launch ---")
    ok, msg = launch(install, user_agent=ua, proxy_port=proxy_port)
    print(msg)
    if not ok:
        if navigator:
            navigator.stop()
        if proxy:
            proxy.stop()
        return 1

    if proxy is not None:
        print()
        print("Прокси работает. Играйте в Play Machine. Ctrl+C — остановить прокси.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nОстанавливаю...")
            stop_vkapp()
            if navigator:
                navigator.stop()
            proxy.stop()
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    run_proxy_forever(port=args.proxy_port, user_agent=args.user_agent or MODERN_USER_AGENT)
    return 0


def cmd_patch_ua(args: argparse.Namespace) -> int:
    install = require_install_dir(args.path)
    try:
        _print_lines(patch_libcef(install, target_major=args.major))
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_restore_ua(args: argparse.Namespace) -> int:
    install = require_install_dir(args.path)
    try:
        _print_lines(restore_libcef(install))
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vkpm_fix",
        description=(
            "VK Play Machine Fix — badbrowser, X-Frame-Options, кэш, запуск."
        ),
    )
    parser.add_argument("--version", action="version", version=f"vkpm_fix {__version__}")
    parser.add_argument(
        "--path",
        help=r"Папка Play Machine (по умолчанию %%LOCALAPPDATA%%\Play Machine)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_diag = sub.add_parser("diagnose", help="Разобрать логи и версию CEF")
    p_diag.set_defaults(func=cmd_diagnose)

    p_rep = sub.add_parser("repair", help="Закрыть клиент и очистить кэш/хранилище")
    p_rep.set_defaults(func=cmd_repair)

    p_fix = sub.add_parser(
        "fix",
        help="Ремонт + локальный proxy (снимает XFO) + запуск с UA",
    )
    p_fix.add_argument(
        "--force-repair",
        action="store_true",
        help="Устарело: repair в fix выполняется всегда",
    )
    p_fix.add_argument(
        "--user-agent",
        default=None,
        help="Свой User-Agent (по умолчанию Chrome/131)",
    )
    p_fix.add_argument(
        "--proxy-port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Порт локального proxy (по умолчанию {DEFAULT_PORT})",
    )
    p_fix.add_argument(
        "--no-proxy",
        action="store_true",
        help="Не поднимать proxy (только UA) — embed VK снова будет блокироваться",
    )
    p_fix.set_defaults(func=cmd_fix)

    p_proxy = sub.add_parser("proxy", help="Только поднять proxy (без запуска клиента)")
    p_proxy.add_argument("--proxy-port", type=int, default=DEFAULT_PORT)
    p_proxy.add_argument("--user-agent", default=None)
    p_proxy.set_defaults(func=cmd_proxy)

    p_patch = sub.add_parser(
        "patch-ua",
        help="Патч libcef.dll (если --user-agent не помогает). Делает .vkpm.bak",
    )
    p_patch.add_argument(
        "--major",
        type=int,
        default=131,
        help="Целевая major-версия Chrome в строках DLL (по умолчанию 131)",
    )
    p_patch.set_defaults(func=cmd_patch_ua)

    p_rest = sub.add_parser("restore-ua", help="Откатить libcef.dll из .vkpm.bak")
    p_rest.set_defaults(func=cmd_restore_ua)

    return parser


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nОтменено.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
