from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from .diagnose import is_process_running
from .paths import CACHE_CHROME


CACHE_SUBDIRS = (
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "GPUCache",
    "Code Cache",
)


def stop_old_fixes() -> int:
    pid = os.getpid()
    code = (
        "Get-CimInstance Win32_Process | Where-Object { "
        f"$_.ProcessId -ne {pid} -and "
        "$_.Name -match '^python(w)?\\.exe$' -and "
        "$_.CommandLine -match '-m\\s+vkpm_fix\\s+(fix|proxy)' "
        "} | ForEach-Object { "
        "$_.ProcessId; Stop-Process -Id $_.ProcessId -Force "
        "}"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", code],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return 0
    return len([line for line in result.stdout.splitlines() if line.strip().isdigit()])


def stop_vkapp(timeout_sec: float = 15.0) -> bool:
    if not is_process_running():
        return True
    subprocess.run(
        ["taskkill", "/IM", "VKApp.exe", "/T"],
        capture_output=True,
        text=True,
        check=False,
    )
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if not is_process_running():
            return True
        time.sleep(0.4)
    subprocess.run(
        ["taskkill", "/F", "/IM", "VKApp.exe", "/T"],
        capture_output=True,
        text=True,
        check=False,
    )
    time.sleep(0.5)
    return not is_process_running()


def _rm_tree(path: Path) -> tuple[bool, str]:
    if not path.exists():
        return True, f"нет: {path.name}"
    try:
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=False)
        else:
            path.unlink()
        return True, f"удалено: {path.name}"
    except OSError as exc:
        return False, f"не удалось {path.name}: {exc}"


def clear_browser_cache(install_dir: Path) -> list[str]:
    messages: list[str] = []
    cache_root = install_dir / CACHE_CHROME
    if not cache_root.is_dir():
        messages.append(f"Кэш не найден: {cache_root}")
        return messages

    for name in CACHE_SUBDIRS:
        ok, msg = _rm_tree(cache_root / name)
        messages.append(("OK  " if ok else "ERR ") + msg)

    for pattern in ("LOG", "LOG.OLD", "LOCK"):
        for p in cache_root.rglob(pattern):
            try:
                if p.is_file():
                    p.unlink()
            except OSError:
                pass

    messages.append("Кэш браузера очищен (куки/хранилище сессии сброшены).")
    return messages


def repair(install_dir: Path) -> list[str]:
    lines: list[str] = []
    if is_process_running():
        lines.append("Останавливаю VKApp.exe...")
        if stop_vkapp():
            lines.append("Клиент закрыт.")
        else:
            lines.append("Не удалось полностью закрыть VKApp.exe — закройте вручную и повторите.")
            return lines
    else:
        lines.append("VKApp.exe не запущен.")

    lines.extend(clear_browser_cache(install_dir))
    lines.append("Готово. Дальше запускайте через: python -m vkpm_fix fix")
    lines.append("Важно: не запускайте Play Machine от имени администратора.")
    return lines
