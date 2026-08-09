from __future__ import annotations

import re
import shutil
from pathlib import Path

from .diagnose import is_process_running
from .paths import libcef_path
from .repair import stop_vkapp

BACKUP_SUFFIX = ".vkpm.bak"


def backup_path(dll: Path) -> Path:
    return Path(str(dll) + BACKUP_SUFFIX)


def _replace_same_length(data: bytearray, old: bytes, new: bytes) -> int:
    if len(old) != len(new):
        raise ValueError("длина old/new должна совпадать")
    count = 0
    start = 0
    while True:
        idx = data.find(old, start)
        if idx < 0:
            break
        data[idx : idx + len(old)] = new
        count += 1
        start = idx + len(old)
    return count


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


def build_replacements(target_major: int = 131) -> list[tuple[bytes, bytes]]:
    pairs: list[tuple[bytes, bytes]] = []

    if target_major >= 100:
        ver_old = b"87.0.4280.141"
        ver_new = b"131.0.00000.0"
        full_old = b"chromium-87.0.4280.141"
        full_new = b"chromium-131.0.00000.0"
        pairs.extend(
            [
                (ver_old, ver_new),
                (full_old, full_new),
                (_utf16(ver_old.decode()), _utf16(ver_new.decode())),
                (_utf16(full_old.decode()), _utf16(full_new.decode())),
            ]
        )
    else:
        pairs.extend(
            [
                (b"87.0.4280.141", b"99.0.9999.999"),
                (b"chromium-87.0.4280.141", b"chromium-99.0.9999.99"),
            ]
        )

    return [(o, n) for o, n in pairs if len(o) == len(n)]


def patch_libcef(install_dir: Path, target_major: int = 131) -> list[str]:
    messages: list[str] = []
    dll = libcef_path(install_dir)
    if not dll.is_file():
        raise FileNotFoundError(f"Не найден {dll}")

    if is_process_running():
        messages.append("Останавливаю VKApp.exe перед патчем...")
        if not stop_vkapp():
            raise RuntimeError("Закройте VKApp.exe и повторите patch-ua")

    bak = backup_path(dll)
    if not bak.is_file():
        shutil.copy2(dll, bak)
        messages.append(f"Бэкап создан: {bak.name}")
    else:
        messages.append(f"Бэкап уже есть: {bak.name}")

    raw = bytearray(dll.read_bytes())
    total = 0
    ordered = sorted(build_replacements(target_major), key=lambda p: len(p[0]), reverse=True)
    for old, new in ordered:
        n = _replace_same_length(raw, old, new)
        if n:
            total += n
            preview = old[:40]
            messages.append(f"Заменено {n}× {preview!r} → {new[:40]!r}")

    if total == 0:
        sample = sorted(set(re.findall(rb"Chrome/\d+\.[\d.]+", bytes(raw))))[:8]
        messages.append(
            "Подходящих строк для патча не найдено. "
            f"Примеры в DLL: {sample or 'нет'}"
        )
        return messages

    dll.write_bytes(raw)
    messages.append(
        f"Патч записан в {dll.name} ({total} замен). Дальше: python -m vkpm_fix fix"
    )
    return messages


def restore_libcef(install_dir: Path) -> list[str]:
    messages: list[str] = []
    dll = libcef_path(install_dir)
    bak = backup_path(dll)
    if not bak.is_file():
        raise FileNotFoundError(f"Бэкап не найден: {bak}")

    if is_process_running():
        messages.append("Останавливаю VKApp.exe...")
        if not stop_vkapp():
            raise RuntimeError("Закройте VKApp.exe и повторите restore-ua")

    shutil.copy2(bak, dll)
    messages.append(f"Восстановлен оригинал из {bak.name}")
    return messages
