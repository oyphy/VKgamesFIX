from __future__ import annotations

import os
from pathlib import Path


APP_DIR_NAME = "Play Machine"
EXE_NAME = "VKApp.exe"
LIBCEF_REL = Path("Chrome") / "libcef.dll"
VKAPP_LOG = "VKApp.log"
CHROME_LOG = "Chrome.log"
CACHE_CHROME = Path("Cache") / "Chrome"


def default_install_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        local = str(Path.home() / "AppData" / "Local")
    return Path(local) / APP_DIR_NAME


def resolve_install_dir(explicit: str | Path | None = None) -> Path:
    if explicit:
        path = Path(explicit).expanduser().resolve()
    else:
        path = default_install_dir()
    return path


def require_install_dir(explicit: str | Path | None = None) -> Path:
    path = resolve_install_dir(explicit)
    exe = path / EXE_NAME
    if not exe.is_file():
        raise FileNotFoundError(
            f"VK Play Machine не найден: {exe}\n"
            f"Укажите папку через --path, если клиент установлен в другом месте."
        )
    return path


def vkapp_exe(install_dir: Path) -> Path:
    return install_dir / EXE_NAME


def libcef_path(install_dir: Path) -> Path:
    return install_dir / LIBCEF_REL


def cache_chrome_dir(install_dir: Path) -> Path:
    return install_dir / CACHE_CHROME
