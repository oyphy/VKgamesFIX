from __future__ import annotations

import subprocess
from pathlib import Path

from .diagnose import is_current_process_elevated
from .frame_proxy import DEFAULT_PORT
from .paths import vkapp_exe

MODERN_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def build_command(
    install_dir: Path,
    user_agent: str = MODERN_USER_AGENT,
    *,
    proxy_port: int | None = DEFAULT_PORT,
) -> list[str]:
    exe = vkapp_exe(install_dir)
    cmd = [str(exe), f"--user-agent={user_agent}"]
    if proxy_port is not None:
        cmd.append(f"--proxy-server=http://127.0.0.1:{proxy_port}")
        cmd.append("--ignore-certificate-errors")
        cmd.append("--ignore-certificate-errors-spki-list")
        cmd.append("--allow-insecure-localhost")
        cmd.append("--disable-http2")
        cmd.append("--remote-debugging-port=9222")
    return cmd


def launch(
    install_dir: Path,
    user_agent: str = MODERN_USER_AGENT,
    *,
    proxy_port: int | None = DEFAULT_PORT,
) -> tuple[bool, str]:
    exe = vkapp_exe(install_dir)
    if not exe.is_file():
        return False, f"Не найден {exe}"

    if is_current_process_elevated():
        note = (
            "Внимание: утилита запущена от администратора. "
            "Клиент унаследует elevation — куки могут снова сломаться."
        )
    else:
        note = "Запуск без прав администратора — так и нужно."

    cmd = build_command(install_dir, user_agent, proxy_port=proxy_port)
    try:
        subprocess.Popen(
            cmd,
            cwd=str(install_dir),
            close_fds=True,
        )
    except OSError as exc:
        return False, f"Не удалось запустить: {exc}"

    proxy_note = (
        f"Прокси: 127.0.0.1:{proxy_port} (снятие X-Frame-Options)"
        if proxy_port is not None
        else "Прокси: выключен"
    )
    return True, (
        f"{note}\n"
        f"{proxy_note}\n"
        f"User-Agent: Chrome/131\n"
        f"Окно с прокси не закрывайте, пока играете."
    )
