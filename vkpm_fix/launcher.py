from __future__ import annotations

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

from .diagnose import is_current_process_elevated
from .frame_proxy import DEFAULT_PORT
from .paths import vkapp_exe

MODERN_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
_jobs: list[object] = []


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _BasicLimit(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimit),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _kill_with_parent(process: subprocess.Popen) -> None:
    kernel = ctypes.windll.kernel32
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        return
    info = _ExtendedLimit()
    info.BasicLimitInformation.LimitFlags = 0x2000
    ok = kernel.SetInformationJobObject(
        job,
        9,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok or not kernel.AssignProcessToJobObject(
        job, wintypes.HANDLE(process._handle)
    ):
        kernel.CloseHandle(job)
        return
    _jobs.append(job)


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
        process = subprocess.Popen(
            cmd,
            cwd=str(install_dir),
            close_fds=True,
        )
        _kill_with_parent(process)
        time.sleep(1.5)
        code = process.poll()
        if code is not None:
            return False, f"VKApp.exe закрылся сразу после запуска, код {code}"
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
