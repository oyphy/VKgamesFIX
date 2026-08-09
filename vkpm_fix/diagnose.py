from __future__ import annotations

import ctypes
import re
from dataclasses import dataclass, field
from pathlib import Path

from .paths import CHROME_LOG, VKAPP_LOG, libcef_path, vkapp_exe


@dataclass
class Finding:
    code: str
    severity: str
    message: str


@dataclass
class Diagnosis:
    install_dir: Path
    findings: list[Finding] = field(default_factory=list)
    cef_version: str | None = None
    badbrowser_count: int = 0
    ssl_error_count: int = 0
    decrypt_error_count: int = 0
    elevated_in_logs: bool = False
    process_running: bool = False
    needs_repair: bool = False

    @property
    def has_badbrowser(self) -> bool:
        return self.badbrowser_count > 0

    def add(self, code: str, severity: str, message: str) -> None:
        self.findings.append(Finding(code, severity, message))


def is_process_running(image_name: str = "VKApp.exe") -> bool:
    try:
        import subprocess

        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/NH"],
            capture_output=True,
            text=True,
            encoding="oem",
            errors="replace",
            check=False,
        )
        return image_name.lower() in (result.stdout or "").lower()
    except OSError:
        return False


def is_current_process_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def read_file_tail(path: Path, max_bytes: int = 512_000) -> str:
    if not path.is_file():
        return ""
    data = path.read_bytes()
    if len(data) > max_bytes:
        data = data[-max_bytes:]
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _cef_version_from_pe(dll: Path) -> str | None:
    try:
        size = ctypes.windll.version.GetFileVersionInfoSizeW(str(dll), None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(str(dll), 0, size, buf):
            return None

        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [
                ("dwSignature", ctypes.c_uint32),
                ("dwStrucVersion", ctypes.c_uint32),
                ("dwFileVersionMS", ctypes.c_uint32),
                ("dwFileVersionLS", ctypes.c_uint32),
                ("dwProductVersionMS", ctypes.c_uint32),
                ("dwProductVersionLS", ctypes.c_uint32),
                ("dwFileFlagsMask", ctypes.c_uint32),
                ("dwFileFlags", ctypes.c_uint32),
                ("dwFileOS", ctypes.c_uint32),
                ("dwFileType", ctypes.c_uint32),
                ("dwFileSubtype", ctypes.c_uint32),
                ("dwFileDateMS", ctypes.c_uint32),
                ("dwFileDateLS", ctypes.c_uint32),
            ]

        length = ctypes.c_uint()
        pointer = ctypes.c_void_p()
        if not ctypes.windll.version.VerQueryValueW(
            buf, "\\", ctypes.byref(pointer), ctypes.byref(length)
        ):
            return None
        info = VS_FIXEDFILEINFO.from_address(pointer.value)
        major = info.dwFileVersionMS >> 16
        minor = info.dwFileVersionMS & 0xFFFF
        build = info.dwFileVersionLS >> 16
        rev = info.dwFileVersionLS & 0xFFFF
        return f"{major}.{minor}.{build}.{rev}"
    except (AttributeError, OSError, ValueError, TypeError):
        return None


def _cef_version_from_bytes(dll: Path) -> str | None:
    try:
        chunk = 2_000_000
        with dll.open("rb") as fh:
            data = fh.read(chunk)
        m = re.search(br"chromium-(\d+\.\d+\.\d+\.\d+)", data)
        if m:
            return m.group(0).decode("ascii", errors="replace")
        m = re.search(br"Chrome/(\d+\.0\.0\.0)", data)
        if m:
            return m.group(0).decode("ascii", errors="replace")
    except OSError:
        return None
    return None


def get_cef_version(install_dir: Path) -> str | None:
    dll = libcef_path(install_dir)
    if not dll.is_file():
        return None
    pe = _cef_version_from_pe(dll)
    scanned = _cef_version_from_bytes(dll)
    if pe and scanned:
        return f"{pe} ({scanned})"
    return scanned or pe

def _count(pattern: str, text: str, flags: int = re.IGNORECASE) -> int:
    return len(re.findall(pattern, text, flags))


def diagnose(install_dir: Path) -> Diagnosis:
    result = Diagnosis(install_dir=install_dir)

    exe = vkapp_exe(install_dir)
    if exe.is_file():
        result.add("install", "ok", f"Клиент найден: {exe}")
    else:
        result.add("install", "critical", f"VKApp.exe не найден в {install_dir}")
        return result

    cef = get_cef_version(install_dir)
    result.cef_version = cef
    if cef:
        result.add("cef", "info", f"Версия CEF/Chromium (libcef): {cef}")
        major = None
        m = re.search(r"chromium-(\d+)", cef, re.I)
        if m:
            major = int(m.group(1))
        else:
            m = re.search(r"Chrome/(\d+)", cef, re.I)
            if m:
                major = int(m.group(1))
            else:
                m = re.match(r"^(\d{2,3})\.\d+", cef)
                if m:
                    major = int(m.group(1))
        if major is not None and major < 100:
            result.add(
                "cef_old",
                "critical",
                f"Встроенный браузер слишком старый (Chrome/Chromium {major}). "
                "VK часто отвечает badbrowser.php и блокирует вход.",
            )
            result.needs_repair = True
    else:
        result.add("cef", "warn", "Не удалось прочитать версию libcef.dll")
    vk_log = read_file_tail(install_dir / VKAPP_LOG)
    chrome_log = read_file_tail(install_dir / CHROME_LOG)
    combined = vk_log + "\n" + chrome_log

    result.badbrowser_count = _count(r"badbrowser\.php", combined)
    result.ssl_error_count = _count(r"handshake failed|ssl error|net_error -10[017]", combined)
    result.decrypt_error_count = _count(r"Failed to decrypt|os_crypt", combined)
    result.elevated_in_logs = bool(re.search(r"IsElevated=True", vk_log))
    embed_blocks = _count(
        r'LoadError Url="https://vk\.(ru|com)/[^"]*act=embed[^"]*"\s+-27\s+ERR_BLOCKED_BY_RESPONSE',
        combined,
    )

    if result.badbrowser_count:
        result.add(
            "badbrowser",
            "critical",
            f"В логах badbrowser.php: {result.badbrowser_count} раз(а). "
            "VK отклоняет старый браузер — нужен User-Agent / patch-ua.",
        )
        result.needs_repair = True
    if embed_blocks:
        result.add(
            "xfo",
            "critical",
            f"VK embed режется X-Frame-Options ({embed_blocks} раз): ERR_BLOCKED_BY_RESPONSE. "
            "Запускайте: python -m vkpm_fix fix (с proxy, окно не закрывать).",
        )
        result.needs_repair = True
    if not result.badbrowser_count and not embed_blocks:
        if (install_dir / VKAPP_LOG).is_file():
            result.add("badbrowser", "ok", "В последних логах badbrowser/embed-block не найден")
        else:
            result.add("badbrowser", "info", "VKApp.log ещё нет — запустите клиент хотя бы раз")

    if result.ssl_error_count:
        result.add(
            "ssl",
            "warn",
            f"Ошибки SSL handshake: {result.ssl_error_count}. "
            "Проверьте антивирус (проверка HTTPS), VPN и системное время.",
        )

    if result.decrypt_error_count:
        result.add(
            "decrypt",
            "warn",
            f"Ошибки расшифровки кук/хранилища: {result.decrypt_error_count}. "
            "Часто бывает после запуска от администратора — нужна очистка кэша.",
        )
        result.needs_repair = True

    if result.elevated_in_logs:
        result.add(
            "elevated_log",
            "warn",
            "В логах клиент запускался от администратора (IsElevated=True). "
            "Так делать нельзя: ломаются куки DPAPI.",
        )

    if is_current_process_elevated():
        result.add(
            "elevated_now",
            "warn",
            "Сейчас эта утилита запущена от администратора. "
            "Для fix/launch лучше обычный пользователь.",
        )

    result.process_running = is_process_running()
    if result.process_running:
        result.add("process", "info", "VKApp.exe сейчас запущен")
    else:
        result.add("process", "info", "VKApp.exe не запущен")

    return result


def format_diagnosis(d: Diagnosis) -> str:
    lines = [
        "=== Диагностика VK Play Machine ===",
        f"Папка: {d.install_dir}",
    ]
    if d.cef_version:
        lines.append(f"CEF: {d.cef_version}")
    lines.append("")
    icon = {"critical": "[!]", "warn": "[~]", "info": "[i]", "ok": "[+]"}
    for f in d.findings:
        lines.append(f"{icon.get(f.severity, '[?]')} {f.message}")
    lines.append("")
    if d.needs_repair:
        lines.append("Рекомендация: python -m vkpm_fix repair  затем  python -m vkpm_fix fix")
    else:
        lines.append("Критических проблем в логах не видно. Можно: python -m vkpm_fix fix")
    return "\n".join(lines)
