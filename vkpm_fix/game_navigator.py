from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from html import unescape
from pathlib import Path
from typing import Callable

import websocket


DEBUG_PORT = 9222
VIEW_URL_RE = re.compile(
    r"""["'](?:view_url|viewUrl)["']\s*:\s*["']((?:\\.|[^"'])+)["']""",
    re.I,
)
DIRECT_URL_RE = re.compile(
    r"""(https:(?:\\/\\/|//)(?:m\.)?vk\.(?:ru|com)(?:\\/|/)app\d+[^"' <]+)""",
    re.I,
)


def _decode_html(data: bytes) -> str:
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            return unescape(data.decode(enc))
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _clean_url(raw: str) -> str | None:
    try:
        url = json.loads(f'"{raw}"')
    except (json.JSONDecodeError, ValueError):
        url = raw.replace(r"\/", "/")
        url = re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda item: chr(int(item.group(1), 16)),
            url,
        )
    url = unescape(url).replace(r"\/", "/")
    if not re.match(
        r"https://(?:m\.)?vk\.(?:ru|com)/app\d+",
        url,
        re.I,
    ):
        return None
    return url


def _extract_view_url_bytes(data: bytes) -> str | None:
    text = _decode_html(data)
    match = VIEW_URL_RE.search(text)
    if match:
        url = _clean_url(match.group(1))
        if url:
            return url
    for match in DIRECT_URL_RE.finditer(text):
        url = _clean_url(match.group(1))
        if url and ("act=app_r" in url or "act%3Dapp_r" in url):
            return url
    return None


def _extract_view_url(path: Path) -> str | None:
    if not path.is_file():
        return None
    return _extract_view_url_bytes(path.read_bytes())


def _no_url_reason(path: Path) -> str:
    text = _decode_html(path.read_bytes())
    low = text.lower()
    if "badbrowser.php" in low:
        return "VK опять вернул badbrowser"
    if "login.vk." in low and "apps.getembeddedurl" not in low:
        return "VK вернул страницу входа, надо заново войти"
    pos = low.find("apps.getembeddedurl")
    if pos >= 0:
        part = text[pos : pos + 3000]
        code = re.search(r'"error_code"\s*:\s*(\d+)', part, re.I)
        msg = re.search(r'"error_msg"\s*:\s*"([^"]+)', part, re.I)
        if code:
            detail = f"код {code.group(1)}"
            if msg:
                detail += f": {msg.group(1)}"
            return f"VK отказал apps.getEmbeddedUrl, {detail}"
        return "apps.getEmbeddedUrl есть, но прямой адрес в ответе пустой"
    return "в ответе VK нет apps.getEmbeddedUrl, возможно слетела авторизация"


def _page_target() -> dict | None:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{DEBUG_PORT}/json", timeout=2
        ) as response:
            targets = json.load(response)
    except (OSError, ValueError):
        return None
    return next((item for item in targets if item.get("type") == "page"), None)


def _navigate_top(url: str) -> bool:
    target = _page_target()
    if not target:
        return False
    current = str(target.get("url", ""))
    if current == url:
        return True
    if "gameroom.games.mail.ru/app" not in current:
        return False

    ws = websocket.create_connection(
        target["webSocketDebuggerUrl"],
        timeout=5,
        origin=f"http://127.0.0.1:{DEBUG_PORT}",
    )
    try:
        ws.send(
            json.dumps(
                {
                    "id": 1,
                    "method": "Page.navigate",
                    "params": {"url": url},
                }
            )
        )
        deadline = time.time() + 5
        while time.time() < deadline:
            message = json.loads(ws.recv())
            if message.get("id") == 1:
                return "error" not in message
    finally:
        ws.close()
    return False


class GameNavigator:
    def __init__(
        self,
        file: Path,
        log: Callable[[str], None] = print,
    ) -> None:
        self.file = file
        self.log = log
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._time = 0

    def start(self) -> None:
        try:
            self.file.unlink(missing_ok=True)
        except OSError:
            pass
        self._thread = threading.Thread(
            target=self._run,
            name="vkpm-game-navigator",
            daemon=True,
        )
        self._thread.start()
        self.log("[navigator] жду выбора игры…")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.wait(0.5):
            try:
                stat = self.file.stat()
            except OSError:
                continue
            if stat.st_mtime_ns == self._time:
                continue
            self._time = stat.st_mtime_ns

            try:
                url = _extract_view_url(self.file)
                if not url:
                    self.log(f"[navigator] {_no_url_reason(self.file)}")
                    continue
                self.log("[navigator] найден официальный view_url")
                if _navigate_top(url):
                    self.log(
                        "[navigator] игра открыта напрямую; "
                        "обход iframe выполнен"
                    )
                else:
                    self.log(
                        "[navigator] не удалось перевести верхнее окно; "
                        "проверьте DevTools :9222"
                    )
            except Exception as exc:
                self.log(f"[navigator] ошибка: {exc}")
            finally:
                try:
                    self.file.unlink(missing_ok=True)
                except OSError:
                    pass
