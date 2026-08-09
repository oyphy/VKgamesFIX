from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable

import websocket


DEBUG_PORT = 9222
VIEW_URL_RE = re.compile(
    rb'"view_url":"(https:\\/\\/m\.vk\.(?:ru|com)\\/app\d+[^"]+)"'
)


def _extract_view_url(path: Path) -> str | None:
    if not path.is_file():
        return None
    data = path.read_bytes()
    match = VIEW_URL_RE.search(data)
    if not match:
        return None
    return (
        match.group(1)
        .decode("ascii", errors="strict")
        .replace(r"\/", "/")
    )


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
                    self.log("[navigator] VK не вернул view_url игры")
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
