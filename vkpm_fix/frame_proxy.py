from __future__ import annotations

import re
import select
import socket
import ssl
import threading
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable

from .certs import ensure_ca, issue_host_cert

DEFAULT_PORT = 8877
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

MITM_ALLOW_HOSTS = {
    "vk.ru",
    "www.vk.ru",
    "m.vk.ru",
    "login.vk.ru",
    "id.vk.ru",
}


def should_mitm(host: str) -> bool:
    h = host.lower().split(":")[0]
    return h in MITM_ALLOW_HOSTS


def _recv_exact(conn: ssl.SSLSocket | socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _recv_headers(conn: ssl.SSLSocket | socket.socket, limit: int = 1_000_000) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            break
    return data


def _header_value(headers: bytes, name: bytes) -> str | None:
    m = re.search(name + br"\s*:\s*([^\r\n]+)", headers, re.I)
    return m.group(1).decode("latin-1", errors="replace").strip() if m else None


def _rewrite_request_headers(raw: bytes, user_agent: str) -> bytes:
    if b"\r\n\r\n" not in raw:
        return raw
    head, rest = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    out = [lines[0]]
    seen_ae = False
    for line in lines[1:]:
        low = line.lower()
        if low.startswith(b"proxy-connection:"):
            continue
        if low.startswith(b"accept-encoding:"):
            out.append(b"Accept-Encoding: identity")
            seen_ae = True
            continue
        out.append(line)
    if not seen_ae:
        out.append(b"Accept-Encoding: identity")
    return b"\r\n".join(out) + b"\r\n\r\n" + rest


def _strip_frame_headers(raw: bytes) -> bytes:
    if b"\r\n\r\n" not in raw:
        return raw
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    out = [lines[0]]
    for line in lines[1:]:
        if b":" not in line:
            out.append(line)
            continue
        name, value = line.split(b":", 1)
        key = name.strip().lower()
        if key in {
            b"x-frame-options",
            b"cross-origin-opener-policy",
            b"cross-origin-embedder-policy",
            b"cross-origin-resource-policy",
            b"content-security-policy",
            b"content-security-policy-report-only",
        }:
            continue
        out.append(line)
    return b"\r\n".join(out) + b"\r\n\r\n" + body


INJECT_JS = (
    b"<script data-vkpm>(function(){try{"
    b"var R=Location.prototype.replace;"
    b"Location.prototype.replace=function(u){"
    b"if(String(u).indexOf('badbrowser')>=0)return;"
    b"return R.apply(this,arguments);"
    b"};"
    b"var A=Element.prototype.appendChild;"
    b"}catch(e){}})();</script>"
)


def _rewrite_vk_html(body: bytes) -> tuple[bytes, list[str]]:
    notes: list[str] = []
    text = None
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            text = body.decode(enc)
            used = enc
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return body, notes

    original = text

    text2, n = re.subn(
        r"if\s*\(\s*parent\s*&&\s*parent\s*!=\s*window\s*&&\s*\([^)]*browser\.[^)]*\)\s*\)\s*"
        r"\{\s*document\.body\.innerHTML\s*=\s*['\"]['\"]\s*;\s*\}",
        "void 0",
        text,
        flags=re.I,
    )
    if n:
        notes.append(f"anti-iframe x{n}")
        text = text2

    text2, n = re.subn(
        r"document\.body\.innerHTML\s*=\s*['\"]['\"]",
        "void 0",
        text,
        flags=re.I,
    )
    if n:
        notes.append(f"innerHTML-clear x{n}")
        text = text2

    text2, n = re.subn(
        r"needRedirect\"\s*:\s*true",
        'needRedirect":false',
        text,
    )
    if n:
        notes.append(f"needRedirect x{n}")
        text = text2

    if "<head>" in text.lower() and b"vkpm" not in body[:2000]:
        text2, n = re.subn(
            r"(<head[^>]*>)",
            r"\1" + INJECT_JS.decode("ascii"),
            text,
            count=1,
            flags=re.I,
        )
        if n:
            notes.append("inject")
            text = text2

    if text == original:
        return body, notes

    try:
        return text.encode(used), notes
    except Exception:
        return text.encode("utf-8", errors="replace"), notes


def _read_full_body(
    src: ssl.SSLSocket | socket.socket,
    headers: bytes,
    already: bytes,
) -> bytes:
    te = (_header_value(headers, b"Transfer-Encoding") or "").lower()
    cl = _header_value(headers, b"Content-Length")
    chunks = [already] if already else []

    if "chunked" in te:
        leftover = already
        chunks = []
        while True:
            while b"\r\n" not in leftover:
                chunk = src.recv(65536)
                if not chunk:
                    return b"".join(chunks)
                leftover += chunk
            line, leftover = leftover.split(b"\r\n", 1)
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                return b"".join(chunks)
            need = size + 2
            while len(leftover) < need:
                chunk = src.recv(65536)
                if not chunk:
                    return b"".join(chunks)
                leftover += chunk
            if size:
                chunks.append(leftover[:size])
            leftover = leftover[need:]
            if size == 0:
                return b"".join(chunks)

    if cl is not None:
        try:
            need = int(cl)
        except ValueError:
            need = 0
        buf = bytearray(already)
        while len(buf) < need:
            chunk = src.recv(min(65536, need - len(buf)))
            if not chunk:
                break
            buf += chunk
        return bytes(buf[:need])

    buf = bytearray(already)
    while True:
        chunk = src.recv(65536)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _build_response(status_line: bytes, header_lines: list[bytes], body: bytes) -> bytes:
    skip = {
        b"content-length",
        b"transfer-encoding",
        b"content-encoding",
        b"x-frame-options",
        b"content-security-policy",
        b"content-security-policy-report-only",
        b"cross-origin-opener-policy",
        b"cross-origin-embedder-policy",
        b"cross-origin-resource-policy",
    }
    out = [status_line]
    for line in header_lines:
        if b":" not in line:
            continue
        name = line.split(b":", 1)[0].strip().lower()
        if name in skip:
            continue
        out.append(line)
    out.append(b"Content-Length: " + str(len(body)).encode("ascii"))
    out.append(b"Cache-Control: no-store")
    return b"\r\n".join(out) + b"\r\n\r\n" + body


def _forward_body(
    src: ssl.SSLSocket | socket.socket,
    dst: ssl.SSLSocket | socket.socket,
    headers: bytes,
    already: bytes,
    *,
    until_eof: bool = False,
) -> None:
    te = (_header_value(headers, b"Transfer-Encoding") or "").lower()
    cl = _header_value(headers, b"Content-Length")

    if "chunked" in te:
        leftover = already
        while True:
            while b"\r\n" not in leftover:
                chunk = src.recv(4096)
                if not chunk:
                    return
                leftover += chunk
            line, leftover = leftover.split(b"\r\n", 1)
            dst.sendall(line + b"\r\n")
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                return
            need = size + 2
            while len(leftover) < need:
                chunk = src.recv(4096)
                if not chunk:
                    return
                leftover += chunk
            dst.sendall(leftover[:need])
            leftover = leftover[need:]
            if size == 0:
                return
        return

    if cl is not None:
        try:
            need = int(cl)
        except ValueError:
            need = 0
        have = 0
        if already:
            dst.sendall(already[:need])
            have = min(len(already), need)
        while have < need:
            chunk = src.recv(min(65536, need - have))
            if not chunk:
                break
            dst.sendall(chunk)
            have += len(chunk)
        return

    if already:
        dst.sendall(already)

    if not until_eof:
        return

    while True:
        chunk = src.recv(65536)
        if not chunk:
            break
        dst.sendall(chunk)


def _pipe_raw(a: socket.socket, b: socket.socket, preamble_a_to_b: bytes = b"") -> None:
    sockets = [a, b]
    try:
        if preamble_a_to_b:
            b.sendall(preamble_a_to_b)
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 120)
            if errored:
                break
            if not readable:
                break
            for s in readable:
                other = b if s is a else a
                try:
                    data = s.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except OSError:
                    return
    except OSError:
        return
    finally:
        for s in sockets:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _tunnel(
    client: socket.socket,
    host: str,
    port: int,
    preamble: bytes = b"",
) -> None:
    try:
        remote = socket.create_connection((host, port), timeout=20)
    except OSError:
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except OSError:
            pass
        client.close()
        return
    try:
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except OSError:
        client.close()
        remote.close()
        return
    _pipe_raw(client, remote, preamble_a_to_b=preamble)


def _mitm_https(
    client: socket.socket,
    host: str,
    port: int,
    user_agent: str,
    log: Callable[[str], None],
    preamble: bytes = b"",
) -> None:
    try:
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except OSError:
        client.close()
        return

    if preamble:
        original_recv = client.recv
        buf = bytearray(preamble)

        def recv_with_preamble(size: int = 4096, flags: int = 0) -> bytes:
            if buf:
                n = min(size, len(buf))
                data = bytes(buf[:n])
                del buf[:n]
                return data
            return original_recv(size, flags)

        setattr(client, "recv", recv_with_preamble)

    cert_pem, key_pem = issue_host_cert(host)
    cert_file = key_file = ""
    client_ssl = None
    try:
        with NamedTemporaryFile(delete=False, suffix=".crt") as cf:
            cf.write(cert_pem)
            cert_file = cf.name
        with NamedTemporaryFile(delete=False, suffix=".key") as kf:
            kf.write(key_pem)
            key_file = kf.name

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        try:
            context.set_alpn_protocols(["http/1.1"])
        except (AttributeError, NotImplementedError, ssl.SSLError):
            pass
        client_ssl = context.wrap_socket(client, server_side=True)
    except ssl.SSLError as exc:
        log(f"SSL handshake client {host}: {exc}")
        try:
            client.close()
        except OSError:
            pass
        return
    finally:
        for p in (cert_file, key_file):
            if p:
                try:
                    Path(p).unlink(missing_ok=True)
                except OSError:
                    pass

    if client_ssl is None:
        return

    try:
        remote_ctx = ssl.create_default_context()
        try:
            remote_ctx.set_alpn_protocols(["http/1.1"])
        except (AttributeError, NotImplementedError, ssl.SSLError):
            pass
        remote = remote_ctx.wrap_socket(
            socket.create_connection((host, port), timeout=25),
            server_hostname=host,
        )
    except OSError as exc:
        log(f"connect upstream {host}: {exc}")
        client_ssl.close()
        return

    log(f"MITM ok {host}:{port}")
    try:
        client_ssl.settimeout(300)
        remote.settimeout(300)
    except OSError:
        pass
    try:
        while True:
            req = _recv_headers(client_ssl)
            if not req or b"\r\n\r\n" not in req:
                break
            head, already_body = req.split(b"\r\n\r\n", 1)
            req_full_head = _rewrite_request_headers(head + b"\r\n\r\n", user_agent)
            rh, _ = req_full_head.split(b"\r\n\r\n", 1)
            request_line = rh.split(b"\r\n", 1)[0]
            is_embed_request = b"act=embed" in request_line.lower()
            if is_embed_request:
                log(
                    "EMBED "
                    + request_line.decode("latin-1", errors="replace")
                )
            remote.sendall(rh + b"\r\n\r\n")
            _forward_body(client_ssl, remote, rh, already_body, until_eof=False)

            if b"upgrade: websocket" in rh.lower():
                resp = _recv_headers(remote)
                if resp and b"\r\n\r\n" in resp:
                    resp = _strip_frame_headers(resp)
                    rhead, ralready = resp.split(b"\r\n\r\n", 1)
                    client_ssl.sendall(rhead + b"\r\n\r\n")
                    if ralready:
                        client_ssl.sendall(ralready)
                log(f"WS tunnel {host}")
                _pipe_raw(client_ssl, remote)
                return

            resp = _recv_headers(remote)
            if not resp or b"\r\n\r\n" not in resp:
                break
            rhead, ralready = resp.split(b"\r\n\r\n", 1)
            ctype = (_header_value(rhead, b"Content-Type") or "").lower()
            is_html = "text/html" in ctype

            if is_html:
                body = _read_full_body(remote, rhead, ralready)
                body, notes = _rewrite_vk_html(body)
                if notes:
                    log(f"HTML rewrite {host}: {', '.join(notes)}")
                if is_embed_request:
                    debug_dir = Path(__file__).resolve().parent.parent / "data"
                    debug_dir.mkdir(parents=True, exist_ok=True)
                    (debug_dir / "debug-last-embed.html").write_bytes(body)
                    log(
                        f"EMBED saved: {len(body)} bytes, "
                        f"rewrite={notes or ['none']}"
                    )
                lines = rhead.split(b"\r\n")
                status = lines[0] if lines else b"HTTP/1.1 200 OK"
                packed = _build_response(status, lines[1:], body)
                client_ssl.sendall(packed)
            else:
                resp = _strip_frame_headers(rhead + b"\r\n\r\n" + ralready)
                rhead2, ralready2 = resp.split(b"\r\n\r\n", 1)
                client_ssl.sendall(rhead2 + b"\r\n\r\n")
                _forward_body(remote, client_ssl, rhead2, ralready2, until_eof=True)
    except OSError as exc:
        log(f"mitm io {host}: {exc}")
    finally:
        try:
            client_ssl.close()
        except OSError:
            pass
        try:
            remote.close()
        except OSError:
            pass


def _handle_client(
    client: socket.socket,
    user_agent: str,
    log: Callable[[str], None],
) -> None:
    try:
        client.settimeout(120)
        data = _recv_headers(client, limit=65536)
        if not data:
            client.close()
            return
        if b"\r\n\r\n" in data:
            head, leftover = data.split(b"\r\n\r\n", 1)
        else:
            head, leftover = data, b""
        first = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        if first.upper().startswith("CONNECT "):
            parts = first.split()
            target = parts[1]
            host, _, port_s = target.partition(":")
            port = int(port_s or "443")
            if should_mitm(host):
                log(f"CONNECT MITM {host}:{port}")
                _mitm_https(client, host, port, user_agent, log, preamble=leftover)
            else:
                log(f"CONNECT tunnel {host}:{port}")
                _tunnel(client, host, port, preamble=leftover)
            return
        client.sendall(b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n")
        client.close()
    except OSError:
        try:
            client.close()
        except OSError:
            pass


class FrameBypassProxy:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = DEFAULT_PORT,
        user_agent: str = DEFAULT_UA,
    ) -> None:
        self.host = host
        self.port = port
        self.user_agent = user_agent
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.logs: list[str] = []

    def log(self, msg: str) -> None:
        line = f"[proxy] {msg}"
        self.logs.append(line)
        print(line, flush=True)

    def start(self) -> None:
        ensure_ca()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self._sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1
            )
        self._sock.bind((self.host, self.port))
        self._sock.listen(50)
        self._sock.settimeout(1.0)
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="vkpm-proxy", daemon=True)
        self._thread.start()
        self.log(f"слушаю {self.host}:{self.port} (снимаю X-Frame-Options у VK)")

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=_handle_client,
                args=(client, self.user_agent, self.log),
                daemon=True,
            ).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        self.log("остановлен")


def run_proxy_forever(port: int = DEFAULT_PORT, user_agent: str = DEFAULT_UA) -> None:
    proxy = FrameBypassProxy(port=port, user_agent=user_agent)
    proxy.start()
    print("Прокси работает. Не закрывайте окно. Ctrl+C — выход.")
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        proxy.stop()
