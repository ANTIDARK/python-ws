#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import base64
import ipaddress
import logging
import os
import socket
import struct
import sys
import time
from collections import defaultdict
from typing import Optional, Dict, Tuple

import aiohttp
from aiohttp import web

UUID = os.environ.get("UUID", "7bd180e8-1142-4387-93f5-03e8d750a896")
DOMAIN = os.environ.get("DOMAIN", "")
SUB_PATH = os.environ.get("SUB_PATH", "sub")
WSPATH = os.environ.get("WSPATH", UUID[:8])
PORT = int(os.environ.get("SERVER_PORT") or os.environ.get("PORT") or 3000)
DEBUG = os.environ.get("DEBUG", "").lower() == "true"
BUFFER_SIZE = int(os.environ.get("BUFFER_SIZE", 65536))  # 64KB instead of 4KB
DNS_CACHE_TTL = int(os.environ.get("DNS_CACHE_TTL", 3600))  # 1 hour

CurrentDomain = DOMAIN or "change-your-domain.com"
CurrentPort = 443
Tls = "tls" if DOMAIN else "none"

DNS_SERVERS = ["8.8.4.4", "1.1.1.1"]
BLOCKED_DOMAINS = [
    "speedtest.net",
    "fast.com",
    "speedtest.cn",
    "speed.cloudflare.com",
    "speedof.me",
    "testmy.net",
    "bandwidth.place",
    "speed.io",
    "librespeed.org",
    "speedcheck.org",
]

# Precompute UUID bytes
UUID_BYTES = bytes.fromhex(UUID.replace("-", ""))

# Global DNS cache: {hostname -> (ip, timestamp)}
DNS_CACHE: Dict[str, Tuple[str, float]] = {}

# Global HTTP session
HTTP_SESSION: Optional[aiohttp.ClientSession] = None

# Cached index.html content
CACHED_HTML: Optional[str] = None

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
logging.getLogger("aiohttp.server").setLevel(logging.WARNING)
logging.getLogger("aiohttp.client").setLevel(logging.WARNING)
logging.getLogger("aiohttp.internal").setLevel(logging.WARNING)
logging.getLogger("aiohttp.websocket").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


async def get_http_session() -> aiohttp.ClientSession:
    """Get or create global HTTP session with connection pool."""
    global HTTP_SESSION
    if HTTP_SESSION is None or HTTP_SESSION.closed:
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        HTTP_SESSION = aiohttp.ClientSession(connector=connector)
    return HTTP_SESSION


async def close_http_session():
    """Close global HTTP session."""
    global HTTP_SESSION
    if HTTP_SESSION and not HTTP_SESSION.closed:
        await HTTP_SESSION.close()


def is_port_available(port, host="0.0.0.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None


def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith("." + blocked) for blocked in BLOCKED_DOMAINS)


async def resolve_host(host: str) -> str:
    """Resolve hostname with DNS cache."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    now = time.time()
    if host in DNS_CACHE:
        ip, timestamp = DNS_CACHE[host]
        if now - timestamp < DNS_CACHE_TTL:
            if DEBUG:
                logger.debug("DNS cache hit: %s -> %s", host, ip)
            return ip

    session = await get_http_session()
    for _ in DNS_SERVERS:
        try:
            url = f"https://dns.google/resolve?name={host}&type=A"
            async with session.get(url, timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("Status") == 0 and data.get("Answer"):
                        for answer in data["Answer"]:
                            if answer.get("type") == 1:
                                ip = answer.get("data")
                                DNS_CACHE[host] = (ip, now)
                                if DEBUG:
                                    logger.debug("DNS resolved: %s -> %s", host, ip)
                                return ip
        except Exception:
            continue

    return host


async def get_current_endpoint():
    global CurrentDomain, CurrentPort, Tls
    if DOMAIN:
        CurrentDomain = DOMAIN
        CurrentPort = 443
        Tls = "tls"
        return

    try:
        session = await get_http_session()
        async with session.get("https://api-ipv4.ip.sb/ip", timeout=3) as resp:
            if resp.status == 200:
                CurrentDomain = (await resp.text()).strip()
                CurrentPort = PORT
                Tls = "none"
                return
    except Exception as exc:
        logger.warning("Failed to resolve public IP: %s", exc)

    CurrentDomain = "change-your-domain.com"
    CurrentPort = 443
    Tls = "none"


def load_index_html() -> str:
    """Load and cache index.html content."""
    global CACHED_HTML
    if CACHED_HTML is not None:
        return CACHED_HTML

    try:
        with open("index.html", "r", encoding="utf-8") as handle:
            CACHED_HTML = handle.read()
            return CACHED_HTML
    except FileNotFoundError:
        CACHED_HTML = "Hello world!"
        return CACHED_HTML


def parse_vless_header(first_msg: bytes, uuid_bytes: bytes):
    """Parse VLESS protocol header according to specification.
    Format: VER(1) + UUID(16) + CMD(1) + ADD(1) + ATYP(1) + ADDR + PORT(2) + [Addons]
    """
    if len(first_msg) < 20:
        raise ValueError("VLESS header too short")

    if first_msg[0] != 0:
        raise ValueError("invalid VLESS version")
    if first_msg[1:17] != uuid_bytes:
        raise ValueError("uuid mismatch")

    cmd = first_msg[17]
    if cmd not in (0x01, 0x02):
        raise ValueError(f"unsupported CMD: {cmd}")

    addon_len = first_msg[18]
    offset = 19

    if offset + addon_len > len(first_msg):
        raise ValueError("truncated addons")
    offset += addon_len

    if offset >= len(first_msg):
        raise ValueError("truncated VLESS header")

    atyp = first_msg[offset]
    offset += 1

    if atyp == 1:  # IPv4
        if offset + 4 > len(first_msg):
            raise ValueError("invalid IPv4 address")
        host = ".".join(str(b) for b in first_msg[offset:offset + 4])
        offset += 4
    elif atyp == 2:  # Domain
        if offset >= len(first_msg):
            raise ValueError("invalid domain address")
        host_length = first_msg[offset]
        offset += 1
        if offset + host_length > len(first_msg):
            raise ValueError("invalid domain length")
        host = first_msg[offset:offset + host_length].decode("utf-8")
        offset += host_length
    elif atyp == 3:  # IPv6
        if offset + 16 > len(first_msg):
            raise ValueError("invalid IPv6 address")
        host = ":".join(f"{(first_msg[j] << 8) + first_msg[j + 1]:04x}" for j in range(offset, offset + 16, 2))
        offset += 16
    else:
        raise ValueError(f"unsupported address type: {atyp}")

    if offset + 2 > len(first_msg):
        raise ValueError("truncated port")
    port = struct.unpack("!H", first_msg[offset:offset + 2])[0]
    offset += 2

    return host, port, cmd, first_msg[offset:]


async def handle_vless(websocket, first_msg: bytes, uuid_bytes: bytes) -> bool:
    try:
        host, port, cmd, residual = parse_vless_header(first_msg, uuid_bytes)
    except ValueError as exc:
        if DEBUG:
            logger.warning("VLESS parse error: %s", exc)
        return False

    if is_blocked_domain(host):
        if DEBUG:
            logger.warning("Blocked domain: %s", host)
        await websocket.close()
        return False

    if cmd == 0x02:  # UDP
        if DEBUG:
            logger.info("UDP not supported, only TCP")
        await websocket.close()
        return False

    await websocket.send_bytes(b"\x00\x00")

    resolved_host = await resolve_host(host)
    if DEBUG:
        logger.info("VLESS: connecting to %s:%d", resolved_host, port)

    try:
        reader, writer = await asyncio.open_connection(resolved_host, port, ssl=False)
        if residual:
            writer.write(residual)
            await writer.drain()

        async def forward_ws_to_tcp():
            try:
                async for msg in websocket:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        writer.write(msg.data)
                        await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        async def forward_tcp_to_ws():
            try:
                while True:
                    data = await reader.read(BUFFER_SIZE)
                    if not data:
                        break
                    await websocket.send_bytes(data)
            except Exception:
                pass

        await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws())
    except Exception as exc:
        if DEBUG:
            logger.error("VLESS connection error: %s", exc)

    return True


async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    if f"/{WSPATH}" not in request.path:
        await ws.close()
        return ws

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws

        if len(first_msg.data) > 17 and first_msg.data[0] == 0:
            if await handle_vless(ws, first_msg.data, UUID_BYTES):
                return ws

        await ws.close()
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as exc:
        if DEBUG:
            logger.error("WebSocket handler error: %s", exc)
        await ws.close()

    return ws


async def http_handler(request):
    if request.path == "/":
        content = load_index_html()
        return web.Response(text=content, content_type="text/html")

    if request.path == f"/{SUB_PATH}":
        await get_current_endpoint()
        tls_param = "tls" if Tls == "tls" else "none"
        name_part = f"VLESS-{CurrentDomain}"
        vless_url = (
            f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none"
            f"&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws"
            f"&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        )
        encoded = base64.b64encode(vless_url.encode("utf-8")).decode("ascii")
        return web.Response(text=encoded + "\n", content_type="text/plain")

    return web.Response(status=404, text="Not Found\n")


async def main():
    actual_port = PORT
    if not is_port_available(actual_port):
        logger.warning("Port %s is already in use, finding an available one...", actual_port)
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info("Using port %s instead of %s", actual_port, PORT)
        else:
            logger.error("No available ports found")
            sys.exit(1)

    app = web.Application()
    app.router.add_get("/", http_handler)
    app.router.add_get(f"/{SUB_PATH}", http_handler)
    app.router.add_get(f"/{WSPATH}", websocket_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", actual_port)
    await site.start()
    logger.info("✅ VLESS server is running on port %s", actual_port)

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await close_http_session()
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")



def parse_vless_header(first_msg: bytes, uuid_bytes: bytes):
    """Parse VLESS protocol header according to specification.
    Format: VER(1) + UUID(16) + CMD(1) + ADD(1) + ATYP(1) + ADDR + PORT(2) + [Addons]
    """
    if len(first_msg) < 20:
        raise ValueError("VLESS header too short")

    if first_msg[0] != 0:
        raise ValueError("invalid VLESS version")
    if first_msg[1:17] != uuid_bytes:
        raise ValueError("uuid mismatch")

    cmd = first_msg[17]
    if cmd not in (0x01, 0x02):
        raise ValueError(f"unsupported CMD: {cmd}")

    addon_len = first_msg[18]
    offset = 19

    if offset + addon_len > len(first_msg):
        raise ValueError("truncated addons")
    offset += addon_len

    if offset >= len(first_msg):
        raise ValueError("truncated VLESS header")

    atyp = first_msg[offset]
    offset += 1

    if atyp == 1:  # IPv4
        if offset + 4 > len(first_msg):
            raise ValueError("invalid IPv4 address")
        host = ".".join(str(b) for b in first_msg[offset:offset + 4])
        offset += 4
    elif atyp == 2:  # Domain
        if offset >= len(first_msg):
            raise ValueError("invalid domain address")
        host_length = first_msg[offset]
        offset += 1
        if offset + host_length > len(first_msg):
            raise ValueError("invalid domain length")
        host = first_msg[offset:offset + host_length].decode("utf-8")
        offset += host_length
    elif atyp == 3:  # IPv6
        if offset + 16 > len(first_msg):
            raise ValueError("invalid IPv6 address")
        host = ":".join(f"{(first_msg[j] << 8) + first_msg[j + 1]:04x}" for j in range(offset, offset + 16, 2))
        offset += 16
    else:
        raise ValueError(f"unsupported address type: {atyp}")

    if offset + 2 > len(first_msg):
        raise ValueError("truncated port")
    port = struct.unpack("!H", first_msg[offset:offset + 2])[0]
    offset += 2

    return host, port, cmd, first_msg[offset:]


async def handle_vless(websocket, first_msg: bytes, uuid_bytes: bytes) -> bool:
    try:
        host, port, cmd, residual = parse_vless_header(first_msg, uuid_bytes)
    except ValueError as exc:
        if DEBUG:
            logger.warning("VLESS parse error: %s", exc)
        return False

    if is_blocked_domain(host):
        if DEBUG:
            logger.warning("Blocked domain: %s", host)
        await websocket.close()
        return False

    if cmd == 0x02:  # UDP
        if DEBUG:
            logger.info("UDP not supported, only TCP")
        await websocket.close()
        return False

    await websocket.send_bytes(b"\x00\x00")

    resolved_host = await resolve_host(host)
    if DEBUG:
        logger.info("VLESS: connecting to %s:%d", resolved_host, port)

    try:
        reader, writer = await asyncio.open_connection(resolved_host, port, ssl=False)
        if residual:
            writer.write(residual)
            await writer.drain()

        async def forward_ws_to_tcp():
            try:
                async for msg in websocket:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        writer.write(msg.data)
                        await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        async def forward_tcp_to_ws():
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    await websocket.send_bytes(data)
            except Exception:
                pass

        await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws())
    except Exception as exc:
        if DEBUG:
            logger.error("VLESS connection error: %s", exc)

    return True


async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    if f"/{WSPATH}" not in request.path:
        await ws.close()
        return ws

    uuid_bytes = bytes.fromhex(UUID.replace("-", ""))

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws

        if len(first_msg.data) > 17 and first_msg.data[0] == 0:
            if await handle_vless(ws, first_msg.data, uuid_bytes):
                return ws

        await ws.close()
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as exc:
        if DEBUG:
            logger.error("WebSocket handler error: %s", exc)
        await ws.close()

    return ws


async def http_handler(request):
    if request.path == "/":
        try:
            with open("index.html", "r", encoding="utf-8") as handle:
                content = handle.read()
            return web.Response(text=content, content_type="text/html")
        except FileNotFoundError:
            return web.Response(text="Hello world!", content_type="text/html")

    if request.path == f"/{SUB_PATH}":
        await get_current_endpoint()
        tls_param = "tls" if Tls == "tls" else "none"
        name_part = f"VLESS-{CurrentDomain}"
        vless_url = (
            f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none"
            f"&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws"
            f"&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        )
        encoded = base64.b64encode(vless_url.encode("utf-8")).decode("ascii")
        return web.Response(text=encoded + "\n", content_type="text/plain")

    return web.Response(status=404, text="Not Found\n")


async def main():
    actual_port = PORT
    if not is_port_available(actual_port):
        logger.warning("Port %s is already in use, finding an available one...", actual_port)
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info("Using port %s instead of %s", actual_port, PORT)
        else:
            logger.error("No available ports found")
            sys.exit(1)

    app = web.Application()
    app.router.add_get("/", http_handler)
    app.router.add_get(f"/{SUB_PATH}", http_handler)
    app.router.add_get(f"/{WSPATH}", websocket_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", actual_port)
    await site.start()
    logger.info("✅ VLESS server is running on port %s", actual_port)

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
