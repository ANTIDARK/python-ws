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

import aiohttp
from aiohttp import web

UUID = os.environ.get("UUID", "7bd180e8-1142-4387-93f5-03e8d750a896")
DOMAIN = os.environ.get("DOMAIN", "")
SUB_PATH = os.environ.get("SUB_PATH", "sub")
WSPATH = os.environ.get("WSPATH", UUID[:8])
PORT = int(os.environ.get("SERVER_PORT") or os.environ.get("PORT") or 3000)
DEBUG = os.environ.get("DEBUG", "").lower() == "true"

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

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
logging.getLogger("aiohttp.server").setLevel(logging.WARNING)
logging.getLogger("aiohttp.client").setLevel(logging.WARNING)
logging.getLogger("aiohttp.internal").setLevel(logging.WARNING)
logging.getLogger("aiohttp.websocket").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


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
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    for _ in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://dns.google/resolve?name={host}&type=A"
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("Status") == 0 and data.get("Answer"):
                            for answer in data["Answer"]:
                                if answer.get("type") == 1:
                                    return answer.get("data")
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
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api-ipv4.ip.sb/ip", timeout=5) as resp:
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


def parse_vless_header(first_msg: bytes, uuid_bytes: bytes):
    if len(first_msg) < 18 or first_msg[0] != 0:
        raise ValueError("invalid VLESS header")
    if first_msg[1:17] != uuid_bytes:
        raise ValueError("uuid mismatch")

    port_offset = 17
    if first_msg[port_offset] == 0:
        port_offset += 1

    if port_offset + 2 > len(first_msg):
        raise ValueError("truncated VLESS header")

    port = struct.unpack("!H", first_msg[port_offset:port_offset + 2])[0]
    offset = port_offset + 2
    atyp = first_msg[offset]
    offset += 1

    if atyp == 1:
        if offset + 4 > len(first_msg):
            raise ValueError("invalid IPv4 address")
        host = ".".join(str(b) for b in first_msg[offset:offset + 4])
        offset += 4
    elif atyp == 2:
        if offset >= len(first_msg):
            raise ValueError("invalid domain address")
        host_length = first_msg[offset]
        offset += 1
        if offset + host_length > len(first_msg):
            raise ValueError("invalid domain length")
        host = first_msg[offset:offset + host_length].decode("utf-8")
        offset += host_length
    elif atyp == 3:
        if offset + 16 > len(first_msg):
            raise ValueError("invalid IPv6 address")
        host = ":".join(f"{(first_msg[j] << 8) + first_msg[j + 1]:04x}" for j in range(offset, offset + 16, 2))
        offset += 16
    else:
        raise ValueError("unsupported address type")

    return host, port, first_msg[offset:]


async def handle_vless(websocket, first_msg: bytes, uuid_bytes: bytes) -> bool:
    try:
        host, port, residual = parse_vless_header(first_msg, uuid_bytes)
    except ValueError:
        return False

    if is_blocked_domain(host):
        await websocket.close()
        return False

    await websocket.send_bytes(b"\x00\x00")

    resolved_host = await resolve_host(host)
    try:
        reader, writer = await asyncio.open_connection(resolved_host, port)
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
