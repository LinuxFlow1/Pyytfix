import asyncio
import socket
import os
from urllib.parse import urlparse
from aiohttp import ClientSession

# Конфигурация
PROXY_START_PORT = 8080  # Начальный порт для проверки
PROXY_MAX_PORT = 8090    # Максимальный порт для поиска
BLACKLIST_FILE = "blacklist.txt"

def log(message: str) -> None:
    print(f"[*] {message}")

def find_free_port(start: int, end: int) -> int:
    """Находит первый свободный порт в заданном диапазоне"""
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return port
            except OSError:
                continue
    raise OSError(f"No free ports in range {start}-{end}")

def load_blacklist() -> set:
    try:
        with open(BLACKLIST_FILE, 'r') as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        log(f"Файл {BLACKLIST_FILE} не найден. Черный список пуст.")
        return set()

async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception as e:
        log(f"Ошибка передачи данных: {str(e)}")
    finally:
        writer.close()

async def handle_websocket(client_reader, client_writer, host, port):
    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
        client_writer.write(b"HTTP/1.1 101 Switching Protocols\r\n")
        client_writer.write(b"Upgrade: websocket\r\n")
        client_writer.write(b"Connection: Upgrade\r\n\r\n")
        await client_writer.drain()

        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer)
        )
        
    except Exception as e:
        log(f"WebSocket error: {str(e)}")
    finally:
        client_writer.close()

async def handle_https(client_reader, client_writer, host):
    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, 443)
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer)
        )
    except Exception as e:
        log(f"HTTPS error: {str(e)}")
    finally:
        client_writer.close()

def is_domain_blocked(host: str, blacklist: set) -> bool:
    if not host:
        return False
    parts = host.split('.')
    for i in range(len(parts)):
        domain = '.'.join(parts[i:])
        if domain in blacklist:
            log(f"Блокировка: {host} (правило: {domain})")
            return True
    return False

async def handle_client(reader, writer):
    blacklist = load_blacklist()
    try:
        request_data = await reader.readuntil(b'\r\n\r\n')
        headers = request_data.split(b'\r\n')
        first_line = headers[0].decode()
        host = None
        port = 80
        ws_upgrade = False

        headers_dict = {}
        for h in headers[1:]:
            if b': ' in h:
                key, value = h.split(b': ', 1)
                headers_dict[key.decode().lower()] = value.decode()

        if headers_dict.get('upgrade', '').lower() == 'websocket':
            ws_upgrade = True
            host_header = headers_dict.get('host', '')
            if ':' in host_header:
                host, port_str = host_header.split(':', 1)
                port = int(port_str)
            else:
                host = host_header

        elif first_line.startswith('CONNECT'):
            host_port = first_line.split()[1]
            host, port_str = host_port.split(':', 1) if ':' in host_port else (host_port, 443)
            port = int(port_str)

        else:
            method, url, _ = first_line.split()
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or 80

        if host and is_domain_blocked(host, blacklist):
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await writer.drain()
            return

        if ws_upgrade:
            await handle_websocket(reader, writer, host, port)
        elif first_line.startswith('CONNECT'):
            await handle_https(reader, writer, host)
        else:
            async with ClientSession() as session:
                async with session.request(
                    method=first_line.split()[0],
                    url=url,
                    headers=headers_dict,
                    data=request_data,
                    allow_redirects=False
                ) as resp:
                    writer.write(f"HTTP/1.1 {resp.status} {resp.reason}\r\n".encode())
                    for k, v in resp.headers.items():
                        writer.write(f"{k}: {v}\r\n".encode())
                    writer.write(b"\r\n")
                    await writer.drain()

                    async for chunk in resp.content.iter_any():
                        writer.write(chunk)
                        await writer.drain()

    except asyncio.IncompleteReadError:
        log("Клиент закрыл соединение")
    except Exception as e:
        log(f"Ошибка обработки: {str(e)}")
    finally:
        writer.close()

async def main():
    try:
        port = find_free_port(PROXY_START_PORT, PROXY_MAX_PORT)
        if port != PROXY_START_PORT:
            log(f"Порт {PROXY_START_PORT} занят, использую порт {port}")
            
        server = await asyncio.start_server(handle_client, '0.0.0.0', port)
        
        async with server:
            log(f"Прокси запущен на 0.0.0.0:{port}")
            await server.serve_forever()
            
    except OSError as e:
        log(f"Ошибка: {e}")
    except Exception as e:
        log(f"Неожиданная ошибка: {str(e)}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log("Сервер остановлен")
