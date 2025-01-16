import asyncio
import socket
import os
import ssl
import random
import dns.resolver
import gzip
import base64
from stem import Signal
from stem.control import Controller
from aiohttp import ClientSession, web
from datetime import datetime, timedelta
import configparser
from typing import Dict, Tuple, Set, Optional

# Путь к конфигурационному файлу
CONFIG_DIR = 'config'
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.ini')

# Создание конфигурационного файла, если он отсутствует
if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)

if not os.path.exists(CONFIG_FILE):
    config = configparser.ConfigParser()
    config['Proxy'] = {
        'DEFAULT_PROXY_PORT': '8080',
        'DEFAULT_SECONDARY_PROXY_PORT': '8081',
        'BLACKLIST_FILE': 'blacklist.txt',
        'LOG_FILE': 'proxy.log'
    }
    config['Tor'] = {
        'TOR_PORT': '9050'
    }
    config['Cache'] = {
        'CACHE_TTL': '300'
    }
    config['DNS'] = {
        'DNS_OVER_HTTPS': 'https://cloudflare-dns.com/dns-query'
    }
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

# Загрузка конфигурации
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

DEFAULT_PROXY_PORT = int(config.get('Proxy', 'DEFAULT_PROXY_PORT', fallback=8080))
DEFAULT_SECONDARY_PROXY_PORT = int(config.get('Proxy', 'DEFAULT_SECONDARY_PROXY_PORT', fallback=8081))
BLACKLIST_FILE = config.get('Proxy', 'BLACKLIST_FILE', fallback='blacklist.txt')
LOG_FILE = config.get('Proxy', 'LOG_FILE', fallback='proxy.log')
TOR_PORT = int(config.get('Tor', 'TOR_PORT', fallback=9050))
CACHE_TTL = int(config.get('Cache', 'CACHE_TTL', fallback=300))
DNS_OVER_HTTPS = config.get('DNS', 'DNS_OVER_HTTPS', fallback='https://cloudflare-dns.com/dns-query')
AUTH_USER = os.getenv('PROXY_AUTH_USER', 'admin')
AUTH_PASS = os.getenv('PROXY_AUTH_PASS', 'password')

DNS_CACHE: Dict[str, str] = {}
HTTP_CACHE: Dict[Tuple[str, int, bytes], Tuple[bytes, datetime]] = {}

def get_local_ip() -> str:
    """Определяет локальный IP-адрес устройства."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]

PROXY_HOST = get_local_ip()

def ensure_blacklist() -> None:
    """Создает или обновляет файл черного списка."""
    default_blacklist = [
        "youtube.com", "youtu.be", "yt.be", "googlevideo.com", "ytimg.com",
        "ggpht.com", "gvt1.com", "youtube-nocookie.com", "youtube-ui.l.google.com",
        "youtubeembeddedplayer.googleapis.com", "youtube.googleapis.com",
        "youtubei.googleapis.com", "yt-video-upload.l.google.com", "wide-youtube.l.google.com"
    ]
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'w') as f:
            f.writelines(f"{domain}\n" for domain in default_blacklist)
    else:
        with open(BLACKLIST_FILE, 'r') as f:
            current_blacklist = set(line.strip() for line in f)
        new_domains = set(default_blacklist) - current_blacklist
        if new_domains:
            with open(BLACKLIST_FILE, 'a') as f:
                f.writelines(f"{domain}\n" for domain in new_domains)

def load_blacklist() -> Set[str]:
    """Загружает черный список доменов."""
    with open(BLACKLIST_FILE) as f:
        return set(line.strip() for line in f)

def in_blacklist(hostname: str) -> bool:
    """Проверяет, входит ли хост в черный список."""
    return any(domain in hostname for domain in load_blacklist())

async def resolve_dns(host: str, dns_server: str) -> str:
    """Разрешает DNS-имя с кэшированием."""
    if host in DNS_CACHE:
        log(f"[CACHE HIT] {host} -> {DNS_CACHE[host]}")
        return DNS_CACHE[host]
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    try:
        answer = resolver.resolve(host, 'A')
        ip = answer[0].to_text()
        DNS_CACHE[host] = ip
        log(f"[CACHE MISS] {host} -> {ip}")
        return ip
    except dns.resolver.NoAnswer:
        log(f"[DNS ERROR] No answer for {host}")
        raise
    except dns.resolver.NXDOMAIN:
        log(f"[DNS ERROR] Domain {host} does not exist")
        raise
    except dns.resolver.Timeout:
        log(f"[DNS ERROR] Timeout while resolving {host}")
        raise
    except dns.resolver.NoNameservers:
        log(f"[DNS ERROR] All configured nameservers failed for {host}")
        raise

async def resolve_doh(host: str) -> str:
    """Разрешает DNS-имя через DNS-over-HTTPS."""
    if host in DNS_CACHE:
        log(f"[CACHE HIT] {host} -> {DNS_CACHE[host]}")
        return DNS_CACHE[host]
    async with ClientSession() as session:
        try:
            async with session.get(f"{DNS_OVER_HTTPS}?name={host}&type=A") as response:
                data = await response.json()
                ip = data['Answer'][0]['data']
                DNS_CACHE[host] = ip
                log(f"[DNS-over-HTTPS] {host} -> {ip}")
                return ip
        except Exception as e:
            log(f"[DNS-over-HTTPS ERROR] {e}")
            raise

def use_tor_proxy() -> Controller:
    """Запускает Tor прокси для обхода DPI."""
    try:
        controller = Controller.from_port(port=9051)
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        return controller
    except Exception as e:
        log(f"[TOR ERROR] {e}")
        raise

async def make_tor_request(host: str, port: int, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, request: bytes) -> None:
    """Обрабатывает запрос через Tor."""
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl.create_default_context(), proxy='socks5h://127.0.0.1:9050')
        writer.write(request)
        await writer.drain()

        while True:
            data = await reader.read(65535)
            if not data:
                break
            client_writer.write(data)
            await client_writer.drain()

        writer.close()
        await writer.wait_closed()
    except Exception as e:
        log(f"[TOR REQUEST ERROR] {e}")
        raise

def log_request(client_ip: str, requested_url: str) -> None:
    """Записывает запрос в файл логов."""
    with open("proxy_requests.log", "a") as log_file:
        log_file.write(f"{datetime.now().isoformat()} - IP: {client_ip}, URL: {requested_url}\n")

def log(message: str) -> None:
    """Записывает сообщение в файл логов."""
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{datetime.now().isoformat()} - {message}\n")

def authenticate(headers: Dict[str, str]) -> bool:
    """Проверяет аутентификацию."""
    auth_header = headers.get('Authorization')
    if auth_header:
        auth_type, auth_string = auth_header.split()
        if auth_type.lower() == 'basic':
            auth_string = base64.b64decode(auth_string).decode()
            username, password = auth_string.split(':')
            return username == AUTH_USER and password == AUTH_PASS
    return False

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, dns_server: str) -> None:
    """Обрабатывает подключение клиента."""
    try:
        request = await reader.read(65535)
        headers = request.split(b'\n')
        if not authenticate(dict(line.split(b': ', 1) for line in headers[1:] if b': ' in line)):
            writer.write(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Access to the staging site"\r\n\r\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        first_line = headers[0]
        url = first_line.split(b' ')[1]

        client_ip = writer.get_extra_info('peername')[0]
        log_request(client_ip, url.decode())

        http_pos = url.find(b'://')
        temp = url if http_pos == -1 else url[(http_pos + 3):]

        port_pos = temp.find(b':')
        webserver_pos = temp.find(b'/')
        webserver_pos = len(temp) if webserver_pos == -1 else webserver_pos

        webserver = temp[:port_pos] if port_pos != -1 else temp[:webserver_pos]
        port = int(temp[(port_pos + 1):webserver_pos]) if port_pos != -1 else 80

        if in_blacklist(webserver.decode()):
            log(f"[БЛОКИРОВАНО] Домен {webserver.decode()} в черном списке.")
            writer.close()
            await writer.wait_closed()
            return

        try:
            # Используем DNS-over-HTTPS для обхода блокировок DNS
            server_ip = await resolve_doh(webserver.decode())
            await proxy_server(server_ip, port, reader, writer, request)
        except Exception as e:
            log(f"[ОШИБКА] {e}. Попытка использовать Tor...")
            await make_tor_request(webserver.decode(), port, reader, writer, request)
    except Exception as e:
        log(f"[ОШИБКА] {e}")

async def proxy_server(server_ip: str, port: int, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, request: bytes) -> None:
    """Передает запросы между клиентом и сервером."""
    try:
        cache_key = (server_ip, port, request)
        if cache_key in HTTP_CACHE:
            cached_response, timestamp = HTTP_CACHE[cache_key]
            if (datetime.now() - timestamp) < timedelta(seconds=CACHE_TTL):
                log(f"[CACHE HIT] {server_ip}:{port}")
                client_writer.write(cached_response)
                await client_writer.drain()
                return

        reader, writer = await asyncio.open_connection(server_ip, port)

        if port == 443:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            reader, writer = await asyncio.open_connection(server_ip, port, ssl=context)

        writer.write(request)
        await writer.drain()

        response = b''
        while True:
            data = await reader.read(65535)
            if not data:
                break
            response += data
            client_writer.write(data)
            await client_writer.drain()

        # Сжимаем данные перед сохранением в кэш
        compressed_response = gzip.compress(response)
        HTTP_CACHE[cache_key] = (compressed_response, datetime.now())
    except Exception as e:
        log(f"[ОШИБКА ПРОКСИ] {e}")
    finally:
        client_writer.close()
        await client_writer.wait_closed()

def ask_user_for_secondary_proxy() -> bool:
    """Спрашивает пользователя, хочет ли он включить дополнительный прокси-сервер."""
    while True:
        user_input = input("Хотите включить дополнительный прокси-сервер? (да/нет): ").strip().lower()
        if user_input in ['да', 'нет']:
            return user_input == 'да'
        print("Пожалуйста, введите 'да' или 'нет'.")

def select_port(default_port: int) -> int:
    """Позволяет пользователю выбрать порт."""
    while True:
        user_input = input(f"Введите порт для прокси-сервера (по умолчанию {default_port}): ").strip()
        if user_input == '':
            return default_port
        try:
            port = int(user_input)
            if 1 <= port <= 65535:
                return port
            else:
                print("Порт должен быть в диапазоне от 1 до 65535.")
        except ValueError:
            print("Неверный ввод. Пожалуйста, введите число.")

async def start_proxy() -> None:
    """Запускает прокси-сервер."""
    primary_dns = '1.1.1.1'
    secondary_dns = '8.8.8.8'

    primary_port = select_port(DEFAULT_PROXY_PORT)
    secondary_port = select_port(DEFAULT_SECONDARY_PROXY_PORT)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile='path/to/cert.pem', keyfile='path/to/key.pem')

    primary_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, primary_dns), 
        PROXY_HOST, primary_port, ssl=ssl_context
    )
    log(f"[*] Прокси запущен на {PROXY_HOST}:{primary_port} с DNS {primary_dns}")

    if ask_user_for_secondary_proxy():
        secondary_server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, secondary_dns), 
            PROXY_HOST, secondary_port, ssl=ssl_context
        )
        log(f"[*] Дополнительный прокси запущен на {PROXY_HOST}:{secondary_port} с DNS {secondary_dns}")

    async with primary_server:
        if ask_user_for_secondary_proxy():
            async with secondary_server:
                await asyncio.gather(primary_server.serve_forever(), secondary_server.serve_forever())
        else:
            await primary_server.serve_forever()

if __name__ == "__main__":
    try:
        ensure_blacklist()
        asyncio.run(start_proxy())
    except KeyboardInterrupt:
        log("\n[*] Остановка прокси-сервера.")
    except Exception as e:
        log(f"[КРИТИЧЕСКАЯ ОШИБКА] {e}")
