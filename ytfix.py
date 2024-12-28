import asyncio
import socket
import os
import ssl
import random
import dns.resolver
from stem import Signal
from stem.control import Controller
from aiohttp import ClientSession

# Настройки прокси-сервера
PROXY_PORT = 8080
SECONDARY_PROXY_PORT = 8081  # Порт для второго прокси-сервера
BLACKLIST_FILE = 'blacklist.txt'
TOR_PORT = 9050  # Tor порт для SOCKS5
DEFAULT_BLACKLIST = [
    "youtube.com",
    "youtu.be",
    "yt.be",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "gvt1.com",
    "youtube-nocookie.com",
    "youtube-ui.l.google.com",
    "youtubeembeddedplayer.googleapis.com",
    "youtube.googleapis.com",
    "youtubei.googleapis.com",
    "yt-video-upload.l.google.com",
    "wide-youtube.l.google.com",
]

DNS_CACHE = {}

# Получаем локальный IP адрес
def get_local_ip():
    """Определяет локальный IP-адрес устройства."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]

PROXY_HOST = get_local_ip()

# Обеспечиваем наличие черного списка
def ensure_blacklist():
    """Создает или обновляет файл черного списка."""
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'w') as f:
            f.writelines(f"{domain}\n" for domain in DEFAULT_BLACKLIST)
    else:
        with open(BLACKLIST_FILE, 'r') as f:
            current_blacklist = set(line.strip() for line in f)
        new_domains = set(DEFAULT_BLACKLIST) - current_blacklist
        if new_domains:
            with open(BLACKLIST_FILE, 'a') as f:
                f.writelines(f"{domain}\n" for domain in new_domains)

# Загружаем черный список доменов
def load_blacklist():
    """Загружает черный список доменов."""
    with open(BLACKLIST_FILE) as f:
        return set(line.strip() for line in f)

# Проверка на черный список
def in_blacklist(hostname):
    """Проверяет, входит ли хост в черный список."""
    return any(domain in hostname for domain in load_blacklist())

# Кэширование DNS запросов
async def resolve_dns(host, dns_server):
    """Разрешает DNS-имя с кэшированием."""
    if host in DNS_CACHE:
        return DNS_CACHE[host]
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]  # Используем указанный DNS-сервер
    answer = resolver.resolve(host, 'A')
    ip = answer[0].to_text()
    DNS_CACHE[host] = ip
    return ip

# Управление соединениями через Tor
def use_tor_proxy():
    """Запускает Tor прокси для обхода DPI."""
    controller = Controller.from_port(port=9051)  # Управляющий порт для Tor
    controller.authenticate()  # Аутентификация
    controller.signal(Signal.NEWNYM)  # Получение нового IP через Tor
    return controller

# Запросы через Tor SOCKS5 прокси
async def make_tor_request(host, port):
    """Обрабатывает запрос через Tor."""
    conn = asyncio.open_connection(host, port, proxy='socks5h://127.0.0.1:9050')
    return await conn

# Логирование запросов
def log_request(client_ip, requested_url):
    """Записывает запрос в файл логов."""
    with open("proxy_requests.log", "a") as log_file:
        log_file.write(f"IP: {client_ip}, URL: {requested_url}\n")

# Обработка клиента
async def handle_client(reader, writer, dns_server):
    """Обрабатывает подключение клиента."""
    try:
        request = await reader.read(65535)
        first_line = request.split(b'\n')[0]
        url = first_line.split(b' ')[1]

        # Логирование запроса
        client_ip = writer.get_extra_info('peername')[0]
        log_request(client_ip, url.decode())

        # Обработка URL
        http_pos = url.find(b'://')
        temp = url if http_pos == -1 else url[(http_pos + 3):]

        port_pos = temp.find(b':')
        webserver_pos = temp.find(b'/')
        webserver_pos = len(temp) if webserver_pos == -1 else webserver_pos

        webserver = temp[:port_pos] if port_pos != -1 else temp[:webserver_pos]
        port = int(temp[(port_pos + 1):webserver_pos]) if port_pos != -1 else 80

        if in_blacklist(webserver.decode()):
            print(f"[БЛОКИРОВАНО] Домен {webserver.decode()} в черном списке.")
            writer.close()
            await writer.wait_closed()
            return

        server_ip = await resolve_dns(webserver.decode(), dns_server)

        # Проверка на Tor
        if random.choice([True, False]):  # Случайным образом выбираем использование Tor
            print("[INFO] Использование Tor для обхода блокировки.")
            await make_tor_request(server_ip, port)
        else:
            await proxy_server(server_ip, port, reader, writer, request)
    except Exception as e:
        print(f"[ОШИБКА] {e}")

# Проксирование запроса
async def proxy_server(server_ip, port, client_reader, client_writer, request):
    """Передает запросы между клиентом и сервером."""
    try:
        # Подключаемся к целевому серверу (можно использовать SSL)
        reader, writer = await asyncio.open_connection(server_ip, port)

        # Шифруем HTTPS трафик, если необходим
        if port == 443:  # HTTPS
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            reader, writer = await asyncio.open_connection(server_ip, port, ssl=context)

        writer.write(request)
        await writer.drain()

        while True:
            data = await reader.read(65535)
            if not data:
                break
            client_writer.write(data)
            await client_writer.drain()
    except Exception as e:
        print(f"[ОШИБКА ПРОКСИ] {e}")
    finally:
        client_writer.close()
        await client_writer.wait_closed()

# Функция для запроса у пользователя включения дополнительного прокси-сервера
def ask_user_for_secondary_proxy():
    """Спрашивает пользователя, хочет ли он включить дополнительный прокси-сервер."""
    while True:
        user_input = input("Хотите включить дополнительный прокси-сервер? (да/нет): ").strip().lower()
        if user_input in ['да', 'нет']:
            return user_input == 'да'
        print("Пожалуйста, введите 'да' или 'нет'.")

# Запуск прокси-сервера
async def start_proxy():
    """Запускает прокси-сервер."""
    primary_dns = '1.1.1.1'
    secondary_dns = '8.8.8.8'

    primary_server = await asyncio.start_server(lambda r, w: handle_client(r, w, primary_dns), PROXY_HOST, PROXY_PORT)
    print(f"[*] Прокси запущен на {PROXY_HOST}:{PROXY_PORT} с DNS {primary_dns}")

    if ask_user_for_secondary_proxy():
        secondary_server = await asyncio.start_server(lambda r, w: handle_client(r, w, secondary_dns), PROXY_HOST, SECONDARY_PROXY_PORT)
        print(f"[*] Дополнительный прокси запущен на {PROXY_HOST}:{SECONDARY_PROXY_PORT} с DNS {secondary_dns}")

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
        print("\n[*] Остановка прокси-сервера.")
    except Exception as e:
        print(f"[КРИТИЧЕСКАЯ ОШИБКА] {e}")