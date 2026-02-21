import aiohttp
import asyncio
import ssl
import random
import json
import socket
import dns.resolver
from urllib.parse import urlparse
from aiohttp.abc import AbstractResolver
from nexsus.config import Config
from nexsus.utils.logger import Logger

class CustomResolver(AbstractResolver):
    """
    Resolver kustom dengan support manual DNS override
    sambil preserving hostname untuk SNI (Server Name Indication)
    """
    def __init__(self, logger, manual_dns=None):
        self.logger = logger
        self.cache = {}
        self.manual_dns = manual_dns or {}  # {'hostname': 'ip_address'}
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

    async def resolve(self, host, port=0, family=socket.AF_INET):
        """
        Resolve hostname ke IP, dengan dukungan manual override.
        
        PENTING: Selalu return hostname untuk SNI, bukan IP address saja.
        Ini memastikan SSL/TLS certificate validation bekerja dengan proper.
        """
        # Cek manual DNS override
        if host in self.manual_dns:
            ip = self.manual_dns[host]
            self.logger.debug(f"Manual DNS resolve {host} -> {ip}")
            # Return dengan hostname asli untuk SNI ✅
            return [{'hostname': host, 'host': ip, 'port': port, 'family': family, 'proto': 0, 'flags': 0}]
        
        # Cek cache
        if host in self.cache:
            ip = self.cache[host]
            self.logger.debug(f"Custom resolver cache: {host} -> {ip}")
            # Return dengan hostname untuk SNI ✅
            return [{'hostname': host, 'host': ip, 'port': port, 'family': family, 'proto': 0, 'flags': 0}]
        
        # Resolve via DNS
        try:
            answers = self.resolver.resolve(host, 'A')
            if answers:
                ip = str(answers[0])
                self.logger.debug(f"Custom resolver: {host} -> {ip}")
                self.cache[host] = ip
                # Return dengan hostname untuk SNI ✅
                return [{'hostname': host, 'host': ip, 'port': port, 'family': family, 'proto': 0, 'flags': 0}]
        except Exception as e:
            self.logger.debug(f"Custom resolver failed for {host}: {e}")
        
        return []

    async def close(self):
        pass


class SimpleResponse:
    __slots__ = ('status', 'headers', 'body', 'url')
    
    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    async def json(self):
        return json.loads(self.body.decode('utf-8'))

    async def text(self, encoding='utf-8'):
        return self.body.decode(encoding)


class HTTPClient:
    def __init__(self, rate_limiter, validator):
        self.rate_limiter = rate_limiter
        self.validator = validator
        self.logger = Logger("HTTPClient")
        self.user_agents = self._load_user_agents()
        self.proxies = Config.PROXIES
        self.session = None
        self._create_session()

    def _load_user_agents(self):
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.144 Mobile Safari/537.36',
        ]

    def _create_session(self):
        """
        Create aiohttp session dengan SSL/TLS configuration yang proper
        dan support untuk manual DNS resolution dengan SNI.
        """
        headers = {
            'Accept': '*/*',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'id,en;q=0.8', 'en;q=0.7']),
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT, connect=10, sock_read=30)
        proxy = random.choice(self.proxies) if self.proxies else None

        # ✅ PERBAIKAN 1: Proper SSL context dengan SNI support dan certificate verification
        ssl_context = ssl.create_default_context()
        
        # ✅ Enable hostname checking dan certificate verification
        # Jangan disable ini! Ini penyebab utama handshake failure
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # ✅ PERBAIKAN 2: Enforce TLS 1.2 minimum
        # Avoid deprecated SSL versions (SSLv3, TLSv1.0, TLSv1.1)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # ✅ PERBAIKAN 3: Load system CA certificates
        ssl_context.load_default_certs()
        
        # ✅ PERBAIKAN 4: Gunakan custom resolver yang preserve hostname untuk SNI
        # Manual DNS mapping bisa dikonfigurasi di Config.MANUAL_DNS
        # Format: {'www.veed.io': '104.18.34.211'}
        manual_dns = getattr(Config, 'MANUAL_DNS', {})
        resolver = CustomResolver(self.logger, manual_dns)

        connector = aiohttp.TCPConnector(
            force_close=True,
            enable_cleanup_closed=True,
            ssl=ssl_context,
            limit=10,
            ttl_dns_cache=300,
            resolver=resolver
        )

        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=timeout,
            connector=connector,
            proxy=proxy
        )

    async def request(self, method, url, retries=3, **kwargs):
        """
        Perform HTTP request dengan retry logic dan proper error handling.
        """
        if not self.validator.validate(url):
            raise ValueError(f"URL {url} out of scope")

        parsed = urlparse(url)
        host = parsed.hostname

        # Terapkan rate limiting berdasarkan host
        await self.rate_limiter.wait_if_needed(host)

        # Set header default
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers']['Accept-Encoding'] = 'identity'
        kwargs['headers']['User-Agent'] = random.choice(self.user_agents)
        kwargs.setdefault('allow_redirects', True)

        for attempt in range(retries):
            try:
                async with self.session.request(method, url, **kwargs) as resp:
                    if resp.status == 429:
                        wait_time = 2 ** attempt + random.uniform(0, 1)
                        self.logger.warning(f"Rate limited (429) on {url}, waiting {wait_time:.1f}s...")
                        await asyncio.sleep(wait_time)
                        continue

                    try:
                        body = await resp.read()
                    except Exception as e:
                        self.logger.debug(f"Body read failed (attempt {attempt+1}): {e}")
                        if attempt == retries - 1:
                            return None
                        await asyncio.sleep(2 ** attempt)
                        continue

                    return SimpleResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url)
                    )

            except ssl.SSLError as e:
                # ✅ PERBAIKAN 5: Proper SSL error handling dengan detail logging
                error_msg = str(e)
                self.logger.error(
                    f"SSL/TLS Error for {host} (attempt {attempt+1}): {error_msg}"
                )
                
                # Log detail error untuk debugging
                if "CERTIFICATE_VERIFY_FAILED" in error_msg:
                    self.logger.error(
                        f"Certificate verification failed untuk {host}. "
                        f"Kemungkinan penyebab:\n"
                        f"1. Certificate tidak valid atau expired\n"
                        f"2. Certificate tidak signed oleh trusted CA\n"
                        f"3. Hostname tidak sesuai dengan certificate"
                    )
                elif "SSLV3_ALERT_HANDSHAKE_FAILURE" in error_msg:
                    self.logger.error(
                        f"SSL Handshake failure untuk {host}. "
                        f"Kemungkinan penyebab:\n"
                        f"1. Server Name Indication (SNI) tidak cocok\n"
                        f"2. TLS version incompatibility\n"
                        f"3. Certificate mismatch dengan IP address"
                    )
                
                if attempt == retries - 1:
                    self.logger.error(
                        f"SSL/TLS verification failed for {url} "
                        f"after {retries} attempts. Giving up."
                    )
                    return None
                
                await asyncio.sleep(2 ** attempt)

            except (aiohttp.ClientConnectorError, aiohttp.ClientOSError, asyncio.TimeoutError) as e:
                self.logger.debug(f"Connection error (attempt {attempt+1}): {e}")
                if attempt == retries - 1:
                    self.logger.error(f"All retries failed for {url}: {e}")
                    return None
                await asyncio.sleep(2 ** attempt)

            except Exception as e:
                self.logger.error(f"Unexpected error for {url}: {e}")
                return None

        return None

    async def close(self):
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
