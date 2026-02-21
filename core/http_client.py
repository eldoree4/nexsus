import aiohttp
import asyncio
import ssl
import random
import json
from urllib.parse import urlparse
from nexsus.config import Config
from nexsus.utils.logger import Logger

class SimpleResponse:
    __slots__ = ('status', 'headers', 'body', 'url')
    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    async def json(self):
        return json.loads(self.body.decode('utf-8'))

    async def text(self):
        return self.body.decode('utf-8')

class HTTPClient:
    def __init__(self, rate_limiter, validator):
        self.rate_limiter = rate_limiter
        self.validator = validator
        self.logger = Logger("HTTPClient")
        self.user_agents = self._load_user_agents()
        self.proxies = Config.PROXIES
        self.current_proxy = None
        self.session = None
        self._create_session()

    def _load_user_agents(self):
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.144 Mobile Safari/537.36',
        ]

    def _create_session(self):
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': '*/*',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'id,en;q=0.8', 'en;q=0.7']),
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
        proxy = random.choice(self.proxies) if self.proxies else None
        self.current_proxy = proxy

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            force_close=True,
            enable_cleanup_closed=True,
            ssl=ssl_context,
            limit=10
        )

        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=timeout,
            connector=connector,
            proxy=proxy
        )

    async def rotate_session(self):
        if self.session:
            await self.session.close()
        self._create_session()
        self.logger.debug("Session rotated (new User-Agent and proxy)")

    async def resolve_domain(self, domain):
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            answers = resolver.resolve(domain, 'A')
            if answers:
                ip = str(answers[0])
                self.logger.debug(f"Manual DNS resolve {domain} -> {ip}")
                return ip
        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {domain}: {e}")
            return None

    async def request(self, method, url, retries=3, **kwargs):
        if not self.validator.validate(url):
            raise ValueError(f"URL {url} out of scope")

        parsed = urlparse(url)
        host = parsed.hostname

        await self.rate_limiter.wait_if_needed(host)

        is_domain = not host.replace('.', '').isdigit()
        if is_domain:
            ip = await self.resolve_domain(host)
            if ip:
                self.logger.debug(f"Using manual IP {ip} for {host}")
                if 'headers' not in kwargs:
                    kwargs['headers'] = {}
                kwargs['headers']['Host'] = host
                url = url.replace(host, ip, 1)

        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers']['Accept-Encoding'] = 'identity'
        kwargs.setdefault('allow_redirects', True)

        for attempt in range(retries):
            try:
                async with self.session.request(method, url, **kwargs) as resp:
                    if resp.status == 429:
                        self.logger.warning(f"Rate limited (429) on {url}, rotating session...")
                        await self.rotate_session()
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
            except (aiohttp.ClientConnectorError, aiohttp.ClientOSError, asyncio.TimeoutError) as e:
                self.logger.debug(f"Connection error (attempt {attempt+1}): {e}")
                if attempt == retries - 1:
                    self.logger.error(f"All retries failed for {url}: {e}")
                    return None
                await asyncio.sleep(2 ** attempt)
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                return None
        return None

    async def close(self):
        if self.session:
            await self.session.close()
