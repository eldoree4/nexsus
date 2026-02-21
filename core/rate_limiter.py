import asyncio
import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, default_rate=10):
        self.default_rate = default_rate
        self.host_rates = defaultdict(lambda: default_rate)
        self.host_timestamps = defaultdict(list)

    async def wait_if_needed(self, host):
        now = time.time()
        rate = self.host_rates[host]
        timestamps = self.host_timestamps[host]
        timestamps[:] = [t for t in timestamps if t > now - 1]
        if len(timestamps) >= rate:
            sleep_time = 1 - (now - timestamps[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        self.host_timestamps[host].append(time.time())

    def set_rate(self, host, rate):
        self.host_rates[host] = rate
