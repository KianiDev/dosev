# dosev/utils.py – streaming fetch (same as before)

import asyncio
import os
import logging
from typing import List

import aiohttp
import aiohttp.client_exceptions

async def fetch_blocklists(urls: List[str], destination_dir: str = "blocklists") -> None:
    """
    Download each URL and save it as a file inside destination_dir.
    Filename is derived from the URL's last part (e.g., 'domainlist.txt').
    Uses streaming to avoid loading large files into memory.
    """
    os.makedirs(destination_dir, exist_ok=True)
    async with aiohttp.ClientSession() as session:
        for url in urls:
            if not url.strip():
                continue
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        logging.warning("Failed to fetch %s: HTTP %s", url, resp.status)
                        continue
                    filename = url.split('/')[-1] or 'blocklist.txt'
                    if not filename:
                        filename = 'blocklist.txt'
                    filepath = os.path.join(destination_dir, filename)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        async for chunk, _ in resp.content.iter_chunks():
                            if chunk:
                                f.write(chunk.decode('utf-8', errors='ignore'))
                    logging.debug("Saved blocklist %s -> %s", url, filepath)
            except asyncio.TimeoutError:
                logging.warning("Timeout fetching %s", url)
            except aiohttp.client_exceptions.ClientError as e:
                logging.warning("Client error fetching %s: %s", url, e)
            except Exception as e:
                logging.warning("Unexpected error fetching %s: %s", url, e)