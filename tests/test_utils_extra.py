import asyncio
import aiohttp
import pytest

from dosev.utils import fetch_blocklists


@pytest.mark.asyncio
async def test_fetch_blocklists_skips_non_200_and_handles_errors(monkeypatch, tmp_path):
    destination = tmp_path / "blocklists"

    class FakeResponse:
        def __init__(self, status=200, text="ok"):
            self.status = status
            self._text = text

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def text(self):
            return self._text

    class FakeSession:
        def __init__(self):
            self.calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            self.calls.append(url)
            if url.endswith("bad"):
                return FakeResponse(status=404)
            if url.endswith("timeout"):
                raise asyncio.TimeoutError()
            if url.endswith("client"):
                raise aiohttp.ClientError("client")
            if url.endswith("oops"):
                raise RuntimeError("oops")
            return FakeResponse(text="content")

    monkeypatch.setattr(aiohttp, "ClientSession", FakeSession)
    await fetch_blocklists(
        [
            "https://example.com/good",
            "https://example.com/bad",
            "https://example.com/timeout",
            "https://example.com/client",
            "https://example.com/oops",
        ],
        destination_dir=str(destination),
    )

    assert (destination / "good").exists()
    assert not (destination / "bad").exists()
