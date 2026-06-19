import os
import aiohttp
import pytest
from dosev.utils import fetch_blocklists


@pytest.mark.asyncio
async def test_fetch_blocklists_creates_files(tmp_path, monkeypatch):
    called = {}

    class FakeResponse:
        def __init__(self, text, status=200):
            self._text = text
            self.status = status

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def text(self):
            return self._text

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            called['url'] = url
            return FakeResponse('example.com')

    monkeypatch.setattr(aiohttp, 'ClientSession', FakeSession)

    destination = tmp_path / "blocklists"
    await fetch_blocklists(["https://example.com/list.txt"], destination_dir=str(destination))
    assert os.path.exists(destination / "list.txt")
    with open(destination / "list.txt", "r", encoding="utf-8") as f:
        assert f.read() == 'example.com'
