"""Tests for backend.core.browser_engine — ScraplingSpider, PinchTabClient, PlaywrightEngine, Fuzzer, Intel."""
import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


class TestScraplingSpider:
    def test_init(self):
        from backend.core.browser_engine import ScraplingSpider

        spider = ScraplingSpider(["http://example.com"], scan_id="test")
        assert spider.start_urls == ["http://example.com"]
        assert spider.scan_id == "test"

    @pytest.mark.asyncio
    async def test_lightweight_crawl_calls_callback(self):
        from backend.core.browser_engine import ScraplingSpider

        callback = AsyncMock()
        spider = ScraplingSpider(
            ["http://test.example.com"],
            parse_callback=callback,
            scan_id="test",
        )
        # Mock aiohttp to return simple HTML
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='<a href="/page1">Link</a>')
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.get = MagicMock(return_value=mock_resp)

        with patch("backend.core.browser_engine.aiohttp", create=True) as mock_aio:
            mock_aio.ClientSession.return_value = mock_session
            await spider._lightweight_crawl()
        callback.assert_called_once()

    def test_merge_deduplicates(self):
        from backend.core.browser_engine import ScraplingRecon

        list1 = [{"url": "http://a.com"}, {"url": "http://b.com"}]
        list2 = [{"url": "http://a.com"}, {"url": "http://c.com"}]
        merged = ScraplingRecon._merge(list1, list2)
        assert len(merged) == 3
        urls = {e["url"] for e in merged}
        assert urls == {"http://a.com", "http://b.com", "http://c.com"}


class TestScraplingPinchTabClient:
    def test_init_defaults(self):
        from backend.core.browser_engine import ScraplingPinchTabClient

        client = ScraplingPinchTabClient()
        assert client.base_url == "http://127.0.0.1:9867"

    def test_init_custom_url(self):
        from backend.core.browser_engine import ScraplingPinchTabClient

        client = ScraplingPinchTabClient(base_url="http://custom:9999")
        assert client.base_url == "http://custom:9999"

    @pytest.mark.asyncio
    async def test_is_available_when_aiohttp_missing(self):
        from backend.core.browser_engine import ScraplingPinchTabClient

        client = ScraplingPinchTabClient()
        client._aiohttp_available = False
        result = await client.is_available()
        assert result is False

    def test_reset_availability(self):
        from backend.core.browser_engine import ScraplingPinchTabClient

        ScraplingPinchTabClient._available = False
        ScraplingPinchTabClient.reset_availability()
        assert ScraplingPinchTabClient._available is None

    def test_is_known_available(self):
        from backend.core.browser_engine import ScraplingPinchTabClient

        ScraplingPinchTabClient._available = True
        assert ScraplingPinchTabClient.is_known_available() is True
        ScraplingPinchTabClient._available = False
        assert ScraplingPinchTabClient.is_known_available() is False

    @pytest.mark.asyncio
    async def test_health_raises_when_aiohttp_missing(self):
        from backend.core.browser_engine import ScraplingPinchTabClient, PinchTabUnavailable

        client = ScraplingPinchTabClient()
        client._aiohttp_available = False
        with pytest.raises(PinchTabUnavailable):
            await client.health()


class TestScraplingPinchTabEngine:
    def test_init(self):
        from backend.core.browser_engine import ScraplingPinchTabEngine

        engine = ScraplingPinchTabEngine()
        assert engine._available is False

    @pytest.mark.asyncio
    async def test_initialize_when_client_fails(self):
        from backend.core.browser_engine import ScraplingPinchTabEngine

        engine = ScraplingPinchTabEngine()
        with patch.object(engine.client, "is_available", return_value=False):
            result = await engine.initialize()
        assert result is False

    @pytest.mark.asyncio
    async def test_navigate_when_offline(self):
        from backend.core.browser_engine import ScraplingPinchTabEngine

        engine = ScraplingPinchTabEngine()
        engine._available = False
        result = await engine.navigate("http://test.com")
        assert result["success"] is False
        assert result["error"] == "pinchtab_offline"

    @pytest.mark.asyncio
    async def test_extract_endpoints_when_offline(self):
        from backend.core.browser_engine import ScraplingPinchTabEngine

        engine = ScraplingPinchTabEngine()
        engine._available = False
        result = await engine.extract_endpoints_fast("http://test.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_extract_tokens_when_offline(self):
        from backend.core.browser_engine import ScraplingPinchTabEngine

        engine = ScraplingPinchTabEngine()
        engine._available = False
        result = await engine.extract_tokens("http://test.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_page_text_when_offline(self):
        from backend.core.browser_engine import ScraplingPinchTabEngine

        engine = ScraplingPinchTabEngine()
        engine._available = False
        result = await engine.get_page_text()
        assert result == ""


class TestScraplingPlaywrightEngine:
    def test_init(self):
        from backend.core.browser_engine import ScraplingPlaywrightEngine

        engine = ScraplingPlaywrightEngine()
        assert engine._browser is None
        assert engine.current_page is None

    @pytest.mark.asyncio
    async def test_initialize_playwright_not_installed(self):
        from backend.core.browser_engine import ScraplingPlaywrightEngine

        engine = ScraplingPlaywrightEngine()
        with patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
            result = await engine.initialize()
        assert result is False
        assert "playwright_not_installed" in engine.last_init_error or "playwright_import_failed" in engine.last_init_error

    @pytest.mark.asyncio
    async def test_is_truly_available_when_no_browser(self):
        from backend.core.browser_engine import ScraplingPlaywrightEngine

        engine = ScraplingPlaywrightEngine()
        assert await engine.is_truly_available() is False

    @pytest.mark.asyncio
    async def test_navigate_when_not_initialized(self):
        from backend.core.browser_engine import ScraplingPlaywrightEngine

        engine = ScraplingPlaywrightEngine()
        with pytest.raises(RuntimeError, match="not initialized"):
            await engine.navigate("http://test.com")


class TestScraplingFuzzer:
    def test_init(self):
        from backend.core.browser_engine import ScraplingFuzzer

        fuzzer = ScraplingFuzzer("worker1", 9222)
        assert fuzzer.worker_id == "worker1"
        assert fuzzer.port == 9222
        assert fuzzer.using_control_plane is False

    @pytest.mark.asyncio
    async def test_stop_when_nothing_started(self):
        from backend.core.browser_engine import ScraplingFuzzer

        fuzzer = ScraplingFuzzer("worker1", 9222)
        await fuzzer.stop()  # Should not raise


class TestScraplingIntel:
    def test_init(self):
        from backend.core.browser_engine import ScraplingIntel

        browser = MagicMock()
        intel = ScraplingIntel(browser, "scan-123")
        assert intel.scan_id == "scan-123"

    @pytest.mark.asyncio
    async def test_is_available_when_client_fails(self):
        from backend.core.browser_engine import ScraplingIntel

        browser = MagicMock()
        intel = ScraplingIntel(browser, "scan-123")
        with patch.object(intel.client, "is_available", side_effect=Exception("conn refused")):
            available, reason = await intel.is_available()
        assert available is False
        assert "pinchtab_unavailable" in reason

    @pytest.mark.asyncio
    async def test_full_capture_when_unavailable(self):
        from backend.core.browser_engine import ScraplingIntel

        browser = MagicMock()
        intel = ScraplingIntel(browser, "scan-123")
        with patch.object(intel, "is_available", return_value=(False, "offline")):
            result = await intel.full_capture(["http://test.com"])
        assert result["used"] is False
        assert result["entities"] == []


class TestBrowserReconModule:
    def test_init(self):
        from backend.core.browser_engine import ScraplingRecon

        browser = MagicMock()
        recon = ScraplingRecon(browser, "scan-456")
        assert recon.scan_id == "scan-456"

    @pytest.mark.asyncio
    async def test_recon_when_no_browser(self):
        from backend.core.browser_engine import ScraplingRecon

        recon = ScraplingRecon(None, "scan-456")
        result = await recon.recon("http://test.com")
        assert result == []


class TestPentestAdaptor:
    def test_parse_when_scrapling_unavailable(self):
        from backend.core.browser_engine import PentestAdaptor

        with patch("backend.core.browser_engine._SCRAPLING_AVAILABLE", False):
            result = PentestAdaptor.parse("<html></html>")
        assert result is None

    def test_parse_all_when_scrapling_unavailable(self):
        from backend.core.browser_engine import PentestAdaptor

        with patch("backend.core.browser_engine._SCRAPLING_AVAILABLE", False):
            result = PentestAdaptor.parse_all(["<html></html>"])
        assert result == []


class TestPentestSequenceMatcher:
    def test_match_when_scrapling_unavailable(self):
        from backend.core.browser_engine import PentestSequenceMatcher

        with patch("backend.core.browser_engine._SCRAPLING_AVAILABLE", False):
            result = PentestSequenceMatcher.match("abc", "abd")
        assert result["ratio"] == 0.0
