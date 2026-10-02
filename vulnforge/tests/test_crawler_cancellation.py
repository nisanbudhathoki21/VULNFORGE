"""Regression for a child CancelledError leaking from asyncio.gather()."""
import asyncio
from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.profiles import get_profile
from vulnforge.engine.crawler import CANCELLED, SUCCESS, Crawler
from vulnforge.http.client import Requester


def test_cancelled_task_and_successful_task_preserve_crawl(mock_server):
    async def exercise():
        auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True)
        requester=Requester(auth,get_profile("passive"))
        try:
            crawler=Crawler(requester,auth,get_profile("passive"))
            assert not crawler._should_fetch(mock_server+"/.git/config")
            assert not crawler._should_fetch(mock_server+"/README.md")
            assert crawler._should_fetch(mock_server+"/.well-known/security.txt")
            original_fetch=crawler._fetch
            async def controlled_fetch(url,depth):
                if url.endswith("/cancel-me"):
                    raise asyncio.CancelledError()
                return await original_fetch(url,depth)
            crawler._fetch=controlled_fetch
            result=await crawler.run([mock_server+"/cancel-me",mock_server+"/about"])
            assert result.status_counts[CANCELLED] == 1
            assert result.status_counts[SUCCESS] >= 1
            assert result.cancelled == 1
            assert any(page.url.endswith("/about") for page in result.pages)
            assert any(ex.url.endswith("/about") for ex,_parser in result.parsed)
            assert result.outcomes and all(o.status for o in result.outcomes)
            # A child cancellation is isolated: successful discovery still ran.
            return result
        finally:
            await requester.close()
    result=asyncio.run(exercise())
    assert result.cancelled == 1 and result.pages
