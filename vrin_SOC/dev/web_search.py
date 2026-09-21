"""
Web Search Module - Vrindha SOC
Provides online search via DuckDuckGo HTML endpoint for AI context enrichment.
"""
import re
import requests
from bs4 import BeautifulSoup
from typing import List, Optional


def search(query: str, max_results: int = 5) -> List[dict]:
    """
    Search the web via DuckDuckGo HTML endpoint.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        
    Returns:
        List of dicts with 'title', 'url', 'description' keys
    """
    try:
        url = "https://html.duckduckgo.com/html/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        resp = requests.post(url, data={"q": query}, headers=headers, timeout=15)
        resp.raise_for_status()
        
        soup = BeautifulSoup(resp.text, "lxml")
        results = []
        
        for result in soup.find_all("div", class_="result", limit=max_results):
            title_tag = result.find("a", class_="result__a")
            snippet_tag = result.find("a", class_="result__snippet")
            if title_tag:
                results.append({
                    "title": title_tag.text.strip(),
                    "url": title_tag.get("href", ""),
                    "description": snippet_tag.text.strip() if snippet_tag else ""
                })
        
        return results if results else [{"title": "No results", "url": "", "description": f"No results for '{query}'"}]
    except Exception as e:
        return [{"title": "Search Error", "url": "", "description": f"Search failed: {e}"}]


def fetch_url(url: str, char_limit: int = 3000) -> str:
    """
    Fetch and extract readable text from a URL.
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        
        soup = BeautifulSoup(resp.text, "lxml")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        return text[:char_limit]
    except Exception as e:
        return f"Error fetching {url}: {e}"


def search_context(query: str, max_results: int = 3) -> str:
    """
    Search the web and return formatted context for AI consumption.
    """
    results = search(query, max_results)
    if not results:
        return "No search results found."
    
    parts = [f"Web search results for '{query}':"]
    for i, r in enumerate(results, 1):
        parts.append(f"\n{i}. {r['title']}")
        parts.append(f"   URL: {r['url']}")
        parts.append(f"   {r['description'][:200]}")
    
    return "\n".join(parts)


if __name__ == "__main__":
    print(search_context("what is the current version of minecraft"))
