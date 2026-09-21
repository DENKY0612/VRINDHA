"""
Web Search Module - Vrindha SOC
Provides online search capabilities for AI context enrichment.
"""
from typing import List, Optional


def search(query: str, max_results: int = 5) -> List[dict]:
    """
    Search the web via DuckDuckGo.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        
    Returns:
        List of dicts with 'title', 'url', 'description' keys
    """
    try:
        from ddgs import DDGS
        with DDGS() as ddgs:
            results = []
            for r in ddgs.text(query, max_results=max_results):
                results.append({
                    "title": r.get("title", ""),
                    "url": r.get("href", ""),
                    "description": r.get("body", "")
                })
            return results
    except Exception as e:
        return [{"title": "Search Error", "url": "", "description": f"Search failed: {e}"}]


def fetch_url(url: str, char_limit: int = 3000) -> str:
    """
    Fetch and extract readable text from a URL.
    
    Args:
        url: The URL to fetch
        char_limit: Maximum characters to return
        
    Returns:
        Extracted text content
    """
    try:
        import requests
        from bs4 import BeautifulSoup
        
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        
        soup = BeautifulSoup(resp.text, "lxml")
        # Remove scripts and styles
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        return text[:char_limit]
    except Exception as e:
        return f"Error fetching {url}: {e}"


def search_context(query: str, max_results: int = 3) -> str:
    """
    Search the web and return formatted context for AI consumption.
    
    Args:
        query: Search query
        max_results: Number of results to include
        
    Returns:
        Formatted string with search results
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
    # Test
    print(search_context("cybersecurity CVE 2025"))
