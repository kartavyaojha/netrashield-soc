import urllib.request
import re

url = "https://www.bonanza-studios.com/"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        html = resp.read().decode("utf-8", errors="ignore")
    print(f"[*] Fetched {len(html)} bytes from {url}")
    title = re.search(r"<title>(.*?)</title>", html, re.I)
    print("Title:", title.group(1) if title else "N/A")

    # Find css links
    css_links = re.findall(r'href=["\']([^"\']+\.css[^"\']*)["\']', html)
    print("CSS Links:", css_links[:5])

    # Search for fonts, colors, background styling
    colors = set(re.findall(r'#(?:[0-9a-fA-F]{3}){1,2}\b', html))
    print(f"Colors found in HTML ({len(colors)}):", list(colors)[:20])

    # Search for text excerpts
    headings = re.findall(r'<h[1-3][^>]*>(.*?)</h[1-3]>', html, re.DOTALL)
    print("Headings sample:")
    for h in headings[:8]:
        clean_h = re.sub(r'<[^>]+>', '', h).strip()
        if clean_h:
            print("  -", clean_h)

    # Let's inspect the first CSS file if available
    if css_links:
        css_url = css_links[0]
        if not css_url.startswith("http"):
            css_url = "https://www.bonanza-studios.com" + ("" if css_url.startswith("/") else "/") + css_url
        print(f"\n[*] Fetching CSS from {css_url}...")
        css_req = urllib.request.Request(css_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(css_req, timeout=10) as c_resp:
            css_content = c_resp.read().decode("utf-8", errors="ignore")
        print(f"CSS size: {len(css_content)} bytes")
        # Find font-family, background-color, border-radius
        fonts = set(re.findall(r'font-family:\s*([^;]+);', css_content))
        print("Font families:", list(fonts)[:5])
        radii = set(re.findall(r'border-radius:\s*([^;]+);', css_content))
        print("Border radii:", list(radii)[:10])
        bg_colors = set(re.findall(r'background(?:-color)?:\s*([^;]+);', css_content))
        print("Background colors sample:", list(bg_colors)[:10])
except Exception as e:
    print(f"Error fetching bonanza: {e}")
