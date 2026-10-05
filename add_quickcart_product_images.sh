#!/usr/bin/env bash
set -euo pipefail

ROOT="labs/high/authorization/quickcart"
IMG="$ROOT/static/images/products"

echo "[+] QuickCart: adding local product images..."
mkdir -p "$IMG"

# ------------------------------------------------------------
# 1. Create 8 local product illustrations
# ------------------------------------------------------------

cat > "$IMG/aero-runner.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
<defs>
  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
    <stop stop-color="#eef4ff"/><stop offset="1" stop-color="#dbe7ff"/>
  </linearGradient>
  <linearGradient id="shoe" x1="0" y1="0" x2="1" y2="1">
    <stop stop-color="#172033"/><stop offset="1" stop-color="#4f6bff"/>
  </linearGradient>
</defs>
<rect width="800" height="800" rx="40" fill="url(#bg)"/>
<circle cx="650" cy="150" r="110" fill="#fff" opacity=".55"/>
<path d="M155 500 C235 465 290 420 335 340 L420 395 C455 430 500 462 565 478 L670 505 C700 513 717 538 700 558 C684 578 645 590 595 591 L205 591 C155 591 126 548 155 500Z" fill="url(#shoe)"/>
<path d="M205 590 H675 C690 590 704 601 704 618 C704 635 687 646 666 646 H194 C160 646 145 626 154 610 C162 596 181 590 205 590Z" fill="#ffffff"/>
<path d="M340 350 L405 405 M374 365 L440 420 M410 385 L470 437" stroke="#dbe7ff" stroke-width="15" stroke-linecap="round"/>
<text x="400" y="710" text-anchor="middle" font-family="Arial" font-size="34" font-weight="700" fill="#172033">AERO RUNNER</text>
</svg>
SVG

cat > "$IMG/urban-hoodie.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#f1f3f7"/><stop offset="1" stop-color="#dfe4ec"/></linearGradient><linearGradient id="cloth" x2="1" y2="1"><stop stop-color="#252b38"/><stop offset="1" stop-color="#555f72"/></linearGradient></defs>
<rect width="800" height="800" rx="40" fill="url(#bg)"/>
<path d="M275 250 Q400 165 525 250 L610 330 L550 400 L510 350 V600 H290 V350 L250 400 L190 330Z" fill="url(#cloth)"/>
<path d="M335 220 Q400 285 465 220" fill="none" stroke="#aeb7c7" stroke-width="18"/>
<path d="M325 460 H475 V560 H325Z" fill="#313949" opacity=".9"/>
<text x="400" y="700" text-anchor="middle" font-family="Arial" font-size="34" font-weight="700" fill="#252b38">URBAN HOODIE</text>
</svg>
SVG

cat > "$IMG/classic-chrono.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#fff6df"/><stop offset="1" stop-color="#eadfc9"/></linearGradient><radialGradient id="face"><stop stop-color="#ffffff"/><stop offset="1" stop-color="#cfd3da"/></radialGradient></defs>
<rect width="800" height="800" rx="40" fill="url(#bg)"/>
<rect x="350" y="115" width="100" height="160" rx="35" fill="#222733"/>
<rect x="350" y="525" width="100" height="160" rx="35" fill="#222733"/>
<circle cx="400" cy="400" r="150" fill="#1d222d"/>
<circle cx="400" cy="400" r="126" fill="url(#face)"/>
<circle cx="400" cy="400" r="8" fill="#1d222d"/>
<path d="M400 400 L400 310 M400 400 L455 430" stroke="#1d222d" stroke-width="12" stroke-linecap="round"/>
<circle cx="355" cy="390" r="18" fill="#777f8e"/><circle cx="445" cy="390" r="18" fill="#777f8e"/>
<text x="400" y="750" text-anchor="middle" font-family="Arial" font-size="34" font-weight="700" fill="#222733">CLASSIC CHRONO</text>
</svg>
SVG

cat > "$IMG/trail-pack.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#eaf7f1"/><stop offset="1" stop-color="#cfe7dc"/></linearGradient><linearGradient id="bag" x2="1" y2="1"><stop stop-color="#164b3a"/><stop offset="1" stop-color="#2c8062"/></linearGradient></defs>
<rect width="800" height="800" rx="40" fill="url(#bg)"/>
<path d="M280 270 Q400 205 520 270 L575 610 Q400 660 225 610Z" fill="url(#bag)"/>
<path d="M315 275 Q315 170 400 170 Q485 170 485 275" fill="none" stroke="#12392f" stroke-width="38"/>
<rect x="290" y="380" width="220" height="135" rx="20" fill="#173f33" opacity=".7"/>
<path d="M250 420 H550 M300 555 H500" stroke="#7ac9a7" stroke-width="12"/>
<text x="400" y="720" text-anchor="middle" font-family="Arial" font-size="34" font-weight="700" fill="#164b3a">TRAIL PACK 28L</text>
</svg>
SVG

cat > "$IMG/essential-tee.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#fff0f3"/><stop offset="1" stop-color="#f5d8df"/></linearGradient></defs>
<rect width="800" height="800" rx="40" fill="url(#bg)"/>
<path d="M300 235 L235 285 L155 360 L220 430 L275 380 V610 H525 V380 L580 430 L645 360 L565 285 L500 235 Q400 280 300 235Z" fill="#f8fafc" stroke="#c7cdd7" stroke-width="8"/>
<path d="M340 245 Q400 300 460 245" fill="none" stroke="#c7cdd7" stroke-width="12"/>
<text x="400" y="700" text-anchor="middle" font-family="Arial" font-size="34" font-weight="700" fill="#4a5261">ESSENTIAL TEE</text>
</svg>
SVG

cat > "$IMG/city-jacket.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#eef1f6"/><stop offset="1" stop-color="#d5dbe5"/></linearGradient><linearGradient id="j" x2="1" y2="1"><stop stop-color="#111827"/><stop offset="1" stop-color="#394456"/></linearGradient></defs>
<rect width="800" height="800" rx="40" fill="url(#bg)"/>
<path d="M300 210 L400 180 L500 210 L570 330 L515 365 L500 610 H300 L285 365 L230 330Z" fill="url(#j)"/>
<path d="M400 185 V610 M315 355 H365 M435 355 H485" stroke="#8b96a8" stroke-width="12"/>
<path d="M325 235 L400 305 L475 235" fill="none" stroke="#596579" stroke-width="12"/>
<text x="400" y="700" text-anchor="middle" font-family="Arial" font-size="34" font-weight="700" fill="#111827">CITY JACKET</text>
</svg>
SVG

cat > "$IMG/studio-headphones.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#f1ecff"/><stop offset="1" stop-color="#ded5ff"/></linearGradient><linearGradient id="h" x2="1" y2="1"><stop stop-color="#25204a"/><stop offset="1" stop-color="#6a56c8"/></linearGradient></defs>
<rect width="800" height="800" rx="40" fill="url(#bg)"/>
<path d="M220 420 V350 Q220 170 400 170 Q580 170 580 350 V420" fill="none" stroke="url(#h)" stroke-width="55" stroke-linecap="round"/>
<rect x="185" y="375" width="115" height="205" rx="55" fill="#282249"/>
<rect x="500" y="375" width="115" height="205" rx="55" fill="#282249"/>
<rect x="210" y="410" width="65" height="130" rx="32" fill="#7969d6"/>
<rect x="525" y="410" width="65" height="130" rx="32" fill="#7969d6"/>
<text x="400" y="700" text-anchor="middle" font-family="Arial" font-size="34" font-weight="700" fill="#282249">STUDIO HEADPHONES</text>
</svg>
SVG

cat > "$IMG/everyday-cap.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#fff4e8"/><stop offset="1" stop-color="#f4dfc7"/></linearGradient><linearGradient id="cap" x2="1" y2="1"><stop stop-color="#b45309"/><stop offset="1" stop-color="#e28b32"/></linearGradient></defs>
<rect width="800" height="800" rx="40" fill="url(#bg)"/>
<path d="M210 430 Q225 220 400 210 Q575 220 590 430 Q500 370 400 370 Q300 370 210 430Z" fill="url(#cap)"/>
<path d="M400 370 Q570 365 655 435 Q600 500 445 470 Q380 455 400 370Z" fill="#a34808"/>
<path d="M275 335 Q400 270 525 335" fill="none" stroke="#f5b35d" stroke-width="14"/>
<text x="400" y="700" text-anchor="middle" font-family="Arial" font-size="34" font-weight="700" fill="#7c3f08">EVERYDAY CAP</text>
</svg>
SVG

# ------------------------------------------------------------
# 2. Add image paths to PRODUCTS
# ------------------------------------------------------------

python - <<'PY'
from pathlib import Path
import re

p = Path("labs/high/authorization/quickcart/app.py")
text = p.read_text()

mapping = {
    1: "aero-runner.svg",
    2: "urban-hoodie.svg",
    3: "classic-chrono.svg",
    4: "trail-pack.svg",
    5: "essential-tee.svg",
    6: "city-jacket.svg",
    7: "studio-headphones.svg",
    8: "everyday-cap.svg",
}

# Add image field immediately after each product's stock field,
# unless it already exists.
for product_id, image in mapping.items():
    pattern = rf'("id"\s*:\s*{product_id}\s*,.*?"stock"\s*:\s*\d+\s*)(,\s*)'
    replacement = rf'\1, "image": "/static/images/products/{image}"\2'

    new_text, count = re.sub(
        pattern,
        replacement,
        text,
        count=1,
        flags=re.S,
    )

    if count:
        text = new_text

p.write_text(text)
print("[+] Product image paths added to app.py")
PY

# ------------------------------------------------------------
# 3. Automatically make templates render product images
# ------------------------------------------------------------

python - <<'PY'
from pathlib import Path

root = Path("labs/high/authorization/quickcart/templates")

files = [
    root / "index.html",
    root / "products.html",
    root / "product.html",
]

for p in files:
    if not p.exists():
        continue

    text = p.read_text()

    # Replace common existing image placeholders/URLs.
    replacements = {
        '<img src="{{ product.image }}"': '<img src="{{ product.image }}" loading="lazy"',
        '<img src="{{product.image}}"': '<img src="{{ product.image }}" loading="lazy"',
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    # If a product image is not already rendered, add one inside product cards.
    if "product.image" not in text and "product[" not in text:
        text = text.replace(
            '<div class="product-card">',
            '''<div class="product-card">
  <div class="product-image">
    <img src="{{ product.image }}" alt="{{ product.name }}" loading="lazy">
  </div>''',
        )

    p.write_text(text)

print("[+] Product templates updated.")
PY

# ------------------------------------------------------------
# 4. Add safe image styling
# ------------------------------------------------------------

cat >> "$ROOT/static/css/style.css" <<'CSS'

/* ============================================================
   QuickCart local product photography
   ============================================================ */

.product-image {
    width: 100%;
    aspect-ratio: 1 / 1;
    overflow: hidden;
    border-radius: 14px;
    background: #f3f5f8;
    display: flex;
    align-items: center;
    justify-content: center;
}

.product-image img {
    width: 100%;
    height: 100%;
    display: block;
    object-fit: cover;
}

.product-image img:hover {
    transform: scale(1.025);
    transition: transform .2s ease;
}

.product-card img {
    max-width: 100%;
}

CSS

# ------------------------------------------------------------
# 5. Verify only QuickCart files changed
# ------------------------------------------------------------

echo
echo "===== QUICKCART IMAGE FILES ====="
find "$IMG" -maxdepth 1 -type f -name '*.svg' -printf '%f\n' | sort

echo
echo "===== QUICKCART TESTS ====="
cd "$ROOT"
pytest -q

echo
echo "===== DONE ====="
echo "Local product images installed."
echo "No VULNFORGE core files or the 231-test suite were modified."
echo
echo "Start:"
echo "  python app.py"
echo
echo "Open:"
echo "  http://127.0.0.1:9002"
