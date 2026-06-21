# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Tech1k <https://tech1k.com>
"""Self-contained inline SVG assets for the dashboard.

Every mark is a standalone <svg> with no external refs, web fonts, or scripts,
so the dashboard stays zero-dependency and works offline or behind a proxy.
Brand palette follows mwebscan.com (accent periwinkle #6b86ff).
"""

from __future__ import annotations

import base64

# Brand mark: an isometric mined block (the unit a pool produces) + a "found"
# spark, in the periwinkle accent.  Used in the nav and as the favicon.
LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><g stroke="#14161b" stroke-width="0.5" stroke-linejoin="round"><path d="M16 4 L26 9.75 L16 15.5 L6 9.75 Z" fill="#9db2ff"/><path d="M6 9.75 L16 15.5 L16 27 L6 21.25 Z" fill="#6b86ff"/><path d="M26 9.75 L16 15.5 L16 27 L26 21.25 Z" fill="#4f63d8"/></g><path d="M25.5 3.5 L26.3 5.7 L28.5 6.5 L26.3 7.3 L25.5 9.5 L24.7 7.3 L22.5 6.5 L24.7 5.7 Z" fill="#4fbf75" stroke="#14161b" stroke-width="0.4" stroke-linejoin="round"/></svg>'

# Circular coin marks, keyed by coin name; sized by CSS via their viewBox.
COIN_MARKS = {
    # Official brand logos.  Bitcoin/Litecoin use a SOLID colored disc + white symbol
    # so they stay legible on both themes (Litecoin's official mark is white-on-white
    # and would vanish on a light card).  Monero keeps its official white-disc mark:
    # its orange/grey "M" contrasts on any background, so only the disc (not the
    # symbol) drops out on a light card - the canonical "logo on white" look.
    "bitcoin": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4091.27 4091.73" role="img" aria-label="Bitcoin"><path fill="#f7931a" d="M4030.06 2540.77c-273.24,1096.01 -1383.32,1763.02 -2479.46,1489.71 -1095.68,-273.24 -1762.69,-1383.39 -1489.33,-2479.31 273.12,-1096.13 1383.2,-1763.19 2479,-1489.95 1096.06,273.24 1763.03,1383.51 1489.76,2479.57l0.02 -0.02z"/><path fill="#fff" d="M2947.77 1754.38c40.72,-272.26 -166.56,-418.61 -450,-516.24l91.95 -368.8 -224.5 -55.94 -89.51 359.09c-59.02,-14.72 -119.63,-28.59 -179.87,-42.34l90.16 -361.46 -224.36 -55.94 -92 368.68c-48.84,-11.12 -96.81,-22.11 -143.35,-33.69l0.26 -1.16 -309.59 -77.31 -59.72 239.78c0,0 166.56,38.18 163.05,40.53 90.91,22.69 107.35,82.87 104.62,130.57l-104.74 420.15c6.26,1.59 14.38,3.89 23.34,7.49 -7.49,-1.86 -15.46,-3.89 -23.73,-5.87l-146.81 588.57c-11.11,27.62 -39.31,69.07 -102.87,53.33 2.25,3.26 -163.17,-40.72 -163.17,-40.72l-111.46 256.98 292.15 72.83c54.35,13.63 107.61,27.89 160.06,41.3l-92.9 373.03 224.24 55.94 92 -369.07c61.26,16.63 120.71,31.97 178.91,46.43l-91.69 367.33 224.51 55.94 92.89 -372.33c382.82,72.45 670.67,43.24 791.83,-303.02 97.63,-278.78 -4.86,-439.58 -206.26,-544.44 146.69,-33.83 257.18,-130.31 286.64,-329.61l-0.07 -0.05zm-512.93 719.26c-69.38,278.78 -538.76,128.08 -690.94,90.29l123.28 -494.2c152.17,37.99 640.17,113.17 567.67,403.91zm69.43 -723.3c-63.29,253.58 -453.96,124.75 -580.69,93.16l111.77 -448.21c126.73,31.59 534.85,90.55 468.94,355.05l-0.02 0z"/></svg>',
    "litecoin": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 82.6 82.6" role="img" aria-label="Litecoin"><circle cx="41.3" cy="41.3" r="41.3" fill="#345d9d"/><path fill="#fff" d="M42,42.7,37.7,57.2h23a1.16,1.16,0,0,1,1.2,1.12v.38l-2,6.9a1.49,1.49,0,0,1-1.5,1.1H23.2l5.9-20.1-6.6,2L24,44l6.6-2,8.3-28.2a1.51,1.51,0,0,1,1.5-1.1h8.9a1.16,1.16,0,0,1,1.2,1.12v.38L43.5,38l6.6-2-1.4,4.8Z"/></svg>',
    "monero": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 3756.09 3756.49" role="img" aria-label="Monero"><path fill="#fff" d="M4128,2249.81C4128,3287,3287.26,4127.86,2250,4127.86S372,3287,372,2249.81,1212.76,371.75,2250,371.75,4128,1212.54,4128,2249.81Z" transform="translate(-371.96 -371.75)"/><path fill="#f26822" d="M2250,371.75c-1036.89,0-1879.12,842.06-1877.8,1878,0.26,207.26,33.31,406.63,95.34,593.12h561.88V1263L2250,2483.57,3470.52,1263v1579.9h562c62.12-186.48,95-385.85,95.37-593.12C4129.66,1212.76,3287,372,2250,372Z" transform="translate(-371.96 -371.75)"/><path fill="#4d4d4d" d="M1969.3,2764.17l-532.67-532.7v994.14H1029.38l-384.29.07c329.63,540.8,925.35,902.56,1604.91,902.56S3525.31,3766.4,3855,3225.6H3063.25V2231.47l-532.7,532.7-280.61,280.61-280.62-280.61h0Z" transform="translate(-371.96 -371.75)"/></svg>',
}

# Monochrome 16x16 line icons (stroke=currentColor) -> inherit surrounding text.
ICONS = {
    'blocks': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2.2 13.2 5 8 7.8 2.8 5 8 2.2Z"/><path d="M2.8 8 8 10.8 13.2 8"/><path d="M2.8 11 8 13.8 13.2 11"/></svg>',
    'difficulty': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.4 11.5a6 6 0 1 1 11.2 0"/><path d="M8 8.5 10.7 6"/><circle cx="8" cy="8.5" r="0.4" fill="currentColor"/></svg>',
    'effort': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="5.8"/><circle cx="8" cy="8" r="3"/><circle cx="8" cy="8" r="0.4" fill="currentColor"/></svg>',
    'eta': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="5.8"/><path d="M8 4.6V8l2.4 1.6"/></svg>',
    'hashrate': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 8.5h2.2l1.6-4.3 2.4 8 1.6-4.7 1 1.5H14"/></svg>',
    'height': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.8 11 8 13.6 13.2 11"/><path d="M2.8 8 8 10.6 13.2 8"/><path d="M8 6.5V1.8M8 1.8 6.3 3.5M8 1.8 9.7 3.5"/></svg>',
    'live': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" stroke="none"><circle cx="8" cy="8" r="3.2"/></svg>',
    'miners': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="5" r="2"/><path d="M2.5 13v-1a3.5 3.5 0 0 1 7 0v1"/><path d="M11 3.2a2 2 0 0 1 0 3.6"/><path d="M11.5 9.2A3.5 3.5 0 0 1 14 12.5V13"/></svg>',
    'uptime': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M13.5 7a5.5 5.5 0 0 0-9.4-3.2L2.5 5.3"/><path d="M2.5 2.5v2.8h2.8"/><path d="M2.5 9a5.5 5.5 0 0 0 9.4 3.2l1.6-1.5"/><path d="M13.5 13.5v-2.8h-2.8"/></svg>',
    'sun': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="3.1"/><path d="M8 1.4v1.6M8 13v1.6M1.4 8h1.6M13 8h1.6M3.3 3.3l1.1 1.1M11.6 11.6l1.1 1.1M3.3 12.7l1.1-1.1M11.6 4.4l1.1-1.1"/></svg>',
    'moon': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M13.6 9.4A5.6 5.6 0 1 1 6.6 2.4 4.4 4.4 0 0 0 13.6 9.4Z"/></svg>',
    'coins': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="8" cy="4" rx="5" ry="2"/><path d="M3 4v4c0 1.1 2.2 2 5 2s5-.9 5-2V4"/><path d="M3 8v4c0 1.1 2.2 2 5 2s5-.9 5-2V8"/></svg>',
    # trophy -> "Top miners" (leaderboard); star -> "Best share(s)" (a record, not a rate);
    # cpu -> "Workers" (mining rigs/devices); software -> "Connected by software" (clients);
    # payout (banknote) -> payout copy + amounts (money, not a clock). Same 16x16 line style.
    'trophy': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 2.5h7v3a3.5 3.5 0 0 1-7 0Z"/><path d="M4.5 3.5h-2v1a2 2 0 0 0 2 2M11.5 3.5h2v1a2 2 0 0 1-2 2"/><path d="M8 9v2.5M6 13.5h4M6.5 13.5l.4-2h2.2l.4 2"/></svg>',
    'star': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1.8 9.9 5.7l4.3.6-3.1 3 .7 4.3L8 11.6 4.2 13.6l.7-4.3-3.1-3 4.3-.6Z"/></svg>',
    'cpu': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="4.5" y="4.5" width="7" height="7" rx="1"/><rect x="6.6" y="6.6" width="2.8" height="2.8"/><path d="M6 4.5V2.6M10 4.5V2.6M6 13.4v-1.9M10 13.4v-1.9M4.5 6H2.6M4.5 10H2.6M13.4 6h-1.9M13.4 10h-1.9"/></svg>',
    'software': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="12" height="10" rx="1.5"/><path d="M2 5.6h12"/><path d="M4.5 8.4 6.2 9.9l-1.7 1.5M8 11.2h3.2"/></svg>',
    'payout': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1.8" y="4.2" width="12.4" height="7.6" rx="1.4"/><circle cx="8" cy="8" r="1.7"/><path d="M4.2 6.1h.01M11.8 9.9h.01"/></svg>',
    'search': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="7" cy="7" r="4.3"/><path d="M10.2 10.2 14 14"/></svg>',
    # peers -> "Node peers" (network nodes linked together, not a people glyph)
    'peers': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="4.3" cy="8" r="2"/><circle cx="11.7" cy="4" r="2"/><circle cx="11.7" cy="12" r="2"/><path d="M6.1 7.1 9.9 5M6.1 8.9 9.9 11"/></svg>',
    # external -> trailing arrow-out marker on links that leave the site (new tab)
    'external': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 11 11 5"/><path d="M6 5h5v5"/></svg>',
}


def favicon_data_uri() -> str:
    """Base64 data URI of the brand mark, for <link rel=icon>."""
    b64 = base64.b64encode(LOGO_SVG.encode()).decode()
    return "data:image/svg+xml;base64," + b64


def icon(name: str, cls: str = "ico") -> str:
    """Inline a UI icon wrapped in a sizing span (empty string if unknown).

    Icons are decorative - each sits beside a text label - so they are hidden
    from assistive tech to avoid noise.
    """
    svg = ICONS.get(name)
    return f'<span class="{cls}" aria-hidden="true">{svg}</span>' if svg else ""


def coin_mark(coin: str, cls: str = "coin-mark") -> str:
    """Inline a coin's circular mark, or a neutral generic disc if unknown."""
    svg = COIN_MARKS.get(coin)
    if not svg:
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
               '<circle cx="12" cy="12" r="12" fill="#3a3f4a"/></svg>')
    return f'<span class="{cls}">{svg}</span>'
