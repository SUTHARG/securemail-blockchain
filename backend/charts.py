"""Pure Python inline SVG chart generators for SecureMailScope Dashboard (Tier 2 / Prompt T2.7).

Generates zero-dependency, self-contained SVG graphics for:
- TLS version distribution (bar chart)
- Cipher suite distribution (horizontal bar chart)
- Host posture score ranking (colored bar chart)
All graphics render cleanly without JavaScript or external URLs.
"""
from typing import Any, Dict, List


def generate_version_distribution_svg(version_counts: Dict[str, int]) -> str:
    """Generates an inline SVG bar chart for TLS version distributions."""
    if not version_counts:
        return '<svg width="100%" height="80" viewBox="0 0 400 80"><text x="200" y="45" fill="#8b949e" font-size="14" text-anchor="middle">No TLS sessions recorded</text></svg>'

    total = sum(version_counts.values()) or 1
    items = sorted(version_counts.items(), key=lambda x: -x[1])

    width = 540
    bar_height = 24
    gap = 14
    height = max(100, len(items) * (bar_height + gap) + 30)

    # Palette
    color_map = {
        "TLS 1.3": "#3fb950",
        "TLS 1.2": "#58a6ff",
        "TLS 1.1": "#d29922",
        "TLS 1.0": "#db61a2",
        "SSL 3.0": "#f85149",
        "None": "#6e7681",
    }

    svg_parts = [
        f'<svg width="100%" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">',
        '<style>text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }</style>',
    ]

    max_count = max(version_counts.values()) or 1
    chart_x = 100
    chart_max_w = width - chart_x - 90

    for i, (ver, count) in enumerate(items):
        y = 20 + i * (bar_height + gap)
        pct = (count / total) * 100
        bar_w = max(4, int((count / max_count) * chart_max_w))
        color = color_map.get(ver, "#a371f7")

        # Label
        svg_parts.append(
            f'<text x="{chart_x - 10}" y="{y + 17}" fill="#e6edf3" font-size="12" font-weight="600" text-anchor="end">{ver}</text>'
        )
        # Background bar
        svg_parts.append(
            f'<rect x="{chart_x}" y="{y}" width="{chart_max_w}" height="{bar_height}" rx="4" fill="rgba(255,255,255,0.04)"/>'
        )
        # Value bar
        svg_parts.append(
            f'<rect x="{chart_x}" y="{y}" width="{bar_w}" height="{bar_height}" rx="4" fill="{color}"/>'
        )
        # Count & % text
        svg_parts.append(
            f'<text x="{chart_x + bar_w + 10}" y="{y + 17}" fill="#8b949e" font-size="11">{count} ({pct:.1f}%)</text>'
        )

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def generate_cipher_distribution_svg(cipher_counts: Dict[str, int], max_items: int = 6) -> str:
    """Generates an inline SVG horizontal bar chart for cipher suite distribution."""
    if not cipher_counts:
        return '<svg width="100%" height="80" viewBox="0 0 500 80"><text x="250" y="45" fill="#8b949e" font-size="14" text-anchor="middle">No cipher suites recorded</text></svg>'

    items = sorted(cipher_counts.items(), key=lambda x: -x[1])[:max_items]
    total = sum(cipher_counts.values()) or 1

    width = 620
    bar_height = 22
    gap = 14
    height = max(100, len(items) * (bar_height + gap) + 30)

    svg_parts = [
        f'<svg width="100%" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">',
        '<style>text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }</style>',
    ]

    max_count = max(c for _, c in items) or 1
    chart_x = 220
    chart_max_w = width - chart_x - 85

    for i, (cipher, count) in enumerate(items):
        y = 20 + i * (bar_height + gap)
        pct = (count / total) * 100
        bar_w = max(4, int((count / max_count) * chart_max_w))
        # Shorten or clean cipher name if too long
        display_cipher = cipher if len(cipher) <= 30 else cipher[:28] + "…"

        svg_parts.append(
            f'<text x="{chart_x - 10}" y="{y + 16}" fill="#e6edf3" font-size="11" font-family="monospace" text-anchor="end">{display_cipher}</text>'
        )
        svg_parts.append(
            f'<rect x="{chart_x}" y="{y}" width="{chart_max_w}" height="{bar_height}" rx="4" fill="rgba(255,255,255,0.04)"/>'
        )
        svg_parts.append(
            f'<rect x="{chart_x}" y="{y}" width="{bar_w}" height="{bar_height}" rx="4" fill="#388bfd"/>'
        )
        svg_parts.append(
            f'<text x="{chart_x + bar_w + 10}" y="{y + 16}" fill="#8b949e" font-size="11">{count} ({pct:.1f}%)</text>'
        )

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def generate_host_scores_svg(host_scores: List[Dict[str, Any]]) -> str:
    """Generates an inline SVG bar chart for host posture scores."""
    if not host_scores:
        return '<svg width="100%" height="80" viewBox="0 0 500 80"><text x="250" y="45" fill="#8b949e" font-size="14" text-anchor="middle">No host scores recorded</text></svg>'

    width = 620
    bar_height = 26
    gap = 14
    height = max(100, len(host_scores) * (bar_height + gap) + 30)

    grade_colors = {
        "A": "#3fb950",
        "B": "#58a6ff",
        "C": "#d29922",
        "D": "#db61a2",
        "F": "#f85149",
    }

    svg_parts = [
        f'<svg width="100%" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">',
        '<style>text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }</style>',
    ]

    chart_x = 180
    chart_max_w = width - chart_x - 100

    for i, h in enumerate(host_scores):
        y = 20 + i * (bar_height + gap)
        score = int(h.get("score", 0))
        grade = str(h.get("grade", "F"))
        color = grade_colors.get(grade, "#f85149")
        ep = str(h.get("serverEndpoint") or h.get("hostId", "")[:12])
        if len(ep) > 22:
            ep = ep[:20] + "…"

        bar_w = max(4, int((score / 100.0) * chart_max_w))

        svg_parts.append(
            f'<text x="{chart_x - 10}" y="{y + 18}" fill="#e6edf3" font-size="12" font-weight="600" text-anchor="end">{ep}</text>'
        )
        svg_parts.append(
            f'<rect x="{chart_x}" y="{y}" width="{chart_max_w}" height="{bar_height}" rx="5" fill="rgba(255,255,255,0.04)"/>'
        )
        svg_parts.append(
            f'<rect x="{chart_x}" y="{y}" width="{bar_w}" height="{bar_height}" rx="5" fill="{color}"/>'
        )
        svg_parts.append(
            f'<text x="{chart_x + bar_w + 10}" y="{y + 18}" fill="#e6edf3" font-size="12" font-weight="700">{score}/100 <tspan fill="{color}" font-weight="800">[{grade}]</tspan></text>'
        )

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)
