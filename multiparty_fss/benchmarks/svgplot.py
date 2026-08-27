"""Tiny dependency-free SVG line-chart writer for paper figures.

Deliberately minimal: log/linear axes, decade ticks, legend, one polyline per
series with point markers. Output is self-contained SVG suitable for
inclusion in a paper draft or conversion to PDF. No external libraries.
"""

from __future__ import annotations

import math
from pathlib import Path

_COLORS = ["#1b6ca8", "#c0392b", "#1e8449", "#8e44ad", "#d68910", "#34495e", "#16a085"]
_MARKERS_RADIUS = 3.2


def _ticks(lo: float, hi: float, log: bool) -> list[float]:
    if log:
        lo_e = math.floor(math.log10(lo))
        hi_e = math.ceil(math.log10(hi))
        return [10.0**e for e in range(lo_e, hi_e + 1)]
    span = hi - lo or 1.0
    step = 10 ** math.floor(math.log10(span / 4))
    for multiplier in (1, 2, 5, 10):
        if span / (step * multiplier) <= 6:
            step *= multiplier
            break
    first = math.floor(lo / step) * step
    ticks, value = [], first
    while value <= hi + 1e-9:
        ticks.append(round(value, 10))
        value += step
    return ticks


def _fmt(value: float) -> str:
    if value == 0:
        return "0"
    exp = math.log10(abs(value))
    if exp >= 6 or exp < -3:
        power = int(math.floor(exp))
        mant = value / 10**power
        return f"{mant:g}e{power}" if abs(mant - 1) > 1e-9 else f"1e{power}"
    if abs(value) >= 1024 and abs(value) % 1024 == 0:
        return f"{int(value):,}"
    return f"{value:g}"


def line_chart(
    series: list[dict],
    path: str | Path,
    title: str,
    xlabel: str,
    ylabel: str,
    xlog: bool = True,
    ylog: bool = True,
    width: int = 640,
    height: int = 440,
) -> None:
    """series: [{"name": str, "xs": [...], "ys": [...]}] (positive values for log)."""
    margin_left, margin_right, margin_top, margin_bottom = 78, 20, 42, 56
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom
    xs_all = [x for s in series for x in s["xs"]]
    ys_all = [y for s in series for y in s["ys"] if y is not None]
    x_lo, x_hi = min(xs_all), max(xs_all)
    y_lo, y_hi = min(ys_all), max(ys_all)
    if ylog:
        y_lo = 10 ** math.floor(math.log10(y_lo))
        y_hi = 10 ** math.ceil(math.log10(y_hi))
    if xlog:
        x_lo = 10 ** math.floor(math.log10(x_lo))
        x_hi = 10 ** math.ceil(math.log10(x_hi))

    def sx(x: float) -> float:
        if xlog:
            f = (math.log10(x) - math.log10(x_lo)) / (math.log10(x_hi) - math.log10(x_lo))
        else:
            f = (x - x_lo) / (x_hi - x_lo or 1)
        return margin_left + f * plot_w

    def sy(y: float) -> float:
        if ylog:
            f = (math.log10(y) - math.log10(y_lo)) / (math.log10(y_hi) - math.log10(y_lo))
        else:
            f = (y - y_lo) / (y_hi - y_lo or 1)
        return margin_top + (1 - f) * plot_h

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Helvetica,Arial,sans-serif">',
        f'<rect width="{width}" height="{height}" fill="white"/>',
        f'<text x="{width/2}" y="24" text-anchor="middle" font-size="15" '
        f'font-weight="bold" fill="#222">{title}</text>',
    ]
    # gridlines + ticks
    for tick in _ticks(x_lo, x_hi, xlog):
        if tick < x_lo or tick > x_hi:
            continue
        px = sx(tick)
        parts.append(
            f'<line x1="{px:.1f}" y1="{margin_top}" x2="{px:.1f}" '
            f'y2="{margin_top+plot_h}" stroke="#e3e3e3" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{px:.1f}" y="{margin_top+plot_h+18}" text-anchor="middle" '
            f'font-size="11" fill="#444">{_fmt(tick)}</text>'
        )
    for tick in _ticks(y_lo, y_hi, ylog):
        if tick < y_lo or tick > y_hi:
            continue
        py = sy(tick)
        parts.append(
            f'<line x1="{margin_left}" y1="{py:.1f}" x2="{margin_left+plot_w}" '
            f'y2="{py:.1f}" stroke="#e3e3e3" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{margin_left-8}" y="{py+4:.1f}" text-anchor="end" '
            f'font-size="11" fill="#444">{_fmt(tick)}</text>'
        )
    # axes
    parts.append(
        f'<rect x="{margin_left}" y="{margin_top}" width="{plot_w}" '
        f'height="{plot_h}" fill="none" stroke="#666" stroke-width="1.2"/>'
    )
    parts.append(
        f'<text x="{margin_left+plot_w/2}" y="{height-14}" text-anchor="middle" '
        f'font-size="13" fill="#222">{xlabel}</text>'
    )
    parts.append(
        f'<text x="20" y="{margin_top+plot_h/2}" text-anchor="middle" font-size="13" '
        f'fill="#222" transform="rotate(-90 20 {margin_top+plot_h/2})">{ylabel}</text>'
    )
    # series
    for index, s in enumerate(series):
        color = _COLORS[index % len(_COLORS)]
        points = [
            (sx(x), sy(y)) for x, y in zip(s["xs"], s["ys"]) if y is not None
        ]
        if not points:
            continue
        polyline = " ".join(f"{px:.1f},{py:.1f}" for px, py in points)
        parts.append(
            f'<polyline points="{polyline}" fill="none" stroke="{color}" '
            f'stroke-width="2"/>'
        )
        for px, py in points:
            parts.append(
                f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{_MARKERS_RADIUS}" '
                f'fill="{color}"/>'
            )
    # legend
    legend_x = margin_left + 12
    legend_y = margin_top + 12
    for index, s in enumerate(series):
        color = _COLORS[index % len(_COLORS)]
        y = legend_y + index * 18
        parts.append(
            f'<line x1="{legend_x}" y1="{y}" x2="{legend_x+22}" y2="{y}" '
            f'stroke="{color}" stroke-width="2.5"/>'
        )
        parts.append(
            f'<text x="{legend_x+28}" y="{y+4}" font-size="12" fill="#222">'
            f'{s["name"]}</text>'
        )
    parts.append("</svg>")
    Path(path).write_text("\n".join(parts))
