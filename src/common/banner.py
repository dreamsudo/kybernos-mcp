"""Psypher Labs branding — the Kybernos banner (cosmetic only).

`show_banner()` prints the neon diamond + product line; `brand_line()` prints a
compact one-line brand marker for worker services. Degrades to plain text if
`rich` is unavailable, and is fully suppressed by KYBERNOS_BANNER=off.

Kybernos — Greek κυβερνήτης, "the steersman/governor": the root of both
cybernetics and Kubernetes. The gateway that steers what your AI may do.
"""
import os
import sys

TOOL = "Kybernos"
TAGLINE = "Zero-Trust Gateway for AI Agents"
MOTTO = "κυβερνήτης — the steersman for your AI agents"

_DIAMOND = [
    "               *               ",
    "              ***              ",
    "             *****             ",
    "            *******            ",
    "           *********           ",
    "          ***********          ",
    "         *****Psypher*****     ",
    "          *****Labs*****      ",
    "           ***********          ",
    "            *******            ",
    "             *****             ",
    "              ***              ",
    "               *               ",
]


def _enabled(mode_default="full"):
    return os.getenv("KYBERNOS_BANNER", mode_default).lower()


def _safe_print(s):
    """Print without ever raising — the banner is cosmetic and runs at import,
    so a non-UTF-8 stdout (e.g. LANG=C) must not crash service startup on the
    Greek MOTTO / ◆ glyphs. Falls back to an encoding-sanitized write."""
    try:
        print(s)
    except Exception:
        try:
            enc = (sys.stdout.encoding or "ascii")
            sys.stdout.write(s.encode(enc, "replace").decode(enc) + "\n")
        except Exception:
            pass  # give up quietly; branding is never worth an exception


def show_banner(tool=TOOL, tagline=TAGLINE):
    """Full neon-diamond banner. No-op if KYBERNOS_BANNER=off."""
    if _enabled() == "off":
        return
    try:
        from rich.console import Console
        from rich.text import Text
        t = Text()
        t.append("\n")
        for line in _DIAMOND:
            t.append(line + "\n", style="bright_green")
        t.append(f"\n {tool} ", style="bold magenta")
        t.append("by Psypher Labs\n", style="bold bright_green")
        t.append(f" {tagline}\n", style="dim")
        t.append(f" {MOTTO}\n", style="italic dim")
        Console().print(t)
    except Exception:  # rich missing / non-tty / non-UTF-8 stdout
        _safe_print("\n".join(_DIAMOND))
        _safe_print(f"\n {tool} by Psypher Labs — {tagline}\n {MOTTO}\n")


def brand_line(service, tool=TOOL):
    """Compact one-line brand marker for a worker service."""
    if _enabled("line") == "off":
        return
    try:
        from rich.console import Console
        Console().print(f"[bright_green]◆[/bright_green] [bold magenta]{tool}[/bold magenta] "
                        f"· {service} · [dim]Psypher Labs[/dim]")
    except Exception:
        _safe_print(f"◆ {tool} · {service} · Psypher Labs")


if __name__ == "__main__":
    show_banner()
