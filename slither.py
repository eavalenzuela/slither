#!/usr/bin/env python3
"""
slither: replace ASCII characters with randomized Unicode glyphs (cmatrix-ish).

Scripts/pools supported:
- Cyrillic
- Greek
- Japanese (Hiragana, Katakana)
- Chinese/Japanese/Korean (CJK Unified Ideographs)
- Roman/Latin (Latin-1 Supplement, Latin Extended-A/B)
- Roman numerals (Number Forms block)

Usage examples:
  echo "hello world" | ./slither.py
  ./slither.py "status: ok" --seed 42 --consistent
  ./slither.py --prob 0.35 --transform alnum file.txt
  ./slither.py --convo --convo-lines 5 --convo-min-delay 0.2 --convo-max-delay 0.6
"""

from __future__ import annotations

import argparse
import os
import random
import string
import sys
import time
import unicodedata
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


# ----------------------------
# Unicode ranges (inclusive)
# ----------------------------

# Note: CJK Unified Ideographs is huge. We sample from it rather than build all.
RANGES: Dict[str, List[Tuple[int, int]]] = {
    "cyrillic": [
        (0x0400, 0x04FF),  # Cyrillic
        (0x0500, 0x052F),  # Cyrillic Supplement
    ],
    "greek": [
        (0x0370, 0x03FF),  # Greek and Coptic
    ],
    "hiragana": [
        (0x3040, 0x309F),
    ],
    "katakana": [
        (0x30A0, 0x30FF),
    ],
    "cjk": [
        (0x4E00, 0x9FFF),  # CJK Unified Ideographs (common)
        # You can add Ext-A (0x3400-0x4DBF) later if you want
    ],
    "latin": [
        (0x0021, 0x007E),  # basic ASCII printable (kept mostly for fallback / mixing)
        (0x00A1, 0x00FF),  # Latin-1 Supplement (printable-ish)
        (0x0100, 0x017F),  # Latin Extended-A
        (0x0180, 0x024F),  # Latin Extended-B
    ],
    "roman_numerals": [
        (0x2160, 0x2188),  # Number Forms (Roman numerals etc.)
    ],
}

DEFAULT_SCRIPTS = ["cyrillic", "greek", "hiragana", "katakana", "cjk", "latin", "roman_numerals"]


# ----------------------------
# Helpers: safety / selection
# ----------------------------

def is_combining(s: str) -> bool:
    return any(unicodedata.combining(ch) != 0 for ch in s)

def approx_is_single_width(s: str) -> bool:
    """
    Approximate terminal width == 1.
    Avoid combining marks and East Asian Wide/Fullwidth glyphs.
    (Not perfect; wcwidth would be better if you want exactness.)
    """
    if not s or is_combining(s):
        return False
    for ch in s:
        eaw = unicodedata.east_asian_width(ch)
        if eaw in ("W", "F"):
            return False
    return True

def is_reasonable_glyph(ch: str) -> bool:
    """
    Filter out control chars, unassigned, private-use, and whitespace.
    Keep letters/numbers/symbols/punctuation.
    """
    if ch.isspace():
        return False
    cat = unicodedata.category(ch)
    # Exclude control (Cc), surrogate (Cs), unassigned (Cn), private use (Co)
    if cat in ("Cc", "Cs", "Cn", "Co"):
        return False
    # Keep letters, marks (but we later filter combining), numbers, punctuation, symbols
    return cat[0] in ("L", "M", "N", "P", "S")

def build_glyph_pool(
    scripts: Sequence[str],
    safe: bool,
    normalize: str,
    rng: random.Random,
    cjk_sample_size: int,
) -> List[str]:
    """
    Build a glyph pool from the selected scripts.

    For most ranges we enumerate and filter.
    For CJK we sample random codepoints to avoid building a massive list.
    """
    pool: List[str] = []

    def add_char(ch: str) -> None:
        if not is_reasonable_glyph(ch):
            return
        if safe and not approx_is_single_width(ch):
            return
        if normalize == "nfc":
            ch2 = unicodedata.normalize("NFC", ch)
        elif normalize == "nfkc":
            ch2 = unicodedata.normalize("NFKC", ch)
        else:
            ch2 = ch
        if safe and (is_combining(ch2) or not approx_is_single_width(ch2)):
            return
        pool.append(ch2)

    for script in scripts:
        if script not in RANGES:
            continue

        for start, end in RANGES[script]:
            if script == "cjk":
                # Sample random codepoints from the CJK block
                for _ in range(cjk_sample_size):
                    code = rng.randint(start, end)
                    add_char(chr(code))
            else:
                for code in range(start, end + 1):
                    add_char(chr(code))

    # De-dup while keeping order
    seen = set()
    deduped = []
    for g in pool:
        if g not in seen:
            seen.add(g)
            deduped.append(g)

    return deduped


# ----------------------------
# Transform logic
# ----------------------------

@dataclass
class Options:
    mode: str                 # chaos (default) or safe
    seed: Optional[int]
    preserve: Set[str]
    transform: str            # letters|alnum|all
    prob: float
    normalize: str            # none|nfc|nfkc
    consistent: bool
    scripts: List[str]
    cjk_sample_size: int


def should_transform_char(ch: str, opt: Options) -> bool:
    if ch in opt.preserve:
        return False
    if opt.transform == "all":
        # Preserve whitespace & control formatting.
        if ch in ("\n", "\r", "\t"):
            return False
        # Only target basic printable ASCII; treat everything else as pass-through.
        return 0x20 <= ord(ch) <= 0x7E
    if opt.transform == "alnum":
        return ch.isalnum()
    if opt.transform == "letters":
        return ch.isalpha()
    return False


def transform_text(
    text: str,
    pool: List[str],
    opt: Options,
    rng: random.Random,
    cache: Dict[str, str],
) -> str:
    if not pool:
        # Fallback: if pool is empty, do nothing.
        return text

    out_chars: List[str] = []
    for ch in text:
        if not should_transform_char(ch, opt):
            out_chars.append(ch)
            continue
        if rng.random() > opt.prob:
            out_chars.append(ch)
            continue

        if opt.consistent:
            # Per-run: each source char gets one chosen glyph for this execution.
            if ch not in cache:
                cache[ch] = rng.choice(pool)
            out_chars.append(cache[ch])
        else:
            out_chars.append(rng.choice(pool))

    return "".join(out_chars)


# ----------------------------
# CLI + I/O
# ----------------------------

def parse_preserve(preserve_arg: Optional[str]) -> Set[str]:
    """
    Preserve format: literal characters and simple ranges like 0-9, a-z, A-Z.
    Example: "0-9,._-/" preserves digits and common path chars.
    """
    if not preserve_arg:
        return set()

    preserve: Set[str] = set()
    i = 0
    s = preserve_arg
    while i < len(s):
        if i + 2 < len(s) and s[i + 1] == "-" and s[i].isalnum() and s[i + 2].isalnum():
            start = ord(s[i])
            end = ord(s[i + 2])
            lo, hi = (start, end) if start <= end else (end, start)
            for code in range(lo, hi + 1):
                preserve.add(chr(code))
            i += 3
        else:
            preserve.add(s[i])
            i += 1
    return preserve


def iter_input_sources(args: Sequence[str]) -> Iterable[Tuple[str, Optional[str]]]:
    """
    Yields ("literal", text) or ("file", path).
    If a positional arg is an existing file path, treat as file; otherwise literal.
    If no args, stdin is used by caller.
    """
    for a in args:
        if a != "-" and os.path.exists(a) and os.path.isfile(a):
            yield ("file", a)
        else:
            yield ("literal", a)


def random_ascii_string(rng: random.Random, min_len: int, max_len: int) -> str:
    length = rng.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def clamp_delay_range(min_delay: float, max_delay: float) -> Tuple[float, float]:
    lo = max(0.0, min_delay)
    hi = max(0.0, max_delay)
    if lo > hi:
        lo, hi = hi, lo
    return lo, hi


def clear_terminal() -> None:
    if not sys.stdout.isatty():
        return
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="slither", description="Randomize ASCII into Unicode glyphs (chaos-first).")

    p.add_argument("inputs", nargs="*", help='Text literals and/or file paths. Use "-" or no args for stdin.')
    p.add_argument("--seed", type=int, default=None, help="Seed for reproducible output.")
    p.add_argument("--convo", action="store_true", help="Enable auto-typing conversation mode.")
    p.add_argument(
        "--convo-lines",
        type=int,
        default=10,
        help="Number of lines to auto-type (0 for endless).",
    )
    p.add_argument(
        "--convo-forever",
        action="store_true",
        help="Run auto-typing conversation mode indefinitely.",
    )
    p.add_argument(
        "--convo-min-len",
        type=int,
        default=5,
        help="Minimum length of generated input lines.",
    )
    p.add_argument(
        "--convo-max-len",
        type=int,
        default=75,
        help="Maximum length of generated input lines.",
    )
    p.add_argument(
        "--convo-min-delay",
        type=float,
        default=0.3,
        help="Minimum delay (seconds) between typed characters.",
    )
    p.add_argument(
        "--convo-max-delay",
        type=float,
        default=1.5,
        help="Maximum delay (seconds) between typed characters.",
    )
    p.add_argument(
        "--convo-burst",
        action="store_true",
        help="Enable burst typing (clusters of faster keystrokes with longer pauses).",
    )
    p.add_argument(
        "--convo-burst-min",
        type=int,
        default=3,
        help="Minimum burst length in characters.",
    )
    p.add_argument(
        "--convo-burst-max",
        type=int,
        default=8,
        help="Maximum burst length in characters.",
    )
    p.add_argument(
        "--convo-burst-fast-min-mult",
        type=float,
        default=0.2,
        help="Multiplier for min delay during bursts (relative to base min delay).",
    )
    p.add_argument(
        "--convo-burst-fast-max-mult",
        type=float,
        default=0.6,
        help="Multiplier for max delay during bursts (relative to base max delay).",
    )
    p.add_argument(
        "--convo-burst-pause-min-mult",
        type=float,
        default=1.5,
        help="Multiplier for min pause delay between bursts (relative to base min delay).",
    )
    p.add_argument(
        "--convo-burst-pause-max-mult",
        type=float,
        default=3.0,
        help="Multiplier for max pause delay between bursts (relative to base max delay).",
    )
    p.add_argument(
        "--mode",
        choices=["chaos", "safe"],
        default="chaos",
        help="chaos: full pools; safe: tries to avoid weird terminal width/combining issues.",
    )
    p.add_argument("--preserve", type=str, default="", help='Characters (and ranges) to preserve, e.g. "0-9,._-/"')
    p.add_argument("--transform", choices=["letters", "alnum", "all"], default="all",
                   help="Which characters are eligible for replacement.")
    p.add_argument("--prob", type=float, default=1.0, help="Probability (0..1) of replacing any eligible character.")
    p.add_argument("--normalize", choices=["none", "nfc", "nfkc"], default="none",
                   help="Unicode normalization applied to output glyphs.")
    p.add_argument("--consistent", action="store_true",
                   help="Choose one glyph per source character per run (more consistent look).")
    p.add_argument(
        "--scripts",
        type=str,
        default=",".join(DEFAULT_SCRIPTS),
        help="Comma-separated script pools to draw from. "
             f"Default: {','.join(DEFAULT_SCRIPTS)}",
    )
    p.add_argument(
        "--cjk-sample-size",
        type=int,
        default=120,
        help="How many random CJK ideographs to sample into the pool (CJK block is huge).",
    )

    ns = p.parse_args(argv)

    if not (0.0 <= ns.prob <= 1.0):
        print("error: --prob must be between 0 and 1", file=sys.stderr)
        return 2
    if ns.cjk_sample_size < 0:
        print("error: --cjk-sample-size must be >= 0", file=sys.stderr)
        return 2
    if ns.convo_lines < 0:
        print("error: --convo-lines must be >= 0", file=sys.stderr)
        return 2
    if ns.convo_burst_min < 1 or ns.convo_burst_max < 1:
        print("error: --convo-burst-min/--convo-burst-max must be >= 1", file=sys.stderr)
        return 2
    if ns.convo_burst_min > ns.convo_burst_max:
        print("error: --convo-burst-min must be <= --convo-burst-max", file=sys.stderr)
        return 2
    if ns.convo_burst_fast_min_mult < 0 or ns.convo_burst_fast_max_mult < 0:
        print("error: --convo-burst-fast-*-mult must be >= 0", file=sys.stderr)
        return 2
    if ns.convo_burst_fast_min_mult > ns.convo_burst_fast_max_mult:
        print("error: --convo-burst-fast-min-mult must be <= --convo-burst-fast-max-mult", file=sys.stderr)
        return 2
    if ns.convo_burst_pause_min_mult < 0 or ns.convo_burst_pause_max_mult < 0:
        print("error: --convo-burst-pause-*-mult must be >= 0", file=sys.stderr)
        return 2
    if ns.convo_burst_pause_min_mult > ns.convo_burst_pause_max_mult:
        print("error: --convo-burst-pause-min-mult must be <= --convo-burst-pause-max-mult", file=sys.stderr)
        return 2
    if ns.convo_min_len < 0 or ns.convo_max_len < 0:
        print("error: --convo-min-len/--convo-max-len must be >= 0", file=sys.stderr)
        return 2
    if ns.convo_min_len > ns.convo_max_len:
        print("error: --convo-min-len must be <= --convo-max-len", file=sys.stderr)
        return 2
    if ns.convo_min_delay < 0 or ns.convo_max_delay < 0:
        print("error: --convo-min-delay/--convo-max-delay must be >= 0", file=sys.stderr)
        return 2
    if ns.convo_min_delay > ns.convo_max_delay:
        print("error: --convo-min-delay must be <= --convo-max-delay", file=sys.stderr)
        return 2

    scripts = [s.strip().lower() for s in ns.scripts.split(",") if s.strip()]
    # Keep only known scripts; ignore unknowns to avoid surprise crashes
    scripts = [s for s in scripts if s in RANGES]

    rng = random.Random(ns.seed)

    opt = Options(
        mode=ns.mode,
        seed=ns.seed,
        preserve=parse_preserve(ns.preserve),
        transform=ns.transform,
        prob=ns.prob,
        normalize=ns.normalize,
        consistent=ns.consistent,
        scripts=scripts,
        cjk_sample_size=ns.cjk_sample_size,
    )

    pool = build_glyph_pool(
        scripts=opt.scripts,
        safe=(opt.mode == "safe"),
        normalize=opt.normalize,
        rng=rng,
        cjk_sample_size=opt.cjk_sample_size,
    )

    cache: Dict[str, str] = {}

    clear_terminal()

    if ns.convo:
        if ns.convo_forever:
            ns.convo_lines = 0
        if opt.transform == "all":
            opt.preserve = set(opt.preserve)
            opt.preserve.update({" ", "\t", "\n", "\r"})
        base_min_delay, base_max_delay = clamp_delay_range(ns.convo_min_delay, ns.convo_max_delay)
        fast_min_delay, fast_max_delay = clamp_delay_range(
            base_min_delay * ns.convo_burst_fast_min_mult,
            base_max_delay * ns.convo_burst_fast_max_mult,
        )
        pause_min_delay, pause_max_delay = clamp_delay_range(
            base_min_delay * ns.convo_burst_pause_min_mult,
            base_max_delay * ns.convo_burst_pause_max_mult,
        )

        line_count = 0
        burst_remaining = 0
        while ns.convo_lines == 0 or line_count < ns.convo_lines:
            raw_line = random_ascii_string(rng, ns.convo_min_len, ns.convo_max_len)
            transformed = transform_text(raw_line, pool, opt, rng, cache)
            for i, ch in enumerate(transformed):
                sys.stdout.write(ch)
                sys.stdout.flush()
                if ns.convo_burst:
                    if burst_remaining == 0:
                        burst_remaining = rng.randint(ns.convo_burst_min, ns.convo_burst_max)
                    time.sleep(rng.uniform(fast_min_delay, fast_max_delay))
                    burst_remaining -= 1
                    if burst_remaining == 0 and i != len(transformed) - 1:
                        time.sleep(rng.uniform(pause_min_delay, pause_max_delay))
                else:
                    time.sleep(rng.uniform(base_min_delay, base_max_delay))
            sys.stdout.write("\n")
            sys.stdout.flush()
            time.sleep(rng.uniform(base_min_delay, base_max_delay))
            line_count += 1
        return 0

    # stdin mode
    if not ns.inputs or "-" in ns.inputs:
        data = sys.stdin.read()
        sys.stdout.write(transform_text(data, pool, opt, rng, cache))
        return 0

    # positional args: treat existing files as files, otherwise literals
    first_literal = True
    for kind, value in iter_input_sources(ns.inputs):
        if kind == "literal":
            if not first_literal:
                sys.stdout.write(" ")
            first_literal = False
            sys.stdout.write(transform_text(value or "", pool, opt, rng, cache))
        else:
            path = value or ""
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        sys.stdout.write(transform_text(chunk, pool, opt, rng, cache))
            except OSError as e:
                print(f"error: cannot read {path}: {e}", file=sys.stderr)
                return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
