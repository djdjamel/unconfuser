"""
Heuristic analysis functions: Shannon entropy, identifier analysis, and obfuscation metrics.
"""

import math
import re
from typing import List, Dict, Any
from .signatures import INVISIBLE_CHARS


try:  # optional acceleration (Gap A14)
    import numpy as _np
except Exception:  # pragma: no cover
    _np = None

_ENTROPY_SAMPLE_CAP = 4 * 1024 * 1024  # bytes; larger buffers are sampled


def calculate_entropy(data: bytes) -> float:
    """
    Computes Shannon entropy of a byte stream.
    Range: 0.0 (completely uniform/zeroes) to 8.0 (maximum randomness/compressed/encrypted).
    Buffers larger than 4 MB are sampled (head, middle, tail) for speed.
    """
    if not data:
        return 0.0

    if len(data) > _ENTROPY_SAMPLE_CAP:
        third = _ENTROPY_SAMPLE_CAP // 3
        mid = len(data) // 2
        data = data[:third] + data[mid:mid + third] + data[-third:]

    length = len(data)
    if _np is not None:
        byte_counts = _np.bincount(_np.frombuffer(data, dtype=_np.uint8), minlength=256).tolist()
    else:
        from collections import Counter
        c = Counter(data)
        byte_counts = [c.get(i, 0) for i in range(256)]

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def _identifier_entropy(name: str) -> float:
    """Shannon entropy of the character sequence of an identifier name (Phase 5)."""
    if not name:
        return 0.0
    freq: Dict[str, int] = {}
    for c in name:
        freq[c] = freq.get(c, 0) + 1
    ln = len(name)
    return round(-sum((v / ln) * math.log2(v / ln) for v in freq.values()), 4)


CSHARP_KEYWORDS = frozenset({
    "if", "else", "int", "void", "string", "class", "struct", "new", "return", "true",
    "false", "null", "this", "base", "for", "while", "do", "switch", "case", "default",
    "break", "continue", "goto", "try", "catch", "finally", "throw", "byte", "sbyte",
    "short", "ushort", "uint", "long", "ulong", "float", "double", "decimal", "bool",
    "char", "object", "lock", "using", "fixed", "stackalloc", "sizeof", "typeof",
    "delegate", "event", "operator", "explicit", "implicit", "enum", "interface",
    "namespace", "public", "private", "protected", "internal", "static", "readonly",
    "volatile", "virtual", "sealed", "override", "abstract", "extern", "const",
    "params", "ref", "out", "in", "is", "as", "checked", "unchecked", "async",
    "await", "yield",
})


def _is_cjk_or_confusable(c: str) -> bool:
    cp = ord(c)
    return (
        (0x4E00 <= cp <= 0x9FFF)     # CJK Unified Ideographs
        or (0x3400 <= cp <= 0x4DBF) # CJK Extension A
        or (0xAC00 <= cp <= 0xD7AF) # Hangul Syllables
        or (0xE000 <= cp <= 0xF8FF) # Private Use Area
        or (0x2100 <= cp <= 0x214F) # Letterlike symbols
        or (0x0300 <= cp <= 0x036F) # Combining Diacritical Marks
    )


def analyze_identifier(name: str) -> Dict[str, Any]:
    """
    Analyzes an identifier (class, method, field) for obfuscation indicators:
    - Zero-width / invisible characters
    - Non-ASCII / math / symbol characters
    - Short sequential renaming (Phase 5: widened threshold <= 3 + pattern rules)
    - Unprintable control characters
    - High character-entropy names (Phase 5: hash-based / random names)
    - C# reserved keywords used as names
    - CJK / Cyrillic / Math confusable characters
    """
    result = {
        "is_short": False,
        "has_invisible": False,
        "has_non_ascii": False,
        "has_control_chars": False,
        "is_high_entropy_name": False,
        "is_csharp_keyword": False,
        "has_cjk_confusable": False,
        "name_entropy": 0.0,
        "invisible_chars_found": [],
    }

    if not name or name == "<Module>":
        return result

    # Reserved keywords
    if name.lower() in CSHARP_KEYWORDS:
        result["is_csharp_keyword"] = True

    # CJK / confusables
    if any(_is_cjk_or_confusable(c) for c in name):
        result["has_cjk_confusable"] = True

    # ---- Short / obfuscated naming (Phase 5: widened threshold) ----
    # 1. Length <= 3 (was <= 2) using only safe identifier chars
    if len(name) <= 3 and re.match(r"^[a-zA-Z0-9_\$]+$", name):
        result["is_short"] = True
    # 2. 1-2 letters + 1-3 digits  (e.g. a1, b22, aB3, c001)
    elif re.match(r"^[a-zA-Z]{1,2}[0-9]{1,3}$", name):
        result["is_short"] = True
    # 3. All-uppercase 2-5 chars  (e.g. AAAB, BBBR)
    elif re.match(r"^[A-Z]{2,5}$", name):
        result["is_short"] = True

    # ---- Invisible characters ----
    for ch, char_name in INVISIBLE_CHARS.items():
        if ch in name:
            result["has_invisible"] = True
            result["invisible_chars_found"].append(char_name)

    # ---- Non-ASCII characters ----
    if any(ord(c) > 127 for c in name):
        result["has_non_ascii"] = True

    # ---- Control characters ----
    if any(ord(c) < 32 and c not in ("\t", "\n", "\r") for c in name):
        result["has_control_chars"] = True

    # ---- Identifier name entropy / un-wordlikeness (Phase 5 / Phase 10) ----
    result["name_entropy"] = _identifier_entropy(name)
    if (
        len(name) >= 6
        and not name.startswith("<")
        and not name.startswith("_")
        and not name.startswith("$")
        and not name.startswith("__MIDL")
    ):
        from .matching import split_identifier
        from .wordlist import is_wordlike_token

        tokens = split_identifier(name)
        long_tokens = [t for t in tokens if len(t) >= 3]
        is_normal_words = False
        if long_tokens and all(is_wordlike_token(t) for t in long_tokens):
            unwordlike = [t for t in tokens if not is_wordlike_token(t)]
            if not unwordlike or len(unwordlike) <= len(tokens) * 0.2:
                is_normal_words = True

        if not is_normal_words:
            case_switches = sum(
                1 for i in range(len(name) - 1)
                if (name[i].islower() and name[i + 1].isupper())
                or (name[i].isupper() and name[i + 1].islower() and i > 0 and name[i - 1].islower())
            )
            single_char_tokens = sum(1 for t in tokens if len(t) == 1)
            has_vowel = any(c in "aeiouyAEIOUY" for c in name)
            vowel_ratio = sum(1 for c in name if c in "aeiouyAEIOUY") / len(name) if len(name) else 0

            # Flag hash-like, alternating random case, or consonant-packed names
            if (
                single_char_tokens >= len(tokens) * 0.6
                or not has_vowel
                or (vowel_ratio < 0.15 and any(c.isdigit() for c in name))
                or case_switches >= len(name) * 0.35
            ):
                result["is_high_entropy_name"] = True

    return result


def evaluate_identifier_collection(names: List[str]) -> Dict[str, Any]:
    """
    Aggregates identifier metrics across a collection (types, methods, fields).
    """
    total = len(names)
    if total == 0:
        return {
            "total_count": 0,
            "short_count": 0,
            "short_ratio": 0.0,
            "non_ascii_count": 0,
            "non_ascii_ratio": 0.0,
            "invisible_count": 0,
            "invisible_ratio": 0.0,
            "invisible_detected": [],
            "high_entropy_name_count": 0,
            "high_entropy_name_ratio": 0.0,
            "keyword_name_count": 0,
            "cjk_confusable_count": 0,
            "cjk_confusable_ratio": 0.0,
        }

    short_count = 0
    non_ascii_count = 0
    invisible_count = 0
    high_entropy_name_count = 0
    keyword_name_count = 0
    cjk_confusable_count = 0
    invisible_set: set = set()

    for name in names:
        analysis = analyze_identifier(name)
        if analysis["is_short"]:
            short_count += 1
        if analysis["has_non_ascii"]:
            non_ascii_count += 1
        if analysis["has_invisible"]:
            invisible_count += 1
            invisible_set.update(analysis["invisible_chars_found"])
        if analysis["is_high_entropy_name"]:
            high_entropy_name_count += 1
        if analysis["is_csharp_keyword"]:
            keyword_name_count += 1
        if analysis["has_cjk_confusable"]:
            cjk_confusable_count += 1

    return {
        "total_count": total,
        "short_count": short_count,
        "short_ratio": round(short_count / total, 3),
        "non_ascii_count": non_ascii_count,
        "non_ascii_ratio": round(non_ascii_count / total, 3),
        "invisible_count": invisible_count,
        "invisible_ratio": round(invisible_count / total, 3),
        "invisible_detected": sorted(list(invisible_set)),
        "high_entropy_name_count": high_entropy_name_count,
        "high_entropy_name_ratio": round(high_entropy_name_count / total, 3),
        "keyword_name_count": keyword_name_count,
        "cjk_confusable_count": cjk_confusable_count,
        "cjk_confusable_ratio": round(cjk_confusable_count / total, 3),
    }
