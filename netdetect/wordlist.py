"""
English and programming naming bigrams and common syllables (Phase 10).
Used to evaluate identifier 'wordlikeness' without false-positives on PascalCase/camelCase.
"""

# Common 2-letter sequences in English and programming identifiers (lower-case)
COMMON_BIGRAMS = frozenset([
    "th", "he", "in", "er", "an", "re", "ed", "on", "es", "st", "en", "at", "to", "nt", "ha", "nd",
    "ou", "ea", "ng", "as", "or", "ti", "is", "et", "it", "ar", "te", "se", "hi", "of", "al", "de",
    "co", "ro", "li", "ra", "le", "sa", "si", "me", "ch", "ma", "ur", "el", "ta", "la", "ns", "ge",
    "da", "lo", "pe", "fo", "mo", "so", "va", "no", "di", "ba", "ca", "pa", "na", "vi", "ri", "ce",
    "ct", "id", "ll", "ve", "ne", "ac", "em", "om", "un", "fi", "tr", "pr", "pl", "gr", "cl", "sp",
    "sc", "st", "sh", "ph", "wh", "bl", "fl", "gl", "br", "cr", "dr", "fr", "pr", "sk", "sm", "sn",
    "get", "set", "add", "del", "run", "sub", "new", "old", "max", "min", "val", "key", "idx", "len",
    "str", "num", "ptr", "obj", "doc", "app", "sys", "net", "clr", "xml", "json", "http", "view",
    "item", "list", "node", "tree", "file", "data", "base", "user", "name", "type", "call", "send",
    "recv", "read", "load", "save", "sync", "async", "task", "work", "init", "exit", "open", "close",
    "help", "text", "line", "byte", "char", "word", "code", "size", "info", "lock", "link", "pack",
    # common vowel pairs
    "ai", "ay", "ee", "ea", "ie", "oa", "oe", "oo", "ou", "ue", "ui",
    # Programming morphemes
    "impl", "attr", "prop", "desc", "enum", "func", "util", "proc", "mgr", "ctrl", "spec", "arg",
    "pos", "len", "dest", "src", "buf", "temp", "tmp", "curr", "prev", "next", "last", "dest",
])


def is_wordlike_token(token: str) -> bool:
    """
    Checks if an individual sub-token looks like natural English/programming words
    rather than random characters/hashes.
    """
    t = token.lower()
    if len(t) <= 2:
        return True
    # Digits only or hex numbers
    if t.isdigit():
        return True

    # Count bigram matches
    total_bigrams = len(t) - 1
    if total_bigrams <= 0:
        return True
    matched = sum(1 for i in range(total_bigrams) if t[i : i + 2] in COMMON_BIGRAMS)
    coverage = matched / total_bigrams

    # Check for vowel presence (most natural words have at least one vowel/y)
    has_vowel = any(c in "aeiouy" for c in t)

    if coverage >= 0.45 and has_vowel:
        return True
    if coverage >= 0.60:
        return True
    return False
