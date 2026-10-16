"""
Pattern matching utilities and tokenization for signature evaluation.
Supports matching modes:
  - exact: case-insensitive equality
  - prefix: case-insensitive startswith
  - token: word-boundary / token match on camelCase, dots, underscores
  - contains: substring match (requires minimum pattern length)
  - regex: compiled regular expression match
"""

import re
from typing import List, Union, Dict, Any, Optional

# Token splitting regex: splits on '.', '_', '-', '<', '>', '$', '/', '\\', and camelCase boundaries
_CAMEL_SPLIT_REGEX = re.compile(
    r"[._\-<>\$\/\\:]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[a-zA-Z])(?=[0-9])|(?<=[0-9])(?=[a-zA-Z])"
)

# Minimum length for raw 'contains' mode to avoid dangerous substring matches
MIN_CONTAINS_LEN = 8


def split_identifier(name: str) -> List[str]:
    """
    Splits an identifier, type name, namespace, or path into lowercase tokens.
    Examples:
      'InternetZoneManager' -> ['internet', 'zone', 'manager']
      'System.Collections.Specialized' -> ['system', 'collections', 'specialized']
      'uncompressedDataLength' -> ['uncompressed', 'data', 'length']
      'tagENUMLOGFONTEXDVW' -> ['tag', 'enumlogfontexdvw']
    """
    if not name:
        return []
    raw_tokens = _CAMEL_SPLIT_REGEX.split(name)
    tokens = [t.lower() for t in raw_tokens if t]
    return tokens


class Pattern:
    """
    Compiled pattern rule with matching semantics.
    """

    def __init__(
        self,
        pattern: str,
        mode: str = "token",
        tier: Optional[str] = None,
        case_sensitive: bool = False,
    ):
        self.raw = pattern
        self.mode = mode.lower()
        self.tier = tier  # 'definitive', 'strong', 'weak', or None (inherit from field)
        self.case_sensitive = case_sensitive

        if self.mode == "contains" and len(pattern) < MIN_CONTAINS_LEN:
            raise ValueError(
                f"Contains pattern '{pattern}' is shorter than {MIN_CONTAINS_LEN} chars. "
                "Use 'exact', 'token', or 'prefix' instead to avoid false positives."
            )

        self._norm = pattern if case_sensitive else pattern.lower()
        self._tokens = split_identifier(pattern) if self.mode == "token" else []
        self._regex = None
        if self.mode == "regex":
            flags = 0 if case_sensitive else re.IGNORECASE
            self._regex = re.compile(pattern, flags)

    def matches(self, target: str) -> bool:
        if not target:
            return False

        if self.mode == "exact":
            t_norm = target if self.case_sensitive else target.lower()
            return self._norm == t_norm

        elif self.mode == "prefix":
            t_norm = target if self.case_sensitive else target.lower()
            return t_norm.startswith(self._norm)

        elif self.mode == "contains":
            t_norm = target if self.case_sensitive else target.lower()
            return self._norm in t_norm

        elif self.mode == "token":
            t_tokens = split_identifier(target)
            if not self._tokens or not t_tokens:
                return False
            # Check if self._tokens is a contiguous sub-sequence of t_tokens,
            # or if single-token pattern matches any token exactly.
            if len(self._tokens) == 1:
                return self._tokens[0] in t_tokens
            # Multi-token sequence match
            plen = len(self._tokens)
            for i in range(len(t_tokens) - plen + 1):
                if t_tokens[i : i + plen] == self._tokens:
                    return True
            return False

        elif self.mode == "regex":
            if self._regex:
                return bool(self._regex.search(target))
            return False

        else:
            # Fallback exact
            t_norm = target if self.case_sensitive else target.lower()
            return self._norm == t_norm

    def __repr__(self):
        return f"Pattern({self.raw!r}, mode={self.mode!r})"


def compile_pattern(spec: Union[str, Dict[str, Any]], default_mode: str = "token") -> Pattern:
    """
    Converts a string or dict specification into a Pattern instance.
    Spec dict: {"p": "foo", "mode": "exact", "tier": "strong"}
    """
    if isinstance(spec, Pattern):
        return spec
    if isinstance(spec, str):
        return Pattern(spec, mode=default_mode)
    if isinstance(spec, dict):
        p_str = spec.get("p", "")
        mode = spec.get("mode", default_mode)
        tier = spec.get("tier")
        case_sensitive = spec.get("case_sensitive", False)
        return Pattern(p_str, mode=mode, tier=tier, case_sensitive=case_sensitive)
    raise TypeError(f"Invalid pattern specification: {type(spec)}")
