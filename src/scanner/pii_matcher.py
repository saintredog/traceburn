"""
src/scanner/pii_matcher.py — PII Matching Engine

Matches raw page text against user PII identifiers retrieved from the vault.
Uses only stdlib (difflib) — no external Levenshtein library.

Confidence levels:
    1.0 — exact match (case-normalised)
    0.7 — partial match (identifier is a substring of candidate)
    0.5 — fuzzy match (SequenceMatcher ratio above threshold)
    0.0 — no match

Composite score per URL = max(confidences) + 0.1 * (len(matches) - 1), capped at 1.0.
"""

from __future__ import annotations

import difflib
import re
import string
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MatchResult:
    """A single matched PII field within a block of candidate text."""

    field_matched: str
    """Name of the PII field that was matched, e.g. 'full_name'."""

    match_type: str
    """One of: 'exact', 'partial', 'fuzzy'."""

    confidence: float
    """Match confidence in [0.0, 1.0]."""

    snippet: str
    """The portion of the candidate text where the match was found."""


class PIIMatcher:
    """
    Matches raw scraped text against a user's PII identifiers.

    The matcher operates on normalised text throughout — all comparisons
    are case-insensitive and whitespace-collapsed. No PII is stored
    on this object; identifiers are passed in at call time.

    Example::

        matcher = PIIMatcher()
        results = matcher.match(
            "John Smith lives at 123 Main St Springfield",
            profile={"full_name": "John Smith", "city": "Springfield"},
        )
        score = matcher.composite_score(results)
    """

    # ── Text normalisation ────────────────────────────────────────────────

    def normalize(self, text: str) -> str:
        """
        Normalise text for comparison.

        - Converts to lowercase
        - Collapses all whitespace to a single space
        - Strips leading/trailing whitespace
        - Removes punctuation except hyphens and apostrophes (preserves
          hyphenated names and contractions)
        """
        text = text.lower()
        # Remove punctuation except hyphens and apostrophes
        allowed = set(string.ascii_lowercase + string.digits + " -'")
        text = "".join(ch if ch in allowed else " " for ch in text)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text

    # ── Individual match strategies ───────────────────────────────────────

    def match_exact(self, candidate: str, identifier: str) -> float:
        """
        Return 1.0 if *identifier* appears verbatim in *candidate* (after
        normalisation), else 0.0.
        """
        if not identifier:
            return 0.0
        norm_candidate = self.normalize(candidate)
        norm_id = self.normalize(identifier)
        return 1.0 if norm_id in norm_candidate else 0.0

    def match_partial(self, candidate: str, identifier: str) -> float:
        """
        Return 0.7 if any token of *identifier* appears in *candidate*
        (after normalisation) and the token is at least 4 characters long
        (avoids false positives on short common words).

        Returns 0.0 if no partial match is found.
        """
        if not identifier:
            return 0.0
        norm_candidate = self.normalize(candidate)
        norm_id = self.normalize(identifier)
        tokens = [t for t in norm_id.split() if len(t) >= 4]
        if not tokens:
            return 0.0
        for token in tokens:
            if token in norm_candidate:
                return 0.7
        return 0.0

    def match_fuzzy(
        self,
        candidate: str,
        identifier: str,
        threshold: int = 2,
    ) -> float:
        """
        Return 0.5 if difflib.SequenceMatcher ratio is above the threshold
        expressed as a Levenshtein-equivalent edit distance, else 0.0.

        ``threshold`` controls sensitivity: lower = stricter.
        Internally converts to a SequenceMatcher ratio:
            ratio >= 1 - (threshold / max(len(a), len(b)))
        """
        if not identifier:
            return 0.0
        norm_candidate = self.normalize(candidate)
        norm_id = self.normalize(identifier)

        if not norm_id:
            return 0.0

        max_len = max(len(norm_id), len(norm_candidate), 1)
        # Look for the identifier as a window inside the candidate
        # by sliding it across the candidate text
        id_len = len(norm_id)
        best_ratio = 0.0
        step = max(1, id_len // 2)
        for start in range(0, max(1, len(norm_candidate) - id_len + 1), step):
            window = norm_candidate[start : start + id_len + threshold]
            ratio = difflib.SequenceMatcher(None, norm_id, window).ratio()
            if ratio > best_ratio:
                best_ratio = ratio

        # Convert threshold to minimum ratio
        min_ratio = 1.0 - (threshold / max(len(norm_id), 1))
        return 0.5 if best_ratio >= min_ratio else 0.0

    # ── Composite matching ────────────────────────────────────────────────

    def match(
        self,
        candidate_text: str,
        profile: dict[str, Any],
    ) -> list[MatchResult]:
        """
        Run all match strategies against every field in *profile*.

        Returns a list of :class:`MatchResult` objects for every field
        where at least one strategy scores above 0.0. Results are ordered
        from highest to lowest confidence.

        ``profile`` maps field names to plaintext identifier strings,
        e.g. ``{"full_name": "Jane Doe", "city": "Springfield"}``.
        PII values are received here from the vault — they are used only
        during this call and are not stored on the matcher.
        """
        results: list[MatchResult] = []

        for field_name, identifier in profile.items():
            if not identifier or not isinstance(identifier, str):
                continue

            # Try strategies from most to least specific
            exact = self.match_exact(candidate_text, identifier)
            if exact > 0.0:
                snippet = self._extract_snippet(candidate_text, identifier)
                results.append(
                    MatchResult(
                        field_matched=field_name,
                        match_type="exact",
                        confidence=exact,
                        snippet=snippet,
                    )
                )
                continue

            partial = self.match_partial(candidate_text, identifier)
            if partial > 0.0:
                snippet = self._extract_snippet(candidate_text, identifier)
                results.append(
                    MatchResult(
                        field_matched=field_name,
                        match_type="partial",
                        confidence=partial,
                        snippet=snippet,
                    )
                )
                continue

            fuzzy = self.match_fuzzy(candidate_text, identifier)
            if fuzzy > 0.0:
                snippet = self._extract_snippet(candidate_text, identifier)
                results.append(
                    MatchResult(
                        field_matched=field_name,
                        match_type="fuzzy",
                        confidence=fuzzy,
                        snippet=snippet,
                    )
                )

        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def composite_score(self, matches: list[MatchResult]) -> float:
        """
        Compute a composite confidence score from a list of match results.

        Formula: max(confidences) + 0.1 * (len(matches) - 1), capped at 1.0.

        This rewards profiles where multiple PII fields are matched while
        keeping a single exact-match score at 1.0.
        """
        if not matches:
            return 0.0
        max_conf = max(m.confidence for m in matches)
        n = len(matches)
        return min(max_conf + 0.1 * (n - 1), 1.0)

    # ── Private helpers ───────────────────────────────────────────────────

    def _extract_snippet(self, text: str, identifier: str, context: int = 40) -> str:
        """
        Extract a short snippet of *text* around the first occurrence of
        *identifier* (normalised). Returns up to *context* characters on
        each side. Falls back to the first 80 characters of text.
        """
        norm_text = self.normalize(text)
        norm_id = self.normalize(identifier)
        idx = norm_text.find(norm_id)
        if idx == -1:
            return text[:80].replace("\n", " ").strip()
        start = max(0, idx - context)
        end = min(len(text), idx + len(identifier) + context)
        raw_snippet = text[start:end]
        return raw_snippet.replace("\n", " ").strip()
