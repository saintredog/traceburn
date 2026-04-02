"""
tests/unit/test_pii_matcher.py — Unit tests for PIIMatcher (src/scanner/pii_matcher.py).

Coverage:
  - exact / partial / fuzzy matching strategies
  - text normalisation (phone, whitespace, case)
  - composite scoring (single and multi-match boosting)
  - email and phone exact-match priority over fuzzy
  - snippet extraction in match results

No external dependencies — purely stdlib + difflib, no network calls.
"""
from __future__ import annotations

import pytest

from src.scanner.pii_matcher import MatchResult, PIIMatcher


@pytest.fixture
def matcher() -> PIIMatcher:
    """Fresh PIIMatcher instance for each test."""
    return PIIMatcher()


# ─────────────────────────────────────────────────────────────────────────────
# Exact matching
# ─────────────────────────────────────────────────────────────────────────────


class TestExactMatch:
    def test_exact_match_name(self, matcher):
        """'clifford roberts' matches 'clifford roberts' with confidence 1.0."""
        result = matcher.match_exact("clifford roberts", "clifford roberts")
        assert result == 1.0

    def test_exact_match_email(self, matcher):
        """Exact email match returns confidence 1.0 (after normalisation of @ and .)."""
        result = matcher.match_exact(
            "contact john example com today",
            "john@example.com",
        )
        # normalize strips @ and . → both sides become "john example com"
        assert result == 1.0

    def test_exact_match_case_insensitive(self, matcher):
        """Exact matching is case-insensitive after normalisation."""
        result = matcher.match_exact("CLIFFORD ROBERTS", "Clifford Roberts")
        assert result == 1.0

    def test_exact_no_match(self, matcher):
        """Completely different text returns 0.0 for exact matching."""
        result = matcher.match_exact("alice johnson", "clifford roberts")
        assert result == 0.0

    def test_exact_empty_identifier(self, matcher):
        """Empty identifier always returns 0.0 (guards against vacuous match)."""
        assert matcher.match_exact("some text", "") == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Partial matching
# ─────────────────────────────────────────────────────────────────────────────


class TestPartialMatch:
    def test_partial_match(self, matcher):
        """Identifier token found within a longer string returns 0.7."""
        result = matcher.match_partial(
            "John clifford roberts lives at 123 main st",
            "clifford roberts",
        )
        assert result == 0.7

    def test_partial_no_match_short_tokens(self, matcher):
        """Tokens shorter than 4 characters are ignored to avoid false positives."""
        # "joe" is 3 chars — below the 4-char threshold
        result = matcher.match_partial("joe lives here", "joe doe")
        assert result == 0.0

    def test_partial_empty_identifier(self, matcher):
        """Empty identifier returns 0.0 for partial matching."""
        assert matcher.match_partial("some text", "") == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzy matching
# ─────────────────────────────────────────────────────────────────────────────


class TestFuzzyMatch:
    def test_fuzzy_match_typo(self, matcher):
        """
        'cliford roberts' (one 'f' removed from 'clifford') fuzzy-matches
        the identifier 'clifford roberts' and returns 0.5.

        Tests match_fuzzy() directly because the full match() pipeline would
        hit a partial match first if only one token has a typo.
        """
        result = matcher.match_fuzzy("cliford roberts", "clifford roberts")
        assert result == 0.5

    def test_fuzzy_no_match(self, matcher):
        """Completely different text produces no fuzzy match (returns 0.0)."""
        result = matcher.match_fuzzy(
            "the quick brown fox jumped over",
            "clifford roberts",
        )
        assert result == 0.0

    def test_fuzzy_empty_identifier(self, matcher):
        """Empty identifier returns 0.0 for fuzzy matching."""
        assert matcher.match_fuzzy("some text", "") == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Normalisation
# ─────────────────────────────────────────────────────────────────────────────


class TestNormalize:
    def test_normalize_case(self, matcher):
        """Normalisation converts all text to lowercase."""
        assert matcher.normalize("CLIFFORD ROBERTS") == "clifford roberts"

    def test_normalize_whitespace(self, matcher):
        """Extra and mixed whitespace is collapsed to a single space."""
        result = matcher.normalize("  clifford   roberts  ")
        assert result == "clifford roberts"

    def test_normalize_phone(self, matcher):
        """
        Phone normalisation strips parentheses and collapses spaces.

        The vault stores phones as digit-only strings; the matcher normalises
        candidate text so '(619) 555-1234' loses its brackets and extra spaces.
        After normalisation, digits and a retained hyphen remain.
        """
        result = matcher.normalize("(619) 555-1234")
        # Parentheses become spaces → collapsed; hyphen is kept
        assert "619" in result
        assert "555" in result
        assert "1234" in result
        assert "(" not in result
        assert ")" not in result

    def test_normalize_punctuation_stripped(self, matcher):
        """Punctuation characters other than hyphens and apostrophes are removed."""
        result = matcher.normalize("Smith, John.")
        assert "," not in result
        assert "." not in result

    def test_normalize_hyphen_preserved(self, matcher):
        """Hyphens are preserved (important for hyphenated names like 'Smith-Jones')."""
        result = matcher.normalize("Smith-Jones")
        assert "-" in result

    def test_normalize_apostrophe_preserved(self, matcher):
        """Apostrophes are preserved (important for names like \"O'Brien\")."""
        result = matcher.normalize("O'Brien")
        assert "'" in result


# ─────────────────────────────────────────────────────────────────────────────
# Composite scoring
# ─────────────────────────────────────────────────────────────────────────────


class TestCompositeScore:
    def test_composite_score_empty(self, matcher):
        """An empty match list returns a composite score of 0.0."""
        assert matcher.composite_score([]) == 0.0

    def test_composite_score_single(self, matcher):
        """A single exact match returns that match's confidence unchanged."""
        matches = [MatchResult("full_name", "exact", 1.0, "clifford roberts")]
        score = matcher.composite_score(matches)
        assert score == 1.0

    def test_composite_score_single_partial(self, matcher):
        """A single partial match (0.7) returns 0.7 with the formula's n=1 term."""
        matches = [MatchResult("full_name", "partial", 0.7, "clifford")]
        score = matcher.composite_score(matches)
        assert score == pytest.approx(0.7)

    def test_composite_score_multiple(self, matcher):
        """Multiple matches boost score by 0.1 per additional match, capped at 1.0."""
        matches = [
            MatchResult("full_name", "exact", 0.7, "clifford roberts"),
            MatchResult("city", "partial", 0.7, "springfield"),
            MatchResult("email", "exact", 0.7, "clifford example com"),
        ]
        # max=0.7, n=3 → 0.7 + 0.1*2 = 0.9
        score = matcher.composite_score(matches)
        assert score == pytest.approx(0.9)

    def test_composite_score_capped_at_1(self, matcher):
        """Score is capped at 1.0 even when many matches would push it higher."""
        many_matches = [
            MatchResult(f"field_{i}", "partial", 0.7, "snippet")
            for i in range(8)
        ]
        # 0.7 + 0.1*(8-1) = 0.7 + 0.7 = 1.4 → capped at 1.0
        assert matcher.composite_score(many_matches) == 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Full match() pipeline
# ─────────────────────────────────────────────────────────────────────────────


class TestMatchPipeline:
    def test_email_no_fuzzy(self, matcher):
        """
        Email addresses are matched exactly (confidence 1.0), not via fuzzy (0.5).

        When an email appears verbatim in candidate text, the pipeline returns
        match_type='exact' — ensuring no weaker fuzzy match is reported.
        """
        results = matcher.match(
            candidate_text="Reach us at john example com for assistance",
            profile={"email": "john@example.com"},
        )
        assert len(results) == 1
        assert results[0].confidence == 1.0
        assert results[0].match_type == "exact"

    def test_phone_no_fuzzy(self, matcher):
        """
        Phone numbers stored as digit strings produce exact matches when the
        same digits appear in candidate text (after normalisation strips formatting).

        Ensures a known phone number is matched precisely, not via fuzzy similarity.
        """
        # Vault stores "6195551234"; candidate contains the same digits
        results = matcher.match(
            candidate_text="call 6195551234 to opt out",
            profile={"phone": "6195551234"},
        )
        assert len(results) == 1
        assert results[0].match_type == "exact"
        assert results[0].confidence == 1.0

    def test_match_returns_snippet(self, matcher):
        """Each MatchResult includes a non-empty snippet from the candidate text."""
        candidate = "Contact clifford roberts at 123 main street springfield"
        results = matcher.match(candidate, profile={"full_name": "clifford roberts"})
        assert len(results) >= 1
        result = results[0]
        assert isinstance(result.snippet, str)
        assert len(result.snippet) > 0
        # Snippet should contain context around the match
        assert "clifford" in result.snippet.lower() or "roberts" in result.snippet.lower()

    def test_no_match_returns_empty_list(self, matcher):
        """match() returns an empty list when no profile field appears in candidate."""
        results = matcher.match(
            candidate_text="this page has completely unrelated content",
            profile={"full_name": "clifford roberts", "email": "cr@example.com"},
        )
        assert results == []

    def test_results_ordered_by_confidence(self, matcher):
        """match() returns results ordered from highest to lowest confidence."""
        candidate = "clifford roberts lives in springfield and can be reached at clifford"
        results = matcher.match(
            candidate,
            profile={
                "full_name": "clifford roberts",
                "city": "springfield",
            },
        )
        confidences = [r.confidence for r in results]
        assert confidences == sorted(confidences, reverse=True)

    def test_skips_non_string_profile_values(self, matcher):
        """match() silently skips profile entries whose value is not a string."""
        results = matcher.match(
            "clifford roberts",
            profile={"full_name": "clifford roberts", "age": 42, "empty": None},
        )
        # Only the string field should produce a result
        field_names = {r.field_matched for r in results}
        assert "age" not in field_names
        assert "empty" not in field_names

    @pytest.mark.parametrize("identifier,candidate,expected_type", [
        ("clifford roberts", "clifford roberts", "exact"),
        ("clifford roberts", "born clifford roberts springfield", "exact"),
        ("clifford roberts", "clifford j roberts of springfield", "partial"),
    ])
    def test_match_type_selection(self, matcher, identifier, candidate, expected_type):
        """The correct match strategy is selected for each scenario."""
        results = matcher.match(candidate, {"name": identifier})
        assert len(results) >= 1
        assert results[0].match_type == expected_type
