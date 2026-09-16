"""V0 severity-count risk scoring.

Ports the ORES weights matrix from rig-security/ml-services'
rice/risk_score/risk_score.py: one identity's Critical/High/Medium/Low finding
counts go in, a 0-10 score capped by the identity's most severe tier comes out,
along with the named contributions that produced it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path


@dataclass(frozen=True)
class WeightsSpec:
    tiers: tuple[str, ...]
    weights: list[list[float]]
    ceilings: list[float]
    decay_rate: float


def load_spec(path: str | Path) -> WeightsSpec:
    text = Path(path).read_text()
    spec = _spec_from_text(text)
    return spec


def _spec_from_text(text: str) -> WeightsSpec:
    raw = json.loads(text)
    spec = WeightsSpec(
        tiers=tuple(raw["tiers"]),
        weights=raw["weights"],
        ceilings=raw["ceilings"],
        decay_rate=raw["decay_rate"],
    )
    return spec


DEFAULT_SPEC = _spec_from_text(resources.files("rig_ores").joinpath("data/v0_weights.json").read_text())
TIERS = DEFAULT_SPEC.tiers


@dataclass(frozen=True)
class Factor:
    feature: str
    tier: str
    contribution: float
    reasoning: str


@dataclass(frozen=True)
class ScoreResult:
    id: str
    score: float
    capped: bool
    factors: list[Factor]

    def explain(self) -> str:
        score_display = f"{self.score:.2f}"
        if not self.factors:
            no_findings_explanation = f"Score: {score_display} (no findings)"
            return no_findings_explanation

        primary_tier = next(factor.tier for factor in self.factors if factor.feature == "primary")
        ranked_factors = sorted(self.factors, key=lambda factor: factor.contribution, reverse=True)
        lines = [f"Score: {score_display} ({primary_tier})"]
        lines += [f"  +{factor.contribution:.2f}  {factor.reasoning}" for factor in ranked_factors]
        explanation = "\n".join(lines)
        return explanation


def score_identity(
    id: str,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    spec: WeightsSpec = DEFAULT_SPEC,
) -> ScoreResult:
    result = _score(id, [critical, high, medium, low], spec)
    return result


def score_batch(rows: Iterable[Mapping[str, object]], spec: WeightsSpec = DEFAULT_SPEC) -> list[ScoreResult]:
    results = [_score_row(row, spec) for row in rows]
    return results


def _score_row(row: Mapping[str, object], spec: WeightsSpec) -> ScoreResult:
    normalized = {str(key).lower(): value for key, value in row.items()}
    result = score_identity(
        id=normalized["id"],
        critical=int(normalized.get("critical", 0)),
        high=int(normalized.get("high", 0)),
        medium=int(normalized.get("medium", 0)),
        low=int(normalized.get("low", 0)),
        spec=spec,
    )
    return result


def _score(id: str, counts: list[int], spec: WeightsSpec) -> ScoreResult:
    if sum(counts) == 0:
        empty_result = ScoreResult(id=id, score=0.0, capped=False, factors=[])
        return empty_result

    primary_col = next(index for index, count in enumerate(counts) if count > 0)
    primary_count = counts[primary_col]
    same_secondary = primary_count >= 2
    secondary_col = next((index for index in range(primary_col + 1, len(counts)) if counts[index] > 0), None)
    lower_secondary = primary_count == 1 and secondary_col is not None

    rest_counts = list(counts)
    rest_counts[primary_col] -= 1
    if same_secondary:
        rest_counts[primary_col] -= 1
    if lower_secondary:
        rest_counts[secondary_col] -= 1
    rest_counts = [max(count, 0) for count in rest_counts]

    contributions = _contributions(primary_col, same_secondary, secondary_col, lower_secondary, rest_counts, spec)
    raw_score = sum(value for _, _, value, _ in contributions)
    ceiling = spec.ceilings[primary_col]
    capped = raw_score > ceiling
    score = round(min(raw_score, ceiling), 2)
    factors = [
        Factor(feature=feature, tier=spec.tiers[tier], contribution=round(value, 4), reasoning=reasoning)
        for feature, tier, value, reasoning in contributions
        if value != 0
    ]

    result = ScoreResult(id=id, score=score, capped=capped, factors=factors)
    return result


def _contributions(
    primary_col: int,
    same_secondary: bool,
    secondary_col: int | None,
    lower_secondary: bool,
    rest_counts: list[int],
    spec: WeightsSpec,
) -> list[tuple[str, int, float, str]]:
    contributions: list[tuple[str, int, float, str]] = []

    primary_reasoning = f"1 {spec.tiers[primary_col]} finding (highest-severity present)"
    contributions.append(("primary", primary_col, spec.weights[0][primary_col], primary_reasoning))

    if same_secondary:
        same_secondary_reasoning = f"a second {spec.tiers[primary_col]} finding"
        contributions.append(("same_secondary", primary_col, spec.weights[1][primary_col], same_secondary_reasoning))

    if lower_secondary:
        lower_secondary_reasoning = f"1 {spec.tiers[secondary_col]} finding (next tier down)"
        contributions.append(
            ("lower_secondary", secondary_col, spec.weights[2][secondary_col], lower_secondary_reasoning)
        )

    start = 0
    for tier, rest in enumerate(rest_counts):
        if rest > 0:
            decay = (spec.decay_rate**start) * (1 - spec.decay_rate**rest)
            row = "same_tier_rest" if tier == primary_col else "cross_tier_rest"
            weight_row = 3 if row == "same_tier_rest" else 4
            reasoning = f"{rest} further {spec.tiers[tier]} finding(s), diminishing weight"
            contributions.append((row, tier, decay * spec.weights[weight_row][tier], reasoning))
        start += rest

    return contributions
