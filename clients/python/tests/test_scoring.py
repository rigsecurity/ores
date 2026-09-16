from rig_ores import WeightsSpec, score_batch, score_identity


def test_no_findings_scores_zero() -> None:
    result = score_identity("id-1")
    assert result.score == 0.0
    assert result.factors == []


def test_single_critical_finding() -> None:
    result = score_identity("id-1", critical=1)
    assert result.score == 9.0
    assert result.factors[0].feature == "primary"
    assert result.factors[0].tier == "critical"


def test_score_caps_at_primary_tier_ceiling() -> None:
    result = score_identity("id-1", critical=50)
    assert result.score == 10.0
    assert result.capped is True


def test_custom_spec_overrides_default_weights() -> None:
    custom_spec = WeightsSpec(
        tiers=("critical", "high", "medium", "low"),
        weights=[[5, 5, 5, 5], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]],
        ceilings=[10.0, 10.0, 10.0, 10.0],
        decay_rate=0.5,
    )
    result = score_identity("id-1", critical=1, spec=custom_spec)
    assert result.score == 5.0


def test_explain_lists_only_nonzero_contributions_highest_first() -> None:
    result = score_identity("id-1", critical=1, high=2)
    lines = result.explain().splitlines()
    assert lines[0] == "Score: 9.42 (critical)"
    assert len(lines) == 1 + len(result.factors)
    assert lines[1].startswith("  +9.00")


def test_explain_with_no_findings() -> None:
    result = score_identity("id-1")
    assert result.explain() == "Score: 0.00 (no findings)"


def test_batch_preserves_id_and_order() -> None:
    results = score_batch(
        [
            {"id": "id-1", "critical": 1, "high": 0, "medium": 0, "low": 0},
            {"id": "id-2", "critical": 0, "high": 0, "medium": 3, "low": 0},
        ]
    )
    assert [r.id for r in results] == ["id-1", "id-2"]
    assert results[0].score == 9.0
