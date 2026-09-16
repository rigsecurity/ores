# rig-ores

Python client for [ORES](https://github.com/rigsecurity/ores)'s **V0** risk score:
a severity-count model for identities/assets, ported from rig-security/ml-services'
`rice/risk_score/risk_score.py`. It runs entirely locally — no `oresd` daemon or
network call required — so it's suited to notebooks and batch analysis as well as
services.

Given an identity's finding counts by severity (critical / high / medium / low),
it returns a 0–10 score capped by the identity's most severe tier, plus the named
contributions ("factors") that produced it.

## Install

Not yet published to PyPI (see below). Until then, install directly from the repo:

```bash
# editable install from a local clone
pip install -e /path/to/ores/clients/python

# or straight from GitHub, no clone needed
pip install "git+https://github.com/rigsecurity/ores.git#subdirectory=clients/python"
```

## Usage

### Single identity

```python
from rig_ores import score_identity

result = score_identity("cluster-123", critical=1, high=2)

result.score     # 9.42
result.capped    # False
result.factors   # [Factor(feature="primary", tier="critical", contribution=9.0, reasoning="..."), ...]

print(result.explain())
# Score: 9.42 (critical)
#   +9.00  1 critical finding (highest-severity present)
#   +0.35  1 high finding (next tier down)
#   +0.07  1 further high finding(s), diminishing weight
```

`explain()` only lists non-zero contributions, ranked highest first — see
[Examples](#examples) below for the full range of shapes it can take.

### Batch

`score_batch` takes any iterable of mappings with `id`, `critical`, `high`,
`medium`, `low` keys (case-insensitive; missing severities default to 0) — a list
of dicts, or a pandas DataFrame via `df.to_dict("records")`:

```python
from rig_ores import score_batch

rows = [
    {"id": "cluster-123", "critical": 1, "high": 2, "medium": 0, "low": 0},
    {"id": "cluster-456", "critical": 0, "high": 0, "medium": 3, "low": 1},
]

for result in score_batch(rows):
    print(result.id, result.score, result.explain())

# from a DataFrame
# score_batch(findings_df.to_dict("records"))
```

## Examples

24 finding-count combinations chosen to exercise every named contribution
(`primary`, `same_secondary`, `lower_secondary`, `same_tier_rest`,
`cross_tier_rest`) and both non-capped and capped scores, computed with the
default weights:

| Scenario | critical | high | medium | low | Score | Capped | Features exercised |
|---|---:|---:|---:|---:|---:|:---:|---|
| No findings | 0 | 0 | 0 | 0 | 0.00 | no | — |
| Single critical | 1 | 0 | 0 | 0 | 9.00 | no | primary |
| Single high | 0 | 1 | 0 | 0 | 7.00 | no | primary |
| Single medium | 0 | 0 | 1 | 0 | 4.00 | no | primary |
| Single low | 0 | 0 | 0 | 1 | 2.00 | no | primary |
| Same secondary: 2 criticals | 2 | 0 | 0 | 0 | 9.70 | no | primary, same_secondary |
| Same secondary: 2 highs | 0 | 2 | 0 | 0 | 8.05 | no | primary, same_secondary |
| Same secondary: 2 mediums | 0 | 0 | 2 | 0 | 5.75 | no | primary, same_secondary |
| Same secondary: 2 lows | 0 | 0 | 0 | 2 | 2.96 | no | primary, same_secondary |
| Lower secondary: critical + high | 1 | 1 | 0 | 0 | 9.35 | no | primary, lower_secondary |
| Lower secondary: critical + medium | 1 | 0 | 1 | 0 | 9.25 | no | primary, lower_secondary |
| Lower secondary: critical + low | 1 | 0 | 0 | 1 | 9.15 | no | primary, lower_secondary |
| Lower secondary: high + medium | 0 | 1 | 1 | 0 | 7.25 | no | primary, lower_secondary |
| Lower secondary: high + low | 0 | 1 | 0 | 1 | 7.15 | no | primary, lower_secondary |
| Lower secondary: medium + low | 0 | 0 | 1 | 1 | 4.15 | no | primary, lower_secondary |
| Same-tier decay: 4 criticals | 4 | 0 | 0 | 0 | 9.99 | no | primary, same_secondary, same_tier_rest |
| Same-tier decay: 5 mediums | 0 | 0 | 5 | 0 | 6.50 | yes | primary, same_secondary, same_tier_rest |
| Cross-tier decay: critical + 3 highs | 1 | 3 | 0 | 0 | 9.46 | no | primary, lower_secondary, cross_tier_rest |
| Cross-tier decay: critical, 2 medium, 1 low | 1 | 0 | 2 | 1 | 9.33 | no | primary, lower_secondary, cross_tier_rest |
| Full mix, primary = critical ×2 | 2 | 1 | 1 | 1 | 9.81 | no | primary, same_secondary, cross_tier_rest |
| Capped: 50 criticals | 50 | 0 | 0 | 0 | 10.00 | yes | primary, same_secondary, same_tier_rest |
| Capped: 20 mediums | 0 | 0 | 20 | 0 | 6.50 | yes | primary, same_secondary, same_tier_rest |
| Just under the cap: 20 lows | 0 | 0 | 0 | 20 | 3.50 | no | primary, same_secondary, same_tier_rest |
| Realistic mixed cluster | 3 | 5 | 10 | 2 | 9.97 | no | primary, same_secondary, same_tier_rest, cross_tier_rest |

A couple of these in full, via `.explain()`:

```
score_identity("x", critical=1, high=3)
# Score: 9.46 (critical)
#   +9.00  1 critical finding (highest-severity present)
#   +0.35  1 high finding (next tier down)
#   +0.11  2 further high finding(s), diminishing weight
```

```
score_identity("x", critical=0, high=0, medium=20, low=0)
# Score: 6.50 (medium)
#   +4.00  1 medium finding (highest-severity present)
#   +1.75  a second medium finding
#   +0.99  18 further medium finding(s), diminishing weight
```

Note the "just under the cap" row: with enough low-tier findings the decaying
`same_tier_rest` bonus asymptotically approaches — but by design of the decay
formula never quite reaches — the tier's ceiling.

## Configuring the weights

The weights, per-tier ceilings, and decay rate live in
[`src/rig_ores/data/v0_weights.json`](src/rig_ores/data/v0_weights.json) and are
loaded once as `DEFAULT_SPEC`. To score against a different set of weights
(e.g. while tuning), load your own spec file and pass it explicitly — nothing
in the package needs to change:

```python
from rig_ores import load_spec, score_identity

spec = load_spec("my_weights.json")
result = score_identity("cluster-123", critical=1, spec=spec)
```

A weights file must have the same shape as `v0_weights.json`: `tiers` (4 names),
`weights` (5x4 matrix, rows ordered `primary`, `same_secondary`,
`lower_secondary`, `same_tier_rest`, `cross_tier_rest`), `ceilings` (4 values),
and `decay_rate`.

## Publishing to PyPI

Publishing is automated via [`.github/workflows/publish-python.yml`](../../.github/workflows/publish-python.yml):
pushing a tag matching `rig-ores-v*` builds the package and publishes it to
PyPI using [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC — no stored API token).

One manual, one-time step is required before the first publish: a PyPI account
holder (maintainer: liad@rig.security) must create the `rig-ores` project on
PyPI and register this repo/workflow as a trusted publisher under
*Publishing* settings, pointing at:

- Repository: `rigsecurity/ores`
- Workflow: `publish-python.yml`
- Environment: (none)

Maintainers: liad@rig.security, hila@rig.security.
