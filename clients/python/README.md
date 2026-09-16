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
# editable install from a local clonehttps://github.com/rigsecurity/ores
pip install -e /path/to/ores/clients/python

# or straight from GitHub, no clone needed
pip install "git+https://github.com/rigsecurity/ores.git#subdirectory=clients/python"
```

## Usage

### Single identity

```python
from rig_ores import score_identity

result = score_identity("cluster-123", critical=1, high=2)

result.score     # 9.7
result.capped    # False
result.factors   # [Factor(feature="primary", tier="critical", contribution=9.0, reasoning="..."), ...]
```

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
    print(result.id, result.score)

# from a DataFrame
# score_batch(findings_df.to_dict("records"))
```

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
