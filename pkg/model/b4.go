package model

import (
	"errors"
	"math"
	"sort"
)

// B4Parameters holds the tunable constants for the B4 scoring algorithm.
type B4Parameters struct {
	DecayRate   float64 // exponential decay applied to each successive bonus finding
	ScaleFactor float64 // per-finding bonus multiplier before decay
	MaxAdd      float64 // ceiling on the total bonus from additional findings
	MaxAdjust   float64 // maximum absolute swing (±) from each adjustment axis
	BaseOffset  float64 // constant subtracted from the highest finding to form the base
}

// B4Params returns the production B4 parameters as specified in the research.
func B4Params() B4Parameters {
	return B4Parameters{
		DecayRate:   0.5,
		ScaleFactor: 0.15,
		MaxAdd:      2.0,
		MaxAdjust:   2.0,
		BaseOffset:  -0.5,
	}
}

// getB4 is a nil-safe map lookup with a default value.
func getB4(factors map[string]float64, key string, defaultVal float64) float64 {
	if factors == nil {
		return defaultVal
	}

	if v, ok := factors[key]; ok {
		return v
	}

	return defaultVal
}

// computeEnvironmentalAdjust returns the environmental context adjustment in (-MaxAdjust, +MaxAdjust].
// Missing factors default to 0.5 (neutral — no adjustment).
func computeEnvironmentalAdjust(factors map[string]float64, p B4Parameters) float64 {
	criticality := getB4(factors, "asset_criticality", 0.5)
	exposure := getB4(factors, "network_exposure", 0.5)
	sensitivity := getB4(factors, "data_sensitivity", 0.5)

	raw := (criticality*0.4 + exposure*0.3 + sensitivity*0.3 - 0.5) * 4.0

	return math.Max(-p.MaxAdjust, math.Min(p.MaxAdjust, raw))
}

// computeBlastRadiusAdjust returns the blast-radius adjustment in (-MaxAdjust, +MaxAdjust].
func computeBlastRadiusAdjust(factors map[string]float64, p B4Parameters) float64 {
	scope := getB4(factors, "blast_scope", 0.5)
	lateral := getB4(factors, "lateral_movement", 0.5)

	raw := (scope*0.5 + lateral*0.5 - 0.5) * 4.0

	return math.Max(-p.MaxAdjust, math.Min(p.MaxAdjust, raw))
}

// computeRemediationAdjust returns the remediation-burden adjustment in (-MaxAdjust, +MaxAdjust].
func computeRemediationAdjust(factors map[string]float64, p B4Parameters) float64 {
	avail := getB4(factors, "remediation_available", 0.5)
	staleness := getB4(factors, "patch_staleness", 0.5)
	regSeverity := getB4(factors, "regulatory_severity", 0.5)
	compScope := getB4(factors, "compliance_scope", 0.5)

	raw := (avail*0.3 + staleness*0.3 + regSeverity*0.2 + compScope*0.2 - 0.5) * 4.0

	return math.Max(-p.MaxAdjust, math.Min(p.MaxAdjust, raw))
}

// distributeContributions applies the largest-remainder method to convert a slice
// of float64 contributions (which may include negative values) into integers that
// sum exactly to targetScore.
func distributeContributions(floats []float64, targetScore int) []int {
	floors := make([]int, len(floats))
	remainders := make([]float64, len(floats))
	floorSum := 0

	for i, f := range floats {
		floors[i] = int(math.Floor(f))
		remainders[i] = f - math.Floor(f)
		floorSum += floors[i]
	}

	leftover := targetScore - floorSum

	// Build an index slice sorted by remainder descending (largest remainder first).
	indices := make([]int, len(floats))
	for i := range indices {
		indices[i] = i
	}

	sort.Slice(indices, func(a, b int) bool {
		return remainders[indices[a]] > remainders[indices[b]]
	})

	result := make([]int, len(floats))
	copy(result, floors)

	if leftover > 0 {
		for i := range leftover {
			if i < len(indices) {
				result[indices[i]]++
			}
		}
	} else if leftover < 0 {
		// Award negative corrections to entries with the smallest remainders.
		for i := range -leftover {
			idx := len(indices) - 1 - i
			if idx >= 0 {
				result[indices[idx]]--
			}
		}
	}

	return result
}

// ScoreB4 computes the B4 risk score anchored on the most critical finding.
// findings is a slice of 0–10 finding scores; factors is an optional map of
// named environmental context values in [0, 1]. Missing factors default to 0.5.
// Returns an error if findings is nil or empty.
func (m *Model) ScoreB4(findings []float64, factors map[string]float64) (*ScoreResult, error) {
	if len(findings) == 0 {
		return nil, errors.New("b4: at least one finding is required")
	}

	p := B4Params()

	// Step 1 — sort findings descending (copy to avoid mutating the caller's slice).
	sorted := make([]float64, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] > sorted[j] })

	maxFinding := sorted[0]

	// Step 2 — base anchored on the highest finding.
	base := maxFinding + p.BaseOffset

	// Step 3 — decaying bonus from additional findings, capped at MaxAdd.
	var rawBonus float64
	for i := 1; i < len(sorted); i++ {
		rawBonus += sorted[i] * math.Pow(p.DecayRate, float64(i-1)) * p.ScaleFactor
	}

	bonus := math.Min(rawBonus, p.MaxAdd)

	// Step 4 — three adjustment axes.
	envAdj := computeEnvironmentalAdjust(factors, p)
	brAdj := computeBlastRadiusAdjust(factors, p)
	remAdj := computeRemediationAdjust(factors, p)

	// Step 5 — aggregate raw score.
	rawScore := base + bonus + envAdj + brAdj + remAdj

	// Step 6 — clip: must not exceed the highest finding and must be ≥ 0.
	finalScore := math.Max(0, math.Min(rawScore, maxFinding))

	// Step 7 — scale to 0–100 integer (half-up rounding).
	score := int(math.Floor(finalScore*10 + 0.5))

	// Compute per-factor float contributions to the 0–100 score.
	// When raw is positive, scale each component proportionally so that they sum
	// to finalScore×10.  When raw ≤ 0 the final score is 0 and all contributions
	// are zero.
	var (
		baseFloat float64
		bonusFloat float64
		envFloat float64
		brFloat float64
		remFloat float64
	)

	if rawScore > 0 {
		scale := (finalScore * 10) / (rawScore * 10)
		baseFloat = base * 10 * scale
		bonusFloat = bonus * 10 * scale
		envFloat = envAdj * 10 * scale
		brFloat = brAdj * 10 * scale
		remFloat = remAdj * 10 * scale
	}

	contribs := distributeContributions(
		[]float64{baseFloat, bonusFloat, envFloat, brFloat, remFloat},
		score,
	)

	// Build factor RawScores normalized to [0, 1].
	//   base_finding:         maxFinding / 10
	//   additional_findings:  rawBonus / MaxAdd  (pre-cap ratio)
	//   env/br/rem:           (adjust + MaxAdjust) / (2 × MaxAdjust)
	result := &ScoreResult{
		Score: score,
		Factors: []FactorContribution{
			{
				Name:         "base_finding",
				RawScore:     maxFinding / 10.0,
				Weight:       0,
				Contribution: contribs[0],
			},
			{
				Name:         "additional_findings",
				RawScore:     math.Min(rawBonus/p.MaxAdd, 1.0),
				Weight:       0,
				Contribution: contribs[1],
			},
			{
				Name:         "environmental_adjust",
				RawScore:     (envAdj + p.MaxAdjust) / (2 * p.MaxAdjust),
				Weight:       0,
				Contribution: contribs[2],
			},
			{
				Name:         "blast_radius_adjust",
				RawScore:     (brAdj + p.MaxAdjust) / (2 * p.MaxAdjust),
				Weight:       0,
				Contribution: contribs[3],
			},
			{
				Name:         "remediation_adjust",
				RawScore:     (remAdj + p.MaxAdjust) / (2 * p.MaxAdjust),
				Weight:       0,
				Contribution: contribs[4],
			},
		},
	}

	return result, nil
}
