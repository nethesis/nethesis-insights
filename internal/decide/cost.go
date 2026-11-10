// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package decide

import "math"

// Prices are dollars per million tokens.
type Prices struct {
	InputPerMTok, CachedInputPerMTok, OutputPerMTok float64
}

// CostMicros is the call's cost in micro-dollars (dollars per million tokens
// times tokens). Same formula as analyzer.costUSD, without the flex halving.
func (p Prices) CostMicros(u Usage) int64 {
	in := float64(u.InputTokens - u.CachedTokens)
	return int64(math.Round(in*p.InputPerMTok +
		float64(u.CachedTokens)*p.CachedInputPerMTok +
		float64(u.OutputTokens)*p.OutputPerMTok))
}
