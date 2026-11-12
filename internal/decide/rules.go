// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package decide is the pure half of the Decisions API handoff: the written
// review rules, the request body, the response parse and the cost formula.
// No I/O, no clock.
package decide

import _ "embed"

// RulesVersion stamps every stored decision with the rules text it was made
// under. Bump it by hand whenever rules.md changes; the test pins the file's
// hash so forgetting fails the build.
const RulesVersion = "r6"

// Rules is rules.md verbatim.
//
//go:embed rules.md
var Rules string

const rulesSHA256 = "8fadf12b1e18ce4729a1b5e1ee1abe8af581c951fba61930cee1e0c7df658c5f"
