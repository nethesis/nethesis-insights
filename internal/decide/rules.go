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
const RulesVersion = "r7"

// Rules is rules.md verbatim.
//
//go:embed rules.md
var Rules string

const rulesSHA256 = "2f441a1fbe37f9fa4833d1312d18f43ad4c11f12589dc282ffc17e2c0dc84207"
