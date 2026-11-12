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

const rulesSHA256 = "97f7f377dbffec4e186751836c02dc37fb7b2c7cf480b819563f2b100a910526"
