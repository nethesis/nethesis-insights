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
const RulesVersion = "r5"

// Rules is rules.md verbatim.
//
//go:embed rules.md
var Rules string

const rulesSHA256 = "f2510a41f9e375086ea71306b7933db48470339036df13aef5ac29c261884478"
