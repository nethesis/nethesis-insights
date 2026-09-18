// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

import "sort"

// Node attribution: which machine of the reporting cluster a condition was
// seen on.
//
// A system_id is an NS8 *cluster*, not a machine. The collector runs once per
// cluster and reads Loki, which carries a node_id stream label on every
// record, so until now that dimension was aggregated away and a finding could
// only say "somewhere in this cluster". Template.Nodes and Bundle.Nodes carry
// it through.
//
// THE FQDN IS THE ONE PIECE OF CUSTOMER-IDENTIFYING TEXT THIS PIPELINE
// STORES, and it is a deliberate, narrow exception to a rule the rest of the
// code follows hard: both the collector's _mask_hostname and this package's
// replaceHostnames (canonical.go) collapse every hostname in a log line to
// <HOST>, precisely so customer names never reach the server or the model.
// That masking is unchanged. What is added is a single structured field,
// obtained from the cluster's own node roster rather than scraped out of log
// text, validated here against a shape no log line, URL or credential can
// satisfy, and -- see the rules below -- never shown to the LLM.
//
// Three rules hold this together, and none of them is visible from the
// handlers:
//
//  1. Nodes never reach the prompt. prompt.Select does carry them -- that is
//     how ResolveEvidence hands the analyzer a cited template's attribution
//     -- but prompt.Render never emits them, and the golden files are the
//     executable proof. A model that cannot see a node cannot author one.
//  2. Nodes are not part of a finding's identity. fingerprint.Compute does not
//     take them. The cited-template mix already moves between windows -- that
//     is what split one SSH condition into ~160 findings before v2 -- and a
//     node set moves at least as much. Attribution is what a finding *shows*,
//     never what it *is*.
//  3. Nodes are not a gate input, and novelty stays cluster-scoped. Keying
//     system_templates on the node would make every template on a newly added
//     node novel at once and re-fire the gate for the whole machine.
//
// A finding stores node *ids* only. The names are resolved at read time by
// joining the roster, so a renamed host reads correctly instead of leaving a
// stale copy frozen into every row that ever cited it.
const (
	// MaxRosterNodes caps Bundle.Nodes. NS8 clusters are far smaller than
	// this; the cap exists to bound a malformed or hostile bundle, not to
	// express a supported cluster size.
	MaxRosterNodes = 64

	// MaxNodesPerTemplate caps Template.Nodes. A template cannot be seen on
	// more nodes than the cluster has.
	MaxNodesPerTemplate = 64

	// MaxFQDNLen is the DNS limit on a fully qualified name.
	MaxFQDNLen = 253

	// maxLabelLen is the DNS limit on one dot-separated label.
	maxLabelLen = 63
)

// NodeInfo names one node of the reporting cluster. FQDN may be empty: the
// collector's roster lookup is allowed to fail without failing the run, and a
// name that does not survive SanitizeFQDN is dropped while its id is kept.
type NodeInfo struct {
	NodeID int    `json:"node_id"`
	FQDN   string `json:"fqdn,omitempty"`
}

// SanitizeFQDN returns s as a lowercase fully qualified domain name, or "" if
// it is not one.
//
// The charset is the entire control. A log line, a URL, a credential, a file
// path, a JSON fragment and a masked template all contain at least one byte
// outside [a-z0-9.-], so none of them can be smuggled through this field --
// which is a stronger guarantee than any list of forbidden substrings
// somebody has to keep current, and the same argument sizing.Sanitize makes
// for accepting only numbers.
//
// Requiring at least one letter is what stops a bare IP address: an address
// is not a name, it identifies a network interface rather than a machine, and
// the collector has a roster that gives real names.
func SanitizeFQDN(s string) string {
	// Trim ASCII space only. Anything else that looks like whitespace is a
	// control or multi-byte character, and the charset check below rejects
	// it rather than quietly accepting a name with an invisible byte in it.
	s = trimASCIISpace(s)
	// A trailing root dot is valid in DNS and means the same name. Normalise
	// it away so "a.example.org" and "a.example.org." are not two nodes.
	if len(s) > 1 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	if s == "" || len(s) > MaxFQDNLen {
		return ""
	}

	out := make([]byte, len(s))
	hasLetter := false
	labelLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
			hasLetter = true
		case c >= 'a' && c <= 'z':
			hasLetter = true
		case c >= '0' && c <= '9':
		case c == '-':
			// A label may not start or end with a hyphen.
			if labelLen == 0 || i == len(s)-1 || s[i+1] == '.' {
				return ""
			}
		case c == '.':
			// No empty label: neither a leading dot nor "..".
			if labelLen == 0 {
				return ""
			}
			labelLen = -1 // becomes 0 after the increment below
		default:
			// Control characters, spaces, '_', ':', '/', '@' and every
			// non-ASCII byte land here.
			return ""
		}
		out[i] = c
		labelLen++
		if labelLen > maxLabelLen {
			return ""
		}
	}
	if !hasLetter {
		return ""
	}
	return string(out)
}

func trimASCIISpace(s string) string {
	isSpace := func(c byte) bool {
		return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
	}
	for len(s) > 0 && isSpace(s[0]) {
		s = s[1:]
	}
	for len(s) > 0 && isSpace(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	return s
}

// SanitizeNodeIDs returns ids sorted, deduplicated, with anything below 1
// dropped and the result capped at MaxNodesPerTemplate. It returns nil rather
// than an empty slice when nothing survives, so a template without usable
// attribution marshals without the field.
//
// NS8 numbers nodes from 1, so 0 is the zero value of a missing field rather
// than a node, and treating it as one would invent a machine.
func SanitizeNodeIDs(ids []int) []int {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[int]bool, len(ids))
	out := make([]int, 0, len(ids))
	for _, id := range ids {
		if id < 1 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Ints(out)
	if len(out) > MaxNodesPerTemplate {
		out = out[:MaxNodesPerTemplate]
	}
	return out
}

// SanitizeRoster returns in sorted by node id, with ids below 1 dropped,
// duplicate ids collapsed to their first occurrence, every name passed
// through SanitizeFQDN, and the result capped at MaxRosterNodes.
//
// A name that fails validation is cleared while its id is kept. Dropping the
// whole entry would lose the attribution too, and the id alone is still an
// answer -- it just needs the customer's own cluster UI to read.
func SanitizeRoster(in []NodeInfo) []NodeInfo {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[int]bool, len(in))
	out := make([]NodeInfo, 0, len(in))
	for _, n := range in {
		if n.NodeID < 1 || seen[n.NodeID] {
			continue
		}
		seen[n.NodeID] = true
		out = append(out, NodeInfo{NodeID: n.NodeID, FQDN: SanitizeFQDN(n.FQDN)})
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	if len(out) > MaxRosterNodes {
		out = out[:MaxRosterNodes]
	}
	return out
}

// SanitizeNodes returns a copy of b with its roster and every template's node
// set validated. It is applied in the ingest handler, before the bundle is
// published to the queue, so nothing downstream -- the analyzer, the store,
// the UI -- ever handles an unvalidated name.
//
// It copies rather than editing in place: the bundle it is given is a decoded
// request body, and the handler still reads from that value after this call.
func (b Bundle) SanitizeNodes() Bundle {
	out := b
	out.Nodes = SanitizeRoster(b.Nodes)
	if len(b.Templates) > 0 {
		out.Templates = make([]Template, len(b.Templates))
		copy(out.Templates, b.Templates)
		for i := range out.Templates {
			out.Templates[i].Nodes = SanitizeNodeIDs(out.Templates[i].Nodes)
		}
	}
	return out
}

// MergeNodeIDs returns the sorted union of two node sets, capped like any
// other. The analyzer folds the cited templates' sets this way to get the set
// a finding is stored with.
func MergeNodeIDs(a, b []int) []int {
	if len(a) == 0 {
		return SanitizeNodeIDs(b)
	}
	if len(b) == 0 {
		return SanitizeNodeIDs(a)
	}
	return SanitizeNodeIDs(append(append(make([]int, 0, len(a)+len(b)), a...), b...))
}

// ResolveNodeRefs pairs node ids with the names a roster gives them.
//
// An id the roster does not know still produces a NodeRef, with an empty
// FQDN. Dropping it would be worse than showing a bare number: the number is
// the attribution, and the name is only a convenience on top of it.
func ResolveNodeRefs(ids []int, roster map[int]string) []NodeInfo {
	ids = SanitizeNodeIDs(ids)
	if len(ids) == 0 {
		return nil
	}
	out := make([]NodeInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, NodeInfo{NodeID: id, FQDN: roster[id]})
	}
	return out
}
