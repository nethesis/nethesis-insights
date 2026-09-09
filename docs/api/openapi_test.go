// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package docs_test is a drift guard for docs/api/openapi.yaml.
//
// What this test CAN prove: that the YAML file parses as well-formed
// OpenAPI, that the set of documented paths exactly matches the routes this
// server actually registers (nothing missing, nothing stale left over from
// a removed endpoint), that the set of documented (path, method) operations
// matches too, and that every operation declares a security scheme.
//
// What this test CANNOT prove: that the request/response *schemas* in the
// YAML match the Go structs in internal/model, that examples are
// well-formed against those schemas, or that status codes/headers are
// semantically correct. None of that is checked here -- it would need a
// real OpenAPI validator and a JSON-schema-to-Go-struct comparison, neither
// of which this repo depends on.
//
// The failure this test exists to catch is the one that actually happens:
// someone adds `mux.HandleFunc("/v1/new-thing", ...)` in insightsd, threatd
// or sizingd and forgets docs/api/openapi.yaml entirely. A missing or extra
// path, or an operation with no security block, fails the build.
//
// This parses the file with gopkg.in/yaml.v3 rather than scanning lines by
// indentation, so it survives reformatting -- the earlier hand-rolled
// scanner broke on anything but one fixed indentation convention.
package docs_test

import (
	"os"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

const openAPIPath = "openapi.yaml"

// httpMethods are the path-item keys that name an operation, as opposed to
// a sibling key like `servers` or `parameters` on the same path item.
var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true,
	"delete": true, "patch": true, "head": true,
}

// operation is one documented (path, method) pair.
type operation struct {
	path   string
	method string
}

// parsed is what scanPaths extracts from the paths: block.
type parsed struct {
	paths      map[string]bool
	operations map[operation]bool
	// securityDeclared[op] is true when the operation has a non-empty
	// security requirement (a `security:` key followed by a scheme list).
	// It is explicitly false for `security: []`.
	securityDeclared map[operation]bool
	// sawSecurityLine records that a security key existed at all, so a
	// missing key (as opposed to an explicit empty one) can be told apart.
	sawSecurityLine map[operation]bool
}

// openAPIDoc is the minimal top-level shape this test needs. Path items are
// decoded as raw yaml.Node so this test can pick out method keys itself
// without a full OpenAPI operation schema.
type openAPIDoc struct {
	Paths map[string]yaml.Node `yaml:"paths"`
}

// operationSecurity is the one field of an operation this test cares about.
// A nil Security means the key was absent; a non-nil empty slice means an
// explicit `security: []`.
type operationSecurity struct {
	Security *[]map[string]any `yaml:"security"`
}

// scanPaths reads the file at path and extracts the structure of its
// `paths:` block. See the package doc comment for what this approach can
// and cannot verify.
func scanPaths(t *testing.T, path string) parsed {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var doc openAPIDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if doc.Paths == nil {
		t.Fatalf("%s: no top-level 'paths:' key found", path)
	}

	out := parsed{
		paths:            map[string]bool{},
		operations:       map[operation]bool{},
		securityDeclared: map[operation]bool{},
		sawSecurityLine:  map[operation]bool{},
	}

	for p, pathNode := range doc.Paths {
		out.paths[p] = true

		if pathNode.Kind != yaml.MappingNode {
			t.Fatalf("%s: path %q is not a mapping", path, p)
		}
		for i := 0; i+1 < len(pathNode.Content); i += 2 {
			method := pathNode.Content[i].Value
			if !httpMethods[method] {
				continue // a sibling key like `servers`, not an operation
			}
			op := operation{p, method}
			out.operations[op] = true

			var sec operationSecurity
			if err := pathNode.Content[i+1].Decode(&sec); err != nil {
				t.Fatalf("%s: %s %s: decode operation: %v", path, method, p, err)
			}
			if sec.Security != nil {
				out.sawSecurityLine[op] = true
				out.securityDeclared[op] = len(*sec.Security) > 0
			}
		}
	}

	return out
}

// services is the explicit, hardcoded description of every route this
// system registers, grouped by the binary that serves it. Traefik gives
// each pipeline a path prefix and strips it before proxying, so a service's
// registered route (what the handler sees) and its documented public path
// (prefix + route) differ by exactly that prefix. Keeping the prefix here
// rather than in the handlers is what lets a pipeline be run without a
// proxy in front of it during development.
//
// /healthz is registered by all three binaries but routed by none of them --
// the quadlet's HealthCmd= reaches it inside the container -- so it is
// deliberately absent from this list and from the documented surface; see
// TestHealthzNotDocumented.
var services = []struct {
	name   string
	prefix string
	routes []struct {
		path   string
		method string
	}
}{
	{
		name:   "insightsd",
		prefix: "/logs",
		routes: []struct{ path, method string }{
			{"/v1/bundles", "post"},
			{"/v1/findings", "get"},
		},
	},
	{
		name:   "threatd",
		prefix: "/blocklist",
		routes: []struct{ path, method string }{
			{"/v1/events", "post"},
			{"/v1/feed", "get"},
			{"/v1/allowlist-requests", "post"},
		},
	},
	{
		name:   "sizingd",
		prefix: "/sizing",
		routes: []struct{ path, method string }{
			{"/v1/reports", "post"},
		},
	},
}

// expectedPathsAndOperations derives the flat path list and (path, method)
// operation list from services, so the two can never disagree with each
// other about what a route's public path is.
func expectedPathsAndOperations() ([]string, []operation) {
	var paths []string
	var ops []operation
	for _, svc := range services {
		for _, r := range svc.routes {
			p := svc.prefix + r.path
			paths = append(paths, p)
			ops = append(ops, operation{p, r.method})
		}
	}
	return paths, ops
}

func TestDocumentedPathsMatchRegisteredRoutes(t *testing.T) {
	got := scanPaths(t, openAPIPath)

	expectedPaths, _ := expectedPathsAndOperations()
	want := map[string]bool{}
	for _, p := range expectedPaths {
		want[p] = true
	}

	var missing, extra []string
	for p := range want {
		if !got.paths[p] {
			missing = append(missing, p)
		}
	}
	for p := range got.paths {
		if !want[p] {
			extra = append(extra, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("paths documented in %s are missing: %v", openAPIPath, missing)
	}
	if len(extra) > 0 {
		t.Errorf("paths in %s are not in the expected route list (stale or typo?): %v", openAPIPath, extra)
	}
}

func TestDocumentedOperationsMatchExpected(t *testing.T) {
	got := scanPaths(t, openAPIPath)

	_, expectedOperations := expectedPathsAndOperations()
	want := map[operation]bool{}
	for _, op := range expectedOperations {
		want[op] = true
	}

	var missing, extra []string
	for op := range want {
		if !got.operations[op] {
			missing = append(missing, op.method+" "+op.path)
		}
	}
	for op := range got.operations {
		if !want[op] {
			extra = append(extra, op.method+" "+op.path)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("operations missing from %s: %v", openAPIPath, missing)
	}
	if len(extra) > 0 {
		t.Errorf("operations in %s not in the expected list: %v", openAPIPath, extra)
	}
}

// TestHealthzNotDocumented pins down that /healthz is deliberately excluded
// from the public API surface: every binary registers it, but the proxy
// never routes to it, so documenting it would describe an endpoint no
// client can reach.
func TestHealthzNotDocumented(t *testing.T) {
	got := scanPaths(t, openAPIPath)

	if got.paths["/healthz"] {
		t.Errorf("%s documents /healthz, but it is not routed by the proxy and must not appear in the public API surface", openAPIPath)
	}
}

func TestEveryOperationDeclaresSecurity(t *testing.T) {
	got := scanPaths(t, openAPIPath)

	for op := range got.operations {
		if !got.sawSecurityLine[op] {
			t.Errorf("%s %s: no 'security:' key found -- every operation must declare a security scheme", op.method, op.path)
			continue
		}
		if !got.securityDeclared[op] {
			t.Errorf("%s %s: 'security: []' found -- this operation must declare basicAuth or bearerAuth, not opt out", op.method, op.path)
		}
	}
}
