#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fails if any tracked source file is missing its Nethesis GPL header, or
# carries it in the wrong comment form for its file type.
#
# Header lines are checked for an *exact* match on the two lines CLAUDE.md's
# "Invariants" section mandates:
#
#   Copyright (C) 2026 Nethesis S.r.l.
#   SPDX-License-Identifier: GPL-3.0-or-later
#
# wrapped in the comment form for the file's type ("//" Go, "#" SQL/YAML/
# Makefile/shell, "<!-- ... -->" HTML templates, "/* ... */" CSS). This is
# stricter than grepping for the bare SPDX string: a header pasted in the
# wrong comment style (e.g. a "#"-prefixed line copied into a .go file) is a
# real defect -- it doesn't compile as a license notice for that language --
# and a loose grep would wave it through. It stops at exact-line matching
# rather than also enforcing the surrounding blank-comment decoration or the
# blank-line-after-header rule for Go: those are copy-paste details a
# reviewer catches on sight, not a privacy or licensing risk, and encoding
# them here would mean maintaining a second, more brittle parser for no
# safety gained.
#
# Two special cases, both load-bearing (see CLAUDE.md):
#
#  - internal/ui/chrome/static/ hosts vendored third-party files (today
#    Pico CSS's pico.min.css and pico.LICENSE). They must keep their
#    upstream notice byte-for-byte and must NEVER receive our header --
#    doing so would misattribute someone else's file. They are listed in
#    VENDORED_FILES below, are skipped by the "must have our header" pass,
#    and are instead checked for the opposite thing: that our SPDX line has
#    NOT been added to them. That guard is what stops a future "fix" from
#    slapping our header on someone else's file -- without it, exempting a
#    file here is indistinguishable from forgetting to check it at all.
#  - internal/ui/chrome/templates/layout.html carries the header outside any
#    {{define}} block, on purpose, so it ships in the HTML this server
#    actually serves. It gets no special treatment below: it is an ordinary
#    .html file as far as this script is concerned, and the position check
#    (header near the top of the file) passes it the same way it passes
#    every other template.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

COPYRIGHT_TEXT='Copyright (C) 2026 Nethesis S.r.l.'
SPDX_TEXT='SPDX-License-Identifier: GPL-3.0-or-later'

# Files that carry no license header at all: prose, data files whose format
# has no comment syntax, files with a license of their own, and generated /
# fixture output that isn't source we wrote.
#   *.md            - documentation, not source
#   *.json          - no comment syntax; renovate.json is config, not code
#   *.golden        - golden test fixtures (internal/prompt), not source
#   go.mod, go.sum  - Go tooling manifests, not source
#   LICENSE         - is the license text itself
#   .gitignore, .dockerignore - ignore-pattern lists, not source
EXEMPT_BASENAMES=(go.mod go.sum LICENSE .gitignore .dockerignore)

# Vendored third-party files: must NEVER carry our header (see comment
# block above). Add a file here only when it is genuinely someone else's,
# unmodified, with its own upstream notice already in place.
VENDORED_FILES=(
    internal/ui/chrome/static/pico.min.css
    internal/ui/chrome/static/pico.LICENSE
)

is_in() {
    local needle="$1"; shift
    local x
    for x in "$@"; do
        [ "$x" = "$needle" ] && return 0
    done
    return 1
}

missing=0
malformed=0
misattributed=0

while IFS= read -r f; do
    base=$(basename "$f")
    ext="${f##*.}"

    if [ "$ext" = "$f" ]; then
        ext=""
    fi

    if is_in "$base" "${EXEMPT_BASENAMES[@]}" || [ "$ext" = "md" ] || [ "$ext" = "json" ] || [ "$ext" = "golden" ]; then
        continue
    fi

    if is_in "$f" "${VENDORED_FILES[@]}"; then
        if grep -q "$SPDX_TEXT" "$f" 2>/dev/null; then
            echo "misattributed header: $f is vendored (upstream MIT notice) and must never carry our SPDX line" >&2
            misattributed=1
        fi
        continue
    fi

    # Pick the comment form for this file's type. CLAUDE.md: "//" for Go,
    # "#" for SQL/YAML/Makefile/shell, "<!-- ... -->" for HTML templates,
    # "/* ... */" for CSS.
    case "$base" in
        Makefile|Containerfile)
            style=hash ;;
        *)
            case "$ext" in
                go) style=slashslash ;;
                sh|yml|yaml|sql|conf|tmpl|container|volume|pod) style=hash ;;
                html) style=htmlblock ;;
                css) style=cssblock ;;
                *)
                    echo "unrecognized file type, add $f to check-license-headers.sh's exemption or comment-style list: $f" >&2
                    missing=1
                    continue
                    ;;
            esac
            ;;
    esac

    # First 20 lines is enough for a shebang plus a header block; trailing
    # whitespace is trimmed so an editor's stray space doesn't false-fail.
    window=$(head -n 20 "$f" | sed 's/[[:space:]]*$//')

    case "$style" in
        slashslash)
            want_copyright="// $COPYRIGHT_TEXT"
            want_spdx="// $SPDX_TEXT"
            ;;
        hash)
            want_copyright="# $COPYRIGHT_TEXT"
            want_spdx="# $SPDX_TEXT"
            ;;
        htmlblock|cssblock)
            want_copyright="$COPYRIGHT_TEXT"
            want_spdx="$SPDX_TEXT"
            ;;
    esac

    has_copyright=0
    has_spdx=0
    printf '%s\n' "$window" | grep -qxF "$want_copyright" && has_copyright=1
    printf '%s\n' "$window" | grep -qxF "$want_spdx" && has_spdx=1

    if [ "$has_copyright" -eq 1 ] && [ "$has_spdx" -eq 1 ]; then
        if [ "$style" = "slashslash" ]; then
            # "above the package clause": the header must precede it.
            pkg_line=$(grep -n '^package ' "$f" | head -1 | cut -d: -f1)
            spdx_line=$(printf '%s\n' "$window" | grep -nxF "$want_spdx" | head -1 | cut -d: -f1)
            if [ -n "$pkg_line" ] && [ -n "$spdx_line" ] && [ "$spdx_line" -gt "$pkg_line" ]; then
                echo "header after package clause: $f" >&2
                malformed=1
            fi
        fi
        continue
    fi

    if grep -q "$SPDX_TEXT" "$f" 2>/dev/null; then
        echo "SPDX header in wrong comment style for a .$ext file (want '$want_spdx'): $f" >&2
        malformed=1
    else
        echo "missing SPDX header: $f" >&2
        missing=1
    fi
done < <(git ls-files)

if [ "$missing" -ne 0 ] || [ "$malformed" -ne 0 ] || [ "$misattributed" -ne 0 ]; then
    echo "license header check failed" >&2
    exit 1
fi

echo "license headers OK"
