#!/bin/sh
# Sucht in allen Dateien, die ins Repository gehören, nach Dingen, die nicht öffentlich werden sollen. Allgemeine
# Muster stehen hier; eigene (Hostnamen, Domains, Adressen, Mail) als Perl-Regex je Zeile in private/leak-patterns.txt
# oder in der Variable LEAK_PATTERNS (in GitHub Actions ein Secret), damit die Liste selbst nichts verrät.
set -eu
cd "$(dirname "$0")/.."

generic='-----BEGIN [A-Z ]*PRIVATE KEY-----
\bgh[pousr]_[A-Za-z0-9]{36}\b
\bglpat-[A-Za-z0-9_-]{20}\b
\bsk-ant-api[0-9]{2}-[A-Za-z0-9_-]{80,}
/home/(?!user/|lablantern/)[a-z][a-z0-9_-]*/'
own=$( { [ -f private/leak-patterns.txt ] && grep -v '^#' private/leak-patterns.txt; printf '%s\n' "${LEAK_PATTERNS:-}"; } \
    | sed '/^[[:space:]]*$/d')
[ -n "$own" ] || echo "note: no own patterns (private/leak-patterns.txt or LEAK_PATTERNS), generic checks only" >&2

regex=$(printf '%s\n%s\n' "$generic" "$own" | sed '/^$/d' | paste -sd'|' -)
files=$(git ls-files -co --exclude-standard | grep -v '^scripts/check-leaks.sh$' | grep -v 'package-lock.json$' | grep -v 'go.sum$')
# In CI nur Datei und Zeile: das Log eines öffentlichen Repos ist selbst öffentlich, der Fund darf nicht hinein
show() { if [ -n "${CI:-}" ]; then cut -d: -f1,2; else cat; fi; }
if echo "$files" | tr '\n' '\0' | xargs -0 grep -nIP -- "$regex" 2>/dev/null | show | grep .; then
    echo "Leak check failed: the lines above must not be published." >&2
    exit 1
fi
echo "Leak check passed ($(echo "$files" | wc -l) files)."
