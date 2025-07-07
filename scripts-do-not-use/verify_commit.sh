#!/usr/bin/env bash
set -euo pipefail

repo="${1:-}"
if [[ -z "$repo" || ! -d "$repo/.git" ]]; then
    echo "Give the path to a git repo." >&2
    exit 1
fi

cd "$repo"

for commit in $(git rev-list --all); do
    if git cat-file -p "$commit" | grep -q "^gpgsig "; then
        output=$(git verify-commit "$commit" 2>&1)
        if echo "$output" | grep -q "Good signature"; then
            echo "$commit  VERIFIED"
        else
            echo "$commit  BAD_SIGNATURE"
        fi
    else
        echo "$commit  NOT_SIGNED"
    fi
done
