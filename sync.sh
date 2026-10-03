#!/bin/bash
cd "$(dirname "$0")" || exit 1
git add .
git diff --cached --quiet && { echo "Aucune modification"; exit 0; }
git commit -m "${1:-mise a jour}"
if git push; then
    echo "✅ Synchronisation Ok"
else
    echo "❌ Echec Push"
fi
