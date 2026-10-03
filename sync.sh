#!/bin/bash
cd "$(dirname "$0")" || exit 1
git add .
git diff --cached --quiet && { echo "Aucune modification"; exit 0; }
git commit -m "${1:-mise a jour}"
git push
echo "Synchronisation terminee"
