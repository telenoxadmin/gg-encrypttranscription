#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  download_model.sh
#  Downloads en_core_web_lg wheel to the lambda_function/
#  folder for use with METHOD B (local .whl install).
#
#  Run this ONCE on a machine with internet access,
#  then use: docker build --build-arg MODEL_METHOD=local .
# ─────────────────────────────────────────────────────────────
set -euo pipefail

MODEL_VERSION="${MODEL_VERSION:-3.8.0}"
MODEL_NAME="en_core_web_lg-${MODEL_VERSION}-py3-none-any.whl"
MODEL_URL="https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-${MODEL_VERSION}/${MODEL_NAME}"
DEST="lambda_function/${MODEL_NAME}"

echo "Downloading spaCy model: ${MODEL_NAME} (~750 MB)..."
echo "Source: ${MODEL_URL}"
echo "Destination: ${DEST}"
echo ""

curl -L --progress-bar -o "${DEST}" "${MODEL_URL}"

echo ""
echo "✓ Downloaded: ${DEST}"
echo "  Size: $(du -sh ${DEST} | cut -f1)"
echo ""
echo "Now build with:"
echo "  docker build --build-arg MODEL_METHOD=local lambda_function/"
