#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  deploy.sh — Build, push and deploy the Lambda container
#
#  Usage:
#    ./deploy.sh                   full deploy (terraform + docker)
#    ./deploy.sh --image-only      rebuild image only (needs ECR URL)
#    ./deploy.sh --image-only --tag v1.2.3   deploy with specific tag
# ─────────────────────────────────────────────────────────────
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
ENV="${ENV:-prod}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')}"

# Parse flags
IMAGE_ONLY=false
for arg in "$@"; do
  case $arg in
    --image-only) IMAGE_ONLY=true ;;
    --tag=*)      IMAGE_TAG="${arg#*=}" ;;
  esac
done

echo ""
echo "═══════════════════════════════════════════"
echo "  Hotel PII Redaction — Deploy"
echo "  Region : $AWS_REGION  Env: $ENV  Tag: $IMAGE_TAG"
echo "═══════════════════════════════════════════"

# Reject 'latest' on first deploy — ECR is IMMUTABLE so a re-push of 'latest'
# will fail. Force the user to pin a real tag (git SHA or semver).
if [ "$IMAGE_TAG" = "latest" ]; then
  echo "ERROR: IMAGE_TAG='latest' is not allowed (ECR uses IMMUTABLE tags)."
  echo "  Either run inside a git repo (auto-uses short SHA) or pass --tag=v1.2.3"
  exit 1
fi

LAMBDA_NAME="hotel-pii-redaction-${ENV}"

# ─────────────────────────────────────────────────────────────
# Step 1: Bootstrap — create ECR + KMS first, BEFORE building image
# (Lambda resource depends on the image existing in ECR)
# ─────────────────────────────────────────────────────────────
if [ "$IMAGE_ONLY" = false ]; then
  echo "▶ Terraform init..."
  cd terraform
  terraform init -upgrade -reconfigure

  echo "▶ Bootstrap: creating ECR + KMS first..."
  terraform apply -auto-approve \
    -target=aws_kms_key.main \
    -target=aws_kms_alias.main \
    -target=aws_ecr_repository.lambda_repo \
    -target=aws_ecr_lifecycle_policy.lambda_repo \
    -var="aws_region=$AWS_REGION" \
    -var="environment=$ENV" \
    -var="image_tag=$IMAGE_TAG"
  cd ..
  echo "✓ Bootstrap done"
fi

# Step 2: Get ECR URL (from terraform output or env)
if [ -n "${ECR_URL:-}" ]; then
  echo "  Using ECR_URL from env: $ECR_URL"
else
  ECR_URL=$(cd terraform && terraform output -raw ecr_repo_url 2>/dev/null || true)
  if [ -z "$ECR_URL" ]; then
    echo "ERROR: Could not read ecr_repo_url from terraform state."
    echo "  Set ECR_URL env var or run a full deploy first."
    exit 1
  fi
fi

# Step 3: Docker auth to ECR
echo "▶ Authenticating to ECR..."
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_URL"

# Step 4: Build image (linux/amd64 for Lambda)
echo "▶ Building Docker image (tag: $IMAGE_TAG)..."
docker build \
  --platform linux/amd64 \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --build-arg IMAGE_TAG="$IMAGE_TAG" \
  -t "hotel-pii-redaction:$IMAGE_TAG" \
  lambda_function/

# Step 5: Tag + push (must happen BEFORE the Lambda resource is created)
echo "▶ Pushing to ECR..."
docker tag  "hotel-pii-redaction:$IMAGE_TAG" "${ECR_URL}:${IMAGE_TAG}"
docker push "${ECR_URL}:${IMAGE_TAG}"
echo "✓ Image pushed: ${ECR_URL}:${IMAGE_TAG}"

# Step 6: Full Terraform apply — now the Lambda image exists in ECR
if [ "$IMAGE_ONLY" = false ]; then
  echo "▶ Terraform apply (full)..."
  cd terraform
  terraform apply -auto-approve \
    -var="aws_region=$AWS_REGION" \
    -var="environment=$ENV" \
    -var="image_tag=$IMAGE_TAG"
  cd ..
  echo "✓ Terraform done"
fi

# Step 7: For --image-only path, update Lambda code directly
# (For full deploys, Terraform already set image_uri, but Lambda has
#  lifecycle.ignore_changes=[image_uri], so we always update via API.)
echo "▶ Updating Lambda image..."
aws lambda update-function-code \
  --function-name "$LAMBDA_NAME" \
  --image-uri "${ECR_URL}:${IMAGE_TAG}" \
  --region "$AWS_REGION" \
  --no-cli-pager

aws lambda wait function-updated \
  --function-name "$LAMBDA_NAME" \
  --region "$AWS_REGION"
echo "✓ Lambda updated"

# Step 7: Smoke test
echo "▶ Smoke test..."
INPUT_BUCKET=$(cd terraform && terraform output -raw input_bucket)
cat > /tmp/pii_smoke_test.txt << 'EOF'
01: Checking in? Yes, reservation for Priya Sharma.
02: Room 224. Phone 732-423-8389. Email priya@example.com
03: Last name? Brayden. K-I-M-M-E-Y. Card ending in 7756.
EOF

aws s3 cp /tmp/pii_smoke_test.txt "s3://${INPUT_BUCKET}/smoke_test_$(date +%s).txt"
echo "  Uploaded smoke test — check output bucket in ~30s"

echo ""
echo "═══════════════════════════════════════════"
echo "  ✓ Deploy complete!  Tag: $IMAGE_TAG"
echo ""
OUTPUT_BUCKET=$(cd terraform && terraform output -raw output_bucket)
TOKEN_BUCKET=$(cd terraform && terraform output -raw token_map_bucket)
DLQ_URL=$(cd terraform && terraform output -raw dlq_url)
echo "  Input    s3://${INPUT_BUCKET}"
echo "  Output   s3://${OUTPUT_BUCKET}"
echo "  Tokens   s3://${TOKEN_BUCKET}"
echo "  DLQ      ${DLQ_URL}"
echo "═══════════════════════════════════════════"
