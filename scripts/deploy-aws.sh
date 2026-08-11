#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-json}"
EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_AWS_ACCOUNT_ID:-171058045575}"
STACK_NAME="${STACK_NAME:-vulnscope-prod}"
DOMAIN_NAME="${DOMAIN_NAME:-vulnscope.jsontechnology.com}"
ROOT_DOMAIN="${ROOT_DOMAIN:-jsontechnology.com}"
NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL:-}"
MONITORED_CVES="${MONITORED_CVES:-}"
MONITOR_SCHEDULE="${MONITOR_SCHEDULE:-rate(1 day)}"
LAMBDA_ARTIFACT_PATH="${LAMBDA_ARTIFACT_PATH:-}"
LAMBDA_ARTIFACT_SHA256="${LAMBDA_ARTIFACT_SHA256:-}"
ALLOW_LOCAL_UNSIGNED_BUILD="${ALLOW_LOCAL_UNSIGNED_BUILD:-0}"
BUILD_DIR=".deploy/lambda"
export AWS_PROFILE

if [[ "${REGION}" != "us-east-1" ]]; then
  echo "VulnScope CloudFront ACM certificates must be deployed from us-east-1." >&2
  exit 1
fi

rm -rf ".deploy"
mkdir -p "${BUILD_DIR}"
if [[ -n "${LAMBDA_ARTIFACT_PATH}" ]]; then
  if [[ -z "${LAMBDA_ARTIFACT_SHA256}" ]]; then
    echo "LAMBDA_ARTIFACT_SHA256 is required with LAMBDA_ARTIFACT_PATH." >&2
    exit 1
  fi
  ACTUAL_ARTIFACT_SHA256="$(shasum -a 256 "${LAMBDA_ARTIFACT_PATH}" | awk '{print $1}')"
  if [[ "${ACTUAL_ARTIFACT_SHA256}" != "${LAMBDA_ARTIFACT_SHA256}" ]]; then
    echo "Lambda artifact checksum mismatch." >&2
    exit 1
  fi
  gh attestation verify "${LAMBDA_ARTIFACT_PATH}" \
    --repo jaysonguglietta/VulnScope \
    --signer-workflow jaysonguglietta/VulnScope/.github/workflows/release.yml \
    --deny-self-hosted-runners >/dev/null
  cp "${LAMBDA_ARTIFACT_PATH}" ".deploy/lambda.zip"
elif [[ "${ALLOW_LOCAL_UNSIGNED_BUILD}" == "1" ]]; then
  echo "WARNING: deploying an unsigned local build through the explicit break-glass path." >&2
  cp server.mjs lambda.mjs monitor.mjs package.json package-lock.json "${BUILD_DIR}/"
  (cd "${BUILD_DIR}" && npm ci --omit=dev --ignore-scripts >/dev/null)
  (cd "${BUILD_DIR}" && zip -qr "../lambda.zip" .)
else
  echo "Refusing an unsigned production build." >&2
  echo "Provide LAMBDA_ARTIFACT_PATH and LAMBDA_ARTIFACT_SHA256 from the GitHub release workflow." >&2
  echo "Set ALLOW_LOCAL_UNSIGNED_BUILD=1 only for an intentional emergency build." >&2
  exit 1
fi

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
if [[ "${ACCOUNT_ID}" != "${EXPECTED_AWS_ACCOUNT_ID}" ]]; then
  echo "Refusing to deploy to AWS account ${ACCOUNT_ID}; expected ${EXPECTED_AWS_ACCOUNT_ID}." >&2
  echo "Set EXPECTED_AWS_ACCOUNT_ID deliberately when deploying another account." >&2
  exit 1
fi

HOSTED_ZONE_ID="$(
  aws route53 list-hosted-zones-by-name \
    --dns-name "${ROOT_DOMAIN}." \
    --query "HostedZones[?Name=='${ROOT_DOMAIN}.' && Config.PrivateZone==\`false\`].Id | [0]" \
    --output text |
    sed 's#^/hostedzone/##'
)"

if [[ -z "${HOSTED_ZONE_ID}" || "${HOSTED_ZONE_ID}" == "None" ]]; then
  echo "Could not find public Route 53 hosted zone for ${ROOT_DOMAIN}." >&2
  exit 1
fi

DOMAIN_BUCKET_PART="$(echo "${DOMAIN_NAME}" | tr '[:upper:].' '[:lower:]-')"
ARTIFACT_BUCKET="${ARTIFACT_BUCKET:-vulnscope-artifacts-${ACCOUNT_ID}-${REGION}}"
STATIC_BUCKET="${STATIC_BUCKET:-${DOMAIN_BUCKET_PART}-${ACCOUNT_ID}}"
BUILD_ID="$(date -u +%Y%m%d%H%M%S)"
LAMBDA_CODE_KEY="lambda/vulnscope-${BUILD_ID}.zip"

echo "Deploying VulnScope"
echo "  profile: ${AWS_PROFILE}"
echo "  account: ${ACCOUNT_ID}"
echo "  region: ${REGION}"
echo "  domain: ${DOMAIN_NAME}"
echo "  hosted zone: ${HOSTED_ZONE_ID}"

if ! aws s3api head-bucket --bucket "${ARTIFACT_BUCKET}" >/dev/null 2>&1; then
  aws s3api create-bucket --bucket "${ARTIFACT_BUCKET}" --region "${REGION}" >/dev/null
  aws s3api put-public-access-block \
    --bucket "${ARTIFACT_BUCKET}" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null
fi

aws s3api put-bucket-encryption \
  --bucket "${ARTIFACT_BUCKET}" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' >/dev/null

aws s3 cp ".deploy/lambda.zip" "s3://${ARTIFACT_BUCKET}/${LAMBDA_CODE_KEY}" >/dev/null

aws cloudformation deploy \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --template-file "infra/vulnscope.yml" \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    DomainName="${DOMAIN_NAME}" \
    HostedZoneId="${HOSTED_ZONE_ID}" \
    StaticBucketName="${STATIC_BUCKET}" \
    LambdaCodeBucket="${ARTIFACT_BUCKET}" \
    LambdaCodeKey="${LAMBDA_CODE_KEY}" \
    NotificationEmail="${NOTIFICATION_EMAIL}" \
    MonitoredCves="${MONITORED_CVES}" \
    MonitorScheduleExpression="${MONITOR_SCHEDULE}"

OUTPUTS="$(
  aws cloudformation describe-stacks \
    --region "${REGION}" \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs" \
    --output json
)"

STATIC_BUCKET_OUT="$(node -e "const outputs = ${OUTPUTS}; console.log(outputs.find((item) => item.OutputKey === 'StaticBucketName')?.OutputValue || '')")"
DISTRIBUTION_ID="$(node -e "const outputs = ${OUTPUTS}; console.log(outputs.find((item) => item.OutputKey === 'DistributionId')?.OutputValue || '')")"
DISTRIBUTION_DOMAIN="$(node -e "const outputs = ${OUTPUTS}; console.log(outputs.find((item) => item.OutputKey === 'DistributionDomainName')?.OutputValue || '')")"
API_ENDPOINT="$(node -e "const outputs = ${OUTPUTS}; console.log(outputs.find((item) => item.OutputKey === 'ApiEndpoint')?.OutputValue || '')")"

if [[ -z "${STATIC_BUCKET_OUT}" || -z "${DISTRIBUTION_ID}" ]]; then
  echo "Stack outputs were incomplete." >&2
  echo "${OUTPUTS}" >&2
  exit 1
fi

aws s3 sync public "s3://${STATIC_BUCKET_OUT}" \
  --delete \
  --cache-control "public,max-age=60" >/dev/null

aws cloudfront create-invalidation \
  --distribution-id "${DISTRIBUTION_ID}" \
  --paths "/*" >/dev/null

echo "Deployment complete"
echo "  site: https://${DOMAIN_NAME}"
echo "  api: ${API_ENDPOINT}"
echo "  cloudfront: ${DISTRIBUTION_DOMAIN}"
echo "  distribution: ${DISTRIBUTION_ID}"
