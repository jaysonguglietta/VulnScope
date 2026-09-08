#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-json}"
EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_AWS_ACCOUNT_ID:-171058045575}"
STACK_NAME="${STACK_NAME:-vulnscope-prod}"
ARTIFACT_STACK_NAME="${ARTIFACT_STACK_NAME:-vulnscope-artifacts}"
ARTIFACT_RETENTION_DAYS="${ARTIFACT_RETENTION_DAYS:-30}"
DOMAIN_NAME="${DOMAIN_NAME:-vulnscope.jsontechnology.com}"
ROOT_DOMAIN="${ROOT_DOMAIN:-jsontechnology.com}"
NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL:-}"
MONITORED_CVES="${MONITORED_CVES:-}"
MONITOR_SCHEDULE="${MONITOR_SCHEDULE:-rate(1 day)}"
DEPLOYMENT_BUNDLE_PATH="${DEPLOYMENT_BUNDLE_PATH:-}"
DEPLOYMENT_BUNDLE_SHA256="${DEPLOYMENT_BUNDLE_SHA256:-}"
RELEASE_SOURCE_SHA="${RELEASE_SOURCE_SHA:-}"
RELEASE_SOURCE_REF="${RELEASE_SOURCE_REF:-}"
ALLOW_LOCAL_UNSIGNED_BUILD="${ALLOW_LOCAL_UNSIGNED_BUILD:-0}"
ORIGIN_VERIFY_SECRET="${ORIGIN_VERIFY_SECRET:-$(openssl rand -hex 32)}"
export AWS_PROFILE

MONITORED_CVES="${MONITORED_CVES}" NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL}" node --input-type=module -e '
const ids = [...new Set(process.env.MONITORED_CVES.toUpperCase().split(/[\s,]+/).filter(Boolean))];
const email = process.env.NOTIFICATION_EMAIL;
if (ids.length > 25 || ids.some(id => !/^CVE-\d{4}-\d{4,}$/.test(id))) throw new Error("Select at most 25 valid monitored CVEs; no entries are silently omitted.");
if (email && (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) throw new Error("NOTIFICATION_EMAIL is invalid.");
'

if [[ "${REGION}" != "us-east-1" ]]; then
  echo "VulnScope CloudFront certificates require us-east-1." >&2
  exit 1
fi
if [[ "${ALLOW_LOCAL_UNSIGNED_BUILD}" == "1" && -z "${DEPLOYMENT_BUNDLE_PATH}" ]]; then
  echo "WARNING: explicit unsigned local deployment; no release provenance guarantee." >&2
  npm run build:release
  DEPLOYMENT_BUNDLE_PATH=".deploy/deployment.tar.gz"
  DEPLOYMENT_BUNDLE_SHA256="$(shasum -a 256 "${DEPLOYMENT_BUNDLE_PATH}" | awk '{print $1}')"
  RELEASE_SOURCE_SHA="$(git rev-parse HEAD)"
  RELEASE_SOURCE_REF="$(git symbolic-ref HEAD)"
else
  : "${DEPLOYMENT_BUNDLE_PATH:?A verified whole-deployment bundle is required}"
  : "${DEPLOYMENT_BUNDLE_SHA256:?The approved bundle checksum is required}"
  : "${RELEASE_SOURCE_SHA:?The approved source commit is required}"
  : "${RELEASE_SOURCE_REF:?The approved release ref is required}"
  if [[ ! "${RELEASE_SOURCE_SHA}" =~ ^[a-f0-9]{40}$ ]] || [[ ! "${RELEASE_SOURCE_REF}" =~ ^refs/(tags/v[^[:space:]]+|heads/main)$ ]]; then
    echo "Use a full source commit and an approved version tag or main ref." >&2
    exit 1
  fi
  gh attestation verify "${DEPLOYMENT_BUNDLE_PATH}" \
    --repo jaysonguglietta/VulnScope \
    --signer-workflow jaysonguglietta/VulnScope/.github/workflows/release.yml \
    --source-ref "${RELEASE_SOURCE_REF}" --source-digest "${RELEASE_SOURCE_SHA}" \
    --deny-self-hosted-runners >/dev/null
fi
ACTUAL_SHA="$(shasum -a 256 "${DEPLOYMENT_BUNDLE_PATH}" | awk '{print $1}')"
if [[ "${ACTUAL_SHA}" != "${DEPLOYMENT_BUNDLE_SHA256}" ]]; then
  echo "Deployment bundle checksum mismatch." >&2
  exit 1
fi
EXTRACT_DIR="$(mktemp -d)"
trap 'rm -rf "$EXTRACT_DIR"' EXIT
VERIFY_OPTIONS=()
if [[ "${ALLOW_LOCAL_UNSIGNED_BUILD}" == "1" ]]; then VERIFY_OPTIONS+=(--allow-dirty); fi
python3 scripts/verify-bundle.py "${DEPLOYMENT_BUNDLE_PATH}" "${EXTRACT_DIR}" "${RELEASE_SOURCE_SHA}" "${RELEASE_SOURCE_REF}" ${VERIFY_OPTIONS[@]+"${VERIFY_OPTIONS[@]}"}
RELEASE_DIR="${EXTRACT_DIR}/release"

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

aws cloudformation deploy \
  --region "${REGION}" \
  --stack-name "${ARTIFACT_STACK_NAME}" \
  --template-file "${RELEASE_DIR}/infra/vulnscope-artifacts.yml" \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    ArtifactBucketName="${ARTIFACT_BUCKET}" \
    ArtifactRetentionDays="${ARTIFACT_RETENTION_DAYS}"

aws s3 cp "${RELEASE_DIR}/lambda.zip" "s3://${ARTIFACT_BUCKET}/${LAMBDA_CODE_KEY}" >/dev/null

aws cloudformation deploy \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --template-file "${RELEASE_DIR}/infra/vulnscope.yml" \
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
    MonitorScheduleExpression="${MONITOR_SCHEDULE}" \
    ApiOriginSecret="${ORIGIN_VERIFY_SECRET}"

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

aws s3 sync "${RELEASE_DIR}/public" "s3://${STATIC_BUCKET_OUT}" \
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
