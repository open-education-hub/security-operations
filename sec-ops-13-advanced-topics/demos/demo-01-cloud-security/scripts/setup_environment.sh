#!/bin/bash
# Setup misconfigured cloud environment for demo
ENDPOINT="http://localstack:4566"

echo "[*] Creating IAM users..."
aws --endpoint-url=$ENDPOINT iam create-user --user-name service-account 2>/dev/null
aws --endpoint-url=$ENDPOINT iam create-user --user-name dev-user 2>/dev/null
aws --endpoint-url=$ENDPOINT iam create-user --user-name readonly-user 2>/dev/null

echo "[*] Attaching overprivileged policies..."
aws --endpoint-url=$ENDPOINT iam attach-user-policy \
  --user-name service-account \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws --endpoint-url=$ENDPOINT iam attach-user-policy \
  --user-name dev-user \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

aws --endpoint-url=$ENDPOINT iam attach-user-policy \
  --user-name readonly-user \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

echo "[*] Creating S3 buckets..."
aws --endpoint-url=$ENDPOINT s3 mb s3://company-data-backup
aws --endpoint-url=$ENDPOINT s3 mb s3://internal-configs
aws --endpoint-url=$ENDPOINT s3 mb s3://access-logs-private

echo "[*] Making bucket publicly accessible (misconfiguration)..."
aws --endpoint-url=$ENDPOINT s3api put-bucket-acl \
  --bucket company-data-backup \
  --acl public-read

echo "[*] Adding sample data..."
echo "CONFIDENTIAL: DB_PASS=Sup3rS3cr3t!" | \
  aws --endpoint-url=$ENDPOINT s3 cp - s3://company-data-backup/config.txt

echo "[*] CloudTrail NOT configured (intentional omission for demo)"
echo "[+] Demo environment ready."
