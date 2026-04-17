#!/usr/bin/env python3
"""
S3 Bucket Public Access Audit Script
Checks all S3 buckets for public ACLs.
"""
import boto3

ENDPOINT = "http://localstack:4566"

session = boto3.Session(
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name="eu-west-1"
)
s3 = session.client("s3", endpoint_url=ENDPOINT)

print("=" * 60)
print("S3 Bucket Public Access Audit")
print("=" * 60)

buckets = s3.list_buckets().get("Buckets", [])
for bucket in buckets:
    name = bucket["Name"]
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        grants = acl.get("Grants", [])
        public = False
        for grant in grants:
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                public = True

        status = "PUBLIC (!!)" if public else "Private"
        print(f"\nBucket: {name}")
        print(f"  Access: {status}")
        if public:
            print("  [!] CRITICAL: This bucket is publicly accessible!")
            print("  [!] REMEDIATION: Enable 'Block All Public Access' at account level")
            # List objects in public bucket
            try:
                objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
                for obj in objs:
                    print(f"       Exposed file: {obj['Key']} ({obj['Size']} bytes)")
            except Exception:
                pass
    except Exception as e:
        print(f"\nBucket: {name}  [ERROR: {e}]")

print("\n" + "=" * 60)
print("Audit complete.")
