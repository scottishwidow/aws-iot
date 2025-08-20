#!/usr/bin/env python3
# Clean up IoT device provisioning resources: certificates, policies, things, and local files.
# Dependencies: pip install boto3
import argparse, os, sys
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

# Environment variable defaults (consistent with provision.py)
DEFAULT_POLICY_PREFIX = os.getenv('IOT_POLICY_PREFIX', 'DevicePolicy')
DEFAULT_CERT_DIR = os.getenv('IOT_CERT_DIR', 'certs')
IOT_CERT_FILENAME = os.getenv('IOT_CERT_FILENAME', 'device.pem.crt')
IOT_KEY_FILENAME = os.getenv('IOT_KEY_FILENAME', 'private.pem.key')
IOT_CA_FILENAME = os.getenv('IOT_CA_FILENAME', 'AmazonRootCA1.pem')
IOT_ENDPOINT_FILENAME = os.getenv('IOT_ENDPOINT_FILENAME', 'endpoint.txt')

def cleanup_local_files(cert_dir: Path, thing_name: str, force: bool = False):
    """Remove local certificate files and directory"""
    thing_dir = cert_dir / thing_name
    if not thing_dir.exists():
        print(f"[info] Certificate directory does not exist: {thing_dir}")
        return

    files_to_remove = [
        IOT_CERT_FILENAME,
        IOT_KEY_FILENAME,
        IOT_CA_FILENAME,
        IOT_ENDPOINT_FILENAME
    ]
    
    removed_count = 0
    for filename in files_to_remove:
        file_path = thing_dir / filename
        if file_path.exists():
            try:
                if force or input(f"Delete {file_path}? [y/N]: ").lower().startswith('y'):
                    file_path.unlink()
                    print(f"Removed: {file_path}")
                    removed_count += 1
                else:
                    print(f"Skipped: {file_path}")
            except Exception as e:
                print(f"[warn] Could not remove {file_path}: {e}")
        else:
            print(f"[info] File does not exist: {file_path}")
    
    # Remove directory if empty
    try:
        if removed_count > 0 and not any(thing_dir.iterdir()):
            thing_dir.rmdir()
            print(f"Removed empty directory: {thing_dir}")
    except OSError:
        print(f"[info] Directory not empty, keeping: {thing_dir}")

def get_certificate_arn_for_thing(iot, thing_name: str):
    """Get the certificate ARN attached to a thing"""
    try:
        response = iot.list_thing_principals(thingName=thing_name)
        principals = response.get('principals', [])
        
        # Filter for certificate ARNs (not aliases)
        cert_arns = [p for p in principals if ':cert/' in p]
        
        if not cert_arns:
            print(f"[info] No certificates found attached to thing: {thing_name}")
            return None
        elif len(cert_arns) > 1:
            print(f"[warn] Multiple certificates found for thing {thing_name}, using first one")
            for i, arn in enumerate(cert_arns):
                print(f"  {i+1}. {arn}")
        
        return cert_arns[0]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print(f"[info] Thing not found: {thing_name}")
            return None
        else:
            raise

def get_policies_for_certificate(iot, cert_arn: str):
    """Get policies attached to a certificate"""
    try:
        cert_id = cert_arn.split('/')[-1]
        response = iot.list_attached_policies(target=cert_arn)
        return [policy['policyName'] for policy in response.get('policies', [])]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print(f"[info] Certificate not found: {cert_arn}")
            return []
        else:
            raise

def main():
    ap = argparse.ArgumentParser(description="Cleanup IoT device provisioning: detach and delete certificates, policies, things, and local files")
    ap.add_argument("--thing-name", required=True, help="IoT Thing name to clean up")
    ap.add_argument("--policy-name", default=None, help=f"IoT Policy name (default: {DEFAULT_POLICY_PREFIX}_<THING>)")
    ap.add_argument("--cert-dir", default=DEFAULT_CERT_DIR, help="Certificate directory base path")
    ap.add_argument("--region", default=None, help="AWS region (falls back to boto3 default)")
    ap.add_argument("--keep-files", action="store_true", help="Keep local certificate files")
    ap.add_argument("--force", action="store_true", help="Skip confirmation prompts for file deletion")
    ap.add_argument("--dry-run", action="store_true", help="Show what would be deleted without actually deleting")
    args = ap.parse_args()

    thing_name = args.thing_name
    policy_name = args.policy_name or f"{DEFAULT_POLICY_PREFIX}_{thing_name}"
    cert_dir = Path(args.cert_dir)

    if args.dry_run:
        print("[DRY RUN] Showing what would be cleaned up:")

    session = boto3.session.Session(region_name=args.region)
    region = session.region_name
    if not region:
        print("No region resolved. Use --region or set AWS_REGION/AWS_DEFAULT_REGION.", file=sys.stderr)
        sys.exit(1)

    iot = session.client("iot")

    # Get certificate ARN for the thing
    cert_arn = get_certificate_arn_for_thing(iot, thing_name)
    
    if cert_arn:
        cert_id = cert_arn.split('/')[-1]
        print(f"Found certificate: {cert_id}")
        
        # Get attached policies
        attached_policies = get_policies_for_certificate(iot, cert_arn)
        
        if args.dry_run:
            print(f"[DRY RUN] Would detach thing '{thing_name}' from certificate")
            for policy in attached_policies:
                print(f"[DRY RUN] Would detach policy '{policy}' from certificate")
            print(f"[DRY RUN] Would deactivate and delete certificate {cert_id}")
        else:
            # Detach thing from certificate
            try:
                iot.detach_thing_principal(thingName=thing_name, principal=cert_arn)
                print(f"Detached thing '{thing_name}' from certificate")
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    print(f"[info] Thing or certificate already detached")
                else:
                    print(f"[warn] Could not detach thing from certificate: {e.response['Error']['Code']}")

            # Detach policies from certificate
            for policy_name_attached in attached_policies:
                try:
                    iot.detach_policy(policyName=policy_name_attached, target=cert_arn)
                    print(f"Detached policy '{policy_name_attached}' from certificate")
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ResourceNotFoundException":
                        print(f"[info] Policy '{policy_name_attached}' already detached")
                    else:
                        print(f"[warn] Could not detach policy '{policy_name_attached}': {e.response['Error']['Code']}")

            # Deactivate certificate
            try:
                iot.update_certificate(certificateId=cert_id, newStatus='INACTIVE')
                print(f"Deactivated certificate: {cert_id}")
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    print(f"[info] Certificate already deleted: {cert_id}")
                else:
                    print(f"[warn] Could not deactivate certificate: {e.response['Error']['Code']}")

            # Delete certificate
            try:
                iot.delete_certificate(certificateId=cert_id)
                print(f"Deleted certificate: {cert_id}")
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    print(f"[info] Certificate already deleted: {cert_id}")
                elif e.response["Error"]["Code"] == "CertificateStateException":
                    print(f"[warn] Certificate still has attachments or is not INACTIVE: {cert_id}")
                else:
                    print(f"[warn] Could not delete certificate: {e.response['Error']['Code']}")

    # Delete policy
    if args.dry_run:
        print(f"[DRY RUN] Would delete policy: {policy_name}")
    else:
        try:
            iot.delete_policy(policyName=policy_name)
            print(f"Deleted policy: {policy_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                print(f"[info] Policy already deleted: {policy_name}")
            elif e.response["Error"]["Code"] == "DeleteConflictException":
                print(f"[warn] Policy still has attachments: {policy_name}")
            else:
                print(f"[warn] Could not delete policy: {e.response['Error']['Code']}")

    # Delete thing
    if args.dry_run:
        print(f"[DRY RUN] Would delete thing: {thing_name}")
    else:
        try:
            iot.delete_thing(thingName=thing_name)
            print(f"Deleted thing: {thing_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                print(f"[info] Thing already deleted: {thing_name}")
            elif e.response["Error"]["Code"] == "InvalidRequestException":
                print(f"[warn] Thing still has attachments: {thing_name}")
            else:
                print(f"[warn] Could not delete thing: {e.response['Error']['Code']}")

    # Clean up local files
    if not args.keep_files:
        if args.dry_run:
            thing_dir = cert_dir / thing_name
            if thing_dir.exists():
                print(f"[DRY RUN] Would remove certificate files from: {thing_dir}")
                for filename in [IOT_CERT_FILENAME, IOT_KEY_FILENAME, IOT_CA_FILENAME, IOT_ENDPOINT_FILENAME]:
                    file_path = thing_dir / filename
                    if file_path.exists():
                        print(f"[DRY RUN] Would remove: {file_path}")
        else:
            cleanup_local_files(cert_dir, thing_name, args.force)
    else:
        print(f"[info] Keeping local certificate files (--keep-files specified)")

    if args.dry_run:
        print("\n[DRY RUN] No actual changes made. Run without --dry-run to execute cleanup.")
    else:
        print("Provisioning cleanup complete.")

if __name__ == "__main__":
    main()