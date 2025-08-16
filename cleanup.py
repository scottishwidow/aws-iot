#!/usr/bin/env python3
import argparse
from pathlib import Path
import sys
import boto3
from botocore.exceptions import ClientError

def log(msg): print(msg, flush=True)

def arn_to_cert_id(arn: str) -> str:
    # arn:aws:iot:<region>:<acct>:cert/<CERT_ID>
    return arn.rsplit("/", 1)[-1]

def safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        log(f"  · Skipped ({code})")
    except Exception as e:
        log(f"  · Skipped ({e})")

def main():
    p = argparse.ArgumentParser(description="Cleanup AWS IoT resources for a single test device.")
    p.add_argument("--thing-name", required=True, help="Thing name / clientId to clean up")
    p.add_argument("--policy-name", default=None, help="Policy name (default: DevicePolicy_<THING>)")
    p.add_argument("--region", default=None, help="AWS region (fallback: boto3 default)")
    p.add_argument("--cert-dir", default="certs", help="Base dir that contains certs/<thingName>")
    p.add_argument("--delete-local", action="store_true", help="Also delete local cert files directory")
    args = p.parse_args()

    thing = args.thing_name
    policy = args.policy_name or f"DevicePolicy_{thing}"
    session = boto3.session.Session(region_name=args.region)
    region = session.region_name
    if not region:
        log("No region resolved. Use --region or export AWS_REGION / AWS_DEFAULT_REGION.")
        sys.exit(1)

    iot = session.client("iot")

    log(f"Cleaning resources for thing '{thing}' in {region}")

    # 1) Find principals (cert ARNs) attached to Thing
    principals = []
    try:
        resp = iot.list_thing_principals(thingName=thing)
        principals = resp.get("principals", [])
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            log("Thing not found (already deleted?). Continuing.")
        else:
            raise

    # 2) For each attached certificate: detach, detach policies, deactivate + delete cert
    for pr in principals:
        log(f"- Handling principal: {pr}")
        # Detach thing ↔ principal
        safe_call(iot.detach_thing_principal, thingName=thing, principal=pr)

        # List and detach policies from cert
        try:
            pols = iot.list_attached_policies(target=pr).get("policies", [])
        except ClientError as e:
            pols = []
            log(f"  · list_attached_policies skipped: {e.response['Error']['Code']}")

        for pol in pols:
            pn = pol["policyName"]
            log(f"  · Detaching policy {pn}")
            safe_call(iot.detach_policy, policyName=pn, target=pr)

        # Deactivate cert, then delete
        cert_id = arn_to_cert_id(pr)
        log(f"  · Deactivating certificate {cert_id}")
        safe_call(iot.update_certificate, certificateId=cert_id, newStatus="INACTIVE")

        log(f"  · Deleting certificate {cert_id}")
        # force-delete handles INACTIVE/REVOKED that may still be referenced
        try:
            iot.delete_certificate(certificateId=cert_id, forceDelete=True)
        except ClientError as e:
            # Some regions/accounts may require explicit INACTIVE before forceDelete works—already tried above.
            log(f"  · delete_certificate skipped: {e.response['Error']['Code']}")

    # 3) Delete Thing
    log(f"- Deleting thing {thing}")
    safe_call(iot.delete_thing, thingName=thing)

    # 4) Delete Policy (only if it exists and is not in use elsewhere)
    # First verify it exists
    policy_exists = True
    try:
        iot.get_policy(policyName=policy)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            policy_exists = False
        else:
            raise

    if policy_exists:
        log(f"- Deleting policy {policy}")
        # Detach policy from any remaining principals just in case
        # (list targets API doesn’t exist; we best-effort delete, which fails if still attached)
        try:
            iot.delete_policy(policyName=policy)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            log(f"  · delete_policy failed ({code}). It may still be attached to other certs or have non-default versions.")

    # 5) Optionally delete local cert directory
    if args.delete_local:
        cert_path = Path(args.cert_dir) / thing
        if cert_path.exists() and cert_path.is_dir():
            log(f"- Removing local folder {cert_path}")
            for pth in cert_path.glob("*"):
                try:
                    pth.unlink()
                except Exception:
                    pass
            try:
                cert_path.rmdir()
            except Exception:
                pass

    log("Cleanup complete.")

if __name__ == "__main__":
    main()
