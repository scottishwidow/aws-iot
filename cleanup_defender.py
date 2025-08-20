#!/usr/bin/env python3
import argparse, os, sys
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

PROFILE_NAME_DEFAULT = os.getenv('DEFENDER_PROFILE_NAME', 'LabProfile-Strict')
GROUP_NAME_DEFAULT = os.getenv('DEFENDER_GROUP_NAME', 'LabGroup')

def main():
    ap = argparse.ArgumentParser(description="Cleanup Device Defender Detect: detach profile and delete group/profile")
    ap.add_argument("--region", default=None)
    ap.add_argument("--group-name", default=GROUP_NAME_DEFAULT)
    ap.add_argument("--profile-name", default=PROFILE_NAME_DEFAULT)
    args = ap.parse_args()

    session = boto3.session.Session(region_name=args.region)
    region = session.region_name
    if not region:
        print("No region resolved. Use --region or set AWS_REGION/AWS_DEFAULT_REGION.", file=sys.stderr)
        sys.exit(1)

    iot = session.client("iot")

    try:
        group_arn = iot.describe_thing_group(thingGroupName=args.group_name)["thingGroupArn"]
        try:
            iot.detach_security_profile(
                securityProfileName=args.profile_name,
                securityProfileTargetArn=group_arn
            )
            print(f"Detached profile '{args.profile_name}' from '{args.group_name}'")
        except ClientError as e:
            print(f"[skip detach] {e.response['Error']['Code']}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print("[info] Thing group not found; skipping detach")
        else:
            raise

    try:
        things = iot.list_things_in_thing_group(thingGroupName=args.group_name).get("things", [])
        for t in things:
            try:
                iot.remove_thing_from_thing_group(thingGroupName=args.group_name, thingName=t)
                print(f"Removed thing '{t}' from group '{args.group_name}'")
            except ClientError as e:
                print(f"[skip remove thing] {e.response['Error']['Code']}")
        iot.delete_thing_group(thingGroupName=args.group_name)
        print(f"Deleted thing group: {args.group_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print("[info] Thing group already deleted.")
        else:
            print(f"[group delete warn] {e.response['Error']['Code']}")

    try:
        iot.delete_security_profile(securityProfileName=args.profile_name)
        print(f"Deleted security profile: {args.profile_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print("[info] Security profile already deleted.")
        else:
            print(f"[profile delete warn] {e.response['Error']['Code']}")

    print("Cleanup complete.")

if __name__ == "__main__":
    main()