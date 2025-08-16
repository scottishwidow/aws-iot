#!/usr/bin/env python3
# Create a Thing Group, a strict Security Profile (Device Defender Detect),
# and attach the profile to the group so your device(s) are evaluated.
# Dependencies: pip install boto3
import argparse, json, sys
import boto3
from botocore.exceptions import ClientError

PROFILE_NAME_DEFAULT = "LabProfile-Strict"
GROUP_NAME_DEFAULT   = "LabGroup"

BEHAVIORS = [
    {
        "name": "TooManyAuthFailures",
        "metric": "aws:num-authorization-failures",
        "criteria": {
            "comparisonOperator": "greater-than-equals",
            "value": {"count": 1},
            "durationSeconds": 300,
            "consecutiveDatapointsToAlarm": 1,
            "consecutiveDatapointsToClear": 1
        }
    },
    {
        "name": "TooManyMessagesSent",
        "metric": "aws:num-messages-sent",
        "criteria": {
            "comparisonOperator": "greater-than",
            "value": {"count": 10},
            "durationSeconds": 300,
            "consecutiveDatapointsToAlarm": 1,
            "consecutiveDatapointsToClear": 1
        }
    },
    {
        "name": "PayloadTooLarge",
        "metric": "aws:message-byte-size",
        "criteria": {
            "comparisonOperator": "greater-than",
            "value": {"count": 4096},
            "consecutiveDatapointsToAlarm": 1,
            "consecutiveDatapointsToClear": 1
        }
    },
    {
        "name": "TooManyDisconnects",
        "metric": "aws:num-disconnects",
        "criteria": {
            "comparisonOperator": "greater-than",
            "value": {"count": 2},
            "durationSeconds": 300,
            "consecutiveDatapointsToAlarm": 1,
            "consecutiveDatapointsToClear": 1
        }
    }
]

def main():
    ap = argparse.ArgumentParser(description="Setup Device Defender Detect: group + security profile + attachment")
    ap.add_argument("--region", default=None, help="AWS region (falls back to boto3 default)")
    ap.add_argument("--group-name", default=GROUP_NAME_DEFAULT)
    ap.add_argument("--profile-name", default=PROFILE_NAME_DEFAULT)
    ap.add_argument("--thing-name", required=True, help="Thing to place in the group")
    args = ap.parse_args()

    session = boto3.session.Session(region_name=args.region)
    region = session.region_name
    if not region:
        print("No region resolved. Use --region or set AWS_REGION/AWS_DEFAULT_REGION.", file=sys.stderr)
        sys.exit(1)

    iot = session.client("iot")

    # Create or reuse thing group
    try:
        iot.create_thing_group(thingGroupName=args.group_name)
        print(f"Created thing group: {args.group_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            print(f"Thing group exists: {args.group_name} (reusing)")
        else:
            raise

    # Add thing to group
    try:
        iot.add_thing_to_thing_group(thingGroupName=args.group_name, thingName=args.thing_name)
        print(f"Added thing '{args.thing_name}' to '{args.group_name}'")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print("Thing not found; create it first (run the provisioning script).")
            sys.exit(2)
        elif e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            print("Thing already in group.")
        else:
            raise

    # Create or reuse security profile
    try:
        iot.create_security_profile(
            securityProfileName=args.profile_name,
            behaviors=BEHAVIORS
        )
        print(f"Created security profile: {args.profile_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            print(f"Security profile exists: {args.profile_name} (reusing)")
        else:
            raise

    # Attach security profile to group
    group_arn = iot.describe_thing_group(thingGroupName=args.group_name)["thingGroupArn"]
    try:
        iot.attach_security_profile(
            securityProfileName=args.profile_name,
            securityProfileTargetArn=group_arn
        )
        print(f"Attached profile '{args.profile_name}' to group '{args.group_name}'")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            print("Profile already attached to target (reusing).")
        else:
            raise

    print("Setup complete.")

if __name__ == "__main__":
    main()