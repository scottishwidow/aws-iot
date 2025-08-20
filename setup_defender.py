#!/usr/bin/env python3
import argparse, json, os, sys
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

PROFILE_NAME_DEFAULT = os.getenv('DEFENDER_PROFILE_NAME', 'LabProfile-Strict')
GROUP_NAME_DEFAULT = os.getenv('DEFENDER_GROUP_NAME', 'LabGroup')
AUTH_FAILURE_THRESHOLD = int(os.getenv('DEFENDER_AUTH_FAILURE_THRESHOLD', '1'))
MESSAGE_COUNT_THRESHOLD = int(os.getenv('DEFENDER_MESSAGE_COUNT_THRESHOLD', '10'))
PAYLOAD_SIZE_THRESHOLD = int(os.getenv('DEFENDER_PAYLOAD_SIZE_THRESHOLD', '4096'))
DISCONNECT_THRESHOLD = int(os.getenv('DEFENDER_DISCONNECT_THRESHOLD', '2'))
DURATION_SECONDS = int(os.getenv('DEFENDER_DURATION_SECONDS', '300'))

BEHAVIORS = [
    {
        "name": "TooManyAuthFailures",
        "metric": "aws:num-authorization-failures",
        "criteria": {
            "comparisonOperator": "greater-than-equals",
            "value": {"count": AUTH_FAILURE_THRESHOLD},
            "durationSeconds": DURATION_SECONDS,
            "consecutiveDatapointsToAlarm": 1,
            "consecutiveDatapointsToClear": 1
        }
    },
    {
        "name": "TooManyMessagesSent",
        "metric": "aws:num-messages-sent",
        "criteria": {
            "comparisonOperator": "greater-than",
            "value": {"count": MESSAGE_COUNT_THRESHOLD},
            "durationSeconds": DURATION_SECONDS,
            "consecutiveDatapointsToAlarm": 1,
            "consecutiveDatapointsToClear": 1
        }
    },
    {
        "name": "PayloadTooLarge",
        "metric": "aws:message-byte-size",
        "criteria": {
            "comparisonOperator": "greater-than",
            "value": {"count": PAYLOAD_SIZE_THRESHOLD},
            "consecutiveDatapointsToAlarm": 1,
            "consecutiveDatapointsToClear": 1
        }
    },
    {
        "name": "TooManyDisconnects",
        "metric": "aws:num-disconnects",
        "criteria": {
            "comparisonOperator": "greater-than",
            "value": {"count": DISCONNECT_THRESHOLD},
            "durationSeconds": DURATION_SECONDS,
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

    try:
        iot.create_thing_group(thingGroupName=args.group_name)
        print(f"Created thing group: {args.group_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            print(f"Thing group exists: {args.group_name} (reusing)")
        else:
            raise

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