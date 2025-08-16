#!/usr/bin/env python3
import argparse, json, os, sys, time
from pathlib import Path
import boto3
from botocore.exceptions import ClientError
from urllib.request import urlopen

# IoT policy (restrict to this device's clientId/topic prefix)
def make_policy_doc(account_id, region, thing_name):
    base_arn = f"arn:aws:iot:{region}:{account_id}"
    topic_prefix = f"devices/${{iot:ClientId}}/*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {   # Only allow this cert to connect as its own clientId
                "Effect": "Allow",
                "Action": ["iot:Connect"],
                "Resource": [f"{base_arn}:client/${{iot:ClientId}}"]
            },
            {   # Publish only under devices/<clientId>/*
                "Effect": "Allow",
                "Action": ["iot:Publish"],
                "Resource": [f"{base_arn}:topic/{topic_prefix}"]
            },
            {   # Subscribe only under devices/<clientId>/*
                "Effect": "Allow",
                "Action": ["iot:Subscribe"],
                "Resource": [f"{base_arn}:topicfilter/{topic_prefix}"]
            },
            {   # Receive messages for subscribed topics
                "Effect": "Allow",
                "Action": ["iot:Receive"],
                "Resource": [f"{base_arn}:topic/{topic_prefix}"]
            }
        ]
    }

def download_root_ca(dest_path: Path):
    # Amazon Trust Services Root CA 1
    url = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
    pem = urlopen(url, timeout=30).read()
    dest_path.write_bytes(pem)

def main():
    parser = argparse.ArgumentParser(description="Provision a single test AWS IoT device.")
    parser.add_argument("--thing-name", required=True, help="IoT Thing name (and MQTT clientId).")
    parser.add_argument("--policy-name", default=None, help="IoT Policy name (default: DevicePolicy_<THING>)")
    parser.add_argument("--outdir", default="certs", help="Where to write certs/keys")
    parser.add_argument("--region", default=None, help="AWS region (fallback: boto3 default)")
    args = parser.parse_args()

    thing_name = args.thing_name
    policy_name = args.policy_name or f"DevicePolicy_{thing_name}"
    outdir = Path(args.outdir) / thing_name
    outdir.mkdir(parents=True, exist_ok=True)

    session = boto3.session.Session(region_name=args.region)
    region = session.region_name
    if not region:
        print("No region resolved. Use --region or set AWS_REGION.", file=sys.stderr)
        sys.exit(1)

    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    iot = session.client("iot")
    # Data-ATS endpoint for MQTT
    ep = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]

    # Ensure policy exists
    policy_doc = json.dumps(make_policy_doc(account_id, region, thing_name))
    try:
        iot.create_policy(policyName=policy_name, policyDocument=policy_doc)
        print(f"Created policy: {policy_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            print(f"Policy already exists: {policy_name} (reusing)")
        else:
            raise

    # Ensure thing exists
    try:
        iot.create_thing(thingName=thing_name)
        print(f"Created thing: {thing_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            print(f"Thing already exists: {thing_name} (reusing)")
        else:
            raise

    # Create keys & certificate (ACTIVE)
    resp = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = resp["certificateArn"]
    cert_pem = resp["certificatePem"]
    priv_key = resp["keyPair"]["PrivateKey"]

    # Attachments
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)
    print("Attached policy and thing to certificate.")

    # Write files
    cert_file = outdir / "device.pem.crt"
    key_file  = outdir / "private.pem.key"
    root_ca   = outdir / "AmazonRootCA1.pem"
    endpoint_file = outdir / "endpoint.txt"

    cert_file.write_text(cert_pem)
    key_file.write_text(priv_key)
    endpoint_file.write_text(ep + "\n")

    # Root CA
    try:
        download_root_ca(root_ca)
        print(f"Downloaded AmazonRootCA1 to {root_ca}")
    except Exception as e:
        print(f"WARNING: Could not download Root CA automatically ({e}).")
        print("Download manually from https://www.amazontrust.com/repository/AmazonRootCA1.pem")
        print(f"Save as: {root_ca}")

    print("\nProvisioned!")
    print(f"Thing:     {thing_name}")
    print(f"Endpoint:  {ep}")
    print(f"Certs dir: {outdir.resolve()}")

if __name__ == "__main__":
    main()
