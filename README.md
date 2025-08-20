# AWS IoT Core Test Device & Device Defender Lab

This repository contains Python scripts to:
- Provision a test IoT device in **AWS IoT Core**
- Run a simulated **heartbeat device** over MQTT/TLS
- Trigger **Device Defender Detect** alerts (auth failures, message rate, payload size, disconnects)
- Create / attach a **Security Profile** to monitor the device
- Clean up all resources when finished

---

## Prerequisites

- AWS account with IoT Core permissions
- AWS CLI configured (`aws configure`)
- Python 3.9+
- Packages:
  
  `pip install boto3 awsiotsdk awscrt`

---

## Configuration

### Environment Variables

All scripts support configuration via environment variables for flexible deployment across different environments (dev/staging/prod).

**Quick Setup:**
1. Copy the example environment file: `cp .env.example .env`
2. Edit `.env` with your specific values
3. The scripts will automatically use these values as defaults

**Key Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | _(required)_ | AWS region for all services |
| `IOT_CERT_DIR` | `certs` | Base directory for certificates |
| `IOT_KEEP_ALIVE_SECS` | `30` | MQTT keep-alive interval |
| `IOT_TOPIC_PATTERN` | `devices/{client_id}` | Base topic pattern |
| `DEFENDER_PROFILE_NAME` | `LabProfile-Strict` | Security profile name |
| `DEFENDER_GROUP_NAME` | `LabGroup` | Thing group name |
| `IOT_POLICY_PREFIX` | `DevicePolicy` | Policy name prefix |

**Defender Behavior Thresholds:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFENDER_AUTH_FAILURE_THRESHOLD` | `1` | Max auth failures before alert |
| `DEFENDER_MESSAGE_COUNT_THRESHOLD` | `10` | Max messages per window |
| `DEFENDER_PAYLOAD_SIZE_THRESHOLD` | `4096` | Max payload size in bytes |
| `DEFENDER_DISCONNECT_THRESHOLD` | `2` | Max disconnects per window |
| `DEFENDER_DURATION_SECONDS` | `300` | Evaluation window (5 minutes) |

**Invalid Certificate Testing:**

| Variable | Default | Description |
|----------|---------|-------------|
| `IOT_INVALID_CERT_ATTEMPTS` | `3` | Number of invalid certificate connection attempts |
| `IOT_INVALID_CERT_DELAY` | `5` | Delay between invalid cert attempts (seconds) |

See `.env.example` for complete list and environment-specific configurations.

---

## Scripts

1. **Provision a Device**

Creates:

- IoT Thing
- IoT Policy (scoped to the thing)
- Device **certificate & private key**
- Downloads Amazon Root CA
- Attaches policy & cert
- Writes files under `certs/<thing-name>/`

`python3 provision.py --thing-name <thing-name> --region <aws-region>`

Outputs:

```
certs/myTestThing/
  ├── device.pem.crt
  ├── private.pem.key
  ├── AmazonRootCA1.pem
  └── endpoint.txt
```

---

2. **Run the Heartbeat Device**

By default, publishes a heartbeat JSON every 10 seconds to `devices/<thing-name>/heartbeat`, and subscribes to its own topics to echo messages.

`python3 device.py --thing-name <thing-name>`

**Device Configuration:**

| Setting | Flag | Environment Variable | Default | Description |
|---------|------|---------------------|---------|-------------|
| **Certificate directory** | `--cert-dir` | `IOT_CERT_DIR` | `certs` | Base directory for certificates |
| **Heartbeat interval** | `--interval` | `IOT_INTERVAL` | `10` | Seconds between heartbeats |
| **MQTT QoS** | `--qos` | `IOT_QOS` | `1` | Quality of Service (0 or 1) |
| **Retain messages** | `--retain` | `IOT_RETAIN` | `false` | Publish as retained messages |
| **Clean session** | `--clean-session` | `IOT_CLEAN_SESSION` | `false` | Use clean MQTT session |

**Defender Test Behaviors:**

| Behavior | Flag | Environment Variable | Default | Effect |
|----------|------|---------------------|---------|--------|
| **Authorization failures** | `--cause-auth-fail` | `IOT_CAUSE_AUTH_FAIL` | `false` | Subscribe/publish to forbidden topic |
| **Invalid certificates** | `--invalid-cert` | - | `none` | Test with invalid certificates (expired/wrong/missing) |
| **Invalid cert attempts** | `--invalid-cert-attempts` | `IOT_INVALID_CERT_ATTEMPTS` | `3` | Number of invalid certificate connection attempts |
| **Invalid cert delay** | `--invalid-cert-delay` | `IOT_INVALID_CERT_DELAY` | `5` | Delay between invalid cert attempts (seconds) |
| **Message flood** | `--burst-count`, `--burst-interval-ms` | `IOT_BURST_COUNT`, `IOT_BURST_INTERVAL_MS` | `0`, `0` | Send burst of messages |
| **Large payloads** | `--payload-bytes` | `IOT_PAYLOAD_BYTES` | `0` | Add filler data to inflate size |
| **Frequent disconnects** | `--flap-interval` | `IOT_FLAP_INTERVAL` | `0` | Disconnect/reconnect every N seconds |
| **Disable heartbeat** | `--no-heartbeat` | `IOT_NO_HEARTBEAT` | `false` | Skip periodic heartbeat |
| **Delay behaviors** | `--after` | `IOT_AFTER` | `0` | Trigger behaviors after N heartbeats |

Examples:

```python
# Normal heartbeat
python device.py --thing-name myTestThing

# Test with invalid certificates (triggers aws:num-auth-failures)
python device.py --thing-name myTestThing --invalid-cert expired
python device.py --thing-name myTestThing --invalid-cert wrong --invalid-cert-attempts 5
python device.py --thing-name myTestThing --invalid-cert missing

# Burst 100 messages after 3 heartbeats
python device.py --thing-name myTestThing --after 3 --burst-count 100

# Heartbeats with 8KB payloads
python device.py --thing-name myTestThing --payload-bytes 8192

# Disconnect/reconnect every 5s, heartbeat every 1s
python device.py --thing-name myTestThing --flap-interval 5 --interval 1

# Combine multiple behaviors
python device.py --thing-name myTestThing --invalid-cert wrong --cause-auth-fail --burst-count 50
```

**Invalid Certificate Testing:**

The `--invalid-cert` option allows testing TLS/authentication failures to trigger the `aws:num-auth-failures` behavior:

- `expired`: Uses certificates that appear expired/invalid (simulated by corrupting the certificate)
- `wrong`: Creates certificates with invalid PEM content
- `missing`: Attempts to use non-existent certificate files

Each invalid certificate attempt will fail during the TLS handshake, generating authentication failure events that Device Defender can detect and alert on.

---

3. **Setup Device Defender Security Profile**

Creates:

- Thing Group (default: `LabGroup`)
- Security Profile (default: `LabProfile-Strict`) with 5 behaviors:
  - TooManyAuthFailures (authorization failures from forbidden topics)
  - TooManyTLSAuthFailures (TLS/authentication failures from invalid certificates)
  - TooManyMessagesSent
  - PayloadTooLarge
  - TooManyDisconnects
- Adds the thing to the group
- Attaches the profile

```python
python3 setup_defender.py --thing-name <thing-name> --region <aws-region>
```

---

4. **Observe Violations

- **Console:** `AWS Console -> IoT Core -> Security -> Detect -> Security profiles`
- **CLI**:

```bash
aws iot list-violation-events \
  --start-time "$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --security-profile-name LabProfile-Strict
```

---

5. **Cleanup**

Complete cleanup of all resources in reverse order of creation.

**Step 1: Clean up Device Defender resources**

Removes security profiles and thing groups:

```bash
python3 cleanup_defender.py --region <aws-region>
```

**Step 2: Clean up provisioned device resources**

Removes certificates, policies, things, and local files:

```bash
# Full cleanup (includes local certificate files)
python3 cleanup_provision.py --thing-name <thing-name> --region <aws-region>

# Preview what will be deleted
python3 cleanup_provision.py --thing-name <thing-name> --dry-run

# Keep local certificate files
python3 cleanup_provision.py --thing-name <thing-name> --keep-files

# Skip confirmation prompts
python3 cleanup_provision.py --thing-name <thing-name> --force
```

**Cleanup Options:**

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview what would be deleted without making changes |
| `--keep-files` | Preserve local certificate files in `certs/<thing-name>/` |
| `--force` | Skip confirmation prompts for file deletion |
| `--policy-name` | Override policy name (default: `DevicePolicy_<thing-name>`) |
| `--cert-dir` | Override certificate directory (default: `certs`) |

The cleanup script will:
1. Detach the thing from its certificate
2. Detach all policies from the certificate
3. Deactivate the certificate
4. Delete the certificate
5. Delete the policy
6. Delete the thing
7. Remove local certificate files (unless `--keep-files` specified)

---

## Environment Examples

**Development (Sensitive alerts):**
```bash
DEFENDER_AUTH_FAILURE_THRESHOLD=1
DEFENDER_MESSAGE_COUNT_THRESHOLD=5
IOT_INTERVAL=5
```

**Production (Relaxed thresholds):**
```bash
DEFENDER_AUTH_FAILURE_THRESHOLD=5
DEFENDER_MESSAGE_COUNT_THRESHOLD=100
IOT_INTERVAL=60
```

---

## Notes

- Default MQTT topics: `devices/<thing-name>/hello`, `devices/<thing-name>/heartbeat`, `devices/<thing-name>/status`
- Topic patterns are configurable via `IOT_TOPIC_PATTERN` environment variable
- IoT Policy created by provisioning only allows your device's own topic space
- The heartbeat device uses **Last Will** on `status` to report "offline" if it disconnects unexpectedly
- Defender thresholds are set very tight so you can trigger easily in a lab environment
- All certificate filenames are configurable via environment variables for different naming schemes
