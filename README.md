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
| **Message flood** | `--burst-count`, `--burst-interval-ms` | `IOT_BURST_COUNT`, `IOT_BURST_INTERVAL_MS` | `0`, `0` | Send burst of messages |
| **Large payloads** | `--payload-bytes` | `IOT_PAYLOAD_BYTES` | `0` | Add filler data to inflate size |
| **Frequent disconnects** | `--flap-interval` | `IOT_FLAP_INTERVAL` | `0` | Disconnect/reconnect every N seconds |
| **Disable heartbeat** | `--no-heartbeat` | `IOT_NO_HEARTBEAT` | `false` | Skip periodic heartbeat |
| **Delay behaviors** | `--after` | `IOT_AFTER` | `0` | Trigger behaviors after N heartbeats |

Examples:

```python
# Normal heartbeat
python device.py --thing-name myTestThing

# Burst 100 messages after 3 heartbeats
python device.py --thing-name myTestThing --after 3 --burst-count 100

# Heartbeats with 8KB payloads
python device.py --thing-name myTestThing --payload-bytes 8192

# Disconnect/reconnect every 5s, heartbeat every 1s
python device.py --thing-name myTestThing --flap-interval 5 --interval 1
```

---

3. **Setup Device Defender Security Profile**

Creates:

- Thing Group (default: `LabGroup`)
- Security Profile (default: `LabProfile-Strict`) with 4 behaviors:
  - TooManyAuthFailures
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

Remove device + Defender resources.

```bash
# Remove Defender resources (security profile and thing group)
python3 cleanup_defender.py --region <aws-region>

# Note: Device cleanup script not included - remove via AWS Console or CLI
```

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
