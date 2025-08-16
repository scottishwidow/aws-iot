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

## Scripts

1. **Provision a Device**

Creates:

- IoT Thing
- IoT Policy (scoped to the thing)
- Device **certificate & private key**
- Downloads Amazon Root CA
- Attaches policy & cert
- Writes files under `certs/<thing-name>/`

`python3 provision_device.py --thing-name <thing-name> --region <aws-region>`

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

Flags and environment variables let simulate Defender alerts:

| Behavior                   | Flag                                      | Env                                        | Effect                                   |
| -------------------------- | ----------------------------------------- | ------------------------------------------ | ---------------------------------------- |
| **Authorization failures** | `--cause-auth-fail`                       | `IOT_CAUSE_AUTH_FAIL=1`                    | Subscribes/publishes to forbidden topic  |
| **Message flood**          | `--burst-count 50 --burst-interval-ms 20` | `IOT_BURST_COUNT`, `IOT_BURST_INTERVAL_MS` | Sends burst of messages                  |
| **Large payloads**         | `--payload-bytes 8192`                    | `IOT_PAYLOAD_BYTES`                        | Adds filler `blob` field to inflate size |
| **Frequent disconnects**   | `--flap-interval 5`                       | `IOT_FLAP_INTERVAL`                        | Disconnect/reconnect every N seconds     |
| **Disable heartbeat**      | `--no-heartbeat`                          | `IOT_NO_HEARTBEAT=1`                       | Skip periodic heartbeat                  |
| **Delay behaviors**        | `--after 3`                               | `IOT_AFTER=3`                              | Trigger behaviors after N heartbeats     |

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
# Remove Thing, cert, policy, and local cert files
python3 cleanup_device.py --thing-name <thing-name> --region <aws-region> --delete-local

python3 cleanup_defender.py --region <aws-region>

```

---

## Notes

- Default MQTT topics: `devices/<thing-name>/hello`, `devices/<thing-name>/heartbeat`, `devices/<thing-name>/status`
- IoT Policy created by provisioning only allows your device's own topic space
- The heartbeat device uses **Last Will** on `status` to report "offline" if it disconnects unexpectedly
- Defender thresholds are set very tight so you can trigger easily in a lab environment
