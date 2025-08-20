#!/usr/bin/env python3
# Heartbeat device for AWS IoT Core with toggles to trigger Device Defender Detect alerts.
# Dependencies: pip install awsiot awscrt
import argparse, json, os, signal, sys, time, threading
from pathlib import Path
from awscrt import mqtt
from awsiot import mqtt_connection_builder

# Environment variable defaults for additional configuration
IOT_KEEP_ALIVE_SECS = int(os.getenv('IOT_KEEP_ALIVE_SECS', '30'))
IOT_CERT_FILENAME = os.getenv('IOT_CERT_FILENAME', 'device.pem.crt')
IOT_KEY_FILENAME = os.getenv('IOT_KEY_FILENAME', 'private.pem.key')
IOT_CA_FILENAME = os.getenv('IOT_CA_FILENAME', 'AmazonRootCA1.pem')
IOT_ENDPOINT_FILENAME = os.getenv('IOT_ENDPOINT_FILENAME', 'endpoint.txt')
IOT_TOPIC_PATTERN = os.getenv('IOT_TOPIC_PATTERN', 'devices/{client_id}')
IOT_UNAUTH_TOPIC_PATTERN = os.getenv('IOT_UNAUTH_TOPIC_PATTERN', 'bad/{client_id}/oops')
IOT_SLEEP_GRANULARITY = float(os.getenv('IOT_SLEEP_GRANULARITY', '0.25'))

stop = False

def now_ts():
    return int(time.time())

def handle_sigint(signum, frame):
    global stop
    stop = True
    print("\nStopping...")

def getenv_bool(name, default=False):
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")

def subscribe_sync(conn, topic, qos, cb):
    ret = conn.subscribe(topic=topic, qos=qos, callback=cb)
    fut = ret[0] if isinstance(ret, tuple) else ret
    return fut.result()

def main():
    signal.signal(signal.SIGINT, handle_sigint)

    p = argparse.ArgumentParser(description="AWS IoT Core heartbeat device (with Defender test toggles)")
    p.add_argument("--thing-name", required=True, help="Thing name (also used as MQTT clientId)")
    p.add_argument("--cert-dir", default=os.getenv("IOT_CERT_DIR", "certs"), help="Base dir containing certs/<thingName>/")
    p.add_argument("--interval", type=int, default=int(os.getenv("IOT_INTERVAL", "10")), help="Seconds between heartbeats")
    p.add_argument("--qos", type=int, default=int(os.getenv("IOT_QOS", "1")), choices=[0,1], help="QoS 0/1 for pub/sub")
    p.add_argument("--retain", action="store_true" if getenv_bool("IOT_RETAIN", False) else "store_false",
                   help="Publish heartbeats as retained (also enable via IOT_RETAIN=1)")
    p.add_argument("--clean-session", action="store_true" if getenv_bool("IOT_CLEAN_SESSION", False) else "store_false",
                   help="Use clean session; default is persistent session (or set IOT_CLEAN_SESSION=1)")

    # Defender-behavior toggles
    p.add_argument("--cause-auth-fail", action="store_true" if getenv_bool("IOT_CAUSE_AUTH_FAIL", False) else "store_false",
                   help="Publish/subscribe to an unauthorized topic to trigger aws:num-authorization-failures")
    p.add_argument("--burst-count", type=int, default=int(os.getenv("IOT_BURST_COUNT", "0")),
                   help="Extra messages to burst-send (to trip aws:num-messages-sent)")
    p.add_argument("--burst-interval-ms", type=int, default=int(os.getenv("IOT_BURST_INTERVAL_MS", "0")),
                   help="Delay between burst messages in ms")
    p.add_argument("--payload-bytes", type=int, default=int(os.getenv("IOT_PAYLOAD_BYTES", "0")),
                   help="Append a filler 'blob' of this size to each publish (to trip aws:message-byte-size)")
    p.add_argument("--flap-interval", type=int, default=int(os.getenv("IOT_FLAP_INTERVAL", "0")),
                   help="If >0, disconnect/reconnect every N seconds (to trip aws:num-disconnects)")

    # QoL
    p.add_argument("--no-heartbeat", action="store_true" if getenv_bool("IOT_NO_HEARTBEAT", False) else "store_false",
                   help="Disable periodic heartbeat loop")
    p.add_argument("--after", type=int, default=int(os.getenv("IOT_AFTER", "0")),
                   help="Trigger behaviors after N heartbeats (0 = immediately)")

    args = p.parse_args()

    # Paths & client id
    d = Path(args.cert_dir) / args.thing_name
    endpoint = (d / IOT_ENDPOINT_FILENAME).read_text().strip()
    cert = str(d / IOT_CERT_FILENAME)
    key  = str(d / IOT_KEY_FILENAME)
    ca   = str(d / IOT_CA_FILENAME)
    client_id = args.thing_name

    # Topics aligned with the provisioning policy (configurable via environment)
    topic_pattern = IOT_TOPIC_PATTERN.format(client_id=client_id)
    topic_hello  = f"{topic_pattern}/hello"
    topic_hb     = f"{topic_pattern}/heartbeat"
    topic_status = f"{topic_pattern}/status"
    unauth_topic = IOT_UNAUTH_TOPIC_PATTERN.format(client_id=client_id)  # purposely unauthorized

    sub_qos = mqtt.QoS.AT_LEAST_ONCE if args.qos == 1 else mqtt.QoS.AT_MOST_ONCE

    # Last Will
    will_payload = json.dumps({"thing": client_id, "status": "offline", "ts": now_ts()})

    # Set up connection with callbacks
    # We'll capture 'mqtt_connection' and resubscribe topics if session doesn't persist
    def on_conn_interrupted(connection, error, **kwargs):
        print(f"Connection interrupted: {error}")

    # place-holders to be set after creation
    resub_topics = []

    def on_conn_resumed(connection, return_code, session_present, **kwargs):
        print(f"Connection resumed: return_code={return_code}, session_present={session_present}")
        if not session_present:
            # Broker dropped session → re-subscribe to our topics
            for t in resub_topics:
                try:
                    subscribe_sync(connection, t, sub_qos, on_message)
                    print(f"[re-subscribed] {t}")
                except Exception as e:
                    print(f"[re-subscribe failed] {t}: {e}")

    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint=endpoint,
        cert_filepath=cert,
        pri_key_filepath=key,
        ca_filepath=ca,
        client_id=client_id,
        clean_session=args.clean_session,
        keep_alive_secs=IOT_KEEP_ALIVE_SECS,
        on_connection_interrupted=on_conn_interrupted,
        on_connection_resumed=on_conn_resumed,
        will_topic=topic_status,
        will_payload=will_payload,
        will_qos=sub_qos
    )

    print(f"Connecting to {endpoint} as clientId={client_id} ...")
    mqtt_connection.connect().result()
    print("Connected.")

    # Message callback
    def on_message(topic, payload, dup, qos, retain, **kwargs):
        print(f"[MSG] {topic}: {payload.decode()} (retain={retain})")

    # Subscribe to echo topics
    subscribe_sync(mqtt_connection, topic_hello, sub_qos, on_message)
    subscribe_sync(mqtt_connection, topic_hb,    sub_qos, on_message)
    resub_topics = [topic_hello, topic_hb]
    print(f"Subscribed to {topic_hello} and {topic_hb}")

    # Publish 'online' retained indicator
    online = {"thing": client_id, "status": "online", "ts": now_ts()}
    mqtt_connection.publish(topic=topic_status, payload=json.dumps(online), qos=sub_qos, retain=True)

    # Helper to inflate payload
    def make_payload(base: dict):
        if args.payload_bytes > 0:
            base = dict(base)
            base["blob"] = "x" * args.payload_bytes
        return base

    # Optional hello
    hello = make_payload({"thing": client_id, "note": "hello from heartbeat device", "ts": now_ts()})
    mqtt_connection.publish(topic=topic_hello, payload=json.dumps(hello), qos=sub_qos)

    # Intentional authorization failures (subscribe & publish to forbidden topic)
    if args.cause_auth_fail:
        try:
            fut, _ = mqtt_connection.subscribe(topic=unauth_topic, qos=sub_qos, callback=lambda *a, **k: None)
            fut.result()
            print(f"[AUTH-FAIL TEST] attempted subscribe to unauthorized topic: {unauth_topic}")
        except Exception as e:
            print(f"[AUTH-FAIL SUB expected error] {e}")
        try:
            mqtt_connection.publish(topic=unauth_topic, payload=b'{"test":"deny_me"}', qos=sub_qos)
            print(f"[AUTH-FAIL TEST] attempted publish to unauthorized topic: {unauth_topic}")
        except Exception as e:
            print(f"[AUTH-FAIL PUB expected error] {e}")

    # Threaded burst so it doesn't block heartbeat loop
    def do_burst():
        if args.burst_count > 0:
            print(f"[BURST] sending {args.burst_count} messages (interval={args.burst_interval_ms} ms)")
            for i in range(args.burst_count):
                msg = make_payload({"thing": client_id, "seq": i+1, "ts": now_ts(), "type": "burst"})
                try:
                    mqtt_connection.publish(topic=topic_hb, payload=json.dumps(msg), qos=sub_qos, retain=args.retain)
                except Exception as e:
                    print(f"[BURST publish error] {e}")
                if args.burst_interval_ms > 0:
                    time.sleep(args.burst_interval_ms / 1000.0)

    # Determine when to trigger behaviors (immediately or after N heartbeats)
    trigger_after = max(args.after, 0)
    burst_started = False

    seq = 1
    last_flap = time.time()
    if args.no_heartbeat:
        print("[INFO] Heartbeat loop disabled (--no-heartbeat).")
    else:
        print(f"Heartbeat every {args.interval}s (Ctrl+C to stop)...")

    try:
        # If no heartbeat, we still want to optionally trigger behaviors
        if args.no_heartbeat:
            if trigger_after == 0 and not burst_started and args.burst_count > 0:
                threading.Thread(target=do_burst, daemon=True).start()
                burst_started = True

        while not stop and (not args.no_heartbeat):
            # Trigger behaviors when the Nth heartbeat occurs (or immediately if after == 0)
            if (not burst_started) and ((trigger_after == 0 and seq == 1) or (trigger_after > 0 and seq == trigger_after)):
                if args.burst_count > 0:
                    threading.Thread(target=do_burst, daemon=True).start()
                burst_started = True

            # Heartbeat publish
            msg = make_payload({"thing": client_id, "seq": seq, "ts": now_ts(), "type": "heartbeat"})
            try:
                mqtt_connection.publish(topic=topic_hb, payload=json.dumps(msg), qos=sub_qos, retain=args.retain)
                print(f"Published -> {topic_hb}: seq={seq} size≈{len(json.dumps(msg))}B (retain={args.retain})")
            except Exception as e:
                print(f"[heartbeat publish error] {e}")
            seq += 1

            # Optional intentional flap to drive aws:num-disconnects
            if args.flap_interval > 0 and (time.time() - last_flap) >= args.flap_interval:
                print("[FLAP] Disconnecting intentionally to trigger aws:num-disconnects ...")
                try:
                    mqtt_connection.disconnect().result()
                except Exception as e:
                    print(f"[FLAP disconnect error] {e}")
                time.sleep(1)
                print("[FLAP] Reconnecting ...")
                try:
                    mqtt_connection.connect().result()
                except Exception as e:
                    print(f"[FLAP connect error] {e}")
                last_flap = time.time()

            # Sleep in snappy chunks for responsive Ctrl+C
            remaining = args.interval
            while remaining > 0 and not stop:
                time.sleep(min(IOT_SLEEP_GRANULARITY, remaining))
                remaining -= IOT_SLEEP_GRANULARITY

    finally:
        # Non-retained offline status (LWT will also publish if an unexpected drop happens)
        offline = {"thing": client_id, "status": "offline", "ts": now_ts()}
        try:
            mqtt_connection.publish(topic=topic_status, payload=json.dumps(offline), qos=sub_qos, retain=False)
        except Exception:
            pass
        try:
            mqtt_connection.disconnect().result()
        except Exception:
            pass
        print("Disconnected.")

if __name__ == "__main__":
    main()