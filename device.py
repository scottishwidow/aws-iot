#!/usr/bin/env python3
import argparse
import json
import time
import signal
from pathlib import Path
from awscrt import mqtt
from awsiot import mqtt_connection_builder

stop = False
def handle_sigint(signum, frame):
    global stop
    stop = True
    print("\nStopping...")

def subscribe_sync(conn, topic, qos, cb):
    ret = conn.subscribe(topic=topic, qos=qos, callback=cb)
    fut = ret[0] if isinstance(ret, tuple) else ret
    return fut.result()

def main():
    p = argparse.ArgumentParser(description="AWS IoT Core heartbeat device (MQTT over TLS)")
    p.add_argument("--thing-name", required=True, help="Thing name (also used as MQTT clientId)")
    p.add_argument("--cert-dir", default="certs", help="Base directory that contains certs/<thingName>/")
    p.add_argument("--interval", type=int, default=10, help="Seconds between heartbeats")
    p.add_argument("--qos", type=int, default=1, choices=[0, 1], help="MQTT QoS for publish/subscribe")
    p.add_argument("--retain", action="store_true", help="Publish heartbeats as retained")
    p.add_argument("--clean-session", action="store_true", help="Use clean session (default: persistent session)")
    args = p.parse_args()

    signal.signal(signal.SIGINT, handle_sigint)

    d = Path(args.cert_dir) / args.thing_name
    endpoint = (d / "endpoint.txt").read_text().strip()
    cert = str(d / "device.pem.crt")
    key = str(d / "private.pem.key")
    ca = str(d / "AmazonRootCA1.pem")
    client_id = args.thing_name

    topic_hello = f"devices/{client_id}/hello"
    topic_hb = f"devices/{client_id}/heartbeat"
    will_topic = f"devices/{client_id}/status"
    will_payload = json.dumps({"thing": client_id, "status": "offline", "ts": int(time.time())})

    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint=endpoint,
        cert_filepath=cert,
        pri_key_filepath=key,
        ca_filepath=ca,
        client_id=client_id,
        clean_session=args.clean_session,  # default False → persistent session
        keep_alive_secs=30,
        will_topic=will_topic,
        will_payload=will_payload,
        will_qos=mqtt.QoS.AT_LEAST_ONCE if args.qos == 1 else mqtt.QoS.AT_MOST_ONCE,
    )

    print(f"Connecting to {endpoint} as clientId={client_id} ...")
    mqtt_connection.connect().result()
    print("Connected.")

    def on_message(topic, payload, dup, qos, retain, **kwargs):
        print(f"[MSG] {topic}: {payload.decode()} (retain={retain})")

    sub_qos = mqtt.QoS.AT_LEAST_ONCE if args.qos == 1 else mqtt.QoS.AT_MOST_ONCE
    subscribe_sync(mqtt_connection, topic_hello, sub_qos, on_message)
    subscribe_sync(mqtt_connection, topic_hb, sub_qos, on_message)
    print(f"Subscribed to {topic_hello} and {topic_hb}")

    # Announce online
    online = {"thing": client_id, "status": "online", "ts": int(time.time())}
    mqtt_connection.publish(topic=will_topic, payload=json.dumps(online), qos=sub_qos, retain=True)

    # Optional “hello” message
    hello = {"thing": client_id, "note": "hello from heartbeat device", "ts": int(time.time())}
    mqtt_connection.publish(topic=topic_hello, payload=json.dumps(hello), qos=sub_qos)

    print(f"Heartbeat every {args.interval}s (Ctrl+C to stop)...")
    seq = 1
    try:
        while not stop:
            hb = {"thing": client_id, "seq": seq, "ts": int(time.time()), "type": "heartbeat"}
            mqtt_connection.publish(
                topic=topic_hb,
                payload=json.dumps(hb),
                qos=sub_qos,
                retain=args.retain,
            )
            print(f"Published -> {topic_hb}: {hb} (retain={args.retain})")
            seq += 1

            # sleep in small chunks so Ctrl+C is responsive
            remaining = args.interval
            while remaining > 0 and not stop:
                sleep_chunk = 0.25 if remaining >= 0.25 else remaining
                time.sleep(sleep_chunk)
                remaining -= sleep_chunk
    finally:
        # best-effort offline notice (non-retained)
        offline = {"thing": client_id, "status": "offline", "ts": int(time.time())}
        try:
            mqtt_connection.publish(topic=will_topic, payload=json.dumps(offline), qos=sub_qos, retain=False)
        except Exception:
            pass
        mqtt_connection.disconnect().result()
        print("Disconnected.")

if __name__ == "__main__":
    main()
