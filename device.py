#!/usr/bin/env python3
import argparse, json, os, signal, sys, time, threading, tempfile, shutil
from pathlib import Path
from awscrt import mqtt
from awsiot import mqtt_connection_builder
from dotenv import load_dotenv

load_dotenv()

IOT_KEEP_ALIVE_SECS = int(os.getenv('IOT_KEEP_ALIVE_SECS', '20'))
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

def create_invalid_cert_files(cert_path, key_path, ca_path, invalid_type):
    """Create invalid certificate files for testing"""
    temp_dir = tempfile.mkdtemp(prefix="invalid_certs_")
    
    if invalid_type == "missing":
        # Return non-existent paths
        return (
            os.path.join(temp_dir, "missing_cert.pem"),
            os.path.join(temp_dir, "missing_key.pem"),
            os.path.join(temp_dir, "missing_ca.pem")
        )
    
    elif invalid_type == "wrong":
        # Create dummy certificate files with invalid content
        invalid_cert = os.path.join(temp_dir, "wrong_cert.pem")
        invalid_key = os.path.join(temp_dir, "wrong_key.pem")
        invalid_ca = os.path.join(temp_dir, "wrong_ca.pem")
        
        # Write invalid PEM content
        with open(invalid_cert, 'w') as f:
            f.write("-----BEGIN CERTIFICATE-----\n")
            f.write("INVALID_CERTIFICATE_CONTENT_FOR_TESTING\n")
            f.write("-----END CERTIFICATE-----\n")
        
        with open(invalid_key, 'w') as f:
            f.write("-----BEGIN PRIVATE KEY-----\n")
            f.write("INVALID_PRIVATE_KEY_CONTENT_FOR_TESTING\n")
            f.write("-----END PRIVATE KEY-----\n")
        
        with open(invalid_ca, 'w') as f:
            f.write("-----BEGIN CERTIFICATE-----\n")
            f.write("INVALID_CA_CERTIFICATE_CONTENT_FOR_TESTING\n")
            f.write("-----END CERTIFICATE-----\n")
        
        return invalid_cert, invalid_key, invalid_ca
    
    elif invalid_type == "expired":
        # For expired certificates, we'll copy the original files but they should be expired
        # In a real scenario, you'd generate expired certificates
        # For testing purposes, we'll use wrong certificates to simulate the failure
        expired_cert = os.path.join(temp_dir, "expired_cert.pem")
        expired_key = os.path.join(temp_dir, "expired_key.pem")
        expired_ca = os.path.join(temp_dir, "expired_ca.pem")
        
        # Copy original files (in real scenario, these would be expired certificates)
        if os.path.exists(cert_path):
            shutil.copy2(cert_path, expired_cert)
        if os.path.exists(key_path):
            shutil.copy2(key_path, expired_key)
        if os.path.exists(ca_path):
            shutil.copy2(ca_path, expired_ca)
        
        # Modify the cert to make it invalid (simulating expiry)
        if os.path.exists(expired_cert):
            with open(expired_cert, 'r') as f:
                content = f.read()
            # Corrupt the certificate to simulate an expired/invalid cert
            content = content.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n# EXPIRED/INVALID")
            with open(expired_cert, 'w') as f:
                f.write(content)
        
        return expired_cert, expired_key, expired_ca
    
    return cert_path, key_path, ca_path

def attempt_invalid_cert_connection(endpoint, cert, key, ca, client_id, args):
    """Attempt connection with invalid certificates to trigger aws:num-auth-failures"""
    print(f"[INVALID-CERT TEST] Testing with {args.invalid_cert} certificates...")
    
    for attempt in range(args.invalid_cert_attempts):
        print(f"[INVALID-CERT] Attempt {attempt + 1}/{args.invalid_cert_attempts} with {args.invalid_cert} certificates")
        
        try:
            # Create invalid certificate files
            invalid_cert, invalid_key, invalid_ca = create_invalid_cert_files(cert, key, ca, args.invalid_cert)
            
            # Attempt to create MQTT connection with invalid certificates
            invalid_mqtt_connection = mqtt_connection_builder.mtls_from_path(
                endpoint=endpoint,
                cert_filepath=invalid_cert,
                pri_key_filepath=invalid_key,
                ca_filepath=invalid_ca,
                client_id=f"{client_id}_invalid_{attempt}",
                clean_session=True,
                keep_alive_secs=IOT_KEEP_ALIVE_SECS,
                on_connection_interrupted=lambda *args, **kwargs: None,
                on_connection_resumed=lambda *args, **kwargs: None
            )
            
            print(f"[INVALID-CERT] Attempting connection with {args.invalid_cert} certificates...")
            connect_future = invalid_mqtt_connection.connect()
            
            try:
                # Short timeout to fail quickly
                connect_future.result(timeout=10.0)
                print(f"[INVALID-CERT] Unexpected success with {args.invalid_cert} certificates!")
                # If successful, disconnect immediately
                try:
                    disconnect_future = invalid_mqtt_connection.disconnect()
                    disconnect_future.result(timeout=5.0)
                except Exception:
                    pass
            except Exception as e:
                print(f"[INVALID-CERT] Expected failure with {args.invalid_cert} certificates: {e}")
                # This is expected - the connection should fail with invalid certificates
                
        except Exception as e:
            print(f"[INVALID-CERT] Certificate setup error: {e}")
        
        # Clean up temporary files
        try:
            if 'invalid_cert' in locals() and os.path.exists(os.path.dirname(invalid_cert)):
                shutil.rmtree(os.path.dirname(invalid_cert), ignore_errors=True)
        except Exception:
            pass
        
        if attempt < args.invalid_cert_attempts - 1:
            print(f"[INVALID-CERT] Waiting {args.invalid_cert_delay}s before next attempt...")
            time.sleep(args.invalid_cert_delay)
    
    print(f"[INVALID-CERT TEST] Completed {args.invalid_cert_attempts} attempts with {args.invalid_cert} certificates")

def main():
    signal.signal(signal.SIGINT, handle_sigint)

    p = argparse.ArgumentParser(description="AWS IoT Core heartbeat device (with Defender test toggles)")
    p.add_argument("--thing-name", required=True, help="Thing name (also used as MQTT clientId)")
    p.add_argument("--cert-dir", default=os.getenv("IOT_CERT_DIR", "certs"), help="Base dir containing certs/<thingName>/")
    p.add_argument("--interval", type=int, default=int(os.getenv("IOT_INTERVAL", "10")), help="Seconds between heartbeats")
    p.add_argument("--qos", type=int, default=int(os.getenv("IOT_QOS", "1")), choices=[0,1], help="QoS 0/1 for pub/sub")
    p.add_argument("--retain", action="store_true", default=getenv_bool("IOT_RETAIN", False),
                   help="Publish heartbeats as retained (also enable via IOT_RETAIN=1)")
    p.add_argument("--clean-session", action="store_true", default=getenv_bool("IOT_CLEAN_SESSION", False),
                   help="Use clean session; default is persistent session (or set IOT_CLEAN_SESSION=1)")

    p.add_argument("--cause-auth-fail", action="store_true", default=getenv_bool("IOT_CAUSE_AUTH_FAIL", False),
                   help="Publish/subscribe to an unauthorized topic to trigger aws:num-authorization-failures")
    p.add_argument("--burst-count", type=int, default=int(os.getenv("IOT_BURST_COUNT", "0")),
                   help="Extra messages to burst-send (to trip aws:num-messages-sent)")
    p.add_argument("--burst-interval-ms", type=int, default=int(os.getenv("IOT_BURST_INTERVAL_MS", "0")),
                   help="Delay between burst messages in ms")
    p.add_argument("--payload-bytes", type=int, default=int(os.getenv("IOT_PAYLOAD_BYTES", "0")),
                   help="Append a filler 'blob' of this size to each publish (to trip aws:message-byte-size)")
    p.add_argument("--flap-interval", type=int, default=int(os.getenv("IOT_FLAP_INTERVAL", "0")),
                   help="If >0, disconnect/reconnect every N seconds (to trip aws:num-disconnects)")

    p.add_argument("--invalid-cert", choices=["expired", "wrong", "missing"], default=None,
                   help="Test with invalid certificates to trigger aws:num-auth-failures (expired/wrong/missing)")
    p.add_argument("--invalid-cert-attempts", type=int, default=int(os.getenv("IOT_INVALID_CERT_ATTEMPTS", "3")),
                   help="Number of connection attempts with invalid certificates")
    p.add_argument("--invalid-cert-delay", type=int, default=int(os.getenv("IOT_INVALID_CERT_DELAY", "5")),
                   help="Delay between invalid certificate connection attempts in seconds")

    p.add_argument("--no-heartbeat", action="store_true", default=getenv_bool("IOT_NO_HEARTBEAT", False),
                   help="Disable periodic heartbeat loop")
    p.add_argument("--after", type=int, default=int(os.getenv("IOT_AFTER", "0")),
                   help="Trigger behaviors after N heartbeats (0 = immediately)")

    args = p.parse_args()

    d = Path(args.cert_dir) / args.thing_name
    endpoint = (d / IOT_ENDPOINT_FILENAME).read_text().strip()
    cert = str(d / IOT_CERT_FILENAME)
    key  = str(d / IOT_KEY_FILENAME)
    ca   = str(d / IOT_CA_FILENAME)
    client_id = args.thing_name

    topic_pattern = IOT_TOPIC_PATTERN.format(client_id=client_id)
    topic_hello  = f"{topic_pattern}/hello"
    topic_hb     = f"{topic_pattern}/heartbeat"
    topic_status = f"{topic_pattern}/status"
    unauth_topic = IOT_UNAUTH_TOPIC_PATTERN.format(client_id=client_id)

    sub_qos = mqtt.QoS.AT_LEAST_ONCE if args.qos == 1 else mqtt.QoS.AT_MOST_ONCE

    will_payload = json.dumps({"thing": client_id, "status": "offline", "ts": now_ts()})

    def on_conn_interrupted(connection, error, **kwargs):
        print(f"Connection interrupted: {error}")
        time.sleep(0.5)

    resub_topics = []

    def on_conn_resumed(connection, return_code, session_present, **kwargs):
        print(f"Connection resumed: return_code={return_code}, session_present={session_present}")
        if not session_present:
            for t in resub_topics:
                try:
                    subscribe_sync(connection, t, sub_qos, on_message)
                    print(f"[re-subscribed] {t}")
                except Exception as e:
                    print(f"[re-subscribe failed] {t}: {e}")
        else:
            print("[connection resumed] Session persisted, subscriptions maintained")

    # Handle invalid certificate testing
    if args.invalid_cert:
        attempt_invalid_cert_connection(endpoint, cert, key, ca, client_id, args)
        print("[INVALID-CERT] Now proceeding with valid certificates for normal operation...")
    
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
    connect_future = mqtt_connection.connect()
    try:
        connect_future.result(timeout=30.0)
        print("Connected.")
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    def on_message(topic, payload, dup, qos, retain, **kwargs):
        print(f"[MSG] {topic}: {payload.decode()} (retain={retain})")

    subscribe_sync(mqtt_connection, topic_hello, sub_qos, on_message)
    subscribe_sync(mqtt_connection, topic_hb,    sub_qos, on_message)
    resub_topics = [topic_hello, topic_hb]
    print(f"Subscribed to {topic_hello} and {topic_hb}")

    online = {"thing": client_id, "status": "online", "ts": now_ts()}
    mqtt_connection.publish(topic=topic_status, payload=json.dumps(online), qos=sub_qos, retain=True)

    def make_payload(base: dict):
        if args.payload_bytes > 0:
            base = dict(base)
            base["blob"] = "x" * args.payload_bytes
        return base

    hello = make_payload({"thing": client_id, "note": "hello from heartbeat device", "ts": now_ts()})
    mqtt_connection.publish(topic=topic_hello, payload=json.dumps(hello), qos=sub_qos)

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

    trigger_after = max(args.after, 0)
    burst_started = False

    seq = 1
    last_flap = time.time()
    if args.no_heartbeat:
        print("[INFO] Heartbeat loop disabled (--no-heartbeat).")
    else:
        print(f"Heartbeat every {args.interval}s (Ctrl+C to stop)...")

    try:
        if args.no_heartbeat:
            if trigger_after == 0 and not burst_started and args.burst_count > 0:
                threading.Thread(target=do_burst, daemon=True).start()
                burst_started = True

        while not stop and (not args.no_heartbeat):
            if (not burst_started) and ((trigger_after == 0 and seq == 1) or (trigger_after > 0 and seq == trigger_after)):
                if args.burst_count > 0:
                    threading.Thread(target=do_burst, daemon=True).start()
                burst_started = True

            msg = make_payload({"thing": client_id, "seq": seq, "ts": now_ts(), "type": "heartbeat"})
            try:
                publish_future = mqtt_connection.publish(topic=topic_hb, payload=json.dumps(msg), qos=sub_qos, retain=args.retain)
                print(f"Published -> {topic_hb}: seq={seq} size≈{len(json.dumps(msg))}B (retain={args.retain})")
            except Exception as e:
                print(f"[heartbeat publish error] {e}")
                time.sleep(0.1)
            seq += 1

            if args.flap_interval > 0 and (time.time() - last_flap) >= args.flap_interval:
                print("[FLAP] Disconnecting intentionally to trigger aws:num-disconnects ...")
                try:
                    disconnect_future = mqtt_connection.disconnect()
                    try:
                        disconnect_future.result(timeout=5.0)
                    except Exception as e:
                        print(f"[FLAP disconnect timeout/error] {e}")
                except Exception as e:
                    print(f"[FLAP disconnect error] {e}")
                time.sleep(1)
                print("[FLAP] Reconnecting ...")
                try:
                    connect_future = mqtt_connection.connect()
                    try:
                        connect_future.result(timeout=10.0)
                    except Exception as e:
                        print(f"[FLAP connect timeout/error] {e}")
                except Exception as e:
                    print(f"[FLAP connect error] {e}")
                last_flap = time.time()

            remaining = args.interval
            while remaining > 0 and not stop:
                time.sleep(min(IOT_SLEEP_GRANULARITY, remaining))
                remaining -= IOT_SLEEP_GRANULARITY

    finally:
        offline = {"thing": client_id, "status": "offline", "ts": now_ts()}
        try:
            publish_future = mqtt_connection.publish(topic=topic_status, payload=json.dumps(offline), qos=sub_qos, retain=False)
            try:
                publish_future.result(timeout=2.0)
            except Exception:
                pass
        except Exception:
            pass
        try:
            disconnect_future = mqtt_connection.disconnect()
            try:
                disconnect_future.result(timeout=5.0)
            except Exception:
                pass
        except Exception:
            pass
        print("Disconnected.")

if __name__ == "__main__":
    main()