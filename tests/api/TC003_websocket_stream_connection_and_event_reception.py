import websocket
import threading
import time
import json
import requests
import ssl

BASE_URL = "http://localhost:8000/D:\\Antigravity 2\\API Endpoint Scanner"
WS_URL = BASE_URL.replace("http://", "ws://").replace("https://", "wss://")
STREAM_PATH = "/stream?client_type=ui"
TIMEOUT = 30

def test_websocket_stream_connection_and_event_reception():
    """ Test WebSocket connection to /stream?client_type=ui to verify reception of expected messages
        Also test connection failure when backend is down. """

    received_events = {
        "LIFECYCLE_EVENT": False,
        "LIVE_ATTACK_FEED": False,
        "REPORT_READY": False,
        "errors": []
    }
    stop_event = threading.Event()

    def on_message(ws, message):
        try:
            event = json.loads(message)
            event_type = event.get("type")
            if event_type == "LIFECYCLE_EVENT":
                # Expect keys: state, mode in payload
                if isinstance(event.get("payload"), dict) and \
                   "state" in event["payload"] and "mode" in event["payload"]:
                    received_events["LIFECYCLE_EVENT"] = True
            elif event_type == "LIVE_ATTACK_FEED":
                payload = event.get("payload", {})
                expected_keys = {"timestamp", "agent", "method", "endpoint", "severity", "risk_score"}
                if expected_keys.issubset(payload.keys()):
                    received_events["LIVE_ATTACK_FEED"] = True
            elif event_type == "REPORT_READY":
                # Should contain scan_id in payload
                if isinstance(event.get("payload"), dict) and "scan_id" in event["payload"]:
                    received_events["REPORT_READY"] = True
            # else ignore
        except (json.JSONDecodeError, TypeError) as e:
            received_events["errors"].append(f"Malformed or invalid message: {str(e)}")

    def on_error(ws, error):
        received_events["errors"].append(f"WebSocket error: {error}")

    def on_close(ws, close_status_code, close_msg):
        stop_event.set()

    def on_open(ws):
        pass  # No initial message to send for subscription

    ws_url = WS_URL + STREAM_PATH

    # Helper to run the websocket client
    def run_websocket():
        # websocket.WebSocketApp requires callback functions
        ws = websocket.WebSocketApp(
            ws_url,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )
        # Run with SSL disabled for localhost or normal mode according to ws_url
        if ws_url.startswith("wss://"):
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            ws.run_forever()

    # First test: normal connection expecting messages
    ws_thread = threading.Thread(target=run_websocket, daemon=True)
    ws_thread.start()

    # Wait and collect messages for a duration (e.g., 15 seconds)
    timeout_time = time.time() + 15
    while time.time() < timeout_time and not all([received_events["LIFECYCLE_EVENT"],
                                                  received_events["LIVE_ATTACK_FEED"],
                                                  received_events["REPORT_READY"],
                                                  received_events["errors"]]):
        time.sleep(0.5)

    # Stop websocket after wait
    stop_event.set()
    time.sleep(1)  # Allow graceful stop

    # Assert at least all expected event types were received without critical errors
    assert received_events["LIFECYCLE_EVENT"], "Did not receive LIFECYCLE_EVENT message"
    assert received_events["LIVE_ATTACK_FEED"], "Did not receive LIVE_ATTACK_FEED message"
    assert received_events["REPORT_READY"], "Did not receive REPORT_READY message"
    assert len(received_events["errors"]) == 0, f"Errors occurred during WebSocket messages: {received_events['errors']}"

    # Second test: connection failure scenario

    # Attempt connecting to a non-routable or closed port to simulate backend down
    # Modify WS url to invalid port (e.g., 9999) to simulate failure
    fail_ws_url = ws_url.replace("8000", "9999")

    failure_errors = []
    failure_closed = threading.Event()

    def on_error_fail(ws, error):
        failure_errors.append(error)
        failure_closed.set()

    def on_close_fail(ws, code, msg):
        failure_closed.set()

    def run_fail_ws():
        ws = websocket.WebSocketApp(
            fail_ws_url,
            on_error=on_error_fail,
            on_close=on_close_fail
        )
        try:
            ws.run_forever(ping_interval=5, ping_timeout=2, ping_payload="ping")
        except Exception as e:
            failure_errors.append(str(e))
            failure_closed.set()

    fail_thread = threading.Thread(target=run_fail_ws, daemon=True)
    fail_thread.start()

    # Wait up to 15 seconds for connection error/closure event
    failure_closed.wait(timeout=15)

    # We expect connection failure error or handshake failure captured
    assert failure_errors or failure_closed.is_set(), "Expected network error or handshake failure when backend is down"
    # Optionally check error message contains common connection failure strings
    err_msgs = " ".join(map(str, failure_errors)).lower()
    assert any(msg in err_msgs for msg in ["connection refused", "handshake", "error", "failed"]), "No typical network error message detected"

test_websocket_stream_connection_and_event_reception()