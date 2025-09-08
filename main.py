# main.py
import time
import json
import pandas as pd
from datetime import datetime
import sys
import os

# Add the current directory to the system path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our custom modules
import config
from log_parser import parse_log_file
from anomaly_detector import AnomalyDetector
from threat_intel import get_ip_reputation
from alerter import send_email_alert

def process_logs(detector, last_run_df):
    """The main logic to process logs and detect threats."""
    print(f"\n[{datetime.now()}] --- Running analysis ---")

    # 1. Parse all current logs
    df = parse_log_file(config.LOG_FILE_PATH)
    if df.empty:
        print("Log file is empty or unreadable.")
        return df

    # 2. Find new log entries since last run
    if not last_run_df.empty:
        # Simple way to find new logs: get the difference in rows
        new_rows_mask = ~df.isin(last_run_df.to_dict('list')).all(axis=1)
        new_rows = df[new_rows_mask]

        if new_rows.empty:
            print("No new log entries to analyze.")
            return df # Return the full dataframe for the next cycle
    else:
        new_rows = df

    if new_rows.empty:
        print("No new log entries detected.")
        return df

    print(f"Found {len(new_rows)} new log entries.")

    # 3. Use our ML model to find anomalies in the new entries
    anomalies_df = detector.predict(new_rows)

    if anomalies_df.empty:
        print("No anomalies detected in new entries.")
        return df

    print(f"🚨 Found {len(anomalies_df)} potential anomalies!")

    # 4. Investigate anomalies
    for _, anomaly in anomalies_df.iterrows():
        ip = anomaly['ip']
        reason = f"Suspiciously high request rate from IP: {ip}"

        # Check reputation
        reputation = get_ip_reputation(ip)
        if reputation and reputation['abuseConfidenceScore'] > 50:
            reason += f" | High AbuseIPDB Score: {reputation['abuseConfidenceScore']}%"

            # 5. Send Alert and log it
            alert_body = f"Threat Detected:\n\nIP: {ip}\nReason: {reason}\nTimestamp: {anomaly['timestamp']}"
            send_email_alert("Security Alert: Suspicious Activity Detected", alert_body)

            # Log to our JSON file for the dashboard
            alert_data = {**anomaly.to_dict(), "reason": reason}
            alert_data['timestamp'] = alert_data['timestamp'].isoformat()
            with open("alerts.json", "a") as f:
                f.write(json.dumps(alert_data) + "\n")

    return df # Return the full dataframe to use in the next cycle

if __name__ == "__main__":
    # Initialize our tools
    detector = AnomalyDetector()

    # First, train the model on the initial log data to learn "normal"
    initial_df = parse_log_file(config.LOG_FILE_PATH)
    detector.train(initial_df)

    # This will be our memory of what we've already processed
    processed_df = pd.DataFrame() 

    # The main loop to simulate real-time monitoring
    try:
        while True:
            processed_df = process_logs(detector, processed_df)
            # Wait for 30 seconds before checking the log file again
            print("--- Waiting for 30 seconds... ---")
            time.sleep(30)
    except KeyboardInterrupt:
        print("\nShutting down analyzer.")
