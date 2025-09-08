# dashboard.py
import streamlit as st
import pandas as pd
import json
from datetime import datetime

st.set_page_config(layout="wide")
st.title("🚨 Real-Time Security Log Dashboard")

def load_alerts():
    """Loads alerts from our JSON file."""
    try:
        with open("alerts.json", "r") as f:
            # Read line by line to handle JSON objects
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []

alerts = load_alerts()

if not alerts:
    st.warning("No alerts recorded yet. The system might be running or no threats found.")
else:
    df_alerts = pd.DataFrame(alerts)
    df_alerts['timestamp'] = pd.to_datetime(df_alerts['timestamp'])
    df_alerts = df_alerts.sort_values(by="timestamp", ascending=False)

    st.header("Latest Incident Alerts")
    # Display key information
    st.dataframe(df_alerts[['timestamp', 'ip', 'reason', 'uri', 'status']])

    col1, col2 = st.columns(2)

    with col1:
        st.header("Top Suspicious IPs")
        ip_counts = df_alerts['ip'].value_counts()
        st.bar_chart(ip_counts)

    with col2:
        st.header("Alerts Over Time")
        # Resample counts alerts per hour
        time_counts = df_alerts.set_index('timestamp').resample('H').size()
        st.line_chart(time_counts)

st.button("Refresh Data")
