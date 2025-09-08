# log_parser.py
import pandas as pd
import regex as re

# This pattern matches the structure of a standard Apache log line.
APACHE_LOG_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)] "(?P<method>\S+) (?P<uri>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)

def parse_log_file(filepath):
    """Reads a log file and converts it into a structured pandas DataFrame."""
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            match = APACHE_LOG_REGEX.match(line)
            if match:
                records.append(match.groupdict())

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    # Convert columns to the correct data types for analysis
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
    df['status'] = df['status'].astype(int)
    df['size'] = pd.to_numeric(df['size'], errors='coerce').fillna(0)
    return df
