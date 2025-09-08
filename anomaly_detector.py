# anomaly_detector.py
import pandas as pd
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self):
        # The model will flag about 1% of the data as potential anomalies.
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self.is_trained = False

    def _create_features(self, df):
        """
        Converts log data into numbers the model can understand.
        We'll calculate the number of requests per IP in a given time frame.
        """
        if df.empty:
            return pd.DataFrame()
        # For simplicity, we count requests per IP. More features make it smarter!
        features = df['ip'].value_counts().reset_index()
        features.columns = ['ip', 'request_count']
        return features

    def train(self, df):
        """Learns what 'normal' traffic looks like from a sample of log data."""
        print("Training the anomaly detection model...")
        feature_df = self._create_features(df)
        if feature_df.empty:
            print("Not enough data to train.")
            return

        # We train the model on the request counts.
        self.model.fit(feature_df[['request_count']])
        self.is_trained = True
        print("Model training complete.")

    def predict(self, df):
        """Identifies unusual activity in new log data."""
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction.")

        feature_df = self._create_features(df)
        if feature_df.empty:
            return pd.DataFrame()

        # The model predicts; -1 means it's an anomaly.
        predictions = self.model.predict(feature_df[['request_count']])
        anomalous_ips = feature_df[predictions == -1]['ip']

        # Return the original log entries for the IPs that behaved abnormally.
        return df[df['ip'].isin(anomalous_ips)]
