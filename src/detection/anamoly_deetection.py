##############
## TEMPLATE ##
##############

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()

    def preprocess_data(self, data):
        # Convert data to numerical features
        # Example: Convert IP addresses to integers, protocols to one-hot encoding, etc.
        return data

    def train(self, data):
        preprocessed_data = self.preprocess_data(data)
        scaled_data = self.scaler.fit_transform(preprocessed_data)
        self.model.fit(scaled_data)

    def detect_anomalies(self, data):
        preprocessed_data = self.preprocess_data(data)
        scaled_data = self.scaler.transform(preprocessed_data)
        predictions = self.model.predict(scaled_data)
        return predictions

# Example usage
if __name__ == "__main__":
    # Load your data
    data = pd.read_csv("network_logs.csv")

    detector = AnomalyDetector()
    detector.train(data)

    # New data for prediction
    new_data = pd.read_csv("new_network_logs.csv")
    anomalies = detector.detect_anomalies(new_data)

    print("Anomalies detected:", sum(anomalies == -1))