import pandas as pd
import argparse
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

def train_model(input_csv, output_model):
    df = pd.read_csv(input_csv)

    # Encode protocol as numeric
    le = LabelEncoder()
    df['protocol'] = le.fit_transform(df['protocol'])

    features = ['protocol', 'length', 'src_port', 'dst_port', 'tcp_flags']
    X = df[features]

    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X)

    joblib.dump({'model': model, 'le': le}, output_model)
    print(f"Model saved to {output_model}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train anomaly detection model")
    parser.add_argument('--input', type=str, required=True, help="Input CSV features file")
    parser.add_argument('--model', type=str, required=True, help="Output model file")
    args = parser.parse_args()

    train_model(args.input, args.model)
