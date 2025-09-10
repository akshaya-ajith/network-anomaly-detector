import pandas as pd
import argparse
import joblib
from gen_report import gen_report

def detect_anomalies(input_csv, model_file, output_csv):
    df = pd.read_csv(input_csv)
    
    data = joblib.load(model_file)
    model = data['model']
    le = data['le']

    df['protocol'] = le.transform(df['protocol'])
    features = ['protocol', 'length', 'src_port', 'dst_port', 'tcp_flags']
    X = df[features]

    df['anomaly'] = model.predict(X)
    df['anomaly'] = df['anomaly'].apply(lambda x: 1 if x == -1 else 0)

    df[df['anomaly'] == 1].to_csv(output_csv, index=False)
    print(f"Anomalies saved to {output_csv}, total detected: {df['anomaly'].sum()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect anomalies in network traffic")
    parser.add_argument('--input', type=str, required=True, help="Input CSV features file")
    parser.add_argument('--model', type=str, required=True, help="Trained model file")
    parser.add_argument('--output', type=str, required=True, help="Output anomalies CSV file")
    parser.add_argument('--report', type=str, required=False, help="Anomaly report file")
    args = parser.parse_args()

    detect_anomalies(args.input, args.model, args.output)
    if args.report:
        gen_report(args.output, args.report)
