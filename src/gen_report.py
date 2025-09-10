import pandas as pd

def gen_report(anomalies_csv, report_csv):
    df = pd.read_csv(anomalies_csv)
    summary = df.groupby(['src_ip', 'dst_ip', 'protocol']).size().reset_index(name='count')
    summary = summary.sort_values(by='count', ascending=False)
    summary.to_csv(report_csv, index=False)
    print(f"Automated report saved to {report_csv}")
