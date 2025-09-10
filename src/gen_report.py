import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os

def gen_report(anomalies_csv, report_file):
    df = pd.read_csv(anomalies_csv)
    
    # Basic stats
    total_anomalies = len(df)
    anomalies_by_protocol = df['protocol'].value_counts()
    top_src_ips = df['src_ip'].value_counts().head(10)
    top_dst_ports = df['dst_port'].value_counts().head(10)
    
    print(f"Total anomalies detected: {total_anomalies}")
    print("\nAnomalies by protocol:")
    print(anomalies_by_protocol)
    print("\nTop 10 source IPs:")
    print(top_src_ips)
    print("\nTop 10 destination ports:")
    print(top_dst_ports)
    
    # If no report file, just print stats
    if not report_file:
        return
    
    # Plotting
    sns.set_theme(style="whitegrid")
    
    # Protocol distribution
    plt.figure(figsize=(8,5))
    sns.countplot(y='protocol', data=df, order=anomalies_by_protocol.index)
    plt.title("Anomalies by Protocol")
    plt.tight_layout()
    plt.savefig(os.path.splitext(report_file)[0] + "_protocol.png")
    plt.close()
    
    # Top source IPs
    plt.figure(figsize=(8,5))
    sns.barplot(y=top_src_ips.index, x=top_src_ips.values)
    plt.title("Top 10 Source IPs with Anomalies")
    plt.tight_layout()
    plt.savefig(os.path.splitext(report_file)[0] + "_src_ips.png")
    plt.close()
    
    # Top destination ports
    plt.figure(figsize=(8,5))
    sns.barplot(y=top_dst_ports.index.astype(str), x=top_dst_ports.values)
    plt.title("Top 10 Destination Ports with Anomalies")
    plt.tight_layout()
    plt.savefig(os.path.splitext(report_file)[0] + "_dst_ports.png")
    plt.close()
    
    print(f"\nVisual report saved to {report_file} (PNG files)")
