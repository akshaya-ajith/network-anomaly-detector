import pyshark
import pandas as pd
import argparse

def extract_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    rows = []

    for pkt in cap:
        try:
            protocol = pkt.highest_layer
            length = int(pkt.length)
            timestamp = float(pkt.sniff_timestamp)
            
            src_ip = pkt.ip.src if 'IP' in pkt else '0.0.0.0'
            dst_ip = pkt.ip.dst if 'IP' in pkt else '0.0.0.0'
            src_port = int(pkt[protocol].srcport) if hasattr(pkt[protocol], 'srcport') else 0
            dst_port = int(pkt[protocol].dstport) if hasattr(pkt[protocol], 'dstport') else 0
            
            tcp_flags = int(pkt.tcp.flags, 16) if 'TCP' in pkt else 0

            rows.append({
                'timestamp': timestamp,
                'protocol': protocol,
                'length': length,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'tcp_flags': tcp_flags
            })
        except Exception:
            continue

    df = pd.DataFrame(rows)
    return df

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract features from a .pcap file")
    parser.add_argument('--input', type=str, required=True, help="Input .pcap file")
    parser.add_argument('--output', type=str, required=True, help="Output CSV file")
    args = parser.parse_args()

    df = extract_features(args.input)
    df.to_csv(args.output, index=False)
    print(f"Features extracted to {args.output}")