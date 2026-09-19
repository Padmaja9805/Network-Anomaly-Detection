import pyshark
import pandas as pd

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"


def extract_features(pcap_file, label):

    rows = []
    prev_time = None

    try:
        cap = pyshark.FileCapture(
            pcap_file,
            tshark_path=TSHARK_PATH,   # ⭐ VERY IMPORTANT
            keep_packets=False        # low memory
        )

        for i, pkt in enumerate(cap):

            try:
                length = int(pkt.length)

                # protocol → numeric encoding (better for ML)
                protocol = 0
                if hasattr(pkt, "transport_layer"):
                    if pkt.transport_layer == "TCP":
                        protocol = 1
                    elif pkt.transport_layer == "UDP":
                        protocol = 2

                timestamp = float(pkt.sniff_timestamp)

                if prev_time is None:
                    gap = 0
                else:
                    gap = timestamp - prev_time

                prev_time = timestamp

                rows.append([length, protocol, gap, label])

            except:
                continue

        cap.close()

    except Exception as e:
        print("❌ Error reading:", pcap_file, e)

    df = pd.DataFrame(rows, columns=["length", "protocol", "gap", "label"])

    print(f"✅ {len(df)} packets extracted from {pcap_file}")

    return df
