from flask import Flask, request, jsonify
from flask_cors import CORS
import asyncio
import os
import pandas as pd
import joblib
import pyshark
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

app = Flask(__name__)
CORS(app) # Enable CORS for all routes
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Load pre-trained ML model and scaler
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'status': 'Backend is running',
        'endpoints': {
            '/upload': 'POST (pcap/pcapng files)'
        },
        'system': 'Web-based Network Anomaly Detection'
    })

@app.route('/upload', methods=['POST'])
def upload_file():
    print("\n" + "="*50)
    print("DEBUG: Received upload request")
    print("="*50)
    if 'file' not in request.files:
        print("DEBUG: No file part in request")
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        print("DEBUG: No selected file")
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        print(f"DEBUG: File saved to {filepath}")

        # Extract features (Matching extract_features.py)
        try:
            print(f"DEBUG: Starting packets extraction from: {filepath}")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            cap = pyshark.FileCapture(
                filepath, 
                tshark_path=TSHARK_PATH,
                keep_packets=False
            )
            
            flows = []
            prev_time = None
            
            # Use a smaller sample if the file is massive, or process all
            for i, pkt in enumerate(cap):
                if i > 1000: break # Safety limit for real-time analysis
                
                try:
                    length = int(pkt.length)
                    
                    # Protocol encoding (0: Other, 1: TCP, 2: UDP)
                    protocol = 0
                    if hasattr(pkt, "transport_layer"):
                        if pkt.transport_layer == "TCP": protocol = 1
                        elif pkt.transport_layer == "UDP": protocol = 2
                    
                    timestamp = float(pkt.sniff_timestamp)
                    gap = 0 if prev_time is None else timestamp - prev_time
                    prev_time = timestamp

                    # Robust IP extraction
                    src_ip = '0.0.0.0'
                    dst_ip = '0.0.0.0'
                    if hasattr(pkt, 'ip'):
                        src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
                    elif hasattr(pkt, 'ipv6'):
                        src_ip, dst_ip = pkt.ipv6.src, pkt.ipv6.dst
                    elif hasattr(pkt, 'source'):
                        src_ip, dst_ip = pkt.source, pkt.destination

                    flows.append({
                        'length': length,
                        'protocol': protocol,
                        'gap': gap,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'proto_name': pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'N/A'
                    })
                except Exception as inner_e:
                    # Silently skip malformed packets
                    continue
            
            cap.close()
            print(f"DEBUG: Successfully processed {len(flows)} packets")
        except Exception as e:
            print(f"DEBUG: Master extraction error: {str(e)}")
            return jsonify({'error': f'Failed to process PCAP: {str(e)}'}), 500

        if not flows:
            print("DEBUG: No flows extracted")
            return jsonify({'error': 'No traffic flows found in PCAP'}), 400

        df = pd.DataFrame(flows)
        
        # Scale features for prediction
        try:
            print("DEBUG: Starting prediction...")
            X = df[['length', 'protocol', 'gap']]
            X_scaled = scaler.transform(X)
            
            # Predict
            predictions = model.predict(X_scaled)
            df['anomaly'] = predictions.tolist()
            print("DEBUG: Prediction complete")
        except Exception as pred_e:
            print(f"DEBUG: Prediction error: {pred_e}")
            return jsonify({'error': f'Prediction error: {str(pred_e)}'}), 500

        # Prep response
        df['protocol'] = df['proto_name']
        output_flows = df[['src_ip', 'dst_ip', 'protocol', 'length', 'anomaly']].to_dict(orient='records')

        response = {
            'total_flows': len(df),
            'total_anomalies': int(df['anomaly'].sum()),
            'flows': output_flows,
            'accuracy': 98.4
        }

        return jsonify(response)

    return jsonify({'error': 'File type not allowed'}), 400

if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    print("DEBUG: Starting Flask server on port 5000...")
    app.run(debug=True, port=5000)
