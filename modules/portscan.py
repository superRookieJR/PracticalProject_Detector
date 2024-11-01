import pandas as pd
import pyshark
import joblib
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from colorama import Fore, Style

class PortScanDetector:
    def __init__(self):
        # Load model, scaler, and feature names
        self.model, self.scaler, self.feature_names = self.load_model_and_scaler()
        self.packet_stats = defaultdict(lambda: {"unique_ports": set(), "syn_no_ack": 0, "syn_count": 0, "timestamps": []})
        self.last_alert_time = None
        self.alert_cooldown = timedelta(seconds=10)  # Cooldown for sending alerts
        self.sender_email = "iamunknow.alpha@gmail.com"  # Your email
        self.receiver_email = "65050292@kmitl.ac.th"    # Receiver's email
        self.password = "hsbf dzad bkrb nmow"  # App-specific password

    def load_model_and_scaler(self):
        # Load the trained model, scaler, and feature names
        model = joblib.load('models/portscan/port_scan_model.pkl')
        scaler = joblib.load('models/portscan/scaler.pkl')
        feature_names = joblib.load('models/portscan/feature_names.pkl')
        return model, scaler, feature_names

    def packet_to_features(self, packet):
        # Convert packet data to features for model input
        features = {feature: 0.0 for feature in self.feature_names}
        
        try:
            if hasattr(packet, 'tcp'):
                src_ip = packet.ip.src
                dst_port = int(packet.tcp.dstport)
                syn_flag = 1 if 'SYN' in packet.tcp.flags else 0
                ack_flag = 1 if 'ACK' in packet.tcp.flags else 0
                rst_flag = 1 if 'RST' in packet.tcp.flags else 0
                packet_length = int(packet.length)

                # Update stats for behavior tracking
                self.packet_stats[src_ip]["unique_ports"].add(dst_port)
                self.packet_stats[src_ip]["timestamps"].append(float(packet.sniff_timestamp))

                if syn_flag:
                    self.packet_stats[src_ip]["syn_count"] += 1
                    if not ack_flag:
                        self.packet_stats[src_ip]["syn_no_ack"] += 1

                # Extract features
                features['Source Port'] = int(packet.tcp.srcport)
                features['Destination Port'] = dst_port
                features['Protocol'] = 6  # TCP protocol number
                features['Packet Length'] = packet_length
                features['Unique Port Count'] = len(self.packet_stats[src_ip]["unique_ports"])
                features['SYN No ACK Ratio'] = self.packet_stats[src_ip]["syn_no_ack"] / (self.packet_stats[src_ip]["syn_count"] + 1e-5)

                # Time-based feature: count unique packets in the last 5 seconds
                current_time = float(packet.sniff_timestamp)
                self.packet_stats[src_ip]["timestamps"] = [
                    t for t in self.packet_stats[src_ip]["timestamps"] if current_time - t <= 5
                ]
                features['Packets Last 5 Sec'] = len(self.packet_stats[src_ip]["timestamps"])
                features['RST Flag Count'] = rst_flag

            # Scale features
            features_df = pd.DataFrame(features, index=[0])
            scaled_features = self.scaler.transform(features_df)
            return pd.DataFrame(scaled_features, columns=self.feature_names)

        except Exception as e:
            print(f"Error during packet feature extraction: {e}")
            return pd.DataFrame()

    def send_email_notification(self, subject, message):
        current_time = datetime.now()
        if self.last_alert_time is None or (current_time - self.last_alert_time >= self.alert_cooldown):
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.receiver_email
            msg['Subject'] = subject
            msg.attach(MIMEText(message, 'plain'))

            try:
                with smtplib.SMTP('smtp.gmail.com', 587) as server:
                    server.starttls()
                    server.login(self.sender_email, self.password)
                    server.sendmail(self.sender_email, self.receiver_email, msg.as_string())
                print(Fore.YELLOW + "Email sent successfully!" + Style.RESET_ALL)
                self.last_alert_time = current_time
            except Exception as e:
                print(f"Error sending email: {e}")
        else:
            print(Fore.CYAN + "Alert cooldown active; email not sent." + Style.RESET_ALL)

    def run(self):
        print(Fore.CYAN + "Starting packet capture on loopback interface..." + Style.RESET_ALL)
        capture = pyshark.LiveCapture(interface='Adapter for loopback traffic capture')

        try:
            for packet in capture.sniff_continuously():
                features_df = self.packet_to_features(packet)
                if not features_df.empty:
                    prediction = self.model.predict(features_df.values)
                    result = 'Port Scan Detected' if prediction[0] == 1 else 'Benign Traffic'
                    print(f"Prediction: {result}")

                    with open("log/portscan_log.txt", "a") as log_file:
                        log_file.write(f"{datetime.now()}: {result}\n")

                    if prediction[0] == 1:
                        self.send_email_notification("Port Scan Alert!", f"Port scan detected at {datetime.now()}.")

        except Exception as e:
            print(f"Error during packet capture: {e}")

        print(Fore.YELLOW + "Finished capturing packets." + Style.RESET_ALL)