from datetime import datetime
import pickle
import smtplib
import pyshark
from email.mime.text import MIMEText
from colorama import Fore, Style
import binascii
import urllib.parse
import json

# โหลดโมเดล
with open('models/sqli/model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

with open('models/sqli/vectorizer.pkl', 'rb') as vec_file:
    vectorizer = pickle.load(vec_file)

class SQLiDetector:
    def __init__(self):
        self.model = model
        self.vectorizer = vectorizer

    def classify_sql_injection(self, content):
        content_vectorized = self.vectorizer.transform([content])
        prediction = self.model.predict(content_vectorized)
        return prediction[0]

    def extract_http_payload(self, packet):
        try:
            detected_uri_injection = False
            detected_body_injection = False

            if 'HTTP' in packet:
                http_layer = packet.http
                detected_data = ""

                # Handle URI Detection
                if hasattr(http_layer, 'request_uri') and not detected_body_injection:
                    raw_uri = http_layer.request_uri
                    decoded_uri = urllib.parse.unquote(raw_uri)

                    detected_data += f"Request URI: {raw_uri}\n"
                    detected_data += f"Decoded URI: {decoded_uri}\n"

                    prediction = self.classify_sql_injection(decoded_uri)

                    with open("log/sqli_log.txt", "a") as log_file:
                        log_msg = f"{datetime.now()}: "
                        log_msg += "SQL Injection DETECTED in URI.\n" if prediction == 1 else "No SQL Injection in URI.\n"
                        log_file.write(log_msg + "\n")

                    if prediction == 1:
                        print(Fore.RED + "⚠️ SQL Injection DETECTED in Request URI!" + Style.RESET_ALL)
                        print(detected_data)
                        detected_uri_injection = True
                    else:
                        print(Fore.GREEN + "✅ No SQL Injection detected in Request URI." + Style.RESET_ALL)

            # Handle Body Detection via TCP Payload (only if URI wasn't detected)
            if 'TCP' in packet and not detected_uri_injection:
                tcp_layer = packet.tcp
                if hasattr(tcp_layer, 'payload'):
                    try:
                        # Payload: Raw TCP data in hexadecimal format
                        raw_tcp_payload = binascii.unhexlify(tcp_layer.payload.replace(':', ''))

                        # Decode the payload content to UTF-8 (handling errors if not valid)
                        decoded_payload = raw_tcp_payload.decode('utf-8', errors='ignore')

                        # Split the payload to extract the body (after \r\n\r\n)
                        if '\r\n\r\n' in decoded_payload:
                            body_part = decoded_payload.split('\r\n\r\n', 1)[1]

                            # URL-decode the body to remove encoded characters (e.g., %27)
                            body_part = urllib.parse.unquote(body_part)

                            # Try parsing the body if it's JSON
                            try:
                                body_json = json.loads(body_part)
                                print(Fore.CYAN + "💬 Detected JSON Body: Parsing for SQLi..." + Style.RESET_ALL)
                                body_part = body_json["command"]  # Rebuild JSON string for consistency
                                print(body_part)
                            except json.JSONDecodeError:
                                pass

                            # Classify the SQLi attempt in the body
                            prediction = self.classify_sql_injection(body_part)

                            with open("log/sqli_log.txt", "a") as log_file:
                                log_msg = f"{datetime.now()}: "
                                log_msg += "SQL Injection DETECTED in HTTP Body.\n" if prediction == 1 else "No SQL Injection in HTTP Body.\n"
                                log_file.write(log_msg + "\n")

                            if prediction == 1:
                                print(Fore.RED + "⚠️ SQL Injection DETECTED in HTTP Body!" + Style.RESET_ALL)
                                print(f"Body Content: {body_part}")
                                detected_body_injection = True
                            else:
                                print(Fore.GREEN + "✅ No SQL Injection detected in HTTP Body." + Style.RESET_ALL)

                    except Exception as e:
                        print(Fore.YELLOW + f"Error decoding TCP payload: {e}" + Style.RESET_ALL)

        except Exception as e:
            print(Fore.RED + f"Error extracting payload: {e}" + Style.RESET_ALL)

    def run(self):
        print(Fore.CYAN + "🌐 Starting packet capture on loopback interface..." + Style.RESET_ALL)
        try:
            # Change to loopback interface
            capture = pyshark.LiveCapture(interface='lo0', display_filter='http')
            for packet in capture.sniff_continuously():
                self.extract_http_payload(packet)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n🛑 Packet capture stopped by user." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Error in capture: {e}" + Style.RESET_ALL)