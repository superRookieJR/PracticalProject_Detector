from datetime import datetime, timedelta
import pickle
import smtplib
import pyshark
from email.mime.text import MIMEText
from colorama import Fore, Style

# Gmail SMTP configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_ADDRESS = 'iamunknow.alpha@gmail.com'  # Replace with your Gmail address
EMAIL_PASSWORD = 'hsbf dzad bkrb nmow'  # Replace with your app-specific password from Gmail
TO_EMAIL = '65050969@kmitl.ac.th'  # Replace with the recipient's email

# Load the pre-trained model and vectorizer
with open('models/sqli/model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

with open('models/sqli/vectorizer.pkl', 'rb') as vec_file:
    vectorizer = pickle.load(vec_file)

class SQLi:
    def __init__(self):
        self.model = model
        self.vectorizer = vectorizer

    # Function to classify content for SQL injection
    def classify_sql_injection(self, content):
        content_vectorized = self.vectorizer.transform([content])
        prediction = self.model.predict(content_vectorized)
        return prediction[0]
    
    # Function to send email notification
    def send_email_alert(self, detected_data):
        subject = "SQL Injection Detected"
        body = f"SQL Injection attempt detected.\n\nDetails:\n{detected_data}"
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = f'Automated Threat Alert <{EMAIL_ADDRESS}>'
        msg['To'] = TO_EMAIL
        
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()  # Upgrade the connection to secure
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                server.sendmail(EMAIL_ADDRESS, TO_EMAIL, msg.as_string())
            print(Fore.YELLOW + "Alert email sent successfully!" + Style.RESET_ALL)
        except Exception as e:
            print(f"Failed to send email: {e}")

    # Function to extract HTTP payload and classify potential SQL injection
    def extract_http_payload(self, packet):
        try:
            detected_data = ""
            if 'IP' in packet:
                ip_layer = packet.ip
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                detected_data += f"\nSource IP: {src_ip}\nDestination IP: {dst_ip}\n"

            if 'HTTP' in packet:
                http_layer = packet.http
                if hasattr(http_layer, 'host'):
                    detected_data += f"Host: {http_layer.host}\n"
                if hasattr(http_layer, 'request_method'):
                    detected_data += f"Request Method: {http_layer.request_method}\n"
                if hasattr(http_layer, 'request_uri'):
                    detected_data += f"Request URI: {http_layer.request_uri}\n"
                    
                    # Detect SQL injection in the URL
                    prediction = self.classify_sql_injection(http_layer.request_uri)

                    with open("log/sqli_log.txt", "a") as log_file:
                        log_file.write(f"{datetime.now()}: {"SQL Injection detected in the URL: " + http_layer.request_uri if prediction == 1 else "No SQL Injection detected in the URL"}\n\n")

                    if prediction == 1:
                        print(Fore.RED + "SQL Injection detected in the URL!" + Style.RESET_ALL)
                        self.send_email_alert(detected_data + f"Detected in: Request URI\nURI: {http_layer.request_uri}")
                    else:
                        print(Fore.GREEN + "No SQL Injection detected in the URL." + Style.RESET_ALL)

                if hasattr(http_layer, 'file_data'):
                    if isinstance(http_layer.file_data, str):
                        detected_data += f"Raw HTTP Body: {http_layer.file_data}\n"
                        prediction = self.classify_sql_injection(http_layer.file_data)

                        with open("log/sqli_log.txt", "a") as log_file:
                            log_file.write(f"{datetime.now()}: {"SQL Injection detected in the HTTP body: " + http_layer.file_data if prediction == 1 else "No SQL Injection detected in the HTTP body"}\n\n")

                        if prediction == 1:
                            print(Fore.RED + "SQL Injection detected in the HTTP body!" + Style.RESET_ALL)
                            self.send_email_alert(detected_data + "Detected in: HTTP Body\n")
                        else:
                            print(Fore.GREEN + "No SQL Injection detected in the HTTP body." + Style.RESET_ALL)
        except Exception as e:
            print(f"Error extracting payload: {e}")
            
    def run(self):
        # Use a continuous loop to capture packets indefinitely
        print(Fore.CYAN + "\nStarting packet capture on loopback interface...\n" + Style.RESET_ALL)
        try:
            # Capture on the loopback interface
            capture = pyshark.LiveCapture(interface='Adapter for loopback traffic capture', display_filter='http')
            
            for packet in capture.sniff_continuously():
                self.extract_http_payload(packet)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nPacket capture stopped." + Style.RESET_ALL)