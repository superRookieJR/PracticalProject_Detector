from modules.portscan import PortScanDetector
from modules.sqli import SQLiDetector

sqli_detector = SQLiDetector()
sqli_detector.run()

# portscan_detector = PortScanDetector()
# portscan_detector.run()