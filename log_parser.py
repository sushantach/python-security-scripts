import re
from collections import Counter

class LogAnalyzer:
    """A class to ingest, parse, and analyze server logs for security anomalies."""
    
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        # Regex pattern to match standard log formats (IP, Timestamp, Request, Status Code)
        self.log_pattern = re.compile(
            r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"(?P<method>\w+) (?P<request>.*?) HTTP/.*?" (?P<status>\d{3})'
        )

    def parse_logs(self):
        """Reads the log file line by line and extracts structured data."""
        parsed_events = []
        try:
            with open(self.log_file_path, 'r') as file:
                for line in file:
                    match = self.log_pattern.search(line)
                    if match:
                        parsed_events.append(match.groupdict())
        except FileNotFoundError:
            print(f"Error: The file '{self.log_file_path}' was not found.")
        return parsed_events

    def detect_brute_force(self, parsed_events, threshold=5):
        """Flags IP addresses with failed login attempts exceeding the threshold."""
        failed_attempts = []
        for event in parsed_events:
            # Simulating a failed login attempt (Status code 401 Unauthorized or 403 Forbidden)
            if event['status'] in ['401', '403'] or 'login' in event['request'].lower():
                failed_attempts.append(event['ip'])
        
        # Count occurrences per IP
        ip_counts = Counter(failed_attempts)
        suspect_ips = {ip: count for ip, count in ip_counts.items() if count >= threshold}
        
        return suspect_ips

    def generate_security_report(self):
        """Orchestrates the parsing and analysis to output a clean security summary."""
        print("=== Starting Security Log Analysis ===")
        events = self.parse_logs()
        
        if not events:
            print("No valid log data parsed.")
            return

        print(f"Total log lines processed: {len(events)}")
        
        # Run brute force detection
        suspects = self.detect_brute_force(events)
        
        print("\n--- Brute Force & Anomalous Activity Report ---")
        if suspects:
            print(f"[ALERT] The following IPs exceeded the failed attempt threshold:")
            for ip, count in suspects.items():
                print(f"🚨 IP Address: {ip} | Failed Attempts: {count}")
        else:
            print("✅ No suspicious brute-force activity detected.")
        print("=======================================")

# Example Usage:
if __name__ == "__main__":
    # In a real environment, you would point this to a real access.log file
    analyzer = LogAnalyzer("server_access.log")
    analyzer.generate_security_report()
          
