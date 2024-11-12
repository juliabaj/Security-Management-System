import random
from datetime import datetime, timedelta
from prettytable import PrettyTable

# Mapping for incidents and their corresponding playbooks
title_type_dict = {
    "SOC287 - Arbitrary File Read on Checkpoint Security Gateway CVE-2024-24919": "Web attack",
    "SOC282 - Phishing Alert - Deceptive Mail Detected": "Exchange",
    "SOC176 - RDP Brute Force Detected": "Brute Force",
    "SOC239 - Remote Code Execution Detected in Splunk Enterprise": "Unauthorized access",
    "SOC202 - FakeGPT Malicious Chrome Extension": "Data Leakage",
    "SOC173 - Follina 0-Day Detected": "Malware"
}

severity = ['High', 'Medium', 'Critical']

# Function to generate a random date
def generate_random_date():
    today = datetime.today()
    random_days = random.randint(0, 30)
    random_date = today - timedelta(days=random_days)
    random_time = f"{random.randint(0, 23):02}:{random.randint(0, 59):02}"
    return random_date.strftime(f"%Y-%m-%d {random_time}")

# Function to generate random IP addresses
def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Generate random incidents for the table
def generating_and_monitoring_incidents():
    incidents = []
    incident_number = 10
    for i in range(incident_number):
        random_title = random.choice(list(title_type_dict.keys()))
        incident = {
            'id': i+1,
            'date': generate_random_date(),
            'title': random_title,
            'type': title_type_dict[random_title],
            'severity': random.choice(severity),
            'ip': generate_random_ip()
        }
        incidents.append(incident)
    return incidents


def print_table(incidents):
    headers = ['ID', 'Date', 'Title', 'Type', 'Severity', 'Source IP']
    table = PrettyTable(headers)

    for incident in incidents:
        table.add_row([incident['id'], incident['date'], incident['title'], incident['type'], incident['severity'], incident['ip']])


    return table




