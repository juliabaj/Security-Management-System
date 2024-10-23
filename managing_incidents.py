import random
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk


title_type_dict = {"SOC287 - Arbitrary File Read on Checkpoint Security Gateway CVE-2024-24919": "Web attack", "SOC282 - Phishing Alert - Deceptive Mail Detected":"Exchange", "SOC176 - RDP Brute Force Detected": "Brute Force", "SOC239 - Remote Code Execution Detected in Splunk Enterprise":"Unauthorized access", "SOC202 - FakeGPT Malicious Chrome Extension": "Data Leakage", "SOC173 - Follina 0-Day Detected":"Malware"}

severity = ['High', 'Medium', 'Critical']

severity = ['Medium', 'High', 'Critical']

def generate_random_date():
    today = datetime.today()
    random_days = random.randint(0, 30)
    random_date = today - timedelta(days=random_days)
    random_time = f"{random.randint(0, 23):02}:{random.randint(0, 59):02}"
    return random_date.strftime(f"%Y-%m-%d {random_time}")


def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
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

#def view_incidents():



def playbook():
    playbook = {
        "Web attack": ["Step 1. Sprawdź kto jest właścicielem adresu IP\n Czy ruch pochodzi z zewnątrz\n Zweryfikuj bezpieczeństwo tego adresu (VirusTotal)",
                       "Step 2. Przeanalizuj ruch HTTP (SQL Injections, XSS etc.",
                       "Step 3. jak napisac po polsku is the traffic malicious xddd? "

                        ]
    }




#def update_status_and_generate_raport():


#Interfejs
def show_incident(event):
    selected_item = tree.selection()[0]  # Pobranie zaznaczonego wiersza
    incident = tree.item(selected_item)['values']  # Pobranie danych incydentu

    id_label.config(text=f"ID: {incident[0]}")
    title_label.config(text=f"Title: {incident[1]}")
    type_label.config(text=f"Type: {incident[2]}")
    severity_label.config(text=f"Severity: {incident[3]}")
    date_label.config(text=f"Date: {incident[4]}")
    ip_label.config(text=f"Source Address: {incident[5]}")

list_of_incidents = generating_and_monitoring_incidents()
#print(list_of_incidents)

root = tk.Tk()
root.title("Incident Management System")

tree = ttk.Treeview(root, columns=("ID", "Title", "Type", "Severity", "Date", "IP"), show="headings")

# Ustawienia nagłówków
tree.heading("ID", text="ID")
tree.heading("Title", text="Title")
tree.heading("Type", text="Type")
tree.heading("Severity", text="Severity")
tree.heading("Date", text="Date")
tree.heading("IP", text="Source ip")


# Dodanie incydentów do tabeli
for incident in list_of_incidents:
    tree.insert('', tk.END, values=(incident['id'], incident['title'], incident['type'], incident['severity'], incident['date'], incident['ip']))

tree.pack(pady=20)

# Po wybraniu danego incydentu, wyswietlaja sie szczegoly
tree.bind('<<TreeviewSelect>>', show_incident)

#Definicja etykiet szczegółow
id_label = tk.Label(root, text="ID: ", font=("Arial", 12), fg="red", underline=True)  # Podkreślenie tekstu
id_label.pack()

title_label = tk.Label(root, text="Title: ", font=("Arial", 12))
title_label.pack()

type_label = tk.Label(root, text="Type: ", font=("Arial", 12))
type_label.pack()

severity_label = tk.Label(root, text="Severity: ", font=("Arial", 12))
severity_label.pack()

date_label = tk.Label(root, text="Date: ", font=("Arial", 12))
date_label.pack()

ip_label = tk.Label(root, text="Source Address: ", font=("Arial", 12))
ip_label.pack()

# Uruchomienie głównej pętli tkinter
root.mainloop()
