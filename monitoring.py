<<<<<<< HEAD
import re
import random
import string
from datetime import datetime, timedelta
import time


def generate_logs(file, number_of_logs):
    #list of actions that a client may request from a server during logging
    actions = [
        "GET /index.html",  # request for uploading a page
        "POST /login",      # request for logging
        "GET /products.html",  # request for uploading products page
        "GET /contact.html",  # request for uploading a contact page
        "POST /logout",       # request for log out
        "GET /search?q=example" # request for searching
    ]

    for _ in range(number_of_logs):
        action = random.choice(actions)
        ip = f"192.168.1.{random.randint(0, 255)}"  #generating random ip address
        current_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        log_format = f"{current_time} {ip} {action}\n"

        with open("collect_logs.txt", 'a') as file:
            file.write(log_format)

    print("zapisano do pliku")

def ddos_attack_simulator(ddos_file, ip_num, request_per_ip, attack_duration):
    botnet_ips = []
    for _ in range(ip_num):
        botnet_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        botnet_ips.append(botnet_ip)

    actions = [
        "GET /index.html",  # request for uploading a page
        "POST /login",  # request for logging
        "GET /products.html",  # request for uploading products page
        "GET /contact.html",  # request for uploading a contact page
        "POST /logout",  # request for log out
        "GET /search?q=example"  # request for searching
    ]

    start_time = datetime.now()
    with open("ddos_file.txt", 'w') as ddos_file:
        while (datetime.now() - start_time).total_seconds() < attack_duration:
            for ip in botnet_ips:
                for _ in range(request_per_ip):
                    action = random.choice(actions)
                    current_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
                    log_format = f"{current_time} {ip} {action}\n"
                    ddos_file.write(log_format)

                time.sleep(0.01)

    print(f"Wygenerowano {request_per_ip*ip_num} żądań w ciągu {attack_duration} sekund")

def load_logs(file):
    with open("log_file.txt", 'r') as file:
        logs = file.readlines()

    if logs:
        return logs
    else:
        return []

def domains_generator():
    length = random.randint(5, 10)
    name = ''.join(random.choices(string.ascii_lowercase, k=length))
    ends = ['.com', '.net', '.org', '.info']


    path = random.choice([
        "/login",
        "/verify",
        "/update",
        "/win",
        "/special-prize",
        "/secure",
        "/password",
        "/bank",
        "/money",
        "/register"
        "/homepage",
        "/aboutus",
        "/contact",
        "/services",
        "/products",
        "/blog",
        "/info",
        "/support"
    ])

    domain_name = f"http://{name}{random.choice(ends)}{path}"
    return domain_name

def phising_attack_simulator(phising_file, number_of_logs):

    requests = [
        "GET",
        "POST",
        "PUT"
    ]

    with open("phising_file.txt", 'w') as phising_file:
        for _ in range(number_of_logs):
            ip = f"192.168.1.{random.randint(0, 255)}"  #generating random ip address
            domain_name = domains_generator()
            action = f"{random.choice(requests)} {domain_name}"
            current_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
            log_format = f"{current_time} {ip} {action}\n"
            phising_file.write(log_format)



def analize_logs_detect_incidents(log_file):

# Analyzing Phising logs

    patterns = [
        r"/login",                        # "login into"
        r"/verify",                       # "verify your account"
        r"/update",                       # "update your account"
        r"/win",                          # "YOU WIN A SPECIAL PRIZE"
        r"/special prize"
        r"/secure",                       # "Secure your account now"
        r"/password",                     # "Your password is about to expire"
        r"/bank",                         # "Log into your bank account now in order to.."
        r"/money",                        # "Register now if you want to win big money"
        r"/register",
        r"[^\w\-\.]"                     # Check if there are any special signs in domain name
    ]
    # Iterating through all logs and dividing them into 4 parts to get only the "url" part.
    # Log format = [ date, time, ip, request url] - request url is a 4th part of the log
    logs = load_logs("log_file.txt")
    for log in logs:
        divide_log = log.split(" ")
        url = divide_log[4]
        for pattern in patterns:
            if re.search(pattern, url):
                print(f"Podejrzenie phisingu na stronie {url}")


if __name__ == "__main__":

    #phising_attack_simulator("phising_file.txt", 10)
    #analize_logs_detect_incidents("log_file.txt")
    generate_logs("collect_logs.txt", 10)
    ddos_attack_simulator("ddos_file.txt", 3, 20, 5)
=======
import random
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk


title_type_dict = {"SOC287 - Arbitrary File Read on Checkpoint Security Gateway CVE-2024-24919": "Web attack", "SOC282 - Phishing Alert - Deceptive Mail Detected":"Exchange", "SOC176 - RDP Brute Force Detected": "Brute Force", "SOC239 - Remote Code Execution Detected in Splunk Enterprise":"Unauthorized access", "SOC202 - FakeGPT Malicious Chrome Extension": "Data Leakage", "SOC173 - Follina 0-Day Detected":"Malware"}
severity = ['Low', 'Medium', 'High']
def generate_random_date():
    today = datetime.today()
    random_days = random.randint(0, 30)
    random_date = today - timedelta(days=random_days)
    return random_date.strftime("%Y-%m-%d %H:%M:%S")

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



#def steps():



<<<<<<<< HEAD:management.py
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
========
    phising_attack_simulator("phising_file.txt", 10)
    analize_logs_detect_incidents("log_file.txt")
    #generate_logs("collect_logs.txt", 10)
    #ddos_attack_simulator("ddos_file.txt", 3, 20, 5)
>>>>>>>> 211a5c18fcbca78ab873dff985d1c59e7b9b0f5f:monitoring.py
>>>>>>> 211a5c18fcbca78ab873dff985d1c59e7b9b0f5f
