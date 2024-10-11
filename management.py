import re
import random
from datetime import datetime, timedelta


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

def load_logs(file):
    with open("log_file.txt", 'r') as file:
        logs = file.readlines()

    if logs:
        return logs
    else:
        return []

def generate_phising_attack():
def generate_ddos_attack():
def analize_logs_detect_incidents():


if __name__ == "__main__":

    generate_logs("collect_logs.txt", 10)