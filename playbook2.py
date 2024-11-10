import questionary
from managing_incidents import print_table, generating_and_monitoring_incidents


def brute_force():
    answer_b1 = questionary.select('Czy zauważyłeś jedną z podanych poniżej podejrzanych aktywności?'
                                 '\n-Wielokrotne nieudane próby logowania z tego samego adresu IP.'
                                 '\n-Logowania na wiele kont z jednego adresu IP'
                                 '\n-Logowania na jedno konto z wielu różnych adresów IP.'
                                 '\n-Nadmierne zużycie zasobów przez pojedyncze konto.'
                                 '\n-Nieudane próby logowania z sekwencyjnie alfabetycznymi nazwami użytkowników lub hasłami.'
                                 ,choices=['Tak', 'Nie']).ask()
    if answer_b1 == 'Tak':
        print("Wykryto potencjalny atak brute-force. Działanie podczas ataku:")
        questions1 = [
            {
                "type": "confirm",
                "name": "first",
                "message": "1.Zablokuj adres IP lub zakres IP atakującego – uniemożliw dostęp z adresów IP związanych z atakiem.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "second",
                "message": "2.Natychmiast zablokuj dostęp do konta i skontaktuj się z administratorem systemu.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "third",
                "message": "3.Oddziel dotknięte systemy lub sieci, aby zapobiec rozprzestrzenianiu się ataku.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "fourth",
                "message": "4.Ogranicz szybkość logowania (Rate Limiting) – zmniejsz częstotliwość możliwych logowań na sekundę, aby ograniczyć skuteczność ataku.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "fifth",
                "message": "5.Zastosuj firewalla aplikacji internetowych, monitoruj i filtruj ruch sieciowy, aby zatrzymać nieautoryzowane połączenia.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "sixth",
                "message": "6.Zgromadź logi, pliki, zrzuty ekranu i pakiety sieciowe, aby dokładnie przeanalizować atak.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "seventh",
                "message": "7.Przywróć system do czystego stanu, skorzystaj z kopii zapasowych, aktualizacji i poprawek, aby usunąć wszelkie ślady ataku.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "eighth",
                "message": "8.Przeskanuj systemy, aby wykryć wszelkie złośliwe oprogramowanie, tylne furtki lub luki w zabezpieczeniach.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "nineth",
                "message": "9.Kolejne kroki do rozważenia:\na.Ustaw blokadę konta po określonej liczbie nieudanych prób\n"
                           "b.Opóźnij czas odpowiedzi – im dłuższy czas między próbami logowania, nim trudniej jest atakującemu odgadnąć hasło"
                           "\nc.Rozważ zmianę haseł na trudniejsze do przewidzenia, unikaj stosowania słów, połóż nacisk na nieprzewidywalność hasła, zastosuj małe i duże litery, cyfry oraz znaki specjalne."
                           "\nd.Wdróż uwierzytelnianie wieloskładnikowe.\ne.Zastosuj CAPTCHA, aby uniemożliwić automatyczne ataki.",
                "default": True,
            }
        ]
        questionary.prompt(questions1)
        komentarz = questionary.select("Czy chcesz dodać komentarz do incydentu?", choices = ['Tak', 'Nie']).ask()
        if komentarz == 'Tak':
            with open('komentarz_brute_force.txt', 'w') as kom:
                tekst = input('Dodaj komentarz:\n')
                kom.write(tekst)

    if answer_b1 == 'Nie':
        print("Nie wykryto potencjalnego ataku brute-force. Działanie zapobiegawcze:")
        questions2 = [
            {
                "type": "confirm",
                "name": "first",
                "message": "1.Ustaw blokadę konta po określonej liczbie nieudanych prób",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "second",
                "message": "2.Opóźnij czas odpowiedzi – im dłuższy czas między próbami logowania, nim trudniej jest atakującemu odgadnąć hasło",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "third",
                "message": "3.Rozważ zmianę haseł na trudniejsze do przewidzenia, unikaj stosowania słów, połóż nacisk na nieprzewidywalność hasła, zastosuj małe i duże litery, cyfry oraz znaki specjalne.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "fourth",
                "message": "4.Wdróż uwierzytelnianie wieloskładnikowe.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "fifth",
                "message": "5.Zastosuj CAPTCHA, aby uniemożliwić automatyczne ataki.",
                "default": True,
            }
        ]
        questionary.prompt(questions2)


def unauthorised_access():
    answer_u1 = questionary.select('Czy adres IP jest wewnętrzy czy zewnętrzny?',
                                 choices=['Zewnętrzny', 'Wewnętrzny']).ask()
    if answer_u1 == 'Zewnętrzny':
        answer_u2 = questionary.select('Czy adres IP jest częścią naszej organizacji?',
                                     choices=['Tak', 'Nie']).ask()
        if answer_u2 == 'Tak':
            print('Zidentyfikowano próbę nieautoryzowanego dostępu wewnętrznego')
        else:
            print('Zidentyfikowano próbę nieautoryzowanego dostępu zewnętrznego')


def malware():
    answer_m1 = questionary.select('Czy system zgłasza wykrycie złośliwego oprogramowania',
                                 choices=['Tak', 'Nie']).ask()
    if answer_m1 == 'Tak':
        print('Zidentyfikowano incydent Malware.')
        questions3 = [
            {
                "type": "confirm",
                "name": "first",
                "message": "1.Wyizoluj zainfekowane systemy tak szybko, jak to możliwe.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "second",
                "message": "2.Zlokalizuj inne zainfekowane hosty (jeżeli takie istnieją).",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "third",
                "message": "3.Zbadaj czy złośliwe oprogramowanie działa w kontekście użytkownika. Jeżeli tak, wyłącz to konto (lub konta) do czasu zakończenia dochodzenia",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "fourth",
                "message": "4.Jeśli to możliwe użyj odizolowanego systemu do analizy złośliwego oprogramowania. Połączenie sieciowe na urządzeniu nie powinno być dostępne, aktywność sieciowa może ostrzec atakującego o trwającym dochodzeniu",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "fifth",
                "message": "5.Zaobserwuj wszelkie próby nawiązania połączenia sieciowego oraz wszelkie pliki utworzone lub zmodyfikowane przez złośliwe oprogramowanie. Zapisz miejsce, w którym znajdowało się złośliwe oprogramowanie w zainfekowanym systemie.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "sixth",
                "message": "6.Użyj polecenia PowerShell „Get-FileHash”, aby uzyskać wartość hash SHA-256 pliku złośliwego oprogramowania.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "seventh",
                "message": "7.Przeanalizuj wszystkie możliwe wektory infekcji: e-mail, PDF, strona internetowa, oprogramowanie pakietowe.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "eighth",
                "message": "8.Zamknij luki związane z początkowym punktem wejścia (np. zmiany zapory, blokowanie wiadomości e-mail)",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "nineth",
                "message": "9.Wprowadź tymczasowe zasady bezpieczeństwa (np. segmentacja sieci), aby powstrzymać rozprzestrzenianie się złośliwego oprogramowania",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "tenth",
                "message": "10.Zachowaj istotne dane i kopie zapasowe, np. logi, próbki złośliwego oprogramowania.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "eleventh",
                "message": "11.Wymień lub odbuduj systemy po zabezpieczeniu danych i uzyskaniu krytycznych artefaktów.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "twelveth",
                "message": "12.Przywróć systemy z czystych kopii zapasowych lub odbuduj od podstaw.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "thirteth",
                "message": "13.Zresetuj hasła dla dotkniętych kont i wprowadź zabezpieczenia zapobiegawcze.",
                "default": True,
            },
            {
                "type": "confirm",
                "name": "fourteth",
                "message": "14.Monitoruj aktywność pod kątem dalszej złośliwej działalności związanej z incydentem.",
                "default": True,
            }
        ]
        questionary.prompt(questions3)
        komentarz = questionary.select("Czy chcesz dodać komentarz do incydentu?", choices = ['Tak', 'Nie']).ask()
        if komentarz == 'Tak':
            with open('komentarz_malware.txt', 'w') as kom:
                tekst = input('Dodaj komentarz:\n')
                kom.write(tekst)
    else:
        print('Brak potwierdzenia obecności malware.')

def web_attack():
    print('Zidentyfikowano incydent Web Attack.')
    questions4 = [
        {
            "type": "confirm",
            "name": "first",
            "message": "1.Wykrycie incydentu - Monitoruj logi z systemów IDS/IPS/NIDS/EDR, zapory sieciowej, proxy oraz honeypotów. Zwracaj uwagę na powiadomienia od użytkowników lub z helpdesku.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "second",
            "message": "2.Rejestrowanie podejrzanej aktywności. Użyj narzędzi do przechwytywania ruchu (np. wireshark, tcpdump), aby zebrać podejrzane ramki sieciowe do analizy.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "third",
            "message": "3.Zidentyfikuj techniczne cechy ruchu:\na.Adres(y) IP źródła\nb.Używane pory, TTL, identyfikator pakietu\nc.Używane protokoły\nd.Docelowe maszyny/usługi\ne.Wykorzystane exploity\nf.Zalogowane zdalne konta",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "fourth",
            "message": "4.Przeglądaj logi i statystyki z urządzeń sieciowych, analizuj alerty IDS.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "fifth",
            "message": "5.Jeżeli atak dotyczy kluczowych zasobów, odłącz obszar lub komputery od sieci, aby ograniczyć rozprzestrzenianie się zagrożenia.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "sixth",
            "message": "6.Zablokuj źródło ataku, zastosuj reguły zapory, IPS i EDR, aby zablokować połączenia i atakujące adresy IP. Stwórz reguły IDS wykrywające złośliwe oprogramowanie.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "seventh",
            "message": "7.Zablokuj dostęp do wrażliwych danych, skonfiguruj kontrolę bezpieczeństwa oraz zastosuj środki, takie jak pułapki w dokumentach.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "eighth",
            "message": "8.Zdefiniuj proces remediacji oraz przetestuj go, aby upewnić się, że jest skuteczny i nie zakłóca innych usług. ",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "nineth",
            "message": "9.Upewnij się, że ruch sieciowy wrócił do normy i przywróć dostęp do segmentów sieci, które były wcześniej ograniczone.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "tenth",
            "message": "10.Po upewnieniu się, że zagrożenie jest usunięte, przywróć pełną funkcjonalność systemu.",
            "default": True,
        }
    ]
    questionary.prompt(questions4)
    komentarz = questionary.select("Czy chcesz dodać komentarz do incydentu?", choices=['Tak', 'Nie']).ask()
    if komentarz == 'Tak':
        with open('komentarz_web_attack.txt', 'w') as kom:
            tekst = input('Dodaj komentarz:\n')
            kom.write(tekst)


def data_leakage():
    print('Zidentyfikowano incydent Data Leakage.')
    questions5 = [
        {
            "type": "confirm",
            "name": "first",
            "message": "1.Jeśli w firmie jest narzędzie DLP (Data Loss Prevention), może ono pomoć w identyfikacji źródła wycieku danych. Jeśli nie - zweryfikuj źródło wycieku:"
                       "\na.Sprawdź e-maile wysłane do lub odebrane od podejrzanego konta lub ze specjalnym tematem.\n"
                       "b.Dane mogły być wysłane przez webmail, fora internetowe lub dedykowane strony. Na serwerze proxy lub w SIEM sprawdź logi dotyczące połączeń podejrzanego konta na podejrzanej stronie URL używanej do wycieku danych. Sprawdź historię przeglądarek.\n"
                       "c.Ustal, czy dane były kopiowane na pendrive’y, dyski zewnętrzne lub inne urządzenia.\nd.Sprawdź lokalne systemy plików.\n"
                       "e.Przejrzyj logi sieciowe pod kątem transferu przez FTP, VPN, SSH lub inne kanały.\n"
                       "f.Dane mogą być wysyłane do drukarek podłączonych do sieci, sprawdź ślady na buforze drukarki lub bezpośrednio na drukarce",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "second",
            "message": "2. Przeanalizuj objęte dane",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "third",
            "message": "3.W zależności od wektora wycieku zablokuj dostęp do adresu URI wycieku, serwera, źródła lub odbiorców wycieku. Działanie to musi być przeprowadzone na wszystkich punktach infrastruktury.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "fourth",
            "message": "4.Zawieś logiczne i fizyczne uprawnienia dostępu insidera.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "fifth",
            "message": "5.Izoluj system komputerowy (komputer, drukarka) użyty do wycieku danych.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "sixth",
            "message": "6.Jeśli dane zostały wysłane na publiczne serwery, skontaktuj się z właścicielem o usunięcie ujawnionych danych. Jeżeli nie jest to możliwe przekaż pełną analizę zespołowi PR i kierownictwu.",
            "default": True,
        },
        {
            "type": "confirm",
            "name": "seventh",
            "message": "7.Przywróć system z kopii zapasowej lub odbuduj od podstaw, jeśli był zainfekowany.",
            "default": True,
        }
    ]
    questionary.prompt(questions5)
    komentarz = questionary.select("Czy chcesz dodać komentarz do incydentu?", choices=['Tak', 'Nie']).ask()
    if komentarz == 'Tak':
        with open('komentarz_data_leakage.txt', 'w') as kom:
            tekst = input('Dodaj komentarz:\n')
            kom.write(tekst)

def run_playbook():
    questionary.print("Witaj w systemie zarządzania incydentami bezpieczeństwa!", style="bold italic fg:darkred")
    print(print_table())
    menu = input('Wybierz indeks incydentu, aby poznać dalsze kroki: ')
    incidents = generating_and_monitoring_incidents()
    incident_index = int(menu)
    incident = incidents[incident_index]
    while True:
        if incident['type'] == 'Malware':
            malware()
        elif incident['type'] == 'Brute Force':
            brute_force()
            break
        elif incident['type'] == 'Web attack':
            web_attack()
            break
        elif incident['type'] == 'Data Leakage':
            data_leakage()
            break
        elif menu == 'q':
            break
        else:
            print('Brak takiej opcji')


if __name__ == '__main__':
    run_playbook()