import socket
import re


def resolve_domain(ip):
    """
    Próbuje rozwiązać adres IP na nazwę domeny

    Args:
        ip (str): Adres IP do rozwiązania

    Returns:
        str: Nazwa domeny lub oryginalny adres IP
    """
    try:
        # Próba odwrotnego DNS (reverse DNS)
        domain = socket.gethostbyaddr(ip)[0]

        # Oczyszczenie nazwy domeny
        # Usuń numeryczne sufiksy, które często dodaje resolve
        domain = re.sub(r'\.\d+$', '', domain)

        return domain
    except (socket.herror, socket.gaierror):
        # Próba ekstrakcji domeny z pliku hosts
        try:
            with open('/etc/hosts', 'r') as hosts_file:
                for line in hosts_file:
                    if ip in line:
                        parts = line.split()
                        if len(parts) > 1:
                            return parts[1]
        except:
            pass

        # Jeśli nie udało się rozwiązać, zwróć oryginalny IP
        return ip


def extract_domain_from_url(url):
    """
    Wyodrębnia domenę z pełnego adresu URL

    Args:
        url (str): Pełny adres URL

    Returns:
        str: Domena
    """
    # Usuń protokół
    url = url.replace('http://', '').replace('https://', '').replace('www.', '')

    # Wyodrębnij domenę główną
    domain = url.split('/')[0]

    return domain


def improve_url_identification(original_url, src_ip, dst_ip):
    """
    Ulepsza identyfikację URL poprzez próbę rozwiązania nazw domen

    Args:
        original_url (str): Oryginalny URL
        src_ip (str): Źródłowy adres IP
        dst_ip (str): Docelowy adres IP

    Returns:
        str: Ulepszona identyfikacja URL
    """
    # Jeśli oryginalny URL już zawiera domenę, zwróć go
    if '.' in original_url and not original_url.startswith(('http://', 'https://')):
        return original_url

    # Próba rozwiązania IP na domenę
    src_domain = resolve_domain(src_ip)
    dst_domain = resolve_domain(dst_ip)

    # Preferuj domenę, która wygląda jak prawdziwa domena
    def is_valid_domain(domain):
        return '.' in domain and not domain.replace('.', '').isdigit()

    if is_valid_domain(src_domain):
        return src_domain
    elif is_valid_domain(dst_domain):
        return dst_domain

    # Jeśli oryginalna domena istnieje, użyj jej
    if original_url and '.' in original_url:
        return extract_domain_from_url(original_url)

    # Fallback do IP
    return f"{dst_ip}"