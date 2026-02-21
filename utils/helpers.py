import re

def extract_domains(text):
    return re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', text)

def is_ip(host):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, host) is not None
