import re
from urllib.parse import urlparse, parse_qs, unquote

blacklisted_headers = {
    'c1': 'Runtime',
    'c2': '<%',
    'DNT': "1",
    'suffix': '%>//', 
}

blacklisted_paths = [
    '/tomcatwar.jsp', 
    '/tomcatwar.jsp/',
]

blacklisted_webshell_params = [
    'pwd',
    'cmd',
]

suspicious_keywords = [
    'Runtime',
    'exec',
    'request.getParameter',
    'java.io.InputStream',
    'out.println', 
    'webapps/ROOT', 
    '.jsp', 
    'class.module.classLoader.resources.context.parent.pipeline.first.pattern',
    'class.module.classLoader.resources.context.parent.pipeline.first.suffix',
    'class.module.classLoader.resources.context.parent.pipeline.first.directory',
    'class.module.classLoader.resources.context.parent.pipeline.first.prefix',
]

def is_path_blacklisted(path, blacklist):
    for blacklisted_path in blacklist:
        if path.strip().lower() == blacklisted_path.strip().lower(): 
            return True
    return False

def is_header_blacklisted(headers, blacklist): 
    for header, header_value in headers.items():
        if header in blacklist and header_value == blacklist[header]:
            return True
    return False

def is_param_blacklisted(params, blacklist):
    return bool(set(params.keys()) & set(blacklist))

def has_exploitable_payload(payload, blacklist):
    payload_decoded = unquote(payload)

    for suspicious_keyword in blacklist:
        if re.search(suspicious_keyword, payload_decoded, flags=re.IGNORECASE):
            return True
    return False

def is_spring4shell_attack(self): 
    request_method = self.command
    request_fullpath = urlparse(self.path)
    request_path = request_fullpath.path
    request_params = parse_qs(request_fullpath.query)
    request_headers = self.headers

    if is_path_blacklisted(request_path, blacklisted_paths): 
        return True

    if is_header_blacklisted(request_headers, blacklisted_headers): 
        return True

    if is_param_blacklisted(request_params, blacklisted_webshell_params): 
        return True

    if request_method == 'POST': 
        content_length = int(self.headers.get("Content-Length", 0))
        request_payload = self.rfile.read(content_length).decode("utf-8")

        if has_exploitable_payload(request_payload, suspicious_keywords): 
            return True

    return False