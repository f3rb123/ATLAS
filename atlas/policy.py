"""Canonical URLs and connection-time pinned DNS. Deny wins; no model authority."""
import http.client, ipaddress, socket, ssl, os, re
from urllib.parse import urlsplit, urlunsplit, unquote
from urllib.request import getproxies, proxy_bypass
from pydantic import BaseModel, ConfigDict, Field

class Denied(ValueError): pass
class Strict(BaseModel): model_config=ConfigDict(extra='forbid')
class Rule(Strict):
    host: str
    ports: list[int]=[443]
    schemes: list[str]=['https']
    paths: list[str]=['/']
    methods: list[str]=['GET','HEAD']
class Scope(Strict):
    allow: list[Rule]=[]
    deny: list[Rule]=[]
    lab_networks: list[str]=[]
    expires: float|None=None
    max_requests: int=100
    max_response_bytes: int=1024*1024
    max_seconds: int=15

def host(h):
    h=h.rstrip('.').lower()
    try: return str(ipaddress.ip_address(h))
    except ValueError: pass
    try: h=h.encode('idna').decode('ascii')
    except UnicodeError: raise Denied('Invalid IDNA host')
    if len(h)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',s) for s in h.split('.')): raise Denied('Malformed hostname')
    if re.fullmatch(r'[0-9.xa-f]+',h) and (h.startswith('0x') or h.replace('.','').isdigit()): raise Denied('Ambiguous numeric host')
    return h

def normalize(url):
    if re.search(r'[\x00-\x20\x7f\\]',url): raise Denied('Unsafe URL character')
    try:
        u=urlsplit(url)
        if u.scheme not in ('https','http') or not u.hostname or u.username or u.password: raise Denied('Unsupported URL')
        h=host(u.hostname);p=u.port if u.port is not None else (443 if u.scheme=='https' else 80)
        if not 1<=p<=65535:raise Denied('Invalid destination port')
    except ValueError as e: raise Denied(str(e))
    path=u.path or '/'
    decoded=unquote(path)
    if decoded!=path or any(s in ('.','..') for s in path.split('/')) or '//' in path: raise Denied('Ambiguous encoded path')
    net=f'[{h}]' if ':' in h else h
    return urlunsplit((u.scheme,f'{net}:{p}',path,u.query,'')),h,p,path,u.scheme

def match(rule,h,p,path,scheme,method):
    pattern=rule.host
    if '/' in pattern:
        try: ok=ipaddress.ip_address(h) in ipaddress.ip_network(pattern,strict=False)
        except ValueError: ok=False
    elif pattern.startswith('*.'):
        suffix=host(pattern[2:]);ok=h.endswith('.'+suffix) and h!=suffix
    else:ok=h==host(pattern)
    return ok and p in rule.ports and scheme in rule.schemes and method in rule.methods and any(path==x or path.startswith(x.rstrip('/')+'/') for x in rule.paths)

def addresses(h,p,lab=(),resolver=socket.getaddrinfo):
    try: ips=sorted({r[4][0] for r in resolver(h,p,type=socket.SOCK_STREAM)})
    except OSError:raise Denied('DNS resolution failed')
    if not ips:raise Denied('No destination addresses')
    for ip in ips:
        addr=ipaddress.ip_address(ip)
        if addr.is_link_local or addr.is_multicast or addr.is_unspecified or getattr(addr,'ipv4_mapped',None): raise Denied('Forbidden destination')
        permitted=any(addr in ipaddress.ip_network(n) for n in lab)
        if not addr.is_global and not permitted: raise Denied('Non-public destination')
    return ips

def authorize(scope,url,method='GET',resolver=socket.getaddrinfo):
    import time
    s=Scope.model_validate(scope) if isinstance(scope,dict) else scope
    if s.expires and s.expires<time.time():raise Denied('Policy expired')
    n,h,p,path,scheme=normalize(url)
    if any(match(r,h,p,path,scheme,method) for r in s.deny) or not any(match(r,h,p,path,scheme,method) for r in s.allow):raise Denied('Out of scope')
    return n,h,p,addresses(h,p,s.lab_networks,resolver)

class PinnedConnection(http.client.HTTPConnection):
    def __init__(self,hostname,ip,port,tls,timeout):
        super().__init__(hostname,port,timeout=timeout);self.ip=ip;self.tls=tls
    def connect(self):
        proxies=getproxies();proxy=proxies.get('https' if self.tls else 'http')
        if proxy and not proxy_bypass(self.host):
            u=urlsplit(proxy)
            if u.scheme!='http' or u.username or u.password:raise Denied('Unsupported egress proxy configuration')
            relay=http.client.HTTPConnection(u.hostname,u.port or 80,timeout=self.timeout)
            relay.set_tunnel(self.ip,self.port);relay.connect();self.sock=relay.sock
        else:self.sock=socket.create_connection((self.ip,self.port),self.timeout)
        if self.tls:self.sock=ssl.create_default_context().wrap_socket(self.sock,server_hostname=self.host)

def request(url,method='GET',headers=None,body=None,scope=None,max_bytes=1048576,timeout=15,return_redirect=False):
    n,h,p,ips=authorize(scope,url,method)
    c=PinnedConnection(h,ips[0],p,n.startswith('https:'),timeout)
    u=urlsplit(n);target=u.path+('?' +u.query if u.query else '')
    try:
        c.request(method,target,body=body,headers=headers or {})
        r=c.getresponse()
        if 300<=r.status<400 and not return_redirect:raise Denied('Redirect disabled; destination must be independently approved')
        if r.getheader('Content-Encoding','identity')!='identity':raise Denied('Compressed responses not accepted')
        content=r.read(max_bytes+1)
        if len(content)>max_bytes:raise Denied('Response size exceeded')
        return r.status,dict(r.getheaders()),content
    finally:c.close()
