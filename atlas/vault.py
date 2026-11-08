"""Per-secret AES256-GCM DEK, KEK wrapping, identity-bound AAD. No read-back API."""
import base64,json,os,re
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import settings
from .db import digest

def b64(b): return base64.b64encode(b).decode()
def un64(s): return base64.b64decode(s,validate=True)
def master():
    p=Path(settings().master_key_file)
    if not p.is_file(): raise RuntimeError('Missing secrets master key file')
    if p.stat().st_mode & 0o077: raise RuntimeError('Master key file must be mode 0600 or 0400')
    k=p.read_bytes()
    if len(k)!=32: raise RuntimeError('Invalid master key')
    return k

def seal(text, identity, key=None):
    dek=os.urandom(32);n=os.urandom(12);w=os.urandom(12);aad=identity.encode()
    return json.dumps({'version':1,'key_version':digest(key or master())[:12], 'nonce':b64(n),'wrapped_nonce':b64(w),'ciphertext':b64(AESGCM(dek).encrypt(n,text.encode(),aad)),'wrapped_dek':b64(AESGCM(key or master()).encrypt(w,dek,aad))})
def open_secret(blob, identity,key=None):
    d=json.loads(blob);aad=identity.encode();dek=AESGCM(key or master()).decrypt(un64(d['wrapped_nonce']),un64(d['wrapped_dek']),aad)
    return AESGCM(dek).decrypt(un64(d['nonce']),un64(d['ciphertext']),aad).decode()
def rewrap(blob,identity,old,new):
    d=json.loads(blob);aad=identity.encode();dek=AESGCM(old).decrypt(un64(d['wrapped_nonce']),un64(d['wrapped_dek']),aad);n=os.urandom(12)
    d.update(wrapped_nonce=b64(n),wrapped_dek=b64(AESGCM(new).encrypt(n,dek,aad)),key_version=digest(new)[:12]);return json.dumps(d)
def redact(text):
    text=re.sub(r'(?i)(bearer\s+|(?:api[_-]?key|token|password|secret)\s*[=:]\s*)[^\s,;"\']+',r'\1[REDACTED]',text)
    return re.sub(r'\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]+','[REDACTED]',text)
