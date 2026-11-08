#!/usr/bin/env python3
"""Generate local secret files without printing values; never overwrite existing material."""
import os,secrets
from pathlib import Path
root=Path('.runtime/secrets');root.mkdir(mode=0o700,parents=True,exist_ok=True)
for name in ['master_key','research_token','verify_token','api_token','postgres_password','app_postgres_password','redis_password','backup_password']:
 p=root/name
 if not p.exists():
  fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  with os.fdopen(fd,'wb') as f:f.write(os.urandom(32) if name=='master_key' else secrets.token_urlsafe(48).encode())
config=root/'redis.conf'
if not config.exists():
 config.write_text('bind 0.0.0.0\nprotected-mode yes\nrequirepass '+(root/'redis_password').read_text()+'\nsave \"\"\nappendonly no\n')
 config.chmod(0o600)
print('Secret files prepared; values were not printed. Back up KEK separately.')
