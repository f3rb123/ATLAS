import json,os
import pytest
from hypothesis import given,strategies as st
from atlas.policy import *
from atlas.vault import seal,open_secret,rewrap
from cryptography.exceptions import InvalidTag

def dns(ip):return lambda *a,**k:[(2,1,6,'',(ip,443))]
def test_scope_edges():
 s=Scope(allow=[Rule(host='*.example.com')],deny=[Rule(host='bad.example.com')])
 assert authorize(s,'https://api.example.com/a',resolver=dns('8.8.8.8'))[1]=='api.example.com'
 for u in ['https://example.com','https://example.com.attacker.tld','https://bad.example.com','https://api.example.com/%2e%2e/private','https://user:pw@api.example.com','http://api.example.com']:
  with pytest.raises(Denied):authorize(s,u,resolver=dns('8.8.8.8'))
 for ip in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','224.0.0.1']:
  with pytest.raises(Denied):authorize(s,'https://api.example.com',resolver=dns(ip))
@given(st.text(alphabet='abcdefghijklmnopqrstuvwxyz',min_size=1,max_size=20))
def test_suffix_boundary(suffix):
 rule=Rule(host='*.example.com')
 assert not match(rule,'example.com.'+suffix,443,'/','https','GET')
def test_envelope_identity_rotation():
 a=os.urandom(32);b=os.urandom(32);blob=seal('testing-secret','owner:provider:1',a)
 assert 'testing-secret' not in blob
 assert open_secret(blob,'owner:provider:1',a)=='testing-secret'
 with pytest.raises(InvalidTag):open_secret(blob,'other-owner',a)
 assert open_secret(rewrap(blob,'owner:provider:1',a,b),'owner:provider:1',b)=='testing-secret'
def test_master_corrupt():
 with pytest.raises(InvalidTag):open_secret(seal('x','id',os.urandom(32)),'id',os.urandom(32))

def test_database_kek_rotation_transaction(db,provider_server=None):
 from atlas.db import User,Document,document,canonical,uid
 from atlas.auth import ph
 from atlas.vault import rotate_database_keys,master
 old=master();new=os.urandom(32)
 u=User(id=uid(),email='fixture@example.invalid',password=ph.hash('long fixture-only password 123456'))
 u.totp=seal('TOTP-FIXTURE',f'totp:{u.id}',old);db.add(u)
 id=uid();d=document(db,'provider',u.id,{'secret':seal('not-a-real-provider-key',f'provider:{u.id}:{id}:1',old),'secret_headers':seal('{}',f'headers:{u.id}:{id}:1',old)},id)
 db.commit();assert rotate_database_keys(db,new,old)==3;db.commit()
 assert open_secret(d.value()['secret'],f'provider:{u.id}:{id}:1',new)=='not-a-real-provider-key'
 with pytest.raises(InvalidTag):open_secret(d.value()['secret'],f'provider:{u.id}:{id}:1',old)
 assert open_secret(u.totp,f'totp:{u.id}',new)=='TOTP-FIXTURE'
