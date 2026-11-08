import time,json
from fastapi.testclient import TestClient
from atlas.api import app
from atlas.db import *
from atlas.auth import *


def test_bootstrap_password_session_and_csrf(db):
 token=bootstrap_token(db)
 with TestClient(app) as c:
  assert c.get('/api/v1/campaigns').status_code==401
  assert c.post('/api/v1/auth/bootstrap',json={'token':token,'email':'owner@example.invalid','password':'short'}).status_code==400
  r=c.post('/api/v1/auth/bootstrap',json={'token':token,'email':'owner@example.invalid','password':'a long generated test passphrase 73420'})
  assert r.status_code==200
  assert 'HttpOnly' in r.headers['set-cookie'] and 'SameSite=strict' in r.headers['set-cookie']
  assert c.post('/api/v1/auth/bootstrap',json={'token':token,'email':'other@example.invalid','password':'another long test passphrase'}).status_code==400
  assert c.get('/api/v1/campaigns').status_code==403
  assert c.post('/api/v1/auth/totp/setup').status_code==403
  csrf=r.json()['csrf_token'];h={'Origin':'http://localhost:8000','X-CSRF-Token':csrf}
  r=c.post('/api/v1/auth/totp/setup',headers=h)
  assert r.status_code==200
  assert 'otpauth://' in r.json()['provisioning_uri']
  db.expire_all();u=db.query(User).one()
  assert 'argon2id' in u.password
  assert db.query(Session).one().token_hash not in c.cookies.values()

def authenticated(db):
 u=User(id=uid(),email='admin@example.invalid',password=ph.hash('a long fixture-only password 9824'));db.add(u);db.flush()
 document(db,'passkey',u.id,{'credential_id':'fixture-only','public_key':'not-a-real-key','sign_count':0})
 s,t,csrf=issue(db,u,True);s.stepup=time.time();db.commit();c=TestClient(app);c.cookies.set('atlas_dev',t)
 c.headers.update({'Origin':'http://localhost:8000','X-CSRF-Token':csrf});return c,u,s

def test_campaign_ownership_idempotency_and_kill(db):
 c,u,s=authenticated(db)
 r=c.post('/api/v1/campaigns',json={'name':'Lab','authorization_ref':'local lab','authorization_attested':True})
 assert r.status_code==200;r=r.json()
 headers={'Idempotency-Key':'run-1'}
 a=c.post('/api/v1/campaigns/'+r['id']+'/runs',json={},headers=headers)
 b=c.post('/api/v1/campaigns/'+r['id']+'/runs',json={},headers=headers)
 assert a.status_code==200 and a.json()['id']==b.json()['id']
 db.expire_all();other=document(db,'campaign','another-user',{'name':'private'});db.commit()
 assert c.get('/api/v1/campaigns/'+other.id).status_code==404
 assert c.post('/api/v1/admin/kill-switch').status_code==200
 assert c.post('/api/v1/campaigns/'+r['id']+'/runs',json={}).status_code==403
 assert c.get('/api/v1/runs/'+a.json()['id']).json()['status']=='cancelled'

def test_passkey_bad_challenge_no_replay(db):
 c,u,s=authenticated(db)
 r=c.post('/api/v1/auth/webauthn/authentication/options');assert r.status_code==200
 assert c.post('/api/v1/auth/webauthn/authentication/verify',json={'credential':{'id':'invalid'}}).status_code==400
 db.expire_all();assert db.query(Document).filter_by(kind='challenge').count()==0

def test_recovery_single_use_and_totp_replay(db):
 c,u,s=authenticated(db)
 codes=recovery_codes(db,u);db.commit()
 recovery_consume(db,u,s,codes[0]);db.commit()
 with __import__('pytest').raises(ValueError):recovery_consume(db,u,s,codes[0])
 assert all(codes[1] not in d.data for d in db.query(Document).filter_by(kind='recovery'))
 uri=totp_setup(db,u,s);db.commit();seed=__import__('urllib.parse',fromlist=['parse_qs']).parse_qs(__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(uri).query)['secret'][0]
 code=__import__('pyotp').TOTP(seed).now();totp_verify(db,u,s,code,True);db.commit()
 with __import__('pytest').raises(ValueError):totp_verify(db,u,s,code)
