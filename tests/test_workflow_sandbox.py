import pytest,time,io,os
from atlas.db import *
from atlas.workflow import *
from atlas.verification import successful_test
from atlas.tools import *
from atlas.backup import encrypt,decrypt
from cryptography.exceptions import InvalidTag

def test_every_fsm_transition_and_invalid_edges(db):
 for i,current in enumerate(ORDER):
  for target in ORDER:
   run=document(db,'run','u',{'state':current.value,'status':'running','campaign_id':'c'})
   if i+1<len(ORDER) and target==ORDER[i+1]:transition(db,run,target,'test');assert run.value()['state']==target
   else:
    with pytest.raises(ValueError):transition(db,run,target,'test')
 db.commit()
 for j in db.query(Journal):assert j.hash==digest(j.previous+str(j.sequence)+j.payload)

def test_tool_errors_not_findings():
 for value in [{'exit_code':1,'output':'Ran 1 test\nOK'},{'exit_code':0,'output':''},{'exit_code':0,'output':'Ran 0 tests\nOK'},{'exit_code':None,'timed_out':True,'output':'404'}]:assert not successful_test(value)
 assert successful_test({'exit_code':0,'output':'Ran 2 tests\n\nOK'})

def test_repository_paths_and_secrets(tmp_path):
 (tmp_path/'.env').write_text('password=secret');(tmp_path/'visible.py').write_text('x=1');(tmp_path/'escape').symlink_to('/etc/passwd');r=Repository(tmp_path)
 assert r.files()[0]==['visible.py']
 for path in ['../secret','.env','escape']:
  with pytest.raises(Denied):r.path(path)

def test_encrypted_backup_restore_and_truncation():
 password=os.urandom(48);data=os.urandom(1048600);out=io.BytesIO();encrypt(io.BytesIO(data),out,password);blob=out.getvalue();result=io.BytesIO();decrypt(io.BytesIO(blob),result,password);assert result.getvalue()==data
 with pytest.raises((ValueError,InvalidTag)):decrypt(io.BytesIO(blob[:-20]),io.BytesIO(),password)
 with pytest.raises(InvalidTag):decrypt(io.BytesIO(blob),io.BytesIO(),os.urandom(48))

@pytest.mark.sandbox
def test_offline_sandbox_denies_host_network_and_writes(tmp_path):
 p=tmp_path/'tests';p.mkdir();(p/'test_isolation.py').write_text('''import unittest,socket,os
class Isolation(unittest.TestCase):
 def test_no_host(self):self.assertFalse(os.path.exists('/etc/passwd'));self.assertFalse(os.path.exists('/var/run/docker.sock'))
 def test_readonly(self):
  with self.assertRaises(OSError):open('/work/write','w')
 def test_offline(self):
  s=socket.socket();s.settimeout(1)
  with self.assertRaises(OSError):s.connect(('8.8.8.8',53))
''')
 result=execute_offline(Repository(tmp_path),ExecutionInput(template='python_unittest'));assert successful_test(result),result
