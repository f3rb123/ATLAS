"""Versioned local invariant fixtures, vulnerable and patched; no live targets."""

import tempfile
from pathlib import Path
from .tools import Repository, ExecutionInput, execute_offline
from .verification import successful_test
from .db import document, now, digest

FIXTURES = """import unittest,json,base64,hmac,hashlib,os,socket
from pathlib import PurePosixPath

def authorized(actor,owner,patched):return actor==owner if patched else True
def algorithm(header,patched):return 'HS256' if patched else header.get('alg')
def cachekey(user,path,patched):return (user,path) if patched else path
def storage(path,patched):
 if patched and ('..' in PurePosixPath(path).parts or path.startswith('/')):raise ValueError('unsafe path')
 return '/store/'+path
def query(value,patched):return ('SELECT * FROM records WHERE id=?',[value]) if patched else ('SELECT * FROM records WHERE id='+value,[])
def allowed(ip,patched):return not ip.startswith(('127.','10.','169.254.')) if patched else True
class Invariants(unittest.TestCase):
 def test_authz(self):self.assertTrue(authorized('a','b',False));self.assertFalse(authorized('a','b',True))
 def test_jwt(self):self.assertEqual(algorithm({'alg':'none'},False),'none');self.assertEqual(algorithm({'alg':'none'},True),'HS256')
 def test_cache(self):self.assertEqual(cachekey('a','/private',False),cachekey('b','/private',False));self.assertNotEqual(cachekey('a','/private',True),cachekey('b','/private',True))
 def test_path(self):self.assertIn('..',storage('../secret',False));self.assertRaises(ValueError,storage,'../secret',True)
 def test_injection(self):self.assertIn('OR',query('1 OR 1=1',False)[0]);self.assertNotIn('OR',query('1 OR 1=1',True)[0])
 def test_ssrf(self):self.assertTrue(allowed('169.254.169.254',False));self.assertFalse(allowed('169.254.169.254',True))
 def test_benign(self):self.assertTrue(authorized('a','a',True));self.assertEqual(query('42',True)[1],['42'])
"""


def run_local(db, owner):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "tests"
        p.mkdir()
        (p / "test_invariants.py").write_text(FIXTURES)
        result = execute_offline(
            Repository(td), ExecutionInput(template="python_unittest")
        )
    return document(
        db,
        "benchmark",
        owner,
        {
            "dataset_version": "atlas-invariants-1",
            "fixture_hash": digest(FIXTURES),
            "passed": successful_test(result),
            "result": result,
            "created_at": now(),
            "kind": "deterministic_harness",
            "model_compared": False,
        },
    )
