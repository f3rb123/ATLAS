"""TEST ONLY local model fixture; never imported by production code."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'{"data":[{"id":"fixture-json"}]}')
 def do_POST(self):
  p=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
  text=p.get('messages',[{}])[-1].get('content','')
  try:context=json.loads(text);stage=context['stage'];content={'summary':'No executable vulnerability claim in synthetic benign source fixture.'}
  except (ValueError,KeyError):content={'ok':True}
  if 'stage' in locals() and stage=='THREAT_MODEL':content['threat_model']={'attacker_model':'Untrusted synthetic caller','protected_assets':['Test objects'],'security_invariants':['Only the owner accesses its object'],'citations':['app.py:1-2']}
  result={'id':'fixture-response','choices':[{'message':{'content':json.dumps(content)},'finish_reason':'stop'}],'usage':{'prompt_tokens':100,'completion_tokens':30}}
  self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(result).encode())
if __name__=='__main__':ThreadingHTTPServer(('127.0.0.1',9001),Handler).serve_forever()
