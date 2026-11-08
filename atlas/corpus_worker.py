"""Dedicated source acquisition worker; public source egress is distinct from targets/providers."""
import time
from .db import session,Document,canonical
from .corpus import sync_bulk,sync_api

def tick():
    with session() as db:
        d=db.query(Document).filter_by(kind='corpus_request').with_for_update(skip_locked=True).all()
        request=next((r for r in d if r.value()['status']=='queued'),None)
        if not request:return
        v=request.value();v['status']='running';request.data=canonical(v);db.commit();id=request.id
    try:result=sync_bulk(v['source'],v['limit']) if v['source'] in ('cve','ghsa') else sync_api(v['source'],v['limit'])
    except Exception as e:result={'status':'blocked','error':type(e).__name__}
    with session() as db:
        d=db.get(Document,id);v.update(status=result['status'],result=result);d.data=canonical(v);db.commit()
if __name__=='__main__':
    while True:tick();time.sleep(2)
