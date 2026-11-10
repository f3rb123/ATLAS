'use client';

import {useEffect, useRef, useState} from 'react';

type Upload = {id:string,status:string,sha256:string,filename:string,byte_size:number,uploaded_bytes:number,uploaded_parts:number,total_parts:number,part_bytes:number,job_id?:string,result?:{error?:string,counts?:Record<string,unknown>}};
type Restored = {id:string,records:number,vectors:number,withheld_raw_artifacts:number,restored_at:string};
type Api = (path:string,method?:string,body?:any)=>Promise<any>;

export default function CorpusTransfer({call,changed}:{call:Api,changed:()=>Promise<void>}) {
  const [uploads,setUploads]=useState<Upload[]>([]);
  const [restored,setRestored]=useState<Restored[]>([]);
  const [selected,setSelected]=useState<Upload|null>(null);
  const [error,setError]=useState('');
  const [busy,setBusy]=useState(false);
  const pause=useRef(false);
  const completion=useRef(new Set<string>());
  const refresh=useRef(changed);
  refresh.current=changed;

  useEffect(()=>{
    let active=true;
    async function update() {
      try {
        const data=await call('corpus/transfers');
        if(!active)return;
        setUploads(data.uploads);setRestored(data.restored);
        for(const row of data.uploads as Upload[]) {
          if(row.status==='completed'&&!completion.current.has(row.id)) {
            completion.current.add(row.id);await refresh.current();
          }
        }
        setSelected(old=>old?data.uploads.find((x:Upload)=>x.id===old.id)||old:null);
      } catch(e:any) {if(active)setError(e.message)}
    }
    update();const timer=setInterval(update,3000);
    return ()=>{active=false;clearInterval(timer)};
  },[call]);

  async function upload(form:HTMLFormElement) {
    const data=new FormData(form),file=data.get('archive') as File;
    const sha=String(data.get('sha256')).trim().toLowerCase();
    if(!file?.size||file.size>1024**3)throw new Error('Choose a ZIP of at most 1 GiB.');
    if(!/^[a-f0-9]{64}$/.test(sha))throw new Error('Enter the package SHA256 checksum.');
    pause.current=false;setBusy(true);setError('');
    try {
      let row=selected?.status==='uploading'&&selected.sha256===sha&&selected.byte_size===file.size
        ?await call('corpus/transfers/'+selected.id)
        :await call('corpus/transfers','POST',{sha256:sha,byte_size:file.size,filename:file.name});
      setSelected(row);
      while(row.uploaded_parts<row.total_parts&&!pause.current) {
        const index=row.uploaded_parts;
        row=await call('corpus/transfers/'+row.id+'/parts/'+index,'PUT',file.slice(index*row.part_bytes,Math.min(file.size,(index+1)*row.part_bytes)));
        setSelected(row);
      }
      if(!pause.current) {
        row=await call('corpus/transfers/'+row.id+'/complete','POST',{});
        setSelected(row);
      }
    } catch(e:any) {setError(e.message)} finally {setBusy(false)}
  }

  return <section className="card" aria-label="Corpus package restore">
    <h2>Restore a corpus package</h2>
    <p>Import prepared records, semantic vectors and the verified local model together. Supplied identities are preserved. Existing knowledge is never replaced.</p>
    {restored.map(r=><div key={r.id} role="status"><strong>{r.records.toLocaleString()} records · {r.vectors.toLocaleString()} vectors installed</strong>
      <p>{r.withheld_raw_artifacts} original source artifacts were withheld from the review package. Their provenance remains recorded.</p></div>)}
    <details open={!restored.length}><summary>Upload or resume a package</summary>
      <p>Requires an empty corpus and an owner account. Large ZIPs upload in bounded parts; queued restoration continues in the background.</p>
      <form onSubmit={e=>{e.preventDefault();upload(e.currentTarget).catch(e=>setError(e.message))}}>
        <label>Corpus ZIP<input name="archive" type="file" accept=".zip" required disabled={busy}/></label>
        <label>Package SHA256<input name="sha256" required pattern="[a-fA-F0-9]{64}" minLength={64} maxLength={64} defaultValue={selected?.sha256||''} key={selected?.id||'new'} disabled={busy}/></label>
        <button disabled={busy||Boolean(restored.length)}>{busy?'Uploading…':selected?.status==='uploading'?'Resume selected transfer':'Upload and restore'}</button>
        {busy&&<button type="button" className="secondary" onClick={()=>{pause.current=true}}>Pause after current part</button>}
      </form>
    </details>
    {selected&&<p role="status">{selected.filename}: {selected.status} · {Math.round(selected.uploaded_bytes/selected.byte_size*100)}% uploaded</p>}
    {uploads.map(row=><article key={row.id}>
      <p><strong>{row.filename}</strong> · {row.status} · {row.uploaded_parts}/{row.total_parts} parts</p>
      {row.status==='uploading'&&<button className="secondary" disabled={busy} onClick={()=>setSelected(row)}>Resume this transfer</button>}
      {['uploading','blocked'].includes(row.status)&&<button className="secondary" disabled={busy} onClick={async()=>{try{await call('corpus/transfers/'+row.id,'DELETE');setSelected(null)}catch(e:any){setError(e.message)}}}>Discard uploaded copy</button>}
      {row.result?.error&&<p className="error" role="alert">Restore stopped: {row.result.error}. Existing corpus data was preserved.</p>}
      {row.result?.counts&&<p>Restore completed. Counts and model integrity were checked by the corpus service.</p>}
    </article>)}
    {error&&<p className="error" role="alert">{error}</p>}
  </section>;
}
