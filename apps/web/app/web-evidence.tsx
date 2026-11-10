'use client';
import {useEffect,useState} from 'react';
type Api=(path:string,method?:string,body?:any)=>Promise<any>;
export default function WebEvidence({runId,findingId,call}:{runId?:string,findingId?:string,call:Api}){
 const [rows,R]=useState<any[]>([]),[error,E]=useState(''),[offset,O]=useState(0);
 useEffect(()=>{let live=true;async function refresh(){try{const result=await call(findingId?`findings/${findingId}/evidence`:`runs/${runId}/web-evidence?offset=${offset}`);if(live){R(findingId?result:result.items);E('')}}catch(e:any){if(live)E(e.message)}}refresh();const timer=setInterval(refresh,5000);return()=>{live=false;clearInterval(timer)}},[runId,findingId,offset,call]);
 return <section className="card"><h2>{findingId?'Independent finding evidence':'Web and network evidence'}</h2><p>Captured requests and responses belong to this engagement. Imported or scanner observations remain unverified until independent proof/control replay.</p>{rows.map(row=><details key={row.id}><summary>{row.method||row.kind} · {row.url||row.hostname||row.tool_name} · {row.response?.status||row.state||''}</summary><p>Evidence ID: {row.id}</p><pre>{JSON.stringify(row,null,2)}</pre></details>)}{!rows.length&&!error&&<p>No captured evidence on this page.</p>}{!findingId&&<div className="actions"><button disabled={!offset} onClick={()=>O(Math.max(0,offset-50))}>Newer evidence</button><button disabled={rows.length<50} onClick={()=>O(offset+50)}>Older evidence</button></div>}{error&&<p className="error" role="alert">{error}</p>}</section>
}
