'use client';
import {useEffect,useState} from 'react';
type Api=(path:string,method?:string,body?:any)=>Promise<any>;
export default function ModelRouting({call}:{call:Api}){
  const [status,S]=useState<any>(),[preview,P]=useState<any>(),[error,E]=useState('');
  useEffect(()=>{call('model-routing').then(S).catch(e=>E(e.message))},[call]);
  return <section className="card"><h2>Model selection</h2><p>Automatic runs select from your configured, verified models. Each run pins its choices. Independent validation keeps its assigned model, and requests with uncertain billing are held for review.</p>
    {status?.aliases?.map((a:any)=><div className="row" key={a.alias}><span><strong>{a.alias}</strong> · {a.model_id}<small>{a.provider_name} · {a.structured_verified?'JSON verified':'JSON unverified'} · {a.tools_verified?'tools verified':'tools unverified'} · pricing {a.pricing_status}</small></span><span className="badge">{a.circuit.open?'Cooling down':'Available'}</span></div>)}
    <form onSubmit={async e=>{e.preventDefault();E('');const f=new FormData(e.currentTarget);try{P(await call('model-routing/preview','POST',{alias:f.get('alias'),question:f.get('question'),input_bytes:Number(f.get('bytes')),output_tokens:1024}))}catch(e:any){E(e.message)}}}>
      <label>Role<select name="alias">{['reasoning','fast','coding','deep_research','verifier'].map(a=><option key={a}>{a}</option>)}</select></label>
      <label>Task description<input name="question" maxLength={2000}/></label><label>Estimated input bytes<input name="bytes" type="number" min={1} max={2000000} defaultValue={4000}/></label><button>Preview selection</button>
    </form><p>Preview uses no model tokens. Context limits are operator declarations until independently verified.</p>
    {preview&&<div role="status">{preview.candidates.length?preview.candidates.map((c:any,i:number)=><p key={c.model_record_id}>{i+1}. {c.model_id} · {c.complexity} complexity · {c.context_window.toLocaleString()} declared context · {c.pricing_confirmed?'verified pricing':'price unverified'}</p>):<p>No verified model fits this task. Review aliases, context limits and connection health.</p>}</div>}
    {error&&<p role="alert" className="error">{error}</p>}
  </section>;
}
