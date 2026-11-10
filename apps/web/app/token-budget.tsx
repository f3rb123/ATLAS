'use client';
import {useEffect,useState} from 'react';

type Api=(path:string,method?:string,body?:any)=>Promise<any>;
type Budget={cap:number,allocation:number,used:Record<string,number>,reserved_tokens:number,remaining_global:number,remaining_allocation:number,held_for_validation:number,unknown_billing_reservations:number,blocked:boolean,pending_reservations:{id:string,state:string,ceiling:number,role:string}[]};

export default function TokenBudget({call}:{call:Api}) {
  const [budget,setBudget]=useState<Budget|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function refresh(){try{setBudget(await call('budgets/tokens'));setError('')}catch(e:any){setError(e.message)}}
  useEffect(()=>{refresh();const timer=setInterval(refresh,4000);return()=>clearInterval(timer)},[call]);
  return <section className="card" aria-label="Global token budget"><h2>Global token allowance</h2>
    <p>Shared by every provider, agent, specialist and validator. Consumption persists across restarts and never resets automatically.</p>
    {budget&&<>
      <div className="metrics">
        {[['Authorized cap',budget.cap],['Allocated',budget.allocation],['Consumed',budget.used.total_tokens],['In-flight / uncertain',budget.reserved_tokens],['Allocation remaining',budget.remaining_allocation],['Held for validation',budget.held_for_validation]].map(([label,value])=><section className="card" key={String(label)}><p>{label}</p><strong>{Number(value).toLocaleString()}</strong></section>)}
      </div>
      <p>Input: {budget.used.input_tokens.toLocaleString()} · Output: {budget.used.output_tokens.toLocaleString()} · Cached input: {budget.used.cached_input_tokens.toLocaleString()} · Cache creation: {budget.used.cache_creation_input_tokens.toLocaleString()} · Reasoning: {budget.used.reasoning_tokens.toLocaleString()}</p>
      <p>Cached input and reasoning are included in the input/output totals. USD cost is accounted separately; unverified prices remain estimates.</p>
      {budget.blocked&&<p className="error" role="alert">A provider reported usage above its reservation. New calls are blocked for operator review.</p>}
      {budget.unknown_billing_reservations>0&&<p role="status">{budget.unknown_billing_reservations} request outcomes have uncertain billing. Their reserved capacity remains held until verified reconciliation.</p>}
      <details><summary>Adjust the explicit allocation</summary><form onSubmit={async e=>{e.preventDefault();const f=new FormData(e.currentTarget);setBusy(true);try{setBudget(await call('budgets/tokens','PATCH',{cap:budget.cap,allocation:Number(f.get('allocation')),validation_reserve:Number(f.get('validation'))}));setError('')}catch(e:any){setError(e.message)}finally{setBusy(false)}}}>
        <label>Allocated tokens<input name="allocation" type="number" min={1} max={budget.cap} defaultValue={budget.allocation} required/></label>
        <label>Protected validation capacity<input name="validation" type="number" min={0} max={budget.cap} defaultValue={budget.held_for_validation} required/></label>
        <p>Changing limits preserves all usage and reservations. The authorized 50-million-token ceiling cannot be exceeded.</p><button disabled={busy}>Save allocation</button>
      </form></details>
      <details><summary>Pending reservations ({budget.pending_reservations.length})</summary>{budget.pending_reservations.map(r=><p key={r.id}>{r.role} · {r.state} · {r.ceiling.toLocaleString()} tokens · {r.id}</p>)}</details>
    </>}
    {error&&<p className="error" role="alert">{error}</p>}
  </section>;
}
