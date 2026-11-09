'use client';
import {useEffect,useState} from 'react';

type Task={id:string,role:string,status:string,attempts:number,reason?:string,parent_event?:string,result:Record<string,unknown>};
type Event={type:string,actor:string,timestamp:string,payload:Record<string,unknown>};
type State={execution_mode:string,agent_count:number,tasks:Task[],events:Event[],usage:{input_tokens:number,output_tokens:number,cost:number,requests:number,includes_estimates:boolean}};

export default function Swarm({runId,load}:{runId:string,load:(path:string)=>Promise<any>}){
 const [state,setState]=useState<State|null>(null),[error,setError]=useState('');
 useEffect(()=>{let live=true;async function refresh(){try{const data=await load('runs/'+runId+'/swarm');if(live){setState(data);setError('')}}catch(e:any){if(live)setError(e.message)}}refresh();const timer=setInterval(refresh,2000);return()=>{live=false;clearInterval(timer)}},[runId,load]);
 if(error)return <p role="alert" className="error">{error}</p>;
 if(!state||state.execution_mode!=='swarm')return null;
 return <section className="card" aria-label="Live swarm">
  <h2>Live swarm</h2>
  <p>{state.agent_count} concurrent task slots · {state.tasks.filter(t=>t.status==='running').length} running · {state.tasks.filter(t=>t.status==='completed').length} completed · {state.tasks.filter(t=>t.status==='dead_letter').length} need attention</p>
  <p>{state.usage.requests} recorded model responses · {state.usage.input_tokens} input / {state.usage.output_tokens} output tokens · ${state.usage.cost.toFixed(4)}{state.usage.includes_estimates?' (includes estimates)':''}</p>
  <p>Knowledge sources and discoveries below are research evidence. Confirmation requires independent reproduction.</p>
  <h3>Agent responsibilities and tasks</h3>
  {state.tasks.map(t=><details key={t.id}><summary>{t.role} · {t.status} · attempt {t.attempts}</summary><p>{t.reason}</p>{t.parent_event&&<p>Triggered by discovery {t.parent_event}</p>}<pre>{JSON.stringify(t.result,null,2)}</pre></details>)}
  <h3>Discoveries, knowledge and skills</h3>
  {!state.events.length&&<p>No persisted swarm activity yet.</p>}
  {state.events.slice(-60).map((e,i)=><details key={i}><summary>{e.type} · {e.actor}</summary><pre>{JSON.stringify(e.payload,null,2)}</pre></details>)}
 </section>
}
