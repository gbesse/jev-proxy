import { appendJsonLine, readJsonLines } from "./audit.js";
import {open,mkdir,unlink}from 'node:fs/promises';
import {dirname,resolve}from 'node:path';
async function withApprovalLock<T>(path:string,action:()=>Promise<T>):Promise<T>{
 const lock=resolve(path)+'.lock';await mkdir(dirname(lock),{recursive:true,mode:0o700});const deadline=Date.now()+5000;let handle;
 while(!handle){try{handle=await open(lock,'wx',0o600);}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;if(Date.now()>=deadline)throw new Error('Verrou approbation indisponible / Approval lock unavailable / Bloqueo de aprobación no disponible');await new Promise(r=>setTimeout(r,10));}}
 try{return await action();}finally{await handle.close();await unlink(lock);}
}

interface ApprovalEvent {
  timestamp: string;
  type: "grant" | "consume" | "revoke";
  fingerprint: string;
  auditId: string;
}

function isApprovalEvent(value: unknown): value is ApprovalEvent {
  if (!value || typeof value !== "object") return false;
  const event = value as Record<string, unknown>;
  return (event.type === "grant" || event.type === "consume" || event.type === "revoke") && typeof event.fingerprint === "string" && typeof event.auditId === "string";
}

export async function grantApproval(path: string, fingerprint: string, auditId: string): Promise<void> {
  await withApprovalLock(path,()=>appendJsonLine(path, { timestamp: new Date().toISOString(), type: "grant", fingerprint, auditId } satisfies ApprovalEvent));
}

export async function consumeApproval(path: string, fingerprint: string): Promise<string | null> {
  return withApprovalLock(path,async()=>{
  const events = (await readJsonLines(path)).filter(isApprovalEvent);
  const grants = events.filter((event) => event.type === "grant" && event.fingerprint === fingerprint);
  const consumed = new Set(events.filter((event) => event.type === "consume" || event.type === "revoke").map((event) => event.auditId));
  const grant = grants.find((event) => !consumed.has(event.auditId));
  if (!grant) return null;
  await appendJsonLine(path, {
    timestamp: new Date().toISOString(),
    type: "consume",
    fingerprint,
    auditId: grant.auditId,
  } satisfies ApprovalEvent);
  return grant.auditId;
  });
}

export async function revokeApproval(path:string,auditId:string):Promise<boolean>{
 if(typeof auditId!=='string'||!auditId||auditId.length>1000)throw new TypeError('Identifiant invalide / Invalid identifier / Identificador inválido');
 return withApprovalLock(path,async()=>{const events=(await readJsonLines(path)).filter(isApprovalEvent);const grant=events.find(e=>e.type==='grant'&&e.auditId===auditId);if(!grant||events.some(e=>(e.type==='consume'||e.type==='revoke')&&e.auditId===auditId))return false;
 await appendJsonLine(path,{timestamp:new Date().toISOString(),type:'revoke',fingerprint:grant.fingerprint,auditId} satisfies ApprovalEvent);return true;});
}
