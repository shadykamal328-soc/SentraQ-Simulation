import { useEffect, useState } from "react";
import type { AttackScenario } from "../types";

export default function AttackScreen({
  scenario,
  mode,
  onRestart,
}: {
  scenario: AttackScenario;
  mode: "manual" | "sentraq";
  onRestart: () => void;
}) {
  const [logs, setLogs] = useState<typeof scenario.attackLogs>([]);
  const [showOutcome, setShowOutcome] = useState(false);

  useEffect(() => {
    setLogs([]);
    setShowOutcome(false);
    let i = 0;
    const interval = setInterval(() => {
      if (i >= scenario.attackLogs.length) {
        clearInterval(interval);
        setTimeout(() => setShowOutcome(true), 700);
        return;
      }
      setLogs((prev) => [...prev, scenario.attackLogs[i]]);
      i++;
    }, 260);
    return () => clearInterval(interval);
  }, [scenario]);

  return (
    <div className="fixed inset-0 z-50 bg-black flex items-center justify-center overflow-hidden p-4">
      <div className={`absolute inset-0 ${
        mode === "sentraq"
          ? "bg-[linear-gradient(120deg,#042f2e,#020617_45%,#052e16)]"
          : "bg-[linear-gradient(120deg,#240606,#020617_45%,#111827)]"
      }`} />
      <div className="absolute inset-0 bg-[repeating-linear-gradient(0deg,transparent,transparent_2px,rgba(148,163,184,0.07)_2px,rgba(148,163,184,0.07)_4px)]" />

      {!showOutcome ? (
        <div className="relative w-full max-w-4xl animate-[fadeIn_0.3s]">
          <div className="mb-5 flex items-end justify-between gap-4">
            <div>
              <div className={`text-sm font-mono tracking-widest mb-2 ${mode === "sentraq" ? "text-emerald-300" : "text-red-300"}`}>
                {mode === "sentraq" ? "SENTRAQ RESPONSE ACTIVE" : "BREACH DETECTED"}
              </div>
              <h1 className="text-4xl font-black text-white">{scenario.name}</h1>
              <p className="text-slate-400 mt-2 max-w-2xl">
                {mode === "sentraq"
                  ? "AI investigation correlates ELK alerts, enriches with MISP, classifies risk, and launches response actions."
                  : scenario.attackerAutomation}
              </p>
            </div>
            <div className={`rounded-md border px-4 py-3 text-right ${
              mode === "sentraq" ? "border-emerald-500/50 bg-emerald-950/30" : "border-red-500/50 bg-red-950/40"
            }`}>
              <div className={`text-[11px] uppercase tracking-wider ${mode === "sentraq" ? "text-emerald-300" : "text-red-300"}`}>
                {mode === "sentraq" ? "Containment target" : "Target"}
              </div>
              <div className="font-mono text-white">{scenario.targetNode}</div>
            </div>
          </div>

          <div className={`bg-black/90 border rounded-lg shadow-2xl overflow-hidden ${
            mode === "sentraq" ? "border-emerald-500/50 shadow-emerald-950" : "border-red-500/50 shadow-red-950"
          }`}>
            <div className={`flex items-center gap-2 px-4 py-2 border-b ${
              mode === "sentraq" ? "border-emerald-500/30 bg-emerald-950/30" : "border-red-500/30 bg-red-950/40"
            }`}>
              <div className={`h-3 w-3 rounded-full ${mode === "sentraq" ? "bg-emerald-500" : "bg-red-500"}`} />
              <div className="h-3 w-3 rounded-full bg-amber-500" />
              <div className="h-3 w-3 rounded-full bg-emerald-500" />
              <span className={`${mode === "sentraq" ? "text-emerald-200" : "text-red-200"} text-xs font-mono ml-2`}>
                {mode === "sentraq" ? "sentraq-ai-response" : "attacker-automation"} :: {scenario.id}
              </span>
            </div>
            <div className="p-5 font-mono text-sm h-96 overflow-y-auto">
              {mode === "sentraq" ? (
                <SentraqTerminal />
              ) : (
                logs.map((log, index) => (
                  <div key={`${log.t}-${index}`} className="mb-2">
                    <span className="text-red-300">{log.t}</span>
                    <span className="text-slate-500"> [{log.source}] </span>
                    <span className={log.severity === "critical" ? "text-red-200 font-bold" : "text-slate-300"}>
                      {log.message}
                    </span>
                  </div>
                ))
              )}
              <div className={`${mode === "sentraq" ? "text-emerald-400" : "text-red-400"} animate-pulse`}>processing...</div>
            </div>
          </div>
        </div>
      ) : (
        <div className="relative max-w-3xl animate-[fadeIn_0.4s]">
          <div className={`rounded-lg border bg-black/80 p-6 shadow-2xl ${
            mode === "sentraq" ? "border-emerald-500/50 shadow-emerald-950" : "border-red-500/50 shadow-red-950"
          }`}>
            <div className={`text-sm font-mono tracking-widest mb-2 ${mode === "sentraq" ? "text-emerald-300" : "text-red-300"}`}>
              SIMULATION OUTCOME
            </div>
            <h1 className="text-4xl font-black text-white mb-3">
              {mode === "sentraq" ? "Attack contained before business impact" : scenario.outcomeTitle}
            </h1>
            <p className="text-slate-400 mb-5">
              {mode === "sentraq"
                ? "Sentraq handled the same attack stream by correlating alerts, enriching context, prioritizing risk, and executing response actions before the chain completed."
                : scenario.summary}
            </p>

            <div className="space-y-3 mb-6">
              {(mode === "sentraq" ? [
                "ELK alerts were clustered into a single incident instead of leaving L1 with a growing queue.",
                "MISP enrichment raised the risk score early by matching attacker infrastructure and known techniques.",
                "Response actions blocked the attacker path: Block IP, Disable User, Isolate Host, Kill Process, and Update Incident Case.",
              ] : scenario.outcome).map((item) => (
                <div key={item} className="rounded-md border border-slate-800 bg-slate-950 p-3 text-slate-200">
                  <span className={`${mode === "sentraq" ? "text-emerald-300" : "text-red-300"} font-bold`}>
                    {mode === "sentraq" ? "Response: " : "Impact: "}
                  </span>
                  {item}
                </div>
              ))}
            </div>

            <div className={`rounded-md border p-4 mb-6 ${
              mode === "sentraq" ? "border-emerald-500/30 bg-emerald-950/20" : "border-amber-500/30 bg-amber-950/20"
            }`}>
              <div className={`${mode === "sentraq" ? "text-emerald-300" : "text-amber-300"} font-bold mb-1`}>What the demo shows</div>
              <p className="text-slate-300 text-sm leading-relaxed">
                {mode === "sentraq"
                  ? "The value is not just faster alert reading. It is investigation, enrichment, risk classification, case generation, escalation, and response in one flow."
                  : "L1 did not fail because they ignored the console. They failed because manual first-level triage was slower than the attacker's automation, and the real chain looked like ordinary alert noise."}
              </p>
            </div>

            <button
              onClick={onRestart}
              className={`px-5 py-3 rounded-md text-white font-bold ${
                mode === "sentraq" ? "bg-emerald-600 hover:bg-emerald-500" : "bg-red-600 hover:bg-red-500"
              }`}
            >
              Restart this simulation
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function SentraqTerminal() {
  const lines = [
    "[T+00:02] ELK ingest: 47 alerts normalized and clustered into INC-SENTRAQ-2048",
    "[T+00:05] MISP enrichment: attacker IP, payload hash, and phishing domain matched active threat cluster",
    "[T+00:08] Risk classification: critical, multi-stage attack chain detected",
    "[T+00:11] Summary generated: initial access, affected host, user, evidence, and recommended actions",
    "[T+00:14] Escalation: complex case routed to L2/IR with complete investigation package",
    "[T+00:15] Action prepared: Block IP 185.220.101.45 at firewall and proxy",
    "[T+00:16] Action prepared: Disable compromised user and revoke active sessions",
    "[T+00:17] Action prepared: Isolate host and kill malicious process tree",
    "[T+00:18] Containment complete: incident case updated with evidence and response actions",
  ];

  return (
    <>
      {lines.map((line) => (
        <div key={line} className="mb-2 text-slate-300">
          <span className="text-emerald-300">{line.slice(0, 8)}</span>
          {line.slice(8)}
        </div>
      ))}
    </>
  );
}
