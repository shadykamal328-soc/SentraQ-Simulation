import { useEffect, useState } from "react";
import type { Alert } from "../types";
import { INVESTIGATION_STEPS } from "../data";

export default function InvestigationPanel({
  alert,
  onClose,
}: {
  alert: Alert;
  onClose: () => void;
}) {
  const [steps, setSteps] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    setSteps([]);
    setProgress(0);
    let i = 0;
    const interval = setInterval(() => {
      if (i >= INVESTIGATION_STEPS.length) {
        clearInterval(interval);
        return;
      }
      setSteps((prev) => [...prev, INVESTIGATION_STEPS[i]]);
      i++;
      setProgress((i / INVESTIGATION_STEPS.length) * 100);
    }, 600);

    return () => clearInterval(interval);
  }, [alert.id]);

  return (
    <div className="fixed inset-0 z-40 flex items-end sm:items-center justify-center bg-black/85 p-0 sm:p-4 backdrop-blur-md animate-[fadeIn_0.2s_ease-out]">
      <div className="w-full max-w-3xl max-h-[100dvh] sm:max-h-[92vh] overflow-hidden rounded-t-2xl sm:rounded-2xl border-t sm:border border-slate-800 bg-slate-950 shadow-2xl flex flex-col">
        <div className="flex items-center justify-between gap-3 border-b border-slate-850 bg-gradient-to-r from-slate-900 via-slate-950 to-slate-900 px-4 py-3.5 sm:px-5 sm:py-3.5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <div>
              <h2 className="text-sm sm:text-base font-black tracking-wide text-white uppercase">Investigation Console</h2>
              <p className="text-[10px] sm:text-xs text-slate-500 font-mono">
                ALERT_ID #{alert.id} • {alert.category}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-400 transition hover:bg-slate-900 hover:text-white"
            aria-label="Close"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="space-y-4 p-4 sm:p-5 flex-1 overflow-y-auto">
          <div className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
            <DetailField label="Rule" value={alert.rule} />
            <DetailField label="Category" value={alert.category} />
            <DetailField label="Source" value={alert.source} mono />
            <DetailField label="Destination" value={alert.dest} mono />
            <DetailField label="Severity" value={alert.severity.toUpperCase()} accent={
              alert.severity === "critical" ? "text-red-400" :
              alert.severity === "high" ? "text-orange-400" :
              alert.severity === "medium" ? "text-amber-400" : "text-sky-400"
            } />
            <DetailField label="Time" value={alert.time} mono />
          </div>

          <div>
            <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">
              Event Details
            </div>
            <pre className="overflow-hidden rounded-lg border border-slate-850 bg-black/60 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words text-emerald-300">
              {alert.details.join("\n")}
            </pre>
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                Automated Investigation
              </span>
              <span className="font-mono text-xs font-bold text-cyan-400">
                {Math.round(progress)}%
              </span>
            </div>
            <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-slate-900">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 shadow-lg shadow-cyan-500/50 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="max-h-44 space-y-1.5 overflow-y-auto rounded-lg border border-slate-850 bg-black/45 p-3">
              {steps.map((s, i) => (
                <div key={i} className="font-mono text-xs text-emerald-400 break-words">
                  <span className="text-slate-600">[{String(i + 1).padStart(2, "0")}]</span>{" "}
                  {s}
                </div>
              ))}
              {progress < 100 && (
                <div className="animate-pulse font-mono text-xs text-amber-400">analyzing...</div>
              )}
              {progress >= 100 && (
                <div className="mt-2 font-mono text-xs font-bold text-cyan-400">
                  Investigation complete
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="grid gap-2 border-t border-slate-850 bg-slate-900/40 px-4 py-3.5 sm:flex sm:justify-end sm:px-5 sm:py-3">
          <button
            onClick={onClose}
            className="min-h-10 rounded-lg bg-slate-900 border border-slate-800 px-4 py-2.5 text-xs sm:text-sm font-semibold text-slate-200 transition hover:bg-slate-850 hover:text-white"
          >
            Mark False Positive
          </button>
          <button
            onClick={onClose}
            className="min-h-10 rounded-lg bg-gradient-to-r from-amber-600 to-orange-600 px-4 py-2.5 text-xs sm:text-sm font-semibold text-white shadow-lg shadow-amber-500/10 transition hover:from-amber-500 hover:to-orange-500"
          >
            Escalate Incident
          </button>
        </div>
      </div>
    </div>
  );
}

function DetailField({
  label,
  value,
  mono,
  accent,
}: {
  label: string;
  value: string;
  mono?: boolean;
  accent?: string;
}) {
  return (
    <div className="rounded-lg border border-slate-700/50 bg-slate-800/50 p-3">
      <div className="mb-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-500">
        {label}
      </div>
      <div className={`${mono ? "font-mono text-xs" : "text-sm"} break-words font-medium ${accent || "text-slate-100"}`}>
        {value}
      </div>
    </div>
  );
}
