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
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-[fadeIn_0.2s]">
      <div className="w-full max-w-3xl overflow-hidden rounded-2xl border-2 border-slate-700 bg-slate-900 shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-700 bg-gradient-to-r from-slate-800 to-slate-900 px-4 py-4 sm:px-5 sm:py-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg">
              Search
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Investigation Console</h2>
              <p className="text-xs text-slate-400">
                Alert ID #{alert.id} - {alert.category}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex min-h-11 min-w-11 items-center justify-center rounded-lg px-3 py-3 text-lg text-slate-400 transition hover:bg-slate-700 hover:text-white"
          >
            X
          </button>
        </div>

        <div className="space-y-4 p-4 sm:p-5">
          <div className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
            <DetailField label="Rule" value={alert.rule} />
            <DetailField label="Category" value={alert.category} />
            <DetailField label="Source" value={alert.source} mono />
            <DetailField label="Destination" value={alert.dest} mono />
            <DetailField label="Severity" value={alert.severity.toUpperCase()} accent="text-amber-400" />
            <DetailField label="Time" value={alert.time} mono />
          </div>

          <div>
            <div className="mb-2 text-xs font-bold uppercase tracking-wider text-slate-400">
              Event Details
            </div>
            <pre className="overflow-hidden rounded-lg border border-slate-800 bg-black/60 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words text-emerald-300">
              {alert.details.join("\n")}
            </pre>
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Automated Investigation
              </span>
              <span className="font-mono text-sm font-bold text-cyan-400">
                {Math.round(progress)}%
              </span>
            </div>
            <div className="mb-3 h-2 overflow-hidden rounded-full bg-slate-800">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 shadow-lg shadow-cyan-500/50 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="max-h-44 space-y-1.5 overflow-y-auto rounded-lg border border-slate-800 bg-black/40 p-3">
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

        <div className="grid gap-2 border-t border-slate-700 bg-slate-800/50 px-4 py-4 sm:flex sm:justify-end sm:px-5 sm:py-3">
          <button
            onClick={onClose}
            className="min-h-11 rounded-lg bg-slate-700 px-4 py-3 text-sm font-medium text-slate-200 transition hover:bg-slate-600"
          >
            Mark False Positive
          </button>
          <button
            onClick={onClose}
            className="min-h-11 rounded-lg bg-amber-600 px-4 py-3 text-sm font-medium text-white shadow-lg shadow-amber-500/30 transition hover:bg-amber-500"
          >
            Escalate
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
