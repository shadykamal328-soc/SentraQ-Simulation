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
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-[fadeIn_0.2s]">
      <div className="w-full max-w-3xl bg-slate-900 border-2 border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-700 bg-gradient-to-r from-slate-800 to-slate-900">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg">
              🔍
            </div>
            <div>
              <h2 className="text-white font-bold text-base">
                Investigation Console
              </h2>
              <p className="text-xs text-slate-400">
                Alert ID #{alert.id} · {alert.category}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg w-8 h-8 flex items-center justify-center text-lg transition"
          >
            ✕
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* Alert summary */}
          <div className="grid grid-cols-2 gap-3 text-sm">
            <DetailField label="Rule" value={alert.rule} />
            <DetailField label="Category" value={alert.category} />
            <DetailField label="Source" value={alert.source} mono />
            <DetailField label="Destination" value={alert.dest} mono />
            <DetailField
              label="Severity"
              value={alert.severity.toUpperCase()}
              accent="text-amber-400"
            />
            <DetailField label="Time" value={alert.time} mono />
          </div>

          {/* Event details */}
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400 font-bold mb-2">
              Event Details
            </div>
            <pre className="bg-black/60 border border-slate-800 rounded-lg p-3 text-emerald-300 text-xs whitespace-pre-wrap font-mono leading-relaxed">
              {alert.details.join("\n")}
            </pre>
          </div>

          {/* Investigation progress */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs uppercase tracking-wider text-slate-400 font-bold">
                Automated Investigation
              </span>
              <span className="text-sm font-mono text-cyan-400 font-bold">
                {Math.round(progress)}%
              </span>
            </div>
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden mb-3">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300 shadow-lg shadow-cyan-500/50"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="space-y-1.5 max-h-44 overflow-y-auto bg-black/40 rounded-lg p-3 border border-slate-800">
              {steps.map((s, i) => (
                <div key={i} className="text-emerald-400 text-xs font-mono">
                  <span className="text-slate-600">[{String(i + 1).padStart(2, "0")}]</span>{" "}
                  {s}
                </div>
              ))}
              {progress < 100 && (
                <div className="text-amber-400 text-xs font-mono animate-pulse">
                  ▊ analyzing...
                </div>
              )}
              {progress >= 100 && (
                <div className="text-cyan-400 text-xs font-mono font-bold mt-2">
                  ✓ Investigation complete
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-700 bg-slate-800/50 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 font-medium transition"
          >
            Mark False Positive
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-medium transition shadow-lg shadow-amber-500/30"
          >
            🚨 Escalate
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
    <div className="bg-slate-800/50 rounded-lg p-2.5 border border-slate-700/50">
      <div className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-0.5">
        {label}
      </div>
      <div
        className={`${mono ? "font-mono text-xs" : "text-sm"} ${
          accent || "text-slate-100"
        } font-medium truncate`}
      >
        {value}
      </div>
    </div>
  );
}
