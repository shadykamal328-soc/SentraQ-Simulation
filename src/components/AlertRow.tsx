import type { Alert } from "../types";

const SEV_DOT = {
  low: "bg-sky-400",
  medium: "bg-amber-400",
  high: "bg-orange-400",
  critical: "bg-red-500 animate-pulse shadow-lg shadow-red-500/50",
};

const SEV_STYLES = {
  low: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/50",
  critical: "bg-red-500/25 text-red-300 border-red-500/60",
};

export default function AlertRow({
  alert,
  onClick,
  fresh,
}: {
  alert: Alert;
  onClick: () => void;
  fresh?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={`alert-row w-full text-left border-b border-slate-800/70 hover:bg-slate-800/70 transition font-mono ${
        fresh ? "animate-[slideIn_0.25s_ease-out] bg-slate-800/30" : ""
      } ${alert.isAttack ? "bg-red-950/20 hover:bg-red-950/35" : ""} ${
        alert.isFalsePositive ? "bg-amber-950/20 hover:bg-amber-950/35" : ""
      } ${
        alert.severity === "critical"
          ? "border-l-2 border-l-red-500"
          : alert.severity === "high"
          ? "border-l-2 border-l-orange-400"
          : ""
      }`}
    >
      {/* Compact layout: severity dot + rule name + time */}
      <div className="flex items-center gap-1.5 px-2 py-1.5 sm:px-3 sm:py-2">
        <span
          className={`h-2 w-2 shrink-0 rounded-full ${
            alert.isAttack
              ? "bg-red-400 animate-pulse shadow-lg shadow-red-500/50"
              : alert.isFalsePositive
              ? "bg-amber-300"
              : SEV_DOT[alert.severity]
          }`}
        />
        <span className={`shrink-0 px-1 py-0.5 rounded border text-[8px] sm:text-[10px] uppercase font-bold hidden sm:inline ${SEV_STYLES[alert.severity]}`}>
          {alert.severity.slice(0, 4)}
        </span>
        <span className="flex-1 truncate text-slate-100 text-[10px] sm:text-xs">
          {alert.isAttack && <span className="text-red-300 mr-0.5 font-bold">ATK</span>}
          {alert.isFalsePositive && <span className="text-amber-300 mr-0.5">FP?</span>}
          {alert.rule}
        </span>
        <span className="text-slate-500 text-[9px] sm:text-[11px] shrink-0">{alert.time.slice(0, 5)}</span>
      </div>
    </button>
  );
}
