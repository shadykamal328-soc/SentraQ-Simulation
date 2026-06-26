import type { Alert } from "../types";

const SEV_STYLES = {
  low: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/50",
  critical: "bg-red-500/25 text-red-300 border-red-500/60",
};

const SEV_DOT = {
  low: "bg-sky-400",
  medium: "bg-amber-400",
  high: "bg-orange-400",
  critical: "bg-red-500 animate-pulse shadow-lg shadow-red-500/50",
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
      className={`w-full text-left grid grid-cols-1 gap-2 px-4 py-3 border-b border-slate-800/70 hover:bg-slate-800/70 transition text-sm font-mono items-start sm:grid-cols-12 sm:items-center ${
        fresh ? "animate-[slideIn_0.25s_ease-out] bg-slate-800/30" : ""
      } ${
        alert.isAttack ? "bg-red-950/20 hover:bg-red-950/35" : ""
      } ${
        alert.isFalsePositive ? "bg-amber-950/20 hover:bg-amber-950/35" : ""
      } ${
        alert.severity === "critical"
          ? "border-l-2 border-l-red-500"
          : alert.severity === "high"
          ? "border-l-2 border-l-orange-400"
          : ""
      }`}
    >
      <span className="text-slate-400 text-xs sm:col-span-2">{alert.time}</span>
      <span className="flex items-center sm:justify-center sm:col-span-1">
        <span
          title={alert.isAttack ? "Attack signal" : alert.isFalsePositive ? "Likely false positive" : "Noise"}
          className={`h-2.5 w-2.5 rounded-full ${
            alert.isAttack
              ? "bg-red-400 animate-pulse shadow-lg shadow-red-500/50"
              : alert.isFalsePositive
              ? "bg-amber-300"
              : SEV_DOT[alert.severity]
          }`}
        />
      </span>
      <span className="sm:col-span-1">
        <span
          className={`px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${
            SEV_STYLES[alert.severity]
          }`}
        >
          {alert.severity}
        </span>
      </span>
      <span className="break-words text-slate-100 font-medium sm:col-span-4">
        {alert.isAttack && <span className="text-red-300 mr-1">ATTACK</span>}
        {alert.isFalsePositive && <span className="text-amber-300 mr-1">FP?</span>}
        {alert.rule}
      </span>
      <span className="break-words text-slate-400 text-xs sm:col-span-2">
        {alert.source}
      </span>
      <span className="break-words text-slate-400 text-xs sm:col-span-2">
        {alert.dest}
      </span>
    </button>
  );
}
