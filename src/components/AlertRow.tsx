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
      className={`alert-row w-full text-left border-b border-slate-800/70 hover:bg-slate-800/70 transition font-mono ${
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
      {/* Ultra-compact mobile layout: single line for narrow columns */}
      <div className="flex items-center gap-1 px-1 py-1 lg:hidden">
        <span
          title={alert.isAttack ? "Attack signal" : alert.isFalsePositive ? "Likely false positive" : "Noise"}
          className={`h-1.5 w-1.5 sm:h-2 sm:w-2 shrink-0 rounded-full ${
            alert.isAttack
              ? "bg-red-400 animate-pulse shadow-lg shadow-red-500/50"
              : alert.isFalsePositive
              ? "bg-amber-300"
              : SEV_DOT[alert.severity]
          }`}
        />
        <span className="flex-1 truncate text-slate-100 text-[8px] sm:text-[10px] leading-tight">
          {alert.isAttack && <span className="text-red-300 mr-0.5">!</span>}
          {alert.rule}
        </span>
        <span className="text-slate-500 text-[7px] sm:text-[9px] shrink-0">{alert.time.slice(0, 5)}</span>
      </div>

      {/* Desktop layout: full grid row */}
      <div className="hidden lg:grid lg:grid-cols-12 lg:items-center lg:gap-2 lg:px-4 lg:py-3 text-sm">
        <span className="col-time text-slate-400 text-xs col-span-2">{alert.time}</span>
        <span className="col-sig flex items-center justify-center col-span-1">
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
        <span className="col-sev col-span-1">
          <span
            className={`px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${
              SEV_STYLES[alert.severity]
            }`}
          >
            {alert.severity}
          </span>
        </span>
        <span className="col-rule break-words text-slate-100 font-medium col-span-4">
          {alert.isAttack && <span className="text-red-300 mr-1">ATTACK</span>}
          {alert.isFalsePositive && <span className="text-amber-300 mr-1">FP?</span>}
          {alert.rule}
        </span>
        <span className="col-source break-words text-slate-400 text-xs col-span-2">
          {alert.source}
        </span>
        <span className="col-target break-words text-slate-400 text-xs col-span-2">
          {alert.dest}
        </span>
      </div>
    </button>
  );
}
