import type { AnalystState } from "../types";

interface Props {
  state: AnalystState;
  thought: string;
  stressLevel: number; // 0-100
}

export default function Analyst({ state, thought, stressLevel }: Props) {
  const sweating = stressLevel > 35;
  const panicking = stressLevel > 70;
  const shirtColor = panicking ? "#dc2626" : "#1e3a8a";
  const shirtShade = panicking ? "#991b1b" : "#1e40af";

  return (
    <div className="relative flex flex-col items-center justify-center h-full w-full pt-8">
      {/* Thought bubble */}
      {thought && (
        <div key={thought} className="absolute top-0 left-2 right-2 z-10 animate-[slideDown_0.25s_ease-out]">
          <div className="rounded-md border border-slate-800 bg-slate-950/95 px-3 py-2 text-[11px] leading-snug font-medium text-slate-100 shadow-xl border-l-2 border-l-cyan-500">
            <span className="mr-1 text-cyan-400">💭</span>
            {thought}
          </div>
        </div>
      )}

      {/* Analyst SVG */}
      <div className={`relative ${panicking ? "animate-bounce" : ""}`}>
        <svg viewBox="0 0 220 240" className="w-56 h-60 drop-shadow-2xl">
          {/* Chair back */}
          <rect x="55" y="150" width="110" height="80" rx="14" fill="#1e293b" />
          <rect x="60" y="155" width="100" height="70" rx="10" fill="#334155" />

          {/* Body / shirt */}
          <path
            d="M45 220 Q45 135 110 135 Q175 135 175 220 Z"
            fill={shirtColor}
          />
          <path
            d="M45 220 Q45 135 110 135 L110 220 Z"
            fill={shirtShade}
            opacity="0.4"
          />
          {/* Collar */}
          <path
            d="M95 135 L110 150 L125 135 L120 145 L110 158 L100 145 Z"
            fill="#f1f5f9"
          />

          {/* Neck */}
          <rect x="100" y="115" width="20" height="22" fill="#e8b89a" />
          <rect x="100" y="115" width="20" height="6" fill="#c99578" opacity="0.5" />

          {/* Head */}
          <ellipse cx="110" cy="88" rx="36" ry="38" fill="#f0c5a3" />
          {/* Face shading */}
          <ellipse cx="110" cy="88" rx="36" ry="38" fill="url(#faceShade)" opacity="0.3" />

          {/* Hair */}
          <path
            d="M76 78 Q74 50 110 48 Q146 50 144 78 Q142 65 130 60 Q120 56 110 56 Q100 56 90 60 Q78 65 76 78 Z"
            fill="#2d1810"
          />
          <path
            d="M76 78 Q80 70 88 68 Q95 72 90 80 Q82 82 76 78 Z"
            fill="#1a0d08"
          />

          {/* Ears */}
          <ellipse cx="74" cy="90" rx="5" ry="8" fill="#e8b89a" />
          <ellipse cx="146" cy="90" rx="5" ry="8" fill="#e8b89a" />

          {/* Eyebrows */}
          {panicking ? (
            <>
              <path d="M85 76 L100 72" stroke="#2d1810" strokeWidth="2.5" strokeLinecap="round" />
              <path d="M120 72 L135 76" stroke="#2d1810" strokeWidth="2.5" strokeLinecap="round" />
            </>
          ) : state === "confused" ? (
            <>
              <path d="M85 78 L100 74" stroke="#2d1810" strokeWidth="2.5" strokeLinecap="round" />
              <path d="M120 78 L135 78" stroke="#2d1810" strokeWidth="2.5" strokeLinecap="round" />
            </>
          ) : (
            <>
              <path d="M85 78 Q92 75 100 78" stroke="#2d1810" strokeWidth="2.5" strokeLinecap="round" fill="none" />
              <path d="M120 78 Q128 75 135 78" stroke="#2d1810" strokeWidth="2.5" strokeLinecap="round" fill="none" />
            </>
          )}

          {/* Eyes */}
          {state === "defeated" ? (
            <>
              <path d="M85 92 L97 86 M85 86 L97 92" stroke="#1f2937" strokeWidth="2.5" strokeLinecap="round" />
              <path d="M123 92 L135 86 M123 86 L135 92" stroke="#1f2937" strokeWidth="2.5" strokeLinecap="round" />
            </>
          ) : panicking ? (
            <>
              <circle cx="91" cy="90" r="7" fill="white" stroke="#1f2937" strokeWidth="1.5" />
              <circle cx="129" cy="90" r="7" fill="white" stroke="#1f2937" strokeWidth="1.5" />
              <circle cx="91" cy="90" r="3" fill="#1f2937" />
              <circle cx="129" cy="90" r="3" fill="#1f2937" />
              <circle cx="92" cy="89" r="1" fill="white" />
              <circle cx="130" cy="89" r="1" fill="white" />
            </>
          ) : (
            <>
              <ellipse cx="91" cy="90" rx="3" ry="3.5" fill="#1f2937" />
              <ellipse cx="129" cy="90" rx="3" ry="3.5" fill="#1f2937" />
              <circle cx="92" cy="89" r="1" fill="white" />
              <circle cx="130" cy="89" r="1" fill="white" />
            </>
          )}

          {/* Glasses */}
          <circle cx="91" cy="90" r="11" fill="none" stroke="#0f172a" strokeWidth="2" />
          <circle cx="129" cy="90" r="11" fill="none" stroke="#0f172a" strokeWidth="2" />
          <line x1="102" y1="90" x2="118" y2="90" stroke="#0f172a" strokeWidth="2" />
          <line x1="80" y1="88" x2="74" y2="86" stroke="#0f172a" strokeWidth="2" />
          <line x1="140" y1="88" x2="146" y2="86" stroke="#0f172a" strokeWidth="2" />
          {/* Glasses reflection */}
          <ellipse cx="88" cy="86" rx="3" ry="2" fill="white" opacity="0.4" />
          <ellipse cx="126" cy="86" rx="3" ry="2" fill="white" opacity="0.4" />

          {/* Mouth */}
          {state === "defeated" ? (
            <path d="M95 112 Q110 104 125 112" fill="none" stroke="#7f1d1d" strokeWidth="2.5" strokeLinecap="round" />
          ) : panicking ? (
            <ellipse cx="110" cy="112" rx="8" ry="6" fill="#7f1d1d" />
          ) : state === "confused" ? (
            <path d="M98 112 Q110 116 122 108" fill="none" stroke="#7f1d1d" strokeWidth="2.5" strokeLinecap="round" />
          ) : state === "investigating" ? (
            <line x1="100" y1="112" x2="120" y2="112" stroke="#7f1d1d" strokeWidth="2.5" strokeLinecap="round" />
          ) : (
            <path d="M100 110 Q110 114 120 110" fill="none" stroke="#7f1d1d" strokeWidth="2.5" strokeLinecap="round" />
          )}

          {/* Sweat drops */}
          {sweating && (
            <>
              <ellipse cx="148" cy="85" rx="3.5" ry="5.5" fill="#60a5fa" opacity="0.9">
                <animate attributeName="cy" values="85;120;85" dur="1.2s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.9;0;0.9" dur="1.2s" repeatCount="indefinite" />
              </ellipse>
              <ellipse cx="72" cy="92" rx="3" ry="5" fill="#60a5fa" opacity="0.9">
                <animate attributeName="cy" values="92;125;92" dur="1.5s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.9;0;0.9" dur="1.5s" repeatCount="indefinite" />
              </ellipse>
            </>
          )}

          {/* Headset */}
          <path
            d="M70 75 Q70 45 110 45 Q150 45 150 75"
            stroke="#0f172a"
            strokeWidth="4"
            fill="none"
            strokeLinecap="round"
          />
          <rect x="63" y="75" width="11" height="18" rx="4" fill="#0f172a" />
          <rect x="146" y="75" width="11" height="18" rx="4" fill="#0f172a" />
          <circle cx="68.5" cy="84" r="2" fill="#3b82f6" />
          <circle cx="151.5" cy="84" r="2" fill="#3b82f6" />
          {/* Mic */}
          <path d="M146 88 Q138 100 130 108" stroke="#0f172a" strokeWidth="2" fill="none" />
          <circle cx="130" cy="108" r="2.5" fill="#0f172a" />

          {/* Arms */}
          <rect x="48" y="160" width="18" height="48" rx="9" fill={shirtColor}>
            {(state === "typing" || state === "investigating") && (
              <animate attributeName="y" values="160;154;160" dur="0.18s" repeatCount="indefinite" />
            )}
          </rect>
          <rect x="154" y="160" width="18" height="48" rx="9" fill={shirtColor}>
            {(state === "typing" || state === "investigating") && (
              <animate attributeName="y" values="160;154;160" dur="0.22s" repeatCount="indefinite" />
            )}
          </rect>

          {/* Hands */}
          <circle cx="57" cy="210" r="9" fill="#f0c5a3">
            {(state === "typing" || state === "investigating") && (
              <animate attributeName="cy" values="210;204;210" dur="0.18s" repeatCount="indefinite" />
            )}
          </circle>
          <circle cx="163" cy="210" r="9" fill="#f0c5a3">
            {(state === "typing" || state === "investigating") && (
              <animate attributeName="cy" values="210;204;210" dur="0.22s" repeatCount="indefinite" />
            )}
          </circle>

          <defs>
            <radialGradient id="faceShade" cx="0.5" cy="1" r="0.8">
              <stop offset="0" stopColor="#8b5a3c" stopOpacity="0.4" />
              <stop offset="1" stopColor="#8b5a3c" stopOpacity="0" />
            </radialGradient>
          </defs>
        </svg>
      </div>

      {/* Status badge */}
      <div className="mt-1 flex items-center gap-2 bg-slate-800/80 px-3 py-1 rounded-full border border-slate-700">
        <div
          className={`h-2 w-2 rounded-full ${
            panicking ? "bg-red-500 animate-pulse" : sweating ? "bg-amber-400" : "bg-emerald-500"
          }`}
        />
        <span className="text-xs text-slate-300 font-semibold uppercase tracking-wider">
          {state}
        </span>
      </div>
    </div>
  );
}
