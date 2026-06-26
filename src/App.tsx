import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Alert, AnalystState, AttackLog, AttackScenario, Severity } from "./types";
import {
  ANALYST_THOUGHTS,
  ATTACK_SCENARIOS,
  EXT_IPS,
  HOSTS,
  RULES,
  USERS,
  pick,
  randomIP,
} from "./data";
import AlertRow from "./components/AlertRow";
import Analyst from "./components/Analyst";
import InvestigationPanel from "./components/InvestigationPanel";

const TOTAL_DURATION = 20;
const ATTACK_AT = 20;
const SENTRAQ_CONTAIN_AT = 10;
const MAX_ALERTS = 90;

type SimulationMode = "manual" | "sentraq";

const FEATURED_ATTACK_IDS = ["ransomware-full-flow", "ddos-attack-flow", "lateral-movement-flow"];
const FEATURED_ATTACK_SCENARIOS = ATTACK_SCENARIOS.filter((scenario) => FEATURED_ATTACK_IDS.includes(scenario.id));

const SENTRAQ_STEPS = [
  {
    at: 2,
    label: "ELK ingest",
    detail: "Alerts streamed from ELK and normalized into one investigation case.",
    action: "Create/Update Incident Case",
  },
  {
    at: 5,
    label: "MISP enrichment",
    detail: "IPs, domains, hashes, and user context enriched with MISP threat intelligence.",
    action: "Attach Threat Intel",
  },
  {
    at: 7,
    label: "Investigation summary",
    detail: "AI generates a concise timeline, affected assets, evidence, and recommended response.",
    action: "Generate Summary",
  },
  {
    at: 8,
    label: "Risk classification",
    detail: "Related alerts are correlated into a high-risk multi-stage attack chain.",
    action: "Escalate Complex Case",
  },
  {
    at: 9,
    label: "Response actions",
    detail: "Recommended containment actions are prepared with clear business impact.",
    action: "Block IP / Disable User / Isolate Host / Kill Process",
  },
  {
    at: SENTRAQ_CONTAIN_AT,
    label: "Containment",
    detail: "Host isolated, user disabled, malicious process killed, and attacker IP blocked.",
    action: "Contain Attack",
  },
];

const VIRTUAL_L1_THOUGHTS = [
  "Virtual L1 is clustering ELK alerts into one incident.",
  "MISP enrichment matched attacker infrastructure.",
  "Risk is critical because multiple signals correlate.",
  "Summary, evidence, and recommended actions are ready.",
  "Containment actions are being prepared.",
  "Human analyst can review the generated case instead of triaging raw noise.",
];

function fmtTime(d = new Date()) {
  return d.toTimeString().slice(0, 8);
}

function stageIndexFor(elapsed: number, scenario: AttackScenario) {
  const step = ATTACK_AT / Math.max(1, scenario.attackLogs.length - 1);
  return Math.min(scenario.attackLogs.length - 1, Math.floor(elapsed / step));
}

function timelineLabel(index: number, total: number) {
  const seconds = total <= 1 ? 0 : Math.round((index / (total - 1)) * ATTACK_AT);
  return `T+00:${String(seconds).padStart(2, "0")}`;
}

function getAnalystThought(log: AttackLog | undefined, scenario: AttackScenario, mode: SimulationMode) {
  if (!log) {
    if (mode === "sentraq") {
      return `Virtual L1 is monitoring. Analyzing logs for ${scenario.shortName}...`;
    } else {
      return `Starting L1 triage for ${scenario.shortName}. Monitoring queues...`;
    }
  }

  const msg = log.message.toLowerCase();
  
  if (mode === "sentraq") {
    if (msg.includes("delivered") || msg.includes("received") || msg.includes("ingress") || msg.includes("recon")) {
      return `Clustering incoming indicators for ${scenario.shortName}. Normalizing logs.`;
    }
    if (msg.includes("spawned") || msg.includes("token") || msg.includes("login") || msg.includes("auth")) {
      return `AI detected credential abuse. Cross-referencing sign-in token with user profile.`;
    }
    if (msg.includes("psexec") || msg.includes("smb") || msg.includes("outbound") || msg.includes("forward")) {
      return `Correlating lateral movement. Internal SMB scan is linked to the active case.`;
    }
    if (msg.includes("vssadmin") || msg.includes("delete") || msg.includes("exfil") || msg.includes("download") || msg.includes("backlog")) {
      return `Critical threat detected! Auto-generating response playbook to isolate targets.`;
    }
    return `Virtual L1 normalized ${log.source} telemetry and appended it to the current case.`;
  } else {
    if (msg.includes("delivered") || msg.includes("received")) {
      return `Just an email delivery log from ${log.source}. Is it a phishing attempt? I should check later.`;
    }
    if (msg.includes("spawned") || msg.includes("rundll32")) {
      return `EDR says process spawned powershell.exe? Let me Google if this is a Teams false positive...`;
    }
    if (msg.includes("proxy") || msg.includes("connect")) {
      return `Connection to external IP from ${log.source}. Looks like standard telemetry traffic, probably fine.`;
    }
    if (msg.includes("token") || msg.includes("login") || msg.includes("auth")) {
      return `Privileged token requested? Let me open a ticket to ask the backup team if this is theirs.`;
    }
    if (msg.includes("smb") || msg.includes("scan") || msg.includes("fan-out")) {
      return `High volume of SMB sessions... Maybe someone is copying files? Queue is filling up, I'm stressed.`;
    }
    if (msg.includes("vssadmin") || msg.includes("delete") || msg.includes("shadows")) {
      return `Wait, shadow copies deleted on SRV-FILE02?! That's a ransomware behavior! Let me double check...`;
    }
    if (msg.includes("failed") || msg.includes("spray")) {
      return `Thousands of failed sign-ins from different IPs. Credential stuffing? I'll review after this ticket.`;
    }
    if (msg.includes("oauth") || msg.includes("consent")) {
      return `An OAuth app was granted Files.Read? That's weird, but I have 40 other alerts in queue.`;
    }
    if (msg.includes("download") || msg.includes("exfil")) {
      return `Large SharePoint download. Is the user exfiltrating data, or just archiving their projects?`;
    }
    if (msg.includes("psexec") || msg.includes("remote")) {
      return `PsExec service created... This is extremely suspicious. Oh no, systems are starting to encrypt!`;
    }
    if (msg.includes("backlog") || msg.includes("latenc") || msg.includes("availability")) {
      return `WAF and load balancer are saturating. The app is down! I'm drowning in alerts right now!`;
    }
    return `Reviewing ${log.source} logs... There are so many similar alerts, it's hard to tell what's real.`;
  }
}

function recommendationsFor(scenario: AttackScenario) {
  if (scenario.id.includes("ddos")) {
    return [
      "Activate DDoS mitigation profile at CDN/WAF.",
      "Apply rate limits for SYN, UDP, HTTP GET/POST, and DNS amplification patterns.",
      "Block or challenge high-volume source ASNs and botnet IPs from MISP.",
      "Scale load balancer capacity and protect origin IP exposure.",
      "Create incident case with NetFlow, WAF, CDN, firewall, and availability evidence.",
    ];
  }

  if (scenario.id.includes("ransomware") || scenario.id.includes("phishing")) {
    return [
      `Isolate impacted host ${scenario.entryNode}.`,
      "Disable compromised user and revoke active sessions.",
      "Kill malicious PowerShell/script process tree.",
      "Block C2 IP/domain and hunt for payload hash across endpoints.",
      "Preserve evidence and create ransomware incident case for IR escalation.",
    ];
  }

  if (scenario.id.includes("lateral")) {
    return [
      "Disable suspected admin/service account and revoke Kerberos tickets.",
      "Block SMB/PsExec movement from the compromised host.",
      "Isolate source workstation and touched servers.",
      "Collect authentication timeline and remote service creation events.",
      "Escalate to IR for credential reset and domain-wide lateral movement hunt.",
    ];
  }

  if (scenario.id.includes("cloud")) {
    return [
      "Disable suspicious user session and revoke refresh tokens.",
      "Remove malicious OAuth consent and review app permissions.",
      "Block risky IPs and enforce conditional access challenge.",
      "Stop mailbox forwarding rule and preserve audit logs.",
      "Open cloud exfiltration incident case with MISP enrichment attached.",
    ];
  }

  if (scenario.id.includes("devops")) {
    return [
      "Revoke developer and CI/CD tokens immediately.",
      "Freeze package publishing and rollback suspicious artifact version.",
      "Disable compromised automation identity.",
      "Scan repository workflow changes and build artifacts.",
      "Create supply-chain incident case and notify engineering owners.",
    ];
  }

  return [
    "Block malicious infrastructure.",
    "Disable compromised identity.",
    "Isolate impacted host.",
    "Kill suspicious process.",
    "Create and update incident case with investigation summary.",
  ];
}

function makeNoiseAlert(id: number, mode: SimulationMode): Alert {
  const rule = pick(RULES);
  const src = Math.random() > 0.55 ? randomIP() : pick(USERS);
  const dst = Math.random() > 0.5 ? pick(HOSTS) : pick(EXT_IPS);

  return {
    id,
    time: fmtTime(),
    severity: rule.severity,
    source: src,
    dest: dst,
    rule: rule.rule,
    category: rule.category,
    details: [
      `event.id=${id}`,
      `source.product=SIEM`,
      `rule.name="${rule.rule}"`,
      `category="${rule.category}"`,
      `src=${src}`,
      `dst=${dst}`,
      `process=${pick(["powershell.exe", "chrome.exe", "outlook.exe", "teams.exe", "svchost.exe"])}`,
      `risk_score=${Math.floor(Math.random() * 55) + 10}`,
      `queue=${mode === "sentraq" ? "SENTRAQ_AI_CASE" : "L1_INITIAL_TRIAGE"}`,
      `disposition=${mode === "sentraq" ? "auto_clustered_low_risk" : "pending"}`,
    ],
  };
}

function makeFalsePositiveAlert(id: number, scenario: AttackScenario, mode: SimulationMode): Alert {
  return {
    id,
    time: fmtTime(),
    severity: "medium",
    source: scenario.entryNode,
    dest: "SIEM",
    rule: scenario.falsePositiveFocus,
    category: "Initial L1 Triage",
    isFalsePositive: true,
    details: [
      `event.id=${id}`,
      `case.type=${mode === "sentraq" ? "sentraq_auto_investigation" : "manual_l1_investigation"}`,
      `reason="${scenario.falsePositiveFocus}"`,
      "triage.signal=medium",
      `enrichment.status=${mode === "sentraq" ? "misp_enriched_in_5s" : "slow"}`,
      "historical.disposition=false_positive_7_of_last_9",
      `analyst.note=${mode === "sentraq" ? "auto_suppressed_but_kept_as_context" : "needs manual validation before escalation"}`,
    ],
  };
}

function makeAttackAlert(id: number, scenario: AttackScenario, elapsed: number, mode: SimulationMode): Alert {
  const stageIndex = stageIndexFor(elapsed, scenario);
  const rule = scenario.attackRules[Math.min(scenario.attackRules.length - 1, stageIndex)];
  const log = scenario.attackLogs[stageIndex];

  return {
    id,
    time: fmtTime(),
    severity: rule.severity,
    source: scenario.entryNode,
    dest: scenario.targetNode,
    rule: rule.rule,
    category: rule.category,
    isAttack: true,
    phase: rule.phase,
    details: [
      `event.id=${id}`,
      `attack.scenario="${scenario.name}"`,
      `attack.phase=${rule.phase}`,
      `automation="${scenario.attackerAutomation}"`,
      `latest_log="${log.message}"`,
      `src=${scenario.entryNode}`,
      `dst=${scenario.targetNode}`,
      `risk_score=${rule.severity === "critical" ? 96 : 82}`,
      `queue=${mode === "sentraq" ? "SENTRAQ_AI_CASE" : "L1_INITIAL_TRIAGE"}`,
      `correlation.status=${mode === "sentraq" ? "correlated_with_active_incident" : "not_yet_reviewed"}`,
      `recommended.actions=${mode === "sentraq" ? "block_ip,disable_user,isolate_host,kill_process,update_case" : "none_yet"}`,
    ],
  };
}

export default function App() {
  const [scenario, setScenario] = useState<AttackScenario>(ATTACK_SCENARIOS[0]);
  const [mode, setMode] = useState<SimulationMode>("manual");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [attackAlerts, setAttackAlerts] = useState<Alert[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [analystState, setAnalystState] = useState<AnalystState>("typing");
  const [thought, setThought] = useState(ANALYST_THOUGHTS[0]);
  const [missed, setMissed] = useState(0);
  const [reviewed, setReviewed] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [attackTriggered, setAttackTriggered] = useState(false);
  const [hasStarted, setHasStarted] = useState(false);
  const [running, setRunning] = useState(false);
  const [activeLogs, setActiveLogs] = useState<AttackLog[]>([]);
  const [showReport, setShowReport] = useState(false);
  const [showVideo, setShowVideo] = useState(false);
  const [soundMuted, setSoundMuted] = useState(false);
  const [expandedScenario, setExpandedScenario] = useState<string | null>(null);
  const idRef = useRef(1000);
  const listRef = useRef<HTMLDivElement>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const soundTimerRef = useRef<number | null>(null);
  const falsePositiveSeeded = useRef(false);

  const displayAlerts = useMemo(() => [...attackAlerts, ...alerts].slice(0, MAX_ALERTS), [attackAlerts, alerts]);
  const effectiveEndAt = ATTACK_AT;
  const stress = mode === "sentraq"
    ? Math.min(48, 14 + displayAlerts.length * 0.08 + elapsed * 0.45)
    : Math.min(100, 18 + (elapsed / TOTAL_DURATION) * 92 + displayAlerts.length * 0.25);
  const timeLeft = Math.max(0, effectiveEndAt - elapsed);
  const attackProgress = Math.min(100, (elapsed / ATTACK_AT) * 100);
  const sentraqProgress = Math.min(100, (elapsed / SENTRAQ_CONTAIN_AT) * 100);
  const sentraqContained = mode === "sentraq" && elapsed >= SENTRAQ_CONTAIN_AT;
  const rate = elapsed > 0 ? ((idRef.current - 1000) / elapsed).toFixed(1) : "0";
  const executionStatus = !hasStarted
    ? "ready"
    : attackTriggered || sentraqContained
    ? mode === "sentraq"
      ? "contained"
      : "completed"
    : "running";

  const counts = useMemo(
    () => ({
      critical: displayAlerts.filter((a) => a.severity === "critical").length,
      high: displayAlerts.filter((a) => a.severity === "high").length,
      medium: displayAlerts.filter((a) => a.severity === "medium").length,
      low: displayAlerts.filter((a) => a.severity === "low").length,
      attack: displayAlerts.filter((a) => a.isAttack).length,
      falsePositive: displayAlerts.filter((a) => a.isFalsePositive).length,
    }),
    [displayAlerts],
  );

  useEffect(() => {
    if (!hasStarted || !running || attackTriggered) return;
    const interval = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(interval);
  }, [hasStarted, running, attackTriggered]);

  useEffect(() => {
    if (!hasStarted || !running || attackTriggered) return;

    if (!falsePositiveSeeded.current) {
      falsePositiveSeeded.current = true;
      const firstAlert = makeFalsePositiveAlert(idRef.current++, scenario, mode);
      setAlerts([firstAlert]);
      setSelected(null);
      setReviewed(0);
    }

    const ratio = elapsed / TOTAL_DURATION;
    const intervalMs = Math.max(110, 620 - ratio * 470);

    const interval = setInterval(() => {
      setAlerts((prev) => {
        const nextAlert = makeNoiseAlert(idRef.current++, mode);
        const next = [nextAlert, ...prev];

        if (next.length > MAX_ALERTS) {
          const dropped = next.length - MAX_ALERTS;
          setMissed((m) => m + dropped);
          return next.slice(0, MAX_ALERTS);
        }

        return next;
      });
    }, intervalMs);

    return () => clearInterval(interval);
  }, [hasStarted, running, elapsed, attackTriggered, scenario, mode]);

  useEffect(() => {
    if (!hasStarted) {
      setActiveLogs([]);
      return;
    }
    const step = ATTACK_AT / Math.max(1, scenario.attackLogs.length - 1);
    const visibleLogs = scenario.attackLogs.filter((_, index) => elapsed >= index * step);
    setActiveLogs(visibleLogs);
    setAttackAlerts(
      visibleLogs
        .map((_, stage) => makeAttackAlert(9000 + stage, scenario, Math.round(stage * step), mode))
        .reverse(),
    );
    if (!attackTriggered) {
      const latestLog = visibleLogs.at(-1);
      setThought(getAnalystThought(latestLog, scenario, mode));
    }
  }, [hasStarted, elapsed, scenario, mode, attackTriggered]);

  useEffect(() => {
    if (!hasStarted || attackTriggered) return;
    if (mode === "sentraq") setAnalystState("reading");
    else if (selected) setAnalystState("investigating");
    else if (stress > 78) setAnalystState("panic");
    else if (stress > 58) setAnalystState("confused");
    else if (stress > 35) setAnalystState("reading");
    else setAnalystState("typing");
  }, [hasStarted, stress, selected, attackTriggered, mode]);

  useEffect(() => {
    if (hasStarted && elapsed >= effectiveEndAt && !attackTriggered) {
      setAttackTriggered(true);
      setRunning(false);
      setSelected(null);
      setAnalystState(mode === "sentraq" ? "reading" : "defeated");
      setThought(mode === "sentraq" ? "Virtual L1 contained the chain before impact." : "I was still validating the first alert...");
    }
  }, [hasStarted, elapsed, attackTriggered, effectiveEndAt, mode]);

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = 0;
  }, [displayAlerts.length]);

  const unlockAudio = () => {
    if (soundMuted) return;
    const AudioCtor = window.AudioContext;
    if (!AudioCtor) return;
    const ctx = audioCtxRef.current ?? new AudioCtor();
    audioCtxRef.current = ctx;
    if (ctx.state === "suspended") void ctx.resume();
  };

  useEffect(() => {
    const shouldPlay = hasStarted && running && !soundMuted;

    if (!shouldPlay) {
      if (soundTimerRef.current) {
        window.clearInterval(soundTimerRef.current);
        soundTimerRef.current = null;
      }
      return;
    }

    const playPulse = () => {
      const AudioCtor = window.AudioContext;
      if (!AudioCtor) return;
      const ctx = audioCtxRef.current ?? new AudioCtor();
      audioCtxRef.current = ctx;
      if (ctx.state === "suspended") void ctx.resume();

      const oscillator = ctx.createOscillator();
      const gain = ctx.createGain();
      oscillator.type = "sine";
      oscillator.frequency.setValueAtTime(mode === "sentraq" ? 620 : 440, ctx.currentTime);
      gain.gain.setValueAtTime(0.0001, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(mode === "sentraq" ? 0.035 : 0.06, ctx.currentTime + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.18);
      oscillator.connect(gain);
      gain.connect(ctx.destination);
      oscillator.start();
      oscillator.stop(ctx.currentTime + 0.2);
    };

    playPulse();
    soundTimerRef.current = window.setInterval(playPulse, mode === "sentraq" ? 1400 : 700);

    return () => {
      if (soundTimerRef.current) {
        window.clearInterval(soundTimerRef.current);
        soundTimerRef.current = null;
      }
    };
  }, [hasStarted, running, soundMuted, mode]);

  const selectScenario = (nextScenario: AttackScenario) => {
    setScenario(nextScenario);
    setMode("manual");
    setAlerts([]);
    setAttackAlerts([]);
    setSelected(null);
    setMissed(0);
    setReviewed(0);
    setElapsed(0);
    setAttackTriggered(false);
    setAnalystState("idle");
    setThought("Select an execution mode to start the simulation.");
    setActiveLogs([]);
    setShowReport(false);
    setShowVideo(false);
    setHasStarted(false);
    setRunning(false);
    idRef.current = 1000;
    falsePositiveSeeded.current = false;
  };

  const resetSimulation = (nextScenario = scenario, nextMode = mode) => {
    unlockAudio();
    setScenario(nextScenario);
    setMode(nextMode);
    setAlerts([]);
    setAttackAlerts([]);
    setSelected(null);
    setMissed(0);
    setReviewed(0);
    setElapsed(0);
    setAttackTriggered(false);
    setAnalystState(nextMode === "sentraq" ? "reading" : "typing");
    setThought(nextMode === "sentraq" ? "Virtual L1 is investigating the ELK stream automatically." : ANALYST_THOUGHTS[0]);
    setActiveLogs([]);
    setShowReport(false);
    setShowVideo(false);
    setHasStarted(true);
    idRef.current = 1000;
    falsePositiveSeeded.current = false;
    setRunning(true);
  };

  const handleOpen = (alert: Alert) => {
    setSelected(alert);
    setReviewed((r) => r + 1);
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-slate-200 overflow-y-auto">
      <style>{`
        @keyframes slideIn { from { transform: translateX(-24px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes fadeIn { from { opacity: 0; transform: scale(0.98); } to { opacity: 1; transform: scale(1); } }
        @keyframes slideDown { from { transform: translateY(-8px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #10151f; }
        ::-webkit-scrollbar-thumb { background: #42526a; border-radius: 8px; }
      `}</style>

      <header className="border-b border-slate-800/60 bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 px-3 py-3 sm:px-6 sm:py-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          <div className="relative h-8 w-8 flex items-center justify-center shrink-0 select-none">
            {/* Glowing gradient blur behind the logo */}
            <div className="absolute inset-0 bg-gradient-to-tr from-cyan-500 to-emerald-400 rounded-lg opacity-30 blur-[3px]" />
            
            {/* High-tech Cybersecurity Shield SVG */}
            <svg className="relative h-7 w-7" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="logo-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#06b6d4" />
                  <stop offset="50%" stopColor="#10b981" />
                  <stop offset="100%" stopColor="#3b82f6" />
                </linearGradient>
              </defs>
              <path
                d="M16 3L27 8.5v8c0 6.075-4.925 11-11 11S5 22.575 5 16.5v-8L16 3z"
                stroke="url(#logo-grad)"
                strokeWidth="2.5"
                strokeLinejoin="round"
                fill="#020617"
              />
              <circle cx="16" cy="15" r="3.5" fill="#06b6d4" opacity="0.8" />
              <path
                d="M11 15h10M16 10v10"
                stroke="#10b981"
                strokeWidth="1.8"
                strokeLinecap="round"
              />
            </svg>
          </div>
          <div className="min-w-0">
            <h1 className="text-sm sm:text-base font-bold tracking-wide text-white truncate">SOC ATTACK SIMULATOR</h1>
            <p className="text-[11px] sm:text-xs text-slate-500 truncate">Real-time attack simulation platform</p>
          </div>
        </div>

        <div className="flex flex-col gap-2.5 md:items-end w-full md:w-auto">
          {/* Row 1: Simulation status + Containment/Impact Pill */}
          <div className="flex flex-wrap items-center gap-2.5 text-xs text-slate-300">
            <span className="font-semibold text-slate-400">Simulation:</span>
            <span className="font-bold text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">{scenario.name}</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
              mode === "sentraq"
                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
            }`}>
              {mode === "sentraq" ? "With Sentraq" : "Without Sentraq"}
            </span>
            <span className="text-slate-600 hidden sm:inline">•</span>
            
            {/* Ready status tag */}
            <div className="flex items-center gap-1.5 bg-slate-900/60 px-2 py-0.5 rounded border border-slate-800">
              <span className={`h-2 w-2 rounded-full ${
                executionStatus === "contained" ? "bg-emerald-500 animate-pulse" :
                executionStatus === "completed" ? "bg-red-500 animate-pulse" :
                executionStatus === "running" ? "bg-cyan-500 animate-pulse" : "bg-slate-500"
              }`} />
              <span className="capitalize text-slate-300 font-medium font-mono text-[10px]">{executionStatus}</span>
            </div>

            {/* Impact/Containment pill next to the ready status */}
            <StatusPill
              label={mode === "sentraq" ? "Containment" : "Impact"}
              value={`${timeLeft}s`}
              severity={timeLeft <= 7 ? (mode === "sentraq" ? "low" : "critical") : "medium"}
            />
          </div>

          {/* Row 2: Rate Pill + SENTRAQ AI/HUMAN L1 badge + Restart */}
          <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 text-sm md:justify-end">
            <StatusPill label="Rate" value={`${rate}/s`} severity="low" />
            <div className={`h-9 sm:h-10 flex items-center rounded-lg border px-3 py-1.5 font-bold text-xs sm:text-sm ${
              mode === "sentraq"
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                : "border-amber-500/30 bg-amber-500/10 text-amber-400"
            }`}>
              {mode === "sentraq" ? "SENTRAQ AI" : "HUMAN L1"}
            </div>
            <button
              onClick={() => setSoundMuted(!soundMuted)}
              className={`h-9 sm:h-10 rounded-lg border px-3 py-1.5 font-semibold text-xs sm:text-sm transition-all duration-200 flex items-center gap-1.5 ${
                soundMuted
                  ? "border-slate-800 bg-slate-900/60 text-slate-500 hover:bg-slate-800"
                  : "border-cyan-500/40 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 shadow-lg shadow-cyan-500/5"
              }`}
            >
              {soundMuted ? "🔊 Audio: OFF" : "🔊 Audio: ON"}
            </button>
            <button
              onClick={() => resetSimulation(scenario, mode)}
              className="h-9 sm:h-10 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 px-4 py-1.5 font-semibold text-white text-xs sm:text-sm hover:from-cyan-500 hover:to-blue-500 shadow-lg shadow-cyan-500/20 transition-all"
            >
              ↻ Restart
            </button>
          </div>
        </div>
      </header>

      <div className="dashboard-shell grid grid-cols-2 gap-2 p-2 sm:gap-3 sm:p-3">

        {/* ── Row 1: L1 Workload ─ full width ── */}
        <section className={`col-span-2 l1-focus border rounded-lg p-3 sm:p-4 ${
          mode === "sentraq" ? "border-emerald-500/30 bg-emerald-950/10" : "border-amber-500/30 bg-amber-950/10"
        }`}>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex-1 min-w-0">
              <h2 className={`text-xs uppercase tracking-wider font-bold mb-1 ${
                mode === "sentraq" ? "text-emerald-300" : "text-amber-300"
              }`}>
                {mode === "sentraq" ? "Sentraq focus and workload" : "L1 focus and workload"}
              </h2>
              <p className="text-[11px] sm:text-xs text-slate-200 leading-relaxed line-clamp-2">
                {mode === "sentraq"
                  ? "AI clusters noisy context, keeps it attached to the case, and prioritizes the real attack chain."
                  : scenario.falsePositiveFocus}
              </p>
              <div className="mt-2">
                <div className="h-1.5 sm:h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      stress > 75 ? "bg-red-500" : stress > 50 ? "bg-amber-400" : "bg-emerald-400"
                    }`}
                    style={{ width: `${stress}%` }}
                  />
                </div>
                <div className="mt-1 flex items-center justify-between text-[10px] sm:text-[11px] text-slate-400">
                  <span>{Math.round(stress)}% workload</span>
                  <span>{displayAlerts.length} pending alerts</span>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-4 gap-1 sm:gap-1.5 w-full sm:w-auto sm:min-w-[220px]">
              <CompactMetric label="Rev" value={reviewed} />
              <CompactMetric label={mode === "sentraq" ? "Clus" : "Miss"} value={mode === "sentraq" ? displayAlerts.length : missed} danger={mode === "manual"} />
              <CompactMetric label="Atk" value={counts.attack} danger={mode === "manual"} />
              <CompactMetric label="FP" value={counts.falsePositive} />
              <SeverityTile label="Crit" value={counts.critical} color="text-red-300" />
              <SeverityTile label="High" value={counts.high} color="text-orange-300" />
              <SeverityTile label="Med" value={counts.medium} color="text-amber-300" />
              <SeverityTile label="Low" value={counts.low} color="text-sky-300" />
            </div>
          </div>
        </section>

        {/* ── Sentraq banner (conditional, full width) ── */}
        {mode === "sentraq" && sentraqContained && (
          <section className="col-span-2 sentraq-workflow rounded-lg border border-emerald-500/50 bg-emerald-950/30 px-3 py-3 sm:px-4 sm:py-4 shadow-lg shadow-emerald-950/30">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <h2 className="text-xs sm:text-sm font-black uppercase tracking-wider text-emerald-300 truncate">
                  Sentraq detected {scenario.shortName}
                </h2>
                <p className="mt-1 text-[11px] sm:text-xs text-slate-200 line-clamp-2">
                  AI correlated ELK alerts, enriched indicators with MISP, classified the incident as critical, and generated a response report.
                </p>
              </div>
              <button
                onClick={() => setShowReport(true)}
                className="min-h-9 sm:min-h-11 w-full shrink-0 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 sm:px-4 sm:py-3 text-xs font-bold text-cyan-300 hover:bg-cyan-500/20 sm:w-auto"
              >
                View report
              </button>
            </div>
          </section>
        )}

        {/* ── Row 2: SIEM Alerts (left) | SOC L1 Analyst (right) ── */}
        <section className="col-span-1 live-siem-alerts border border-slate-700/40 bg-gradient-to-b from-slate-900 to-slate-950 rounded-lg overflow-hidden flex flex-col h-[250px] sm:h-[320px]">
          <div className="px-2 py-1.5 sm:px-4 sm:py-3 border-b border-slate-800/60 flex items-center justify-between">
            <div className="min-w-0">
              <h2 className="text-[10px] sm:text-sm font-bold uppercase tracking-wider text-white">Live SIEM Alerts</h2>
              <p className="text-[9px] sm:text-xs text-slate-500 truncate">
                {hasStarted ? "Attack alerts mixed with noise." : "Execute an attack to start."}
              </p>
            </div>
          </div>
          <div ref={listRef} className="flex-1 overflow-auto">
            {displayAlerts.length === 0 ? (
              <div className="p-4 text-center text-xs text-slate-500">No live SIEM alerts yet.</div>
            ) : (
              displayAlerts.map((alert, index) => (
                <AlertRow key={alert.id} alert={alert} fresh={index === 0} onClick={() => handleOpen(alert)} />
              ))
            )}
          </div>
        </section>

        <section className="col-span-1 soc-workstation border border-slate-800/60 bg-gradient-to-b from-slate-900 to-slate-950 rounded-lg p-2 sm:p-4 h-[250px] sm:h-[320px] relative overflow-hidden flex flex-col">
          <h2 className="text-[10px] sm:text-xs uppercase tracking-wider text-slate-400 font-bold relative z-10">
            {mode === "sentraq" ? "Virtual L1 AI workstation" : "SOC Tier 1 analyst workstation"}
          </h2>
          <div className="flex-1 flex items-center justify-center relative z-10 scale-[0.78] sm:scale-[0.98] origin-center">
            <Analyst state={analystState} thought={thought} stressLevel={stress} />
          </div>
        </section>

        {/* ── Row 3: Network Topology ─ full width ── */}
        <section className="col-span-2 network-topology border border-slate-700/40 bg-gradient-to-b from-slate-900 to-slate-950 rounded-lg p-2 sm:p-4">
          <div className="flex items-center justify-between mb-2">
            <div className="min-w-0">
              <h2 className="text-xs sm:text-sm font-bold uppercase tracking-wider text-white">Network topology</h2>
              <p className="text-[10px] sm:text-xs text-slate-500 truncate">{scenario.blastRadius}</p>
            </div>
            <div className="w-full max-w-[8rem] sm:max-w-[14rem]">
              <div className="flex items-center justify-between text-[10px] sm:text-[11px] text-slate-500 mb-1">
                <span>Attack progress</span>
                <span>{Math.round(attackProgress)}%</span>
              </div>
              <div className="h-1.5 sm:h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${mode === "sentraq" ? "bg-emerald-400" : "bg-red-500"}`}
                  style={{ width: `${mode === "sentraq" ? sentraqProgress : attackProgress}%` }}
                />
              </div>
            </div>
          </div>
          <div className="overflow-x-auto">
            <Topology scenario={scenario} progress={mode === "sentraq" ? sentraqProgress : attackProgress} contained={sentraqContained} />
          </div>
          {mode === "sentraq" && hasStarted && (
            <button
              onClick={() => setShowVideo(true)}
              className="mt-3 flex w-full items-center justify-center gap-2 rounded-md border border-emerald-400/40 bg-emerald-500 px-4 py-2.5 sm:py-3 text-center text-xs sm:text-sm font-black uppercase tracking-wider text-slate-950 shadow-lg shadow-emerald-950/30 transition hover:bg-emerald-300"
            >
              <span className="h-2.5 w-2.5 rounded-sm bg-slate-950" />
              View Sentraq Dashboard
            </button>
          )}
        </section>

        {/* ── Row 4: Attack Simulations ─ 3 cards full width ── */}
        <section className="col-span-2 attack-simulations border border-slate-800/60 bg-gradient-to-b from-slate-900 to-slate-950 rounded-lg p-3 sm:p-4">
          <div className="flex items-center justify-between mb-3 border-b border-slate-850 pb-2">
            <h2 className="text-xs sm:text-sm uppercase tracking-wider text-slate-400 font-bold">Attack Simulations</h2>
            <span className="text-[10px] sm:text-[11px] text-cyan-400 font-mono">{FEATURED_ATTACK_SCENARIOS.length} scenarios ready</span>
          </div>
          <div className="grid grid-cols-3 gap-2.5 sm:gap-4">
            {FEATURED_ATTACK_SCENARIOS.map((item) => (
              <div
                key={item.id}
                onClick={() => selectScenario(item)}
                className={`rounded-lg border p-2.5 sm:p-4 transition-all duration-300 cursor-pointer hover:shadow-2xl hover:scale-[1.015] active:scale-[0.99] flex flex-col justify-between ${
                  item.id === scenario.id
                    ? "border-cyan-500 bg-cyan-950/15 shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-500/25"
                    : "border-slate-850 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/60"
                }`}
              >
                <div>
                  <div className="flex items-center gap-2 mb-2 min-w-0">
                    <div className="flex h-7 w-7 sm:h-8 sm:w-8 shrink-0 items-center justify-center rounded-lg bg-slate-950 border border-slate-850 shadow-inner">
                      {getScenarioIcon(item.id)}
                    </div>
                    <div className="text-[11px] sm:text-sm font-bold text-white truncate flex-1 leading-none">{item.shortName}</div>
                  </div>
                  <p className="text-[9px] sm:text-[11px] leading-snug text-slate-400 line-clamp-2 mb-3">{item.summary}</p>
                </div>
                <div className="mt-auto flex flex-col gap-1.5">
                  <button
                    onClick={(event) => {
                      event.stopPropagation();
                      resetSimulation(item, "manual");
                    }}
                    className="min-h-[30px] sm:min-h-9 w-full rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[9px] sm:text-[11px] font-bold text-amber-400 hover:bg-amber-500/20 hover:border-amber-400 active:scale-95 transition-all duration-150 shrink-0"
                  >
                    ▶ Without Sentraq
                  </button>
                  <button
                    onClick={(event) => {
                      event.stopPropagation();
                      resetSimulation(item, "sentraq");
                    }}
                    className="min-h-[30px] sm:min-h-9 w-full rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[9px] sm:text-[11px] font-bold text-emerald-400 hover:bg-emerald-500/20 hover:border-emerald-400 active:scale-95 transition-all duration-150 shrink-0"
                  >
                    ▶ With Sentraq
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Row 5: Case Notes (left) | Attack Log (right) ── */}
        <section className="col-span-1 case-notes border border-slate-800/60 bg-gradient-to-b from-slate-900 to-slate-950 rounded-lg p-2 sm:p-4">
          <h2 className="text-[10px] sm:text-xs uppercase tracking-wider text-slate-400 font-bold mb-1.5 sm:mb-2">
            {mode === "sentraq" ? "Sentraq AI workflow" : "Current case notes"}
          </h2>
          <div className="rounded-md border border-slate-800/60 bg-black/40 p-2 sm:p-3 font-mono text-[9px] sm:text-xs max-h-[160px] sm:max-h-[200px] overflow-y-auto">
            {mode === "sentraq" ? (
              <SentraqWorkflow elapsed={elapsed} scenario={scenario} hasStarted={hasStarted} />
            ) : (
              <ManualCaseNotes
                scenario={scenario}
                analystState={analystState}
                activeLogs={activeLogs}
                hasStarted={hasStarted}
                completed={attackTriggered}
              />
            )}
          </div>
        </section>

        <section className="col-span-1 border border-slate-800/60 bg-gradient-to-b from-slate-900 to-slate-950 rounded-lg p-2 sm:p-4">
          <h2 className="text-[10px] sm:text-xs uppercase tracking-wider text-slate-400 font-bold mb-1.5 sm:mb-2">Attack automation log</h2>
          <div className="overflow-y-auto rounded-md bg-black/40 border border-slate-800/60 p-2 font-mono text-[9px] sm:text-xs max-h-[160px] sm:max-h-[200px]">
            {!hasStarted ? (
              <p className="text-slate-600">Logs will start after executing an attack.</p>
            ) : activeLogs.length === 0 ? (
              <p className="text-slate-600">Waiting for telemetry...</p>
            ) : (
              activeLogs.map((log, index) => (
                <div key={`${log.t}-${log.message}`} className="mb-1 truncate">
                  <span className={severityText(log.severity)}>{timelineLabel(index, scenario.attackLogs.length)}</span>
                  <span className="text-slate-600"> [{log.source}]</span>
                  <span className="text-slate-300"> {log.message}</span>
                </div>
              ))
            )}
          </div>
        </section>

      </div>

      {selected && !attackTriggered && <InvestigationPanel alert={selected} onClose={() => setSelected(null)} />}
      {showReport && (
        <ReportViewer
          scenario={scenario}
          mode={mode}
          activeLogs={activeLogs}
          contained={sentraqContained}
          completed={attackTriggered}
          onClose={() => setShowReport(false)}
        />
      )}
      {showVideo && <VideoViewer onClose={() => setShowVideo(false)} />}
    </div>
  );
}

function StatusPill({ label, value, severity }: { label: string; value: string; severity: Severity }) {
  return (
    <div className={`flex h-9 sm:h-10 items-center justify-between gap-2.5 rounded-lg border bg-slate-900/60 px-3 py-1.5 shrink-0 ${borderBySeverity(severity)}`}>
      <span className="text-[10px] sm:text-xs text-slate-500 shrink-0 font-medium">{label}:</span>
      <span className={`font-mono font-bold text-xs sm:text-sm shrink-0 ${severityText(severity)}`}>{value}</span>
    </div>
  );
}

function ReportViewer({
  scenario,
  mode,
  activeLogs,
  contained,
  completed,
  onClose,
}: {
  scenario: AttackScenario;
  mode: SimulationMode;
  activeLogs: AttackLog[];
  contained: boolean;
  completed: boolean;
  onClose: () => void;
}) {
  const recommendations = recommendationsFor(scenario);
  const reportId = `SENTRAQ-${scenario.id.toUpperCase()}-${new Date().getFullYear()}`;
  const status = mode === "sentraq" && contained ? "Contained" : completed ? "Impact Reached" : "In Progress";

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/80 p-0 sm:p-4 backdrop-blur-sm">
      <div className="max-h-[100dvh] sm:max-h-[92vh] w-full max-w-5xl overflow-hidden rounded-t-lg sm:rounded-lg border border-slate-700 bg-slate-950 shadow-2xl flex flex-col">
        <div className="flex items-center justify-between border-b border-slate-800 px-3 py-2 sm:px-5 sm:py-3 shrink-0">
          <div className="min-w-0">
            <div className="text-xs font-bold uppercase tracking-wider text-cyan-300">Incident report</div>
            <h2 className="text-base sm:text-lg font-black text-white truncate">{scenario.name}</h2>
          </div>
          <button
            onClick={onClose}
            className="min-h-11 rounded-md border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-slate-200 hover:bg-slate-800"
          >
            Close
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-3 sm:p-5">
          <div className="rounded-md border border-slate-800 bg-white p-3 text-slate-950 sm:p-6">
            <div className="flex flex-col gap-3 border-b border-slate-300 pb-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <div className="text-xs font-bold uppercase tracking-wider text-slate-500">SentraIQ SOC Incident Report</div>
                <h1 className="mt-1 text-2xl font-black">{scenario.shortName}</h1>
                <p className="mt-1 max-w-2xl text-sm text-slate-600">{scenario.summary}</p>
              </div>
              <div className="text-left text-xs sm:text-right">
                <p className="font-bold text-slate-500">Report ID</p>
                <p className="font-mono">{reportId}</p>
                <p className="mt-2 font-bold text-slate-500">Status</p>
                <p className={status === "Contained" ? "font-bold text-emerald-700" : "font-bold text-red-700"}>{status}</p>
              </div>
            </div>

            <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <ReportMetric label="Severity" value="Critical" tone="red" />
              <ReportMetric label="Mode" value={mode === "sentraq" ? "With Sentraq" : "Without Sentraq"} tone={mode === "sentraq" ? "green" : "amber"} />
              <ReportMetric label="Duration" value="20 seconds" tone="slate" />
              <ReportMetric label="Containment" value={contained ? "T+00:10" : "Not contained"} tone={contained ? "green" : "red"} />
            </div>

            <section className="mt-6">
              <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Case Overview</h3>
              <div className="mt-2 grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
                <ReportField label="Case ID" value={reportId} />
                <ReportField label="Report Type" value={mode === "sentraq" ? "Type A - Automated Containment" : "Type C - Analyst Review Required"} />
                <ReportField label="Status" value={status} />
                <ReportField label="Generated At" value={new Date().toISOString().slice(0, 19).replace("T", " ")} />
                <ReportField label="Source" value={scenario.entryNode} />
                <ReportField label="Destination" value={scenario.targetNode} />
              </div>
            </section>

            <section className="mt-6">
              <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Executive Summary</h3>
              <p className="mt-2 text-sm leading-relaxed">
                Sentraq correlated the alert stream for <strong>{scenario.name}</strong> using ELK telemetry,
                MISP threat intelligence, risk classification, and automated investigation summarization.
                The incident involved <strong>{scenario.entryNode}</strong> as the entry point and <strong>{scenario.targetNode}</strong> as the target.
              </p>
            </section>

            <section className="mt-6">
              <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Threat Classification</h3>
              <div className="mt-2 grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
                <ReportField label="Threat Classification" value={scenario.name} />
                <ReportField label="Severity Classification" value="Critical" />
                <ReportField label="Operational Status" value={status} />
                <ReportField label="MITRE ATT&CK Mapping" value={scenario.attackRules.map((rule) => rule.category).slice(0, 4).join(" / ")} />
              </div>
            </section>

            <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div>
                <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Affected Assets</h3>
                <div className="mt-2 space-y-1 text-sm">
                  <p><strong>Entry node:</strong> {scenario.entryNode}</p>
                  <p><strong>Target node:</strong> {scenario.targetNode}</p>
                  <p><strong>Blast radius:</strong> {scenario.blastRadius}</p>
                </div>
              </div>
              <div>
                <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Detection Logic</h3>
                <div className="mt-2 space-y-1 text-sm">
                  <p>ELK alert clustering</p>
                  <p>MISP IOC enrichment</p>
                  <p>Risk classification: critical correlated chain</p>
                  <p>Case update and escalation package generated</p>
                </div>
              </div>
            </section>

            <section className="mt-6">
              <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Threat Intelligence Enrichment</h3>
              <div className="mt-2 grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
                <ReportField label="Realtime Source" value="AI Detection Engine" />
                <ReportField label="Threat Tags" value={scenario.attackRules.map((rule) => rule.phase).join(", ")} />
                <ReportField label="Threat Summary" value="MISP enrichment attached; indicators correlated with live alert stream." />
                <ReportField label="Decision Basis" value={contained ? "Confidence exceeded containment threshold." : "Manual review required before containment."} />
              </div>
            </section>

            <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div>
                <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Source / Destination Analysis</h3>
                <div className="mt-2 grid grid-cols-1 gap-2 text-sm">
                  <ReportField label="Observed Source" value={scenario.entryNode} />
                  <ReportField label="Observed Destination" value={scenario.targetNode} />
                  <ReportField label="Business Impact Area" value={scenario.blastRadius} />
                </div>
              </div>
              <div>
                <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">GeoIP Intelligence</h3>
                <div className="mt-2 grid grid-cols-1 gap-2 text-sm">
                  <ReportField label="Geo Verdict" value="External activity mapped to high-risk ASN and anonymized infrastructure." />
                  <ReportField label="Reputation" value={mode === "sentraq" ? "MISP matched and scored automatically" : "Pending analyst validation"} />
                  <ReportField label="Confidence" value={contained ? "High confidence" : "Incomplete confidence before impact"} />
                </div>
              </div>
            </section>

            <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div>
                <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Splunk / ELK Correlation Details</h3>
                <div className="mt-2 space-y-2 rounded border border-slate-300 bg-slate-50 p-3 font-mono text-xs text-slate-800">
                  <p>index=soc sourcetype=elk_alert scenario="{scenario.id}"</p>
                  <p>| stats count by source,destination,rule,severity</p>
                  <p>| where severity="critical" OR correlation_score &gt; 85</p>
                  <p>| eval response_mode="{mode === "sentraq" ? "sentraq_virtual_l1" : "manual_l1"}"</p>
                </div>
              </div>
              <div>
                <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Packet / Protocol Details</h3>
                <div className="mt-2 grid grid-cols-1 gap-2 text-sm">
                  <ReportField label="Protocol Pattern" value={scenario.attackRules.map((rule) => rule.category).slice(0, 3).join(" + ")} />
                  <ReportField label="Traffic Behavior" value="Burst activity, chained telemetry, abnormal request and authentication patterns." />
                  <ReportField label="Evidence Quality" value="Correlated logs, endpoint events, network telemetry, and threat intel context." />
                </div>
              </div>
            </section>

            <section className="mt-6">
              <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">AI Detection Reasoning</h3>
              <p className="mt-2 text-sm leading-relaxed">
                Sentraq grouped the live SIEM queue into a single attack story, enriched the indicators through MISP,
                compared the behavior against the current asset baseline, then produced a risk decision and response
                recommendation. {contained
                  ? "The attack was detected and contained at T+00:10 before the simulated impact stage."
                  : "Without Sentraq, the human L1 stayed focused on manual validation while the attack sequence continued."}
              </p>
            </section>

            <section className="mt-6">
              <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Attack Timeline</h3>
              <div className="mt-2 rounded border border-slate-300 overflow-x-auto">
                <table className="w-full min-w-[400px] table-fixed text-left text-xs">
                  <thead className="bg-slate-100 text-slate-600">
                    <tr>
                      <th className="break-words px-3 py-2 align-top">Time</th>
                      <th className="break-words px-3 py-2 align-top">Source</th>
                      <th className="break-words px-3 py-2 align-top">Severity</th>
                      <th className="break-words px-3 py-2 align-top">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(activeLogs.length ? activeLogs : scenario.attackLogs).map((log, index) => (
                      <tr key={`${log.t}-${log.message}`} className="border-t border-slate-200">
                        <td className="break-words px-3 py-2 align-top font-mono">{timelineLabel(index, scenario.attackLogs.length)}</td>
                        <td className="break-words px-3 py-2 align-top">{log.source}</td>
                        <td className="break-words px-3 py-2 align-top font-bold uppercase">{log.severity}</td>
                        <td className="break-words px-3 py-2 align-top">{log.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="mt-6">
              <h3 className="border-b border-slate-300 pb-1 text-sm font-black uppercase tracking-wider">Recommendations</h3>
              <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm">
                {recommendations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ol>
            </section>

            <section className="mt-6 rounded border border-slate-300 bg-slate-50 p-3">
              <h3 className="text-sm font-black uppercase tracking-wider">Containment / Block Status</h3>
              <p className="mt-2 text-sm">
                {contained
                  ? "Automated containment executed: Block IP, Disable User, Isolate Host, Kill Process, and Create/Update Incident Case."
                  : "No automated containment was executed before impact. Manual escalation and containment are required."}
              </p>
            </section>

            <section className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div className="rounded border border-slate-300 bg-slate-50 p-3">
                <h3 className="text-sm font-black uppercase tracking-wider">Analyst Notes</h3>
                <p className="mt-2 text-sm">
                  {mode === "sentraq"
                    ? "Virtual L1 replaced repetitive initial triage, reduced alert fatigue, and produced an investigation summary for escalation."
                    : "Human L1 was delayed by noisy validation and could not complete correlation before the attack chain finished."}
                </p>
              </div>
              <div className="rounded border border-slate-300 bg-slate-50 p-3">
                <h3 className="text-sm font-black uppercase tracking-wider">Realtime Detection Metadata</h3>
                <div className="mt-2 space-y-1 text-sm">
                  <p><strong>Alert source:</strong> Live SIEM alerts</p>
                  <p><strong>Detection window:</strong> 20 seconds</p>
                  <p><strong>Sentraq action time:</strong> T+00:10</p>
                </div>
              </div>
            </section>

            <section className="mt-6 rounded border border-slate-300 bg-slate-50 p-3">
              <h3 className="text-sm font-black uppercase tracking-wider">Evidence Summary</h3>
              <p className="mt-2 text-sm">
                Evidence includes SIEM alert sequence, correlated attack rules, endpoint/network telemetry,
                enrichment status, response decision, and final incident recommendation.
              </p>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}

function VideoViewer({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/85 p-0 sm:p-5 backdrop-blur-sm">
      <div className="w-full max-w-5xl max-h-[100dvh] sm:max-h-none overflow-hidden rounded-t-lg sm:rounded-lg border border-emerald-500/30 bg-slate-950 shadow-2xl flex flex-col">
        <div className="flex items-center justify-between gap-3 border-b border-slate-800 px-4 py-3">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-emerald-300">With Sentraq</div>
            <h2 className="text-base font-black text-white sm:text-lg">Dashboard demonstration video</h2>
          </div>
          <button
            onClick={onClose}
            className="min-h-11 rounded-md border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-slate-200 hover:bg-slate-800"
          >
            Close
          </button>
        </div>
        <div className="bg-black p-2 sm:p-4">
          <video className="h-auto max-h-[80dvh] sm:max-h-[76vh] w-full rounded-md bg-black" controls autoPlay playsInline>
            <source src="/my-dashboard.mp4" type="video/mp4" />
            <source src="/my-dashboard.mkv" type="video/x-matroska" />
            Your browser cannot play this video file.
          </video>
        </div>
      </div>
    </div>
  );
}

function ReportMetric({ label, value, tone }: { label: string; value: string; tone: "red" | "green" | "amber" | "slate" }) {
  const tones = {
    red: "border-red-200 bg-red-50 text-red-800",
    green: "border-emerald-200 bg-emerald-50 text-emerald-800",
    amber: "border-amber-200 bg-amber-50 text-amber-800",
    slate: "border-slate-200 bg-slate-50 text-slate-800",
  };

  return (
    <div className={`rounded border p-3 ${tones[tone]}`}>
      <div className="text-[10px] font-bold uppercase tracking-wider opacity-70">{label}</div>
      <div className="mt-1 text-sm font-black">{value}</div>
    </div>
  );
}

function ReportField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-slate-200 bg-slate-50 p-2">
      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-1 break-words text-sm font-semibold text-slate-900">{value}</div>
    </div>
  );
}

function CompactMetric({ label, value, danger }: { label: string; value: number; danger?: boolean }) {
  return (
    <div className="rounded-md border border-slate-700/40 bg-slate-800/30 px-1.5 py-1 sm:px-2 sm:py-1.5 text-center">
      <div className={`text-sm sm:text-base font-bold font-mono ${danger ? "text-red-400" : "text-slate-100"}`}>{value}</div>
      <div className="text-[8px] sm:text-[9px] text-slate-500 uppercase tracking-wider">{label}</div>
    </div>
  );
}

function SeverityTile({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-md border border-slate-700/40 bg-slate-800/20 px-1.5 py-1 sm:p-2 text-center">
      <div className={`text-sm sm:text-lg font-bold font-mono ${color}`}>{value}</div>
      <div className="text-[8px] sm:text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
    </div>
  );
}

function ManualCaseNotes({
  scenario,
  analystState,
  activeLogs,
  hasStarted,
  completed,
}: {
  scenario: AttackScenario;
  analystState: AnalystState;
  activeLogs: AttackLog[];
  hasStarted: boolean;
  completed: boolean;
}) {
  const latestLog = activeLogs.at(-1);
  const currentRule = scenario.attackRules[Math.min(activeLogs.length, scenario.attackRules.length - 1)];

  if (!hasStarted) {
    return (
      <>
        <p className="text-cyan-300">case: not_started</p>
        <p className="text-slate-400 mt-1">operator: human SOC Tier 1</p>
        <p className="text-slate-500 mt-3">Select Execute without Sentraq to start manual triage.</p>
      </>
    );
  }

  return (
    <>
      <p className="text-cyan-300">case: L1-{scenario.id}</p>
      <p className="text-slate-400 mt-1">analyst_status: {analystState}</p>
      <p className="text-slate-400">operator: human SOC Tier 1</p>
      <p className="text-slate-400">current_stage: {currentRule.category}</p>
      <p className="text-amber-300 mt-3">initial_triage_note:</p>
      <p className="text-slate-300">{scenario.falsePositiveFocus}</p>
      <p className="text-red-300 mt-3">latest_evidence:</p>
      <p className="text-slate-300">
        {latestLog ? `[${latestLog.source}] ${latestLog.message}` : "Waiting for first correlated signal."}
      </p>
      <p className="text-slate-500 mt-3">
        {completed
          ? "Simulation complete: manual L1 triage finished after the attack chain reached business impact."
          : "L1 is validating raw alerts one by one while the attack sequence continues in the background."}
      </p>
      {completed && (
        <div className="mt-3 rounded border border-red-500/30 bg-red-950/20 p-2">
          <p className="text-red-300 font-bold">outcome: {scenario.outcomeTitle}</p>
          <p className="text-slate-300 mt-1">{scenario.outcome[0]}</p>
        </div>
      )}
    </>
  );
}

function SentraqWorkflow({
  elapsed,
  scenario,
  hasStarted,
}: {
  elapsed: number;
  scenario: AttackScenario;
  hasStarted: boolean;
}) {
  const contained = elapsed >= SENTRAQ_CONTAIN_AT;
  const recommendations = recommendationsFor(scenario);

  if (!hasStarted) {
    return (
      <div>
        <p className="text-emerald-300">case: not_started</p>
        <p className="text-slate-400 mt-1">source: ELK alert stream</p>
        <p className="text-slate-400">virtual_l1: standby</p>
        <p className="text-slate-500 mt-3">Select Execute with Sentraq to start AI investigation and response.</p>
      </div>
    );
  }

  return (
    <div>
      <p className="text-emerald-300">case: SENTRAQ-{scenario.id}</p>
      <p className="text-slate-400 mt-1">source: ELK alert stream</p>
      <p className="text-slate-400">threat_intel: MISP enrichment enabled</p>
      <p className="text-slate-400">risk: {elapsed >= 8 ? "critical correlated chain" : "calculating"}</p>

      <div className="mt-3 space-y-2">
        {SENTRAQ_STEPS.map((step) => {
          const active = elapsed >= step.at;
          return (
            <div
              key={step.label}
              className={`rounded-md border p-2 ${
                active ? "border-emerald-500/40 bg-emerald-500/10" : "border-slate-800 bg-slate-900/50"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className={active ? "text-emerald-300 font-bold" : "text-slate-500"}>{step.label}</span>
                <span className="text-slate-500">T+{String(step.at).padStart(2, "0")}s</span>
              </div>
              <p className={active ? "text-slate-200 mt-1" : "text-slate-600 mt-1"}>{step.detail}</p>
              {active && <p className="text-cyan-300 mt-1">action: {step.action}</p>}
            </div>
          );
        })}
      </div>

      <div className={`mt-3 rounded-md border p-2 ${
        contained ? "border-emerald-500/40 bg-emerald-500/10" : "border-amber-500/30 bg-amber-950/10"
      }`}>
        <p className={contained ? "text-emerald-300 font-bold" : "text-amber-300 font-bold"}>
          {contained ? "status: contained before impact" : "status: response in progress"}
        </p>
        <p className="text-slate-400 mt-1">
          Response actions: Block IP, Disable User, Isolate Host, Kill Process, Create/Update Incident Case.
        </p>
      </div>

      {contained && (
        <div className="mt-3 rounded-md border border-cyan-500/30 bg-cyan-950/20 p-2">
          <p className="text-cyan-300 font-bold">Sentraq recommendations</p>
          <div className="mt-2 space-y-1">
            {recommendations.map((item, index) => (
              <p key={item} className="text-slate-300">
                <span className="text-slate-500">R{index + 1}: </span>
                {item}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function getNodeIcon(id: string, role: string) {
  const normId = id.toLowerCase();
  const normRole = role.toLowerCase();

  // Cloud/Internet/Botnet/Proxies
  if (normId.includes("internet") || normId.includes("botnet") || normId.includes("exfil") || normRole.includes("external") || normRole.includes("proxy") || normRole.includes("ingress")) {
    return (
      <svg className="w-3.5 h-3.5 text-sky-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
      </svg>
    );
  }
  // Mail / Exchange
  if (normId.includes("mail") || normRole.includes("mail")) {
    return (
      <svg className="w-3.5 h-3.5 text-amber-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
      </svg>
    );
  }
  // Active Directory / Domain Controller / IDP
  if (normId.includes("idp") || normId.includes("dc") || normId.includes("ad") || normRole.includes("identity") || normRole.includes("controller") || normRole.includes("directory")) {
    return (
      <svg className="w-3.5 h-3.5 text-red-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    );
  }
  // Data Store / File Storage / Database
  if (normId.includes("file") || normId.includes("storage") || normId.includes("db") || normId.includes("data") || normId.includes("repo") || normRole.includes("store") || normRole.includes("share") || normRole.includes("repo")) {
    return (
      <svg className="w-3.5 h-3.5 text-purple-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2.21 3.58 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.58 4 8 4s8-1.79 8-4M4 7c0-2.21 3.58-4 8-4s8 1.79 8 4m0 5c0 2.21-3.58 4-8 4s-8-1.79-8-4" />
      </svg>
    );
  }
  // Backup Vault / Recovery
  if (normId.includes("backup") || normId.includes("vault") || normRole.includes("backup")) {
    return (
      <svg className="w-3.5 h-3.5 text-emerald-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    );
  }
  // Network Protection / Firewall / WAF / CDN / Balancers
  if (normId.includes("fw") || normId.includes("waf") || normId.includes("lb") || normRole.includes("filter") || normRole.includes("protection") || normRole.includes("balancer")) {
    return (
      <svg className="w-3.5 h-3.5 text-orange-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    );
  }
  // Monitoring / Alerts / SIEM / SOC
  if (normId.includes("soc") || normId.includes("siem") || normRole.includes("console") || normRole.includes("alert")) {
    return (
      <svg className="w-3.5 h-3.5 text-cyan-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
      </svg>
    );
  }
  // Default Node Workstation / Client
  return (
    <svg className="w-3.5 h-3.5 text-slate-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
    </svg>
  );
}

function Topology({ scenario, progress, contained }: { scenario: AttackScenario; progress: number; contained?: boolean }) {
  const nodesById = Object.fromEntries(scenario.topology.nodes.map((node) => [node.id, node]));
  const zones = [
    { label: "External Ingress", left: "1%", width: "18%" },
    { label: "DMZ & Identity", left: "20%", width: "18%" },
    { label: "Corporate LAN", left: "39%", width: "20%" },
    { label: "Core Infrastructure", left: "60%", width: "24%" },
    { label: "Critical Assets", left: "85%", width: "14%" },
  ];

  return (
    <div className="topology-map relative h-[210px] sm:h-[240px] rounded-lg border border-slate-700/40 bg-[#040914] overflow-hidden shadow-inner pb-8 animate-[fadeIn_0.5s_ease-out]">
      {/* Sci-fi Blueprint Grid Background */}
      <div className="absolute inset-0 bg-[linear-gradient(#0f1e36_1px,transparent_1px),linear-gradient(90deg,#0f1e36_1px,transparent_1px)] bg-[size:16px_16px] opacity-25" />
      {/* Radial network glow at center */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_40%,rgba(6,182,212,0.08)_0%,transparent_60%)]" />
      
      {zones.map((zone) => (
        <div
          key={zone.label}
          className="absolute top-2 bottom-9 rounded border border-slate-850/40 bg-slate-950/20"
          style={{ left: zone.left, width: zone.width }}
        >
          <div className="px-2 py-1 text-[8px] uppercase tracking-widest text-slate-600 font-bold truncate">{zone.label}</div>
        </div>
      ))}
      
      <svg className="absolute inset-0 h-full w-full pointer-events-none" viewBox="0 0 100 100" preserveAspectRatio="none">
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="0.6" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        
        {scenario.topology.links.map((link, index) => {
          const from = nodesById[link.from];
          const to = nodesById[link.to];
          if (!from || !to) return null;
          
          const active = progress > index * 14;
          const midX = (from.x + to.x) / 2;
          const path = `M ${from.x} ${from.y} Q ${midX} ${from.y} ${midX} ${(from.y + to.y) / 2} Q ${midX} ${to.y} ${to.x} ${to.y}`;
          const isAttack = link.status === "attack";
          
          // Color coding for links
          const strokeColor = contained && isAttack
            ? "#10b981"
            : isAttack && active
              ? "#ef4444"
              : link.status === "noisy"
                ? "#f59e0b"
                : "#1e293b";
                
          return (
            <g key={`${link.from}-${link.to}`}>
              {/* Connection link path */}
              <path
                d={path}
                stroke={strokeColor}
                strokeWidth={isAttack && active ? 0.95 : 0.4}
                strokeDasharray={isAttack && !active ? "2 2" : "0"}
                opacity={active ? 1 : 0.25}
                fill="none"
                filter={isAttack && active ? "url(#glow)" : undefined}
                strokeLinecap="round"
              />
              {/* Animated data packets traveling on paths */}
              {active && (
                <circle r="0.75" fill={contained && isAttack ? "#34d399" : isAttack ? "#fca5a5" : "#fcd34d"}>
                  <animateMotion
                    dur={isAttack ? "1.6s" : "2.8s"}
                    repeatCount="indefinite"
                    path={path}
                  />
                </circle>
              )}
            </g>
          );
        })}
      </svg>

      {scenario.topology.nodes.map((node) => (
        <div
          key={node.id}
          className="absolute -translate-x-1/2 -translate-y-1/2 transition-transform duration-300"
          style={{ left: `${node.x}%`, top: `${node.y - 4}%` }}
        >
          <div className={`topology-node-card w-24 sm:w-28 rounded-lg border p-1.5 shadow-2xl transition-all duration-300 backdrop-blur-md bg-slate-950/80 ${
            contained && node.status !== "noisy"
              ? "bg-emerald-950/70 border-emerald-500/50 shadow-emerald-500/10"
              : nodeStyle(node.status)
          }`}>
            <div className="flex items-center gap-1.5 min-w-0">
              {getNodeIcon(node.id, node.role)}
              <span className="text-[9px] sm:text-[10px] font-bold text-slate-100 truncate flex-1 leading-none">{node.label}</span>
            </div>
            
            <div className="flex items-center justify-between mt-1.5 text-[8px] sm:text-[9px] min-w-0 leading-none">
              <span className="text-slate-500 truncate max-w-[80%]">{node.role}</span>
              <span className={`h-1.5 w-1.5 rounded-full border border-black/40 shrink-0 ${
                contained && node.status !== "noisy" ? "bg-emerald-400 shadow-md shadow-emerald-500/40" : nodeDot(node.status)
              }`} />
            </div>
          </div>
        </div>
      ))}

      {/* Legend bar at the bottom */}
      <div className="absolute bottom-2 left-3 right-3 flex flex-col sm:flex-row sm:items-center sm:justify-between text-[8px] sm:text-[9px] text-slate-500 border-t border-slate-800/40 pt-1.5 pointer-events-none gap-1 sm:gap-0">
        <span className="font-mono text-slate-600">Enterprise Network Topology</span>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> Clean</span>
          <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> Noisy Queue</span>
          <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-orange-400" /> Suspicious</span>
          <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse" /> Compromised</span>
          <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-ping" /> Critical Alert</span>
        </div>
      </div>
    </div>
  );
}

function severityText(severity: Severity) {
  return {
    low: "text-sky-300",
    medium: "text-amber-300",
    high: "text-orange-300",
    critical: "text-red-300",
  }[severity];
}

function borderBySeverity(severity: Severity) {
  return {
    low: "border-sky-500/30",
    medium: "border-amber-500/30",
    high: "border-orange-500/40",
    critical: "border-red-500/50",
  }[severity];
}

function nodeStyle(status: AttackScenario["topology"]["nodes"][number]["status"]) {
  return {
    clean: "bg-slate-950/80 border-slate-850 hover:border-slate-750",
    noisy: "bg-amber-950/30 border-amber-500/30 shadow-amber-500/5",
    suspicious: "bg-orange-950/30 border-orange-500/30 shadow-orange-500/5",
    compromised: "bg-red-950/40 border-red-500/40 shadow-red-500/10",
    critical: "bg-red-950/90 border-red-500 shadow-lg shadow-red-500/20",
  }[status];
}

function nodeDot(status: AttackScenario["topology"]["nodes"][number]["status"]) {
  return {
    clean: "bg-emerald-500 shadow-sm shadow-emerald-500/30",
    noisy: "bg-amber-400 shadow-sm shadow-amber-400/30",
    suspicious: "bg-orange-400 shadow-sm shadow-orange-400/30",
    compromised: "bg-red-500 animate-pulse shadow-md shadow-red-500/40",
    critical: "bg-red-400 animate-ping shadow-lg shadow-red-500/50",
  }[status];
}

function getScenarioIcon(id: string) {
  const normId = id.toLowerCase();
  if (normId.includes("ransomware")) {
    return (
      <svg className="w-4 h-4 text-red-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    );
  }
  if (normId.includes("stuffing") || normId.includes("credential")) {
    return (
      <svg className="w-4 h-4 text-sky-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m-2 4a2 2 0 012 2m-8-10a3 3 0 00-3 3v1a3 3 0 003 3h10a3 3 0 003-3v-1a3 3 0 00-3-3H7zM3 19h18" />
      </svg>
    );
  }
  if (normId.includes("supply") || normId.includes("backdoor")) {
    return (
      <svg className="w-4 h-4 text-purple-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
      </svg>
    );
  }
  if (normId.includes("ddos") || normId.includes("flood")) {
    return (
      <svg className="w-4 h-4 text-amber-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    );
  }
  if (normId.includes("exfil")) {
    return (
      <svg className="w-4 h-4 text-pink-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
      </svg>
    );
  }
  if (normId.includes("lateral") || normId.includes("movement") || normId.includes("ad")) {
    return (
      <svg className="w-4 h-4 text-orange-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4-4m-4 4l4 4" />
      </svg>
    );
  }
  return (
    <svg className="w-4 h-4 text-slate-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  );
}
