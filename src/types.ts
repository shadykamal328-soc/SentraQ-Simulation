export type Severity = "low" | "medium" | "high" | "critical";

export type AttackPhase =
  | "recon"
  | "initial"
  | "execution"
  | "persistence"
  | "lateral"
  | "exfiltration"
  | "impact";

export interface Alert {
  id: number;
  time: string;
  severity: Severity;
  source: string;
  dest: string;
  rule: string;
  category: string;
  isAttack?: boolean;
  isFalsePositive?: boolean;
  phase?: AttackPhase;
  details: string[];
}

export interface AttackLog {
  t: string;
  source: string;
  message: string;
  severity: Severity;
}

export interface TopologyNode {
  id: string;
  label: string;
  role: string;
  x: number;
  y: number;
  status: "clean" | "noisy" | "suspicious" | "compromised" | "critical";
}

export interface TopologyLink {
  from: string;
  to: string;
  status: "normal" | "noisy" | "attack";
}

export interface AttackScenario {
  id: string;
  name: string;
  shortName: string;
  summary: string;
  falsePositiveFocus: string;
  attackerAutomation: string;
  blastRadius: string;
  entryNode: string;
  targetNode: string;
  attackRules: { rule: string; category: string; severity: Severity; phase: AttackPhase }[];
  attackLogs: AttackLog[];
  topology: {
    nodes: TopologyNode[];
    links: TopologyLink[];
  };
  outcomeTitle: string;
  outcome: string[];
}

export type AnalystState =
  | "idle"
  | "typing"
  | "reading"
  | "investigating"
  | "confused"
  | "panic"
  | "defeated";
