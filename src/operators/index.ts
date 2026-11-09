/**
 * T3MP3ST operators, defensive profile.
 *
 * Four operators, each a ReAct agent with a fixed toolkit:
 *   - Recon (posture): passive checks of an operator-entered site.
 *   - Scanner (supply chain & configuration): triages the dependency, secret and IaC/CI scanners'
 *     candidates with read-only repository tools.
 *   - Analyst (code review): reviews the operator's application code (SAST-style) with read-only
 *     repository tools.
 *   - Coordinator: plans the assessment and writes the executive summary. It calls no tools.
 *
 * No operator sends anything but passive requests. The upstream Exploiter, Infiltrator,
 * Exfiltrator and Ghost operators, active checks, credential harvesting, detection-risk "burn"
 * logic and stealth/breach team factories are not part of this build.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import {
  KillChainPhase,
  type OperatorArchetype,
  type Finding,
  type Task,
  type TaskResult,
  type Target,
  type ToolResult,
  type Severity,
} from '../types/index.js';
import type { LLMBackbone } from '../llm/index.js';
import type { AgentLoop } from '../agent/index.js';
import { resolveSystemPrompt } from '../prompts/index.js';
import { gateLiveFinding } from '../evidence/gate.js';
import { SEVERITY_SCORES } from '../evidence/index.js';
import { PASSIVE_CHECKS } from '../arsenal/index.js';
import { REPO_TOOL_NAMES } from '../arsenal/repo-tools.js';

export interface OperatorEvents {
  'task:started': { task: Task };
  'task:completed': { task: Task; result: TaskResult };
  'task:failed': { task: Task; error: string };
  'agent:thinking': { task: Task; content: string };
  'agent:tool_call': { task: Task; name: string; args: Record<string, unknown> };
  'agent:tool_result': { task: Task; name: string; result: ToolResult };
  'finding:discovered': { finding: Finding };
}

export interface ArchetypeProfile {
  name: string;
  description: string;
  primaryPhase: KillChainPhase;
  /** The exact tool names this operator may call. */
  tools: readonly string[];
  systemPrompt: string;
}

export const ARCHETYPE_PROFILES: Record<OperatorArchetype, ArchetypeProfile> = {
  recon: {
    name: 'Posture Operator',
    description: 'Passive posture checks: headers, TLS, technology, DNS and registration data',
    primaryPhase: KillChainPhase.RECON,
    tools: PASSIVE_CHECKS,
    systemPrompt: resolveSystemPrompt('recon'),
  },
  scanner: {
    name: 'Supply-chain & Configuration Scanner',
    description: 'Triage of dependency, secret and IaC/CI findings in the operator\'s repository',
    primaryPhase: KillChainPhase.WEAPONIZE,
    tools: [...REPO_TOOL_NAMES, 'cve_lookup'],
    systemPrompt: resolveSystemPrompt('scanner'),
  },
  analyst: {
    name: 'Code Review Analyst',
    description: 'White-box review of the operator\'s repository and triage of scanner findings',
    primaryPhase: KillChainPhase.ACTIONS,
    tools: [...REPO_TOOL_NAMES, 'cve_lookup'],
    systemPrompt: resolveSystemPrompt('analyst'),
  },
  coordinator: {
    name: 'Assessment Coordinator',
    description: 'Plans the assessment and writes the executive summary',
    primaryPhase: KillChainPhase.C2,
    tools: [],
    systemPrompt: resolveSystemPrompt('coordinator'),
  },
};

/** One operator: a callsign, an archetype profile, and (when wired) an agent loop. */
export class OperatorAgent extends EventEmitter<OperatorEvents> {
  readonly id = randomUUID();
  readonly profile: ArchetypeProfile;
  private readonly findings: Finding[] = [];
  private agentLoop?: AgentLoop;
  private sourceContext = '';

  constructor(
    readonly callsign: string,
    readonly archetype: OperatorArchetype,
    private readonly llm?: LLMBackbone,
  ) {
    super();
    this.profile = ARCHETYPE_PROFILES[archetype];
  }

  /** Wires the ReAct loop this operator drives. The loop's toolkit must be this profile's tools. */
  attachAgentLoop(agentLoop: AgentLoop): void {
    this.agentLoop = agentLoop;
  }

  /** The security-ordered source excerpt the Analyst reviews alongside its task. */
  setSourceContext(source: string): void {
    this.sourceContext = source;
  }

  async assignTask(task: Task, target?: Target): Promise<TaskResult> {
    this.emit('task:started', { task });
    try {
      const result = await this.executeTask(task, target);
      this.emit('task:completed', { task, result });
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emit('task:failed', { task, error: message });
      return { success: false, error: message };
    }
  }

  private async executeTask(task: Task, target?: Target): Promise<TaskResult> {
    if (this.agentLoop && this.llm) {
      const loop = this.agentLoop;
      const onThinking = ({ content }: { content: string }) => this.emit('agent:thinking', { task, content });
      const onToolCall = ({ name, args }: { name: string; args: Record<string, unknown> }) =>
        this.emit('agent:tool_call', { task, name, args });
      const onToolResult = ({ name, result }: { name: string; result: ToolResult }) =>
        this.emit('agent:tool_result', { task, name, result });
      loop.on('agent:thinking', onThinking);
      loop.on('agent:tool_call', onToolCall);
      loop.on('agent:tool_result', onToolResult);
      try {
        const result = await loop.run(task, this.profile.systemPrompt, target, this.sourceContext);
        for (const finding of result.findings) {
          const toolBacked = finding.provenance === 'tool';
          this.recordFinding({
            id: `finding-${randomUUID()}`,
            title: finding.title,
            description: finding.details,
            severity: finding.severity,
            targetId: target?.id || 'repository',
            operatorId: this.id,
            phase: task.phase,
            cvss: finding.cvss,
            cve: finding.cve,
            cwe: finding.cwe,
            evidence: toolBacked
              ? [{ type: 'output', content: finding.toolOutput || finding.details || '', timestamp: Date.now(), metadata: { tool: finding.toolName } }]
              : [],
            remediation: finding.remediation,
            discoveredAt: Date.now(),
          });
        }
        return {
          success: result.success,
          output: result.summary,
          error: result.finalSummaryError,
          findings: result.findings.map((f) => f.title),
        };
      } finally {
        loop.off('agent:thinking', onThinking);
        loop.off('agent:tool_call', onToolCall);
        loop.off('agent:tool_result', onToolResult);
      }
    }
    if (this.llm) {
      const output = await this.llm.prompt(`${task.name}\n\n${task.description}`, this.profile.systemPrompt, {
        temperature: 0.2,
        maxTokens: 4096,
      });
      return { success: true, output };
    }
    return { success: false, error: `Operator ${this.callsign} has no model configured.` };
  }

  /**
   * Records a finding through T3MP3ST's provenance gate: only a finding backed by real tool output
   * is verified, and an unverified claim's severity is capped so it cannot outrank evidence.
   */
  recordFinding(finding: Finding): void {
    const gate = gateLiveFinding(finding);
    finding.verifyGate = { passed: gate.passed, provenance: gate.provenance, reasons: gate.reasons, checkedAt: gate.checkedAt };
    if (gate.passed) {
      finding.verifiedAt = finding.verifiedAt ?? Date.now();
    } else {
      delete finding.verifiedAt;
      const cap: Record<string, Severity> = { none: 'low', context: 'medium' };
      const capped = cap[gate.provenance];
      if (capped && SEVERITY_SCORES[finding.severity] > SEVERITY_SCORES[capped]) {
        finding.assertedSeverity = finding.severity;
        finding.severity = capped;
      }
    }
    this.findings.push(finding);
    this.emit('finding:discovered', { finding });
  }

  getFindings(): Finding[] {
    return [...this.findings];
  }
}

export function createOperator(callsign: string, archetype: OperatorArchetype, llm?: LLMBackbone): OperatorAgent {
  return new OperatorAgent(callsign, archetype, llm);
}
