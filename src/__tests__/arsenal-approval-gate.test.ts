/**
 * Arsenal.execute() enforces the capability-approval gate for gated tools, alongside the scope gate.
 * The defensive build ships no gated tool, but the gate stays: anything gated that is ever added
 * fails closed until an operator approves it.
 */
import { describe, it, expect } from 'vitest';
import { Arsenal, BUILTIN_TOOLS, PASSIVE_CHECKS } from '../arsenal/index.js';
import { ApprovalController } from '../arsenal/approval.js';
import type { CustomTool, ToolContext } from '../types/index.js';

const ctx = (parameters: Record<string, unknown> = {}): ToolContext => ({ parameters });

function probe(name: string, riskTier?: CustomTool['riskTier']): CustomTool & { ran: () => boolean } {
  let ran = false;
  const tool: CustomTool = {
    name, description: 'x', category: 'test', riskTier, parameters: [],
    handler: async () => { ran = true; return { success: true, output: 'DID_RUN' }; },
  };
  return Object.assign(tool, { ran: () => ran });
}

describe('Arsenal.execute() approval gate', () => {
  it('fail-safe: a gated tool is denied (handler never runs) when nothing approves it', async () => {
    const ars = new Arsenal();
    const t = probe('gated_probe', 'intrusive');
    ars.register(t);
    ars.setApprovalController(new ApprovalController());
    const res = await ars.execute('gated_probe', ctx());
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/APPROVAL REQUIRED/);
    expect(t.ran()).toBe(false);
  });

  it('a pre-authorized gated tool runs', async () => {
    const ars = new Arsenal();
    const t = probe('gated_probe', 'intrusive');
    ars.register(t);
    ars.setApprovalController(new ApprovalController({ preApprovedTools: ['gated_probe'] }));
    expect((await ars.execute('gated_probe', ctx())).success).toBe(true);
    expect(t.ran()).toBe(true);
  });

  it('a passive tool is never gated, even with a locked-down controller', async () => {
    const ars = new Arsenal();
    const t = probe('passive_probe', 'passive');
    ars.register(t);
    ars.setApprovalController(new ApprovalController());
    expect((await ars.execute('passive_probe', ctx())).success).toBe(true);
  });
});

describe('defensive profile tiers', () => {
  it('every built-in is passive or local_read: no gated (intrusive/credential/dangerous) tool ships', () => {
    for (const tool of BUILTIN_TOOLS) {
      expect(['passive', 'local_read'], tool.name).toContain(tool.riskTier);
    }
  });

  it('the passive checks are exactly the network-facing built-ins', () => {
    const passive = BUILTIN_TOOLS.filter((t) => t.riskTier === 'passive').map((t) => t.name).sort();
    expect(passive).toEqual([...PASSIVE_CHECKS].sort());
  });
});
