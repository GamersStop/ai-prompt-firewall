/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Unit test suite validating multi-turn conversational session persistence, token consistency, and TTL lifecycles.
 * Author Name: Mayuresh Pandit
 */

import { describe, it, expect } from 'vitest';
import { createSession, scan } from '../src/index.js';
import { Finding } from '../src/core/types.js';

describe('Pillar 1: Multi-Turn Conversation Session Store', () => {
  it('should maintain consistent synthetic tokens across multi-turn conversation turns', () => {
    const session = createSession();

    // Turn 1: Alice introduces herself
    const turn1Prompt = 'Draft agreement for alice@acme.com';
    const turn1Findings: Finding[] = [
      { type: 'EMAIL', severity: 'CRITICAL', startIndex: 20, endIndex: 34 },
    ];
    const turn1Result = session.anonymize(turn1Prompt, undefined, turn1Findings);

    expect(turn1Result.safePrompt).toBe('Draft agreement for <EMAIL_1>');
    expect(turn1Result.tokenMap[0]?.original).toBe('alice@acme.com');

    // Turn 2: Alice is mentioned again alongside Bob
    const turn2Prompt = 'CC alice@acme.com and bob@acme.com';
    const turn2Findings: Finding[] = [
      { type: 'EMAIL', severity: 'CRITICAL', startIndex: 3, endIndex: 17 },
      { type: 'EMAIL', severity: 'CRITICAL', startIndex: 22, endIndex: 34 },
    ];
    const turn2Result = session.anonymize(turn2Prompt, undefined, turn2Findings);

    // Consistency check: alice@acme.com reuses <EMAIL_1>, bob@acme.com gets <EMAIL_2>
    expect(turn2Result.safePrompt).toBe('CC <EMAIL_1> and <EMAIL_2>');
    expect(session.getTokenMap().length).toBe(2);

    // Restore multi-turn LLM response
    const llmTurn2Response = 'Confirmed agreement dispatch to <EMAIL_1> and copy to <EMAIL_2>.';
    const restored = session.restore(llmTurn2Response);

    expect(restored).toBe('Confirmed agreement dispatch to alice@acme.com and copy to bob@acme.com.');
  });

  it('should integrate seamlessly with scanner when scanner is provided', () => {
    const session = createSession(undefined, (prompt, mode, opts) => scan(prompt, mode, opts));

    const prompt = 'Please forward message to contact@enterprise.org';
    const result = session.anonymize(prompt);

    expect(result.safePrompt).toContain('<EMAIL_1>');
    expect(result.findings.some((f) => f.type === 'EMAIL')).toBe(true);

    const restored = session.restore('Forwarded to <EMAIL_1>.');
    expect(restored).toBe('Forwarded to contact@enterprise.org.');
  });

  it('should handle TTL expiration', async () => {
    // 50ms TTL for testing
    const session = createSession({ ttlMs: 50 });

    const findings: Finding[] = [
      { type: 'EMAIL', severity: 'CRITICAL', startIndex: 0, endIndex: 16 },
    ];
    session.anonymize('user@domain.com', undefined, findings);
    expect(session.getTokenMap().length).toBe(1);

    // Wait 60ms to exceed TTL
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(session.isExpired()).toBe(true);
    // On touch, expired session clears
    session.touch();
    expect(session.getTokenMap().length).toBe(0);
  });

  it('should clear all tokens when manual clear() is invoked', () => {
    const session = createSession();
    session.anonymize('test@example.com', undefined, [
      { type: 'EMAIL', severity: 'CRITICAL', startIndex: 0, endIndex: 16 },
    ]);
    expect(session.getTokenMap().length).toBe(1);

    session.clear();
    expect(session.getTokenMap().length).toBe(0);
  });

  it('should enforce maxEntries limit', () => {
    const session = createSession({ maxEntries: 3 });

    for (let i = 1; i <= 5; i++) {
      session.anonymize(`user${i}@example.com`, undefined, [
        { type: 'EMAIL', severity: 'CRITICAL', startIndex: 0, endIndex: `user${i}@example.com`.length },
      ]);
    }

    // Exceeding threshold triggers reset/LRU bound
    expect(session.getTokenMap().length).toBeLessThanOrEqual(3);
  });
});
