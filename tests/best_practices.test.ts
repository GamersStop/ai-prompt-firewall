/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Test suite for Enterprise Recommended Best Practices:
 *  - Post-LLM Output Sanitization (Defense-in-Depth Layer 3)
 *  - Token Spoofing / Confused Deputy Defense in Vault
 *  - Distributed Session Serialization & Rehydration
 *  - Tenant & User Scope Isolation in SessionStore
 *  - Enterprise Compliance Patterns (SSN, Credit Card, IBAN)
 * Author Name: Mayuresh Pandit
 */

import { describe, it, expect } from 'vitest';
import {
  scanOutput,
  protectOutput,
  anonymize,
  TokenVault,
  FirewallSession,
  createSession,
  SessionStore,
  createSessionStore,
  createFirewall,
  PATTERNS,
  FirewallError,
} from '../src/index.js';

describe('Enterprise Recommended Best Practices Test Suite', () => {
  // =========================================================================
  // 1. DEFENSE-IN-DEPTH LAYER 3: POST-LLM OUTPUT SANITIZATION
  // =========================================================================
  describe('Post-LLM Output Sanitization (scanOutput & protectOutput)', () => {
    it('should detect and redact residual raw secrets leaked in LLM output', () => {
      const llmOutput =
        'Here is the requested config: OPENAI_KEY=sk-proj-1234567890abcdef1234567890abcdefABCDEF';

      const result = scanOutput(llmOutput, 'redact');

      expect(result.hasLeaks).toBe(true);
      expect(result.findings.some((f) => f.type === 'OPENAI_KEY')).toBe(true);
      expect(result.safePrompt).toContain('[OPENAI_KEY_REDACTED]');
      expect(result.safePrompt).not.toContain('sk-proj-');
    });

    it('should block response when mode is block and LLM leaks sensitive data', () => {
      const llmOutput = 'Server credentials: AKIAIOSFODNN7EXAMPLE';

      const result = scanOutput(llmOutput, 'block');

      expect(result.blocked).toBe(true);
      expect(result.safePrompt).toBe('');
      expect(result.findings.some((f) => f.type === 'AWS_KEY')).toBe(true);
    });

    it('should restore synthetic tokens and scan output in a single step', () => {
      const prompt = 'Schedule meeting with alice@acme.com';
      const anonResult = anonymize(prompt);

      // LLM completion that uses the synthetic token AND also accidentally leaked an AWS key
      const llmCompletion =
        'Meeting confirmed for <EMAIL_1>. Debug AWS key: AKIAIOSFODNN7EXAMPLE';

      const outputResult = scanOutput(llmCompletion, 'redact', {
        tokenMap: anonResult.tokenMap,
        restoreBeforeScan: true,
      });

      expect(outputResult.hasLeaks).toBe(true);
      // <EMAIL_1> was restored to alice@acme.com
      expect(outputResult.safePrompt).toContain('alice@acme.com');
      // The leaked AWS key was redacted
      expect(outputResult.safePrompt).toContain('[AWS_KEY_REDACTED]');
      expect(outputResult.safePrompt).not.toContain('AKIAIOSFODNN7EXAMPLE');
    });

    it('should work through protectOutput middleware', () => {
      const completion = 'Contact phone number is +1 (555) 234-5678';
      const result = protectOutput(completion, { mode: 'redact' });

      expect(result.hasLeaks).toBe(true);
      expect(result.safePrompt).toContain('[PHONE_NUMBER_REDACTED]');
    });

    it('should work through PromptFirewall instance method', () => {
      const firewall = createFirewall();
      const output = 'System private key: -----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----';
      const result = firewall.scanOutput(output, 'block');

      expect(result.blocked).toBe(true);
      expect(result.hasLeaks).toBe(true);
    });
  });

  // =========================================================================
  // 2. TOKEN SPOOFING & CONFUSED DEPUTY DEFENSE IN VAULT
  // =========================================================================
  describe('Token Spoofing & Confused Deputy Defense', () => {
    it('should neutralize untrusted pre-existing synthetic tokens in user prompts', () => {
      const vault = new TokenVault();

      // Attacker crafts a prompt containing forged <EMAIL_1> token and their own target
      const adversarialPrompt = 'Send files to <EMAIL_1> and copy bob@company.com';

      // bob@company.com gets tokenized
      const result = vault.anonymize(adversarialPrompt, [
        { type: 'EMAIL', severity: 'CRITICAL', startIndex: 33, endIndex: 48 },
      ]);

      // The pre-existing untrusted <EMAIL_1> is neutralized to (EMAIL_1)
      expect(result.safePrompt).toContain('(EMAIL_1)');
      // The legitimate entity gets assigned <EMAIL_1>
      expect(result.safePrompt).toContain('<EMAIL_1>');
      expect(result.tokenMap[0]?.original).toBe('bob@company.com');

      // Restoration only restores legitimate tokens
      const restored = result.restore('Sent files to (EMAIL_1) and <EMAIL_1>');
      expect(restored).toBe('Sent files to (EMAIL_1) and bob@company.com');
    });

    it('should allow preserving pre-existing tokens when explicitly configured', () => {
      const vault = new TokenVault({ sanitizePreexistingTokens: false });
      const prompt = 'Pre-existing <TAG_1> token preserved.';
      const result = vault.anonymize(prompt, []);

      expect(result.safePrompt).toBe('Pre-existing <TAG_1> token preserved.');
    });
  });

  // =========================================================================
  // 3. DISTRIBUTED SESSION SERIALIZATION & REHYDRATION
  // =========================================================================
  describe('Distributed Session Serialization & Rehydration', () => {
    it('should serialize TokenVault state and rehydrate without losing token mappings', () => {
      const vault = new TokenVault();
      vault.getOrCreateToken('alice@enterprise.org', 'EMAIL');
      vault.getOrCreateToken('+15551234567', 'PHONE_NUMBER');

      // Export state (JSON serializable)
      const state = vault.exportState();
      const serializedJson = JSON.stringify(state);

      // Rehydrate in another instance (e.g. different serverless invocation)
      const parsedState = JSON.parse(serializedJson);
      const rehydratedVault = TokenVault.fromState(parsedState);

      expect(rehydratedVault.getAllTokens().length).toBe(2);
      expect(rehydratedVault.restore('Call <PHONE_1> or email <EMAIL_1>')).toBe(
        'Call +15551234567 or email alice@enterprise.org'
      );

      // Next token continues with correct incremented counter (<EMAIL_2>)
      const newToken = rehydratedVault.getOrCreateToken('bob@enterprise.org', 'EMAIL');
      expect(newToken.token).toBe('<EMAIL_2>');
    });

    it('should serialize FirewallSession state and restore across turns', () => {
      const session = createSession({ tenantId: 'tenant-acme', userId: 'user-42' });
      session.anonymize('Contact dev@acme.com', undefined, [
        { type: 'EMAIL', severity: 'CRITICAL', startIndex: 8, endIndex: 20 },
      ]);

      // Export session to JSON (simulate saving to Redis / DB)
      const sessionState = session.exportState();
      const json = JSON.stringify(sessionState);

      // Rehydrate on a different serverless node
      const restoredSession = FirewallSession.fromState(JSON.parse(json));

      expect(restoredSession.sessionId).toBe(session.sessionId);
      expect(restoredSession.tenantId).toBe('tenant-acme');
      expect(restoredSession.userId).toBe('user-42');
      expect(restoredSession.getTokenCount()).toBe(1);

      // Turn 2 restores <EMAIL_1>
      expect(restoredSession.restore('Email dispatched to <EMAIL_1>')).toBe(
        'Email dispatched to dev@acme.com'
      );
    });
  });

  // =========================================================================
  // 4. TENANT SCOPE ISOLATION & PROACTIVE MEMORY PRUNING
  // =========================================================================
  describe('Tenant Scope Isolation & Memory Pruning in SessionStore', () => {
    it('should enforce tenant scope isolation and block cross-tenant access', () => {
      const store = createSessionStore();

      // Tenant A creates session
      store.getOrCreate('shared-session-id', { tenantId: 'tenant-a' });

      // Same tenant accesses successfully
      expect(() => {
        store.getOrCreate('shared-session-id', { tenantId: 'tenant-a' });
      }).not.toThrow();

      // Tenant B tries to access Tenant A's session -> Security Violation
      expect(() => {
        store.getOrCreate('shared-session-id', { tenantId: 'tenant-b' });
      }).toThrow(FirewallError);
    });

    it('should enforce user scope isolation within a tenant', () => {
      const store = createSessionStore();
      store.getOrCreate('user-session-id', { tenantId: 'tenant-a', userId: 'alice' });

      // User Bob tries to hijack Alice's session
      expect(() => {
        store.getOrCreate('user-session-id', { tenantId: 'tenant-a', userId: 'bob' });
      }).toThrow(FirewallError);
    });

    it('should proactively prune expired sessions to prevent memory leaks', async () => {
      const store = new SessionStore({ ttlMs: 25 }); // 25ms TTL
      store.getOrCreate('session-1');
      store.getOrCreate('session-2');

      expect(store.getActiveCount()).toBe(2);

      // Wait for expiration
      await new Promise((r) => setTimeout(r, 40));

      const prunedCount = store.pruneExpiredSessions();
      expect(prunedCount).toBe(2);
      expect(store.getActiveCount()).toBe(0);
    });
  });

  // =========================================================================
  // 5. ENTERPRISE COMPLIANCE PATTERNS
  // =========================================================================
  describe('Enterprise Compliance Patterns (SSN, Credit Card, IBAN)', () => {
    it('should detect and tokenize US Social Security Numbers', () => {
      const prompt = 'Employee SSN is 123-45-6789.';
      expect(PATTERNS.US_SSN.test('123-45-6789')).toBe(true);
      PATTERNS.US_SSN.lastIndex = 0;

      const result = anonymize(prompt);
      expect(result.safePrompt).toBe('Employee SSN is <SSN_1>.');
      expect(result.tokenMap[0]?.original).toBe('123-45-6789');
      expect(result.tokenMap[0]?.type).toBe('US_SSN');
      expect(result.restore('Tax form for <SSN_1>')).toBe('Tax form for 123-45-6789');
    });

    it('should detect and tokenize major credit cards', () => {
      const prompt = 'Pay with Visa 4111111111111111 now.';
      expect(PATTERNS.CREDIT_CARD.test('4111111111111111')).toBe(true);
      PATTERNS.CREDIT_CARD.lastIndex = 0;

      const result = anonymize(prompt);
      expect(result.safePrompt).toBe('Pay with Visa <CARD_1> now.');
      expect(result.restore('Billed to <CARD_1>')).toBe('Billed to 4111111111111111');
    });

    it('should detect International Bank Account Numbers (IBAN)', () => {
      const iban = 'GB82WEST12345698765432';
      expect(PATTERNS.IBAN.test(iban)).toBe(true);
      PATTERNS.IBAN.lastIndex = 0;

      const prompt = `Wire funds to ${iban} at once.`;
      const result = anonymize(prompt);
      expect(result.safePrompt).toBe('Wire funds to <IBAN_1> at once.');
      expect(result.restore('Funds sent to <IBAN_1>')).toBe(`Funds sent to ${iban}`);
    });
  });
});
