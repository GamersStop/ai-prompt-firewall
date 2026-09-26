/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Unit test suite for Reversible Tokenization Vault (Pillar 1) covering token generation, deduplication, and restoration.
 * Author Name: Mayuresh Pandit
 */

import { describe, it, expect } from 'vitest';
import { TokenVault, anonymizePrompt, escapeRegExp } from '../src/index.js';
import { Finding } from '../src/core/types.js';

describe('Pillar 1: Reversible Tokenization Vault', () => {
  describe('Deterministic Synthetic Token Replacement & Deduplication', () => {
    it('should assign deterministic synthetic tokens by entity type', () => {
      const prompt = 'Please contact alice@acme.com and call +1 (555) 234-5678.';
      const findings: Finding[] = [
        {
          type: 'EMAIL',
          severity: 'CRITICAL',
          startIndex: 15,
          endIndex: 29,
          matchedSnippetLength: 14,
        },
        {
          type: 'PHONE_NUMBER',
          severity: 'CRITICAL',
          startIndex: 39,
          endIndex: 56,
          matchedSnippetLength: 17,
        },
      ];

      const { safePrompt, tokenMap, restore } = anonymizePrompt(prompt, findings);

      expect(safePrompt).toBe('Please contact <EMAIL_1> and call <PHONE_1>.');
      expect(tokenMap.length).toBe(2);
      expect(tokenMap.find((t) => t.type === 'EMAIL')?.token).toBe('<EMAIL_1>');
      expect(tokenMap.find((t) => t.type === 'PHONE_NUMBER')?.token).toBe('<PHONE_1>');

      const llmOutput = 'Confirmation sent to <EMAIL_1> and SMS to <PHONE_1>.';
      const restored = restore(llmOutput);
      expect(restored).toBe('Confirmation sent to alice@acme.com and SMS to +1 (555) 234-5678.');
    });

    it('should deduplicate identical sensitive values to the same token', () => {
      const prompt = 'Send copy to alice@acme.com and CC alice@acme.com or bob@acme.com.';
      const findings: Finding[] = [
        {
          type: 'EMAIL',
          severity: 'CRITICAL',
          startIndex: 13,
          endIndex: 27,
          matchedSnippetLength: 14,
        },
        {
          type: 'EMAIL',
          severity: 'CRITICAL',
          startIndex: 35,
          endIndex: 49,
          matchedSnippetLength: 14,
        },
        {
          type: 'EMAIL',
          severity: 'CRITICAL',
          startIndex: 53,
          endIndex: 65,
          matchedSnippetLength: 12,
        },
      ];

      const { safePrompt, tokenMap, restore } = anonymizePrompt(prompt, findings);

      expect(safePrompt).toBe('Send copy to <EMAIL_1> and CC <EMAIL_1> or <EMAIL_2>.');
      expect(tokenMap.length).toBe(2); // Only 2 unique email tokens generated
      expect(tokenMap[0]?.original).toBe('alice@acme.com');
      expect(tokenMap[1]?.original).toBe('bob@acme.com');

      const llmOutput = 'Notified <EMAIL_1> twice, and <EMAIL_2> once.';
      expect(restore(llmOutput)).toBe('Notified alice@acme.com twice, and bob@acme.com once.');
    });

    it('should handle conversational personal name introductions', () => {
      const prompt = 'Hello, my name is Alice Smith. Please review my account.';
      const findings: Finding[] = [
        {
          type: 'USER_NAME_CONTEXT',
          severity: 'HIGH',
          startIndex: 7,
          endIndex: 29, // "my name is Alice Smith"
          matchedSnippetLength: 22,
        },
      ];

      const { safePrompt, tokenMap, restore } = anonymizePrompt(prompt, findings);

      expect(safePrompt).toBe('Hello, my name is <PERSON_1>. Please review my account.');
      expect(tokenMap[0]?.original).toBe('Alice Smith');
      expect(tokenMap[0]?.token).toBe('<PERSON_1>');

      const llmOutput = 'Welcome back, <PERSON_1>! How may I assist you today?';
      expect(restore(llmOutput)).toBe('Welcome back, Alice Smith! How may I assist you today?');
    });

    it('should support bracket prefix format [TYPE_1]', () => {
      const prompt = 'Contact support@company.com';
      const findings: Finding[] = [
        {
          type: 'EMAIL',
          severity: 'CRITICAL',
          startIndex: 8,
          endIndex: 27,
          matchedSnippetLength: 19,
        },
      ];

      const { safePrompt, tokenMap, restore } = anonymizePrompt(
        prompt,
        findings,
        { prefixFormat: 'bracket' }
      );

      expect(safePrompt).toBe('Contact [EMAIL_1]');
      expect(tokenMap[0]?.token).toBe('[EMAIL_1]');
      expect(restore('Email sent to [EMAIL_1]')).toBe('Email sent to support@company.com');
    });

    it('should support custom entity name mappings', () => {
      const prompt = 'Use key sk-1234567890abcdef1234567890abcdef';
      const findings: Finding[] = [
        {
          type: 'OPENAI_KEY',
          severity: 'CRITICAL',
          startIndex: 8,
          endIndex: 44,
          matchedSnippetLength: 36,
        },
      ];

      const { safePrompt, tokenMap } = anonymizePrompt(prompt, findings, {
        entityNameMapping: { OPENAI_KEY: 'SECRET_KEY' },
      });

      expect(safePrompt).toBe('Use key <SECRET_KEY_1>');
      expect(tokenMap[0]?.token).toBe('<SECRET_KEY_1>');
    });
  });

  describe('Restoration Edge Cases', () => {
    it('should eliminate prefix collisions by ordering tokens descending by length', () => {
      const vault = new TokenVault();

      // Register 11 emails to create <EMAIL_1> and <EMAIL_10>
      for (let i = 1; i <= 10; i++) {
        vault.getOrCreateToken(`user${i}@example.com`, 'EMAIL');
      }

      const llmOutput = 'Send report to <EMAIL_10> and <EMAIL_1>.';
      const restored = vault.restore(llmOutput);

      expect(restored).toBe('Send report to user10@example.com and user1@example.com.');
    });

    it('should restore case-variations emitted by LLMs', () => {
      const vault = new TokenVault();
      vault.getOrCreateToken('alice@example.com', 'EMAIL');

      const llmOutput = 'Output for <email_1> and <Email_1>.';
      const restored = vault.restore(llmOutput);

      expect(restored).toBe('Output for alice@example.com and alice@example.com.');
    });

    it('should restore complex formatted LLM completions (JSON & Markdown)', () => {
      const vault = new TokenVault();
      vault.getOrCreateToken('alice@example.com', 'EMAIL');
      vault.getOrCreateToken('+15551234567', 'PHONE_NUMBER');

      const jsonResponse = JSON.stringify({
        recipient: '<EMAIL_1>',
        phone: '<PHONE_1>',
        notes: 'Contact `<EMAIL_1>` via phone `<PHONE_1>`',
      });

      const restoredJson = JSON.parse(vault.restore(jsonResponse));
      expect(restoredJson.recipient).toBe('alice@example.com');
      expect(restoredJson.phone).toBe('+15551234567');
      expect(restoredJson.notes).toBe('Contact `alice@example.com` via phone `+15551234567`');
    });

    it('should safely return empty string or non-string inputs in restore', () => {
      const vault = new TokenVault();
      expect(vault.restore('')).toBe('');
      expect(vault.restore(null as unknown as string)).toBe('');
    });
  });

  describe('Performance & Latency Budget (<0.5ms)', () => {
    it('should anonymize and restore prompts in <0.5ms', () => {
      const prompt = 'User test@example.com contacted 192.168.1.1 about secret sk-1234567890abcdef1234567890abcdef';
      const findings: Finding[] = [
        { type: 'EMAIL', severity: 'CRITICAL', startIndex: 5, endIndex: 21 },
        { type: 'IPV4_ADDRESS', severity: 'CRITICAL', startIndex: 32, endIndex: 43 },
        { type: 'OPENAI_KEY', severity: 'CRITICAL', startIndex: 57, endIndex: 93 },
      ];

      const iterations = 500;
      // Warm-up
      for (let i = 0; i < 50; i++) {
        const { restore } = anonymizePrompt(prompt, findings);
        restore('Result for <EMAIL_1>, <IP_1>, <OPENAI_KEY_1>');
      }

      const start = performance.now();
      for (let i = 0; i < iterations; i++) {
        const { restore } = anonymizePrompt(prompt, findings);
        restore('Result for <EMAIL_1>, <IP_1>, <OPENAI_KEY_1>');
      }
      const totalTime = performance.now() - start;
      const avgTime = totalTime / iterations;

      expect(avgTime).toBeLessThan(0.5); // Well within 0.5ms budget
    });
  });

  describe('Regex Utility Safety', () => {
    it('should escape all regex special characters', () => {
      const dangerous = '[test].*+?^${}()|\\';
      const escaped = escapeRegExp(dangerous);
      expect(() => new RegExp(escaped)).not.toThrow();
      expect(new RegExp(escaped).test(dangerous)).toBe(true);
    });
  });
});
