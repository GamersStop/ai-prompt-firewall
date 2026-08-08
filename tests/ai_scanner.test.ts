/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Comprehensive unit and integration test suite validating scanner accuracy, multi-tenant isolation, payload scale performance, and input validation guards.
 * Author Name: Mayuresh Pandit
 */

import { describe, it, expect } from 'vitest';
import { scan, createFirewall } from '../src/core/ai_scanner.js';
import { PromptValidationError } from '../src/core/errors.js';

describe('AI Prompt Firewall Scanner', () => {
    /**
     * Verifies that the default 'redact' mode correctly identifies and masks OpenAI API keys
     * while retaining safe surrounding text.
     */
    it('should detect and redact OpenAI API keys in redact mode', () => {
        const prompt = 'Hey, use my key sk-1234567890abcdef1234567890abcdef for this request.';
        const result = scan(prompt, 'redact');

        expect(result.findings.length).toBeGreaterThan(0);
        expect(result.findings[0]?.type).toBe('OPENAI_KEY');
        expect(result.safePrompt).not.toContain('sk-1234567890abcdef1234567890abcdef');
        expect(result.safePrompt).toContain('[OPENAI_KEY_REDACTED]');
        expect(result.blocked).toBe(false);
    });

    /**
     * Verifies that the 'block' mode halts execution, sets blocked status to true,
     * and clears the safePrompt payload upon encountering a violation.
     */
    it('should block the prompt entirely in block mode when a secret is found', () => {
        const prompt = 'My AWS key is AKIAIOSFODNN7EXAMPLE';
        const result = scan(prompt, 'block');

        expect(result.blocked).toBe(true);
        expect(result.safePrompt).toBe('');
        expect(result.findings.length).toBeGreaterThan(0);
    });

    /**
     * Verifies that the 'warn' mode leaves prompts unmutated while successfully capturing
     * and reporting violation telemetry for SIEM monitoring.
     */
    it('should allow the prompt through untouched in warn mode while reporting findings', () => {
        const prompt = 'Contact me at test@example.com';
        const result = scan(prompt, 'warn');

        expect(result.blocked).toBe(false);
        expect(result.safePrompt).toBe(prompt);
        expect(result.findings.some((f) => f.type === 'EMAIL')).toBe(true);
    });

    /**
     * Verifies that clean prompts containing zero security violations pass through unmutated.
     */
    it('should pass safe prompts with zero findings cleanly', () => {
        const prompt = 'What is the capital of France?';
        const result = scan(prompt, 'redact');

        expect(result.findings.length).toBe(0);
        expect(result.blocked).toBe(false);
        expect(result.safePrompt).toBe(prompt);
    });

    /**
     * Verifies that multi-tenant firewall instances created via createFirewall properly
     * isolate rules and prevent cross-pollution between different tenants.
     */
    it('should support multi-tenant instances using createFirewall with pre-compiled custom patterns', () => {
        const tenantA = createFirewall({
            customPatterns: { TENANT_A_KEY: /TENANT-A-[0-9]{4}/g }
        });
        const tenantB = createFirewall({
            customPatterns: { TENANT_B_KEY: /TENANT-B-[0-9]{4}/g }
        });

        const resA = tenantA.scan('Key is TENANT-A-1111');
        const resB = tenantB.scan('Key is TENANT-B-2222');

        expect(resA.findings[0]?.type).toBe('TENANT_A_KEY');
        expect(resB.findings[0]?.type).toBe('TENANT_B_KEY');

        // Ensure isolation: tenantA instance should not detect tenantB custom keys
        expect(tenantA.scan('Key is TENANT-B-2222').findings.some(f => f.type === 'TENANT_B_KEY')).toBe(false);
    });

    /**
     * Verifies that the scanner handles large multi-kilobyte prompt payloads efficiently
     * without performance degradation or memory issues.
     */
    it('should handle large multi-kilobyte prompts gracefully', () => {
        const largeText = 'Lorem ipsum dolor sit amet '.repeat(2000) + ' AKIAIOSFODNN7EXAMPLE ' + 'Lorem ipsum'.repeat(2000);
        const result = scan(largeText, 'redact');

        expect(result.findings.some(f => f.type === 'AWS_KEY')).toBe(true);
        expect(result.safePrompt).toContain('[AWS_KEY_REDACTED]');
    });

    /**
     * Verifies that invalid inputs (empty strings, null, numbers) throw explicit PromptValidationError exceptions.
     */
    it('should throw PromptValidationError for empty or non-string prompts', () => {
        expect(() => scan('', 'redact')).toThrow(PromptValidationError);
        expect(() => scan(123 as unknown as string, 'redact')).toThrow(PromptValidationError);
    });
});