/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Comprehensive unit test suite covering core modules (errors, types, patterns, validators) to guarantee strict runtime validation and type integrity.
 * Author Name: Mayuresh Pandit
 */

import { describe, it, expect } from 'vitest';
import { FirewallError, PromptBlockedError, PromptValidationError } from '../src/core/errors.js';
import { PATTERNS } from '../src/core/patterns.js';
import { isValidFirewallMode, validatePrompt, validateCustomPattern } from '../src/core/validators.js';
import type { ScanResult } from '../src/core/types.js';

describe('Core Module Test Suite', () => {

    // --- 1. ERRORS TEST SUITE ---
    describe('Error Taxonomy (errors.ts)', () => {
        it('should correctly instantiate base FirewallError with proper name and message', () => {
            const err = new FirewallError('Base firewall error occurred.');
            expect(err).toBeInstanceOf(Error);
            expect(err).toBeInstanceOf(FirewallError);
            expect(err.name).toBe('FirewallError');
            expect(err.message).toBe('Base firewall error occurred.');
        });

        it('should construct PromptBlockedError with attached ScanResult and extracted finding types', () => {
            const mockScanResult: ScanResult = {
                safePrompt: '',
                findings: [
                    { type: 'OPENAI_KEY', severity: 'CRITICAL', startIndex: 0, endIndex: 10, matchedSnippetLength: 10 },
                    { type: 'EMAIL', severity: 'CRITICAL', startIndex: 15, endIndex: 30, matchedSnippetLength: 15 }
                ],
                blocked: true
            };

            const blockedErr = new PromptBlockedError(mockScanResult);
            expect(blockedErr).toBeInstanceOf(FirewallError);
            expect(blockedErr).toBeInstanceOf(PromptBlockedError);
            expect(blockedErr.name).toBe('PromptBlockedError');
            expect(blockedErr.result).toEqual(mockScanResult);
            expect(blockedErr.message).toContain('OPENAI_KEY, EMAIL');
        });

        it('should construct PromptValidationError with formatted prefix message', () => {
            const validationErr = new PromptValidationError('Input must be a valid string.');
            expect(validationErr).toBeInstanceOf(FirewallError);
            expect(validationErr).toBeInstanceOf(PromptValidationError);
            expect(validationErr.name).toBe('PromptValidationError');
            expect(validationErr.message).toContain('Validation Error: Input must be a valid string.');
        });
    });

    // --- 2. PATTERNS TEST SUITE ---
    describe('Pattern Dictionary (patterns.ts)', () => {
        it('should correctly match OpenAI and Anthropic API keys without cross-pollution', () => {
            const openaiKey = 'sk-proj-1234567890abcdef1234567890abcdefABCDEF';
            const anthropicKey = 'sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ZZZZZZ';

            expect(PATTERNS.OPENAI_KEY.test(openaiKey)).toBe(true);
            // Reset regex lastIndex for global flags
            PATTERNS.OPENAI_KEY.lastIndex = 0;
            expect(PATTERNS.OPENAI_KEY.test(anthropicKey)).toBe(false);
            PATTERNS.OPENAI_KEY.lastIndex = 0;

            expect(PATTERNS.ANTHROPIC_KEY.test(anthropicKey)).toBe(true);
            PATTERNS.ANTHROPIC_KEY.lastIndex = 0;
        });

        it('should correctly match common PII structures like email and IPv4 addresses', () => {
            const email = 'security@enterprise.io';
            const ipv4 = '192.168.1.100';

            expect(PATTERNS.EMAIL.test(email)).toBe(true);
            PATTERNS.EMAIL.lastIndex = 0;

            expect(PATTERNS.IPV4_ADDRESS.test(ipv4)).toBe(true);
            PATTERNS.IPV4_ADDRESS.lastIndex = 0;
        });
    });

    // --- 3. VALIDATORS TEST SUITE ---
    describe('Validators & Type Guards (validator.ts)', () => {
        it('should validate firewall modes correctly using isValidFirewallMode', () => {
            expect(isValidFirewallMode('redact')).toBe(true);
            expect(isValidFirewallMode('block')).toBe(true);
            expect(isValidFirewallMode('warn')).toBe(true);
            expect(isValidFirewallMode('invalid_mode')).toBe(false);
            expect(isValidFirewallMode(123)).toBe(false);
            expect(isValidFirewallMode(null)).toBe(false);
        });

        it('should accept valid non-empty prompt strings and reject invalid types or empty strings', () => {
            expect(validatePrompt('Hello secure world')).toBe('Hello secure world');

            expect(() => validatePrompt('')).toThrow(PromptValidationError);
            expect(() => validatePrompt('   ')).toThrow(PromptValidationError);
            expect(() => validatePrompt(null)).toThrow(PromptValidationError);
            expect(() => validatePrompt(42)).toThrow(PromptValidationError);
        });

        it('should validate custom pattern configurations correctly', () => {
            const customRegex = /CUSTOM-[0-9]+/g;
            expect(() => validateCustomPattern('MY_PATTERN', customRegex)).not.toThrow();

            expect(() => validateCustomPattern('', customRegex)).toThrow(PromptValidationError);
            expect(() => validateCustomPattern('MY_PATTERN', 'not-a-regex' as unknown as RegExp)).toThrow(PromptValidationError);
        });
    });
});