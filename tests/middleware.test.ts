/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Comprehensive integration test suite validating provider middleware wrappers (OpenAI, Anthropic, LangChain) across redaction, blocking, warning telemetry, and callback lifecycles.
 * Author Name: Mayuresh Pandit
 */

import { describe, it, expect, vi } from 'vitest';
import { protectOpenAIPrompt } from '../src/middleware/openai.js';
import { protectAnthropicPrompt } from '../src/middleware/anthropic.js';
import { protectLangChainPrompt } from '../src/middleware/langchain.js';

describe('AI Provider Middleware Security Wrappers', () => {
    const secretPrompt = 'My secret OpenAI key is sk-1234567890abcdef1234567890abcdef';
    const cleanPrompt = 'What is the weather today?';

    describe('OpenAI Middleware', () => {
        /**
         * Verifies that OpenAI prompt wrapper successfully redacts secrets under default redact mode.
         */
        it('should redact secrets in default redact mode', () => {
            const sanitized = protectOpenAIPrompt(secretPrompt, { mode: 'redact' });
            expect(sanitized).not.toContain('sk-1234567890abcdef1234567890abcdef');
            expect(sanitized).toContain('[OPENAI_KEY_REDACTED]');
        });

        /**
         * Verifies that OpenAI prompt wrapper halts execution, throws an error, and triggers the onBlock callback in block mode.
         */
        it('should throw an error and trigger onBlock callback in block mode', () => {
            const onBlockMock = vi.fn();

            expect(() => {
                protectOpenAIPrompt(secretPrompt, { mode: 'block', onBlock: onBlockMock });
            }).toThrowError(/Request blocked due to security violations/);

            expect(onBlockMock).toHaveBeenCalledTimes(1);
        });

        /**
         * Verifies that OpenAI prompt wrapper invokes the warning callback and preserves the prompt in warn mode.
         */
        it('should trigger onWarn callback and return original prompt in warn mode', () => {
            const onWarnMock = vi.fn();
            const sanitized = protectOpenAIPrompt(secretPrompt, { mode: 'warn', onWarn: onWarnMock });

            expect(sanitized).toBe(secretPrompt);
            expect(onWarnMock).toHaveBeenCalledTimes(1);
        });

        /**
         * Verifies that clean OpenAI prompts pass through without modification.
         */
        it('should pass clean prompts untouched', () => {
            const sanitized = protectOpenAIPrompt(cleanPrompt, { mode: 'redact' });
            expect(sanitized).toBe(cleanPrompt);
        });
    });

    describe('Anthropic Middleware', () => {
        /**
         * Verifies that Anthropic prompt wrapper correctly identifies and redacts Claude API keys.
         */
        it('should redact secrets properly for Claude inputs', () => {
            const anthropicSecret = 'Use key sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
            const sanitized = protectAnthropicPrompt(anthropicSecret, { mode: 'redact' });

            expect(sanitized).toContain('[ANTHROPIC_KEY_REDACTED]');
        });

        /**
         * Verifies that Anthropic prompt wrapper enforces zero-trust blocking when violations occur in block mode.
         */
        it('should block requests in block mode', () => {
            const onBlockMock = vi.fn();
            expect(() => {
                protectAnthropicPrompt('Bad prompt with AKIAIOSFODNN7EXAMPLE', { mode: 'block', onBlock: onBlockMock });
            }).toThrowError();
            expect(onBlockMock).toHaveBeenCalled();
        });
    });

    describe('LangChain Middleware', () => {
        /**
         * Verifies that LangChain wrapper scrubs PII and secrets prior to chain template interpolation.
         */
        it('should redact secrets before entering LangChain templates', () => {
            const langchainSecret = 'My email is test@example.com';
            const sanitized = protectLangChainPrompt(langchainSecret, { mode: 'redact' });

            expect(sanitized).toContain('[EMAIL_REDACTED]');
        });

        /**
         * Verifies that LangChain wrapper successfully invokes warning callback hooks under warn mode.
         */
        it('should invoke warning callback in warn mode', () => {
            const onWarnMock = vi.fn();
            const sanitized = protectLangChainPrompt('My IP is 192.168.1.1', { mode: 'warn', onWarn: onWarnMock });

            expect(sanitized).toBe('My IP is 192.168.1.1');
            expect(onWarnMock).toHaveBeenCalledTimes(1);
        });
    });
});