/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Input sanitization, type guarding, and runtime validation utility functions for prompt payloads, firewall modes, and custom regex rules.
 * Author Name: Mayuresh Pandit
 */

import { FirewallMode } from './ai_scanner.js';
import { PromptValidationError } from './errors.js';

/**
 * Validates whether an unknown string input strictly matches a supported FirewallMode ('redact' | 'block' | 'warn').
 * Uses a type guard to safely narrow string types for TypeScript compilation.
 */
export function isValidFirewallMode(mode: unknown): mode is FirewallMode {
    return typeof mode === 'string' && ['redact', 'block', 'warn'].includes(mode);
}

/**
 * Validates that an incoming prompt payload is a valid, non-empty string.
 * Throws structured PromptValidationError exceptions for downstream reliability.
 */
export function validatePrompt(prompt: unknown): string {
    if (typeof prompt !== 'string') {
        throw new PromptValidationError(`Invalid prompt payload: Expected a string value, received ${typeof prompt}.`);
    }

    if (prompt.trim().length === 0) {
        throw new PromptValidationError('Invalid prompt payload: Prompt cannot be empty or consist solely of whitespace.');
    }

    return prompt;
}

/**
 * Validates a custom runtime pattern rule to ensure it satisfies valid RegExp instance contracts.
 */
export function validateCustomPattern(name: unknown, regex: unknown): void {
    if (typeof name !== 'string' || name.trim().length === 0) {
        throw new PromptValidationError('Invalid custom pattern configuration: Pattern name must be a non-empty string.');
    }

    if (!(regex instanceof RegExp)) {
        throw new PromptValidationError(`Invalid pattern configuration for "${name}": Expected a valid RegExp instance.`);
    }
}