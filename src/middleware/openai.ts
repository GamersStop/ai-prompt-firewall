/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Provider security middleware wrapper for OpenAI completion and chat prompts, managing automated redaction, strict blocking, and SIEM warning callbacks.
 * Author Name: Mayuresh Pandit
 */

import { scan } from '../core/ai_scanner.js';
import { FirewallMode, ScanResult } from '../core/types.js';
import { PromptBlockedError } from '../core/errors.js';

/**
 * Configuration options for the OpenAI prompt protection middleware.
 */
export interface OpenAIProtectionOptions {
    /** The firewall enforcement mode to apply ('redact' | 'block' | 'warn'). Defaults to 'redact'. */
    mode?: FirewallMode;
    /** Optional callback executed when a prompt is blocked due to security violations. */
    onBlock?: (result: ScanResult) => void;
    /** Optional callback executed when security findings are detected while running in 'warn' mode. */
    onWarn?: (result: ScanResult) => void;
}

/**
 * Intercepts, inspects, and secures user prompt text before transmission to OpenAI APIs.
 * Enforces the configured security posture (redaction, zero-trust blocking, or audit warning notifications).
 * 
 * @param prompt - The raw user input string to evaluate.
 * @param options - Configuration options controlling firewall mode and event callbacks.
 * @returns The sanitized/redacted prompt string or the original unmutated prompt (in warn mode).
 * @throws {PromptBlockedError} When mode is set to 'block' and security violations are detected.
 */
export function protectOpenAIPrompt(prompt: string, options: OpenAIProtectionOptions = {}): string {
    const mode = options.mode ?? 'redact';
    const result = scan(prompt, mode);

    // Handle security policy violations under 'block' mode
    if (result.blocked) {
        if (options.onBlock) {
            options.onBlock(result);
        }
        throw new PromptBlockedError(result);
    }

    // Handle telemetry monitoring and notification under 'warn' mode
    if (mode === 'warn' && result.findings.length > 0 && options.onWarn) {
        options.onWarn(result);
    }

    // Return the sanitized payload (redacted text or unmutated prompt for warn mode)
    return result.safePrompt;
}