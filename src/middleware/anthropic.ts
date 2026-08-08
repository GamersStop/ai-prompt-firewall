/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Provider security middleware wrapper for Anthropic Claude prompts, handling automated redaction, blocking, and SIEM warning callbacks.
 * Author Name: Mayuresh Pandit
 */

import { scan } from '../core/ai_scanner.js';
import { FirewallMode, ScanResult } from '../core/types.js';
import { PromptBlockedError } from '../core/errors.js';

/**
 * Configuration options for the Anthropic prompt protection wrapper.
 */
export interface AnthropicProtectionOptions {
    /** The firewall enforcement mode to apply ('redact' | 'block' | 'warn'). Defaults to 'redact'. */
    mode?: FirewallMode;
    /** Optional callback executed when a prompt is blocked due to security violations. */
    onBlock?: (result: ScanResult) => void;
    /** Optional callback executed when security findings are detected while running in 'warn' mode. */
    onWarn?: (result: ScanResult) => void;
}

/**
 * Intercepts, inspects, and secures user prompt payloads before transmission to Anthropic models.
 * Enforces the specified security posture (redaction, zero-trust blocking, or audit warning hooks).
 * 
 * @param prompt - The raw user input string to evaluate.
 * @param options - Configuration options controlling firewall mode and event callbacks.
 * @returns The sanitized/redacted prompt string or the original unmutated prompt (in warn mode).
 * @throws {PromptBlockedError} When mode is set to 'block' and security violations are detected.
 */
export function protectAnthropicPrompt(prompt: string, options: AnthropicProtectionOptions = {}): string {
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