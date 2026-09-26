/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Provider security middleware wrapper for OpenAI completion and chat prompts, managing automated redaction, strict blocking, and SIEM warning callbacks.
 * Author Name: Mayuresh Pandit
 */

import { scan } from '../core/ai_scanner.js';
import {
  ChatMessage,
  FirewallMode,
  FirewallOptions,
  ProtectMessagesOptions,
  ProtectMessagesResult,
  ScanResult,
} from '../core/types.js';
import { PromptBlockedError } from '../core/errors.js';
import { protectMessages } from './messages.js';

/**
 * Configuration options for the OpenAI prompt protection middleware.
 */
export interface OpenAIProtectionOptions extends FirewallOptions {
  /** The firewall enforcement mode to apply ('redact' | 'block' | 'warn'). Defaults to 'redact'. */
  mode?: FirewallMode;
  /** Optional callback executed when a prompt is blocked due to security violations. */
  onBlock?: (result: ScanResult) => void;
  /** Optional callback executed when security findings are detected while running in 'warn' mode. */
  onWarn?: (result: ScanResult) => void;
}

/**
 * Protects an OpenAI chat messages array against PII leaks and prompt injection attacks.
 *
 * @param messages - Array of OpenAI chat messages ({ role, content }[]).
 * @param options - Configuration options controlling firewall mode, vaulting, and callbacks.
 * @returns Result payload with sanitized messages, findings, and restoration closure.
 */
export function protectOpenAIMessages(
  messages: ChatMessage[],
  options: OpenAIProtectionOptions & ProtectMessagesOptions = {}
): ProtectMessagesResult {
  return protectMessages(messages, options);
}

/**
 * Intercepts, inspects, and secures user prompt text or message arrays before transmission to OpenAI APIs.
 * Supports string prompts, OpenAI chat message arrays, and optional reversible vaulting.
 *
 * @param promptOrMessages - The raw string prompt or array of ChatMessages to evaluate.
 * @param options - Configuration options controlling firewall mode, vaulting, and callbacks.
 * @returns The sanitized prompt string or sanitized ChatMessage array.
 * @throws {PromptBlockedError} When mode is set to 'block' and security violations are detected.
 */
export function protectOpenAIPrompt(prompt: string, options?: OpenAIProtectionOptions): string;
export function protectOpenAIPrompt(
  messages: ChatMessage[],
  options?: OpenAIProtectionOptions & ProtectMessagesOptions
): ChatMessage[];
export function protectOpenAIPrompt(
  promptOrMessages: string | ChatMessage[],
  options: OpenAIProtectionOptions & ProtectMessagesOptions = {}
): string | ChatMessage[] {
  if (Array.isArray(promptOrMessages)) {
    const result = protectOpenAIMessages(promptOrMessages, options);
    return result.safeMessages;
  }

  const mode = options.mode ?? 'redact';
  const result = scan(promptOrMessages, mode, options);

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
