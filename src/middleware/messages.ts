/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Provider security middleware for inspecting, redacting, and vaulting multi-turn chat message arrays.
 * Author Name: Mayuresh Pandit
 */

import { scan, scanOutput } from '../core/ai_scanner.js';
import { PromptBlockedError, PromptValidationError } from '../core/errors.js';
import { detectPromptInjection } from '../core/injection_scanner.js';
import {
  ChatMessage,
  Finding,
  ProtectMessagesOptions,
  ProtectMessagesResult,
  ScanResult,
  OutputScanOptions,
  OutputScanResult,
} from '../core/types.js';
import { TokenVault } from '../core/vault.js';

/**
 * Inspects, sanitizes, and secures multi-turn chat message arrays ({ role, content }[]).
 * Supports standard redaction, zero-trust blocking, and reversible tokenization across all turns.
 *
 * @param messages - Array of conversation messages in OpenAI/Anthropic format.
 * @param options - Configuration options controlling firewall mode, roles to scan, and vaulting.
 * @returns Result payload with sanitized messages, detected findings, and restoration closure.
 * @throws {PromptValidationError} When messages payload is not an array.
 * @throws {PromptBlockedError} When mode is 'block' and security violations or attacks are detected.
 */
export function protectMessages(
  messages: ChatMessage[],
  options: ProtectMessagesOptions = {}
): ProtectMessagesResult {
  if (!Array.isArray(messages)) {
    throw new PromptValidationError(
      `Invalid messages payload: Expected an array of chat messages, received ${typeof messages}.`
    );
  }

  const mode = options.mode ?? 'redact';
  const rolesToScan = options.rolesToScan ?? ['user', 'system'];
  const enableVault = options.enableVault ?? false;

  const allFindings: Finding[] = [];
  let isBlocked = false;

  const vault = enableVault ? new TokenVault(options.vaultOptions) : null;
  const safeMessages: ChatMessage[] = [];

  for (const message of messages) {
    if (!message || typeof message !== 'object') {
      safeMessages.push(message);
      continue;
    }

    // Only inspect specified conversation roles
    if (!rolesToScan.includes(message.role) || typeof message.content !== 'string') {
      safeMessages.push({ ...message });
      continue;
    }

    const messageFindings: Finding[] = [];

    // 1. Run prompt injection heuristics if enabled
    if (options.detectInjections) {
      const injections = detectPromptInjection(message.content, options.injectionOptions);
      if (injections.length > 0) {
        messageFindings.push(...injections);
        allFindings.push(...injections);

        if (mode === 'block') {
          isBlocked = true;
        }
      }
    }

    // 2. Run secret and PII scanning
    if (enableVault && vault) {
      // In vault mode, scan for coordinates without static redaction
      const scanRes = scan(message.content, 'warn', options);
      for (const f of scanRes.findings) {
        messageFindings.push(f);
        allFindings.push(f);
      }

      if (mode === 'block' && messageFindings.length > 0) {
        isBlocked = true;
      }

      const { safePrompt } = vault.anonymize(message.content, messageFindings);
      safeMessages.push({ ...message, content: safePrompt });
    } else {
      // Standard scanning pipeline (redact, block, or warn)
      const scanRes = scan(message.content, mode, options);
      for (const f of scanRes.findings) {
        allFindings.push(f);
      }

      if (scanRes.blocked) {
        isBlocked = true;
      }

      safeMessages.push({ ...message, content: scanRes.safePrompt });
    }
  }

  // Handle blocking violations under block mode
  if (isBlocked) {
    const blockedResult: ScanResult = {
      safePrompt: '',
      findings: allFindings,
      blocked: true,
    };

    if (options.onBlock) {
      options.onBlock(blockedResult);
    }

    throw new PromptBlockedError(blockedResult);
  }

  // Handle SIEM warning telemetry
  if (mode === 'warn' && allFindings.length > 0 && options.onWarn) {
    options.onWarn({
      safePrompt: '',
      findings: allFindings,
      blocked: false,
    });
  }

  const tokenMap = vault ? vault.getAllTokens() : [];
  const restore = vault
    ? (llmResponse: string) => vault.restore(llmResponse)
    : (llmResponse: string) => llmResponse;

  return {
    safeMessages,
    findings: allFindings,
    blocked: false,
    tokenMap,
    restore,
  };
}

/**
 * Post-LLM output middleware securing and sanitizing completions before returning to end-users.
 */
export function protectOutput(llmResponse: string, options?: OutputScanOptions): OutputScanResult {
  const mode = options?.mode ?? 'redact';
  return scanOutput(llmResponse, mode, options);
}
