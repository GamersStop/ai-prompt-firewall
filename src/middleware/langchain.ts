/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Provider security middleware wrapper for LangChain prompt templates and execution chains, handling automated sanitization, zero-trust blocking, and audit warning hooks.
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
 * Generic shape representing LangChain BaseMessage instances (HumanMessage, AIMessage, SystemMessage).
 */
export interface LangChainMessageLike {
  content: string | unknown;
  _getType?: () => string;
  type?: string;
  role?: string;
  [key: string]: unknown;
}

/**
 * Configuration options for the LangChain prompt protection middleware.
 */
export interface LangChainProtectionOptions extends FirewallOptions {
  /** The firewall enforcement mode to apply ('redact' | 'block' | 'warn'). Defaults to 'redact'. */
  mode?: FirewallMode;
  /** Optional callback executed when a prompt is blocked due to security violations. */
  onBlock?: (result: ScanResult) => void;
  /** Optional callback executed when security findings are detected while running in 'warn' mode. */
  onWarn?: (result: ScanResult) => void;
}

/**
 * Normalizes a LangChain message into a standard ChatMessage structure.
 */
function normalizeLangChainMessage(msg: LangChainMessageLike): ChatMessage {
  let role: string = 'user';
  if (typeof msg._getType === 'function') {
    const type = msg._getType();
    role = type === 'human' ? 'user' : type === 'ai' ? 'assistant' : type;
  } else if (typeof msg.type === 'string') {
    role = msg.type === 'human' ? 'user' : msg.type === 'ai' ? 'assistant' : msg.type;
  } else if (typeof msg.role === 'string') {
    role = msg.role;
  }

  return {
    ...msg,
    role,
    content: typeof msg.content === 'string' ? msg.content : String(msg.content ?? ''),
  };
}

/**
 * Protects an array of LangChain messages (BaseMessage instances or message objects).
 *
 * @param messages - Array of LangChain message instances or objects.
 * @param options - Configuration options controlling firewall mode and vaulting.
 * @returns Result payload with sanitized messages, findings, and restoration closure.
 */
export function protectLangChainMessages<T extends LangChainMessageLike>(
  messages: T[],
  options: LangChainProtectionOptions & ProtectMessagesOptions = {}
): ProtectMessagesResult & { messages: T[] } {
  const normalizedChatMessages = messages.map((m) => normalizeLangChainMessage(m));
  const result = protectMessages(normalizedChatMessages, options);

  const restoredMessages = messages.map((originalMsg, i) => {
    const sanitizedContent = result.safeMessages[i]?.content ?? originalMsg.content;
    return {
      ...originalMsg,
      content: sanitizedContent,
    };
  });

  return {
    ...result,
    messages: restoredMessages,
  };
}

/**
 * Sanitizes template interpolation values dictionary before rendering into LangChain PromptTemplates.
 *
 * @param values - Key-value dictionary of prompt template variables.
 * @param options - Configuration options controlling firewall mode.
 * @returns Sanitized key-value dictionary.
 */
export function protectLangChainValues<T extends Record<string, unknown>>(
  values: T,
  options: LangChainProtectionOptions = {}
): T {
  const sanitized: Record<string, unknown> = { ...values };

  for (const [key, value] of Object.entries(values)) {
    if (typeof value === 'string') {
      sanitized[key] = protectLangChainPrompt(value, options);
    }
  }

  return sanitized as T;
}

/**
 * Intercepts, inspects, and secures user prompt text or message arrays before entering LangChain prompt templates or chains.
 *
 * @param promptOrMessages - The raw string prompt or array of messages to evaluate.
 * @param options - Configuration options controlling firewall mode and event callbacks.
 * @returns The sanitized prompt string or sanitized message array.
 * @throws {PromptBlockedError} When mode is set to 'block' and security violations are detected.
 */
export function protectLangChainPrompt(
  prompt: string,
  options?: LangChainProtectionOptions
): string;
export function protectLangChainPrompt<T extends LangChainMessageLike>(
  messages: T[],
  options?: LangChainProtectionOptions & ProtectMessagesOptions
): T[];
export function protectLangChainPrompt<T extends LangChainMessageLike>(
  promptOrMessages: string | T[],
  options: LangChainProtectionOptions & ProtectMessagesOptions = {}
): string | T[] {
  if (Array.isArray(promptOrMessages)) {
    const result = protectLangChainMessages(promptOrMessages, options);
    return result.messages;
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
