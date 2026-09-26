/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Primary public entry point and export aggregator for the package, exposing core scanning APIs, multi-tenant factories, typed errors, provider middleware wrappers, and TypeScript definitions.
 * Author Name: Mayuresh Pandit
 */

// Core scanning engine, multi-tenant factory class, and factory creator function
export { scan, anonymize, scanOutput, createFirewall, PromptFirewall } from './core/ai_scanner.js';

// Reversible tokenization vault engine and multi-turn session store
export { TokenVault, anonymizePrompt, escapeRegExp, DEFAULT_ENTITY_MAPPING } from './core/vault.js';
export {
  FirewallSession,
  createSession,
  SessionStore,
  createSessionStore,
} from './core/session.js';

// Heuristic prompt injection detection engine and rules catalog (OWASP LLM01)
export { detectPromptInjection } from './core/injection_scanner.js';
export { INJECTION_PATTERNS } from './core/injection_patterns.js';

// Built-in regular expression security pattern dictionary
export { PATTERNS } from './core/patterns.js';

// Structured exception classes for robust error handling
export {
  FirewallError,
  PromptBlockedError,
  PromptValidationError,
  PromptInjectionError,
} from './core/errors.js';

// Provider-specific and chat message security middleware wrappers
export { protectMessages, protectOutput } from './middleware/messages.js';
export {
  protectOpenAIPrompt,
  protectOpenAIMessages,
  type OpenAIProtectionOptions,
} from './middleware/openai.js';
export {
  protectAnthropicPrompt,
  protectAnthropicMessages,
  type AnthropicProtectionOptions,
} from './middleware/anthropic.js';
export {
  protectLangChainPrompt,
  protectLangChainMessages,
  protectLangChainValues,
  type LangChainProtectionOptions,
  type LangChainMessageLike,
} from './middleware/langchain.js';

// Public TypeScript type definitions and interface contracts
export type {
  FirewallMode,
  ScanResult,
  Finding,
  SeverityLevel,
  FirewallOptions,
  VaultOptions,
  VaultState,
  SessionOptions,
  SessionState,
  VaultTokenMap,
  AnonymizeResult,
  OutputScanOptions,
  OutputScanResult,
  InjectionCategory,
  InjectionFinding,
  InjectionPatternDefinition,
  InjectionScannerOptions,
  ChatMessage,
  ProtectMessagesOptions,
  ProtectMessagesResult,
} from './core/types.js';
