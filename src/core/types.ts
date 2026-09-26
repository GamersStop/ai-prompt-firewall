/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Defines core TypeScript interfaces and type definitions (FirewallMode, SeverityLevel, Finding, ScanResult, FirewallOptions) across the scanning pipeline.
 * Author Name: Mayuresh Pandit
 */

/**
 * Supported execution modes for the AI Prompt Firewall engine.
 * - 'redact': Scrubs detected sensitive content using default or custom placeholders.
 * - 'block': Halts execution and rejects the request upon discovering a violation.
 * - 'warn': Passes the payload through unmutated while gathering telemetry findings for SIEM audit logs.
 */
export type FirewallMode = 'redact' | 'block' | 'warn';

/**
 * Severity classification levels for security findings and policy violations.
 */
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * Detailed metadata representing an individual security violation discovered within a prompt.
 */
export interface Finding {
  /** The identifier tag of the matched pattern (e.g., 'OPENAI_KEY', 'EMAIL'). */
  type: string;
  /** The severity tier assigned to the finding. */
  severity: SeverityLevel;
  /** The zero-based character index where the matched snippet begins within the prompt string. */
  startIndex?: number;
  /** The zero-based character index where the matched snippet ends within the prompt string. */
  endIndex?: number;
  /** The total character length of the matched sensitive snippet. */
  matchedSnippetLength?: number;
}

/**
 * The final output contract returned by the firewall scanner after evaluation.
 */
export interface ScanResult {
  /** The sanitized or original prompt text ready for downstream consumption. */
  safePrompt: string;
  /** An array of all security findings detected during the scan. */
  findings: Finding[];
  /** Boolean flag indicating whether the policy violation triggered a block action. */
  blocked: boolean;
}

/**
 * Configuration options for customizing scan behavior and rule extensions.
 */
export interface FirewallOptions {
  /** The firewall enforcement mode to apply ('redact' | 'block' | 'warn'). Defaults to 'redact'. */
  mode?: FirewallMode;
  /** A dictionary of custom regular expression patterns to evaluate alongside built-in rules. */
  customPatterns?: Record<string, RegExp>;

  /** Optional custom redactor callback function to dynamically format replacement tokens for matched snippets. */
  redactor?: (type: string, match: string) => string;
  /** Enables reversible tokenization mode using context-preserving synthetic entities (<TYPE_n>). */
  enableVault?: boolean;
  /** Enables heuristic prompt injection and jailbreak scanning (OWASP LLM01). */
  detectInjections?: boolean;
  /** Granular configuration options for prompt injection scanning. */
  injectionOptions?: {
    enabledCategories?: InjectionCategory[];
    confidenceThreshold?: number;
  };
  /** Configuration options for synthetic vault token formatting. */
  vaultOptions?: VaultOptions;
}

/**
 * Configuration options for synthetic vault token generation and formatting.
 */
export interface VaultOptions {
  /** Enclosing delimiter format for tokens. 'angle' produces <TYPE_1>, 'bracket' produces [TYPE_1]. Defaults to 'angle'. */
  prefixFormat?: 'angle' | 'bracket';
  /** Custom mapping of pattern types to placeholder entity names (e.g. { USER_NAME_CONTEXT: 'PERSON' }). */
  entityNameMapping?: Record<string, string>;
  /**
   * If true (default), neutralizes pre-existing synthetic tokens (e.g. <EMAIL_1>) found in untrusted user prompts
   * before anonymization to prevent token spoofing and confused deputy attacks. Defaults to true.
   */
  sanitizePreexistingTokens?: boolean;
}

/**
 * Configuration options for managing multi-turn conversational firewall sessions.
 */
export interface SessionOptions {
  /** Time-to-live for the session in milliseconds. Defaults to 30 minutes (1800000 ms). */
  ttlMs?: number;
  /** Maximum number of unique token mappings stored in memory before LRU eviction. Defaults to 1000. */
  maxEntries?: number;
  /** Optional tenant identifier to enforce strict tenant scope isolation. */
  tenantId?: string;
  /** Optional user identifier to enforce user scope isolation. */
  userId?: string;
}

/**
 * Serializable state snapshot of a TokenVault for distributed cache or persistent storage.
 */
export interface VaultState {
  tokens: VaultTokenMap[];
  counters: Record<string, number>;
}

/**
 * Serializable state snapshot of a FirewallSession for distributed microservices or serverless persistence.
 */
export interface SessionState {
  sessionId: string;
  tenantId?: string;
  userId?: string;
  createdAt: number;
  lastAccessedAt: number;
  vaultState: VaultState;
}

/**
 * Mapping contract representing a synthetic vault token paired with its original sensitive value.
 */
export interface VaultTokenMap {
  /** The synthetic placeholder token (e.g., "<EMAIL_1>"). */
  token: string;
  /** The original sensitive string value (e.g., "alice@acme.com"). */
  original: string;
  /** The entity type identifier (e.g., "EMAIL", "PHONE_NUMBER"). */
  type: string;
}

/**
 * Return contract for reversible tokenization, offering both safe payload and restoration capability.
 */
export interface AnonymizeResult extends ScanResult {
  /** Bidirectional array of synthetic tokens mapped to original sensitive values. */
  tokenMap: VaultTokenMap[];
  /** Restores an LLM-generated string containing synthetic tokens back to original sensitive values. */
  restore: (llmResponse: string) => string;
}

/**
 * High-level attack categorization for prompt injection and jailbreak attempts (OWASP LLM01).
 */
export type InjectionCategory =
  | 'INSTRUCTION_OVERRIDE'
  | 'PROMPT_LEAK'
  | 'ROLEPLAY_JAILBREAK'
  | 'DELIMITER_INJECTION'
  | 'OBFUSCATION_TRAP';

/**
 * Detailed metadata representing an adversarial prompt injection or jailbreak violation.
 */
export interface InjectionFinding extends Finding {
  /** The high-level attack classification under OWASP LLM01 heuristics. */
  category: InjectionCategory;
  /** Confidence score between 0.0 (low certainty) and 1.0 (exact pattern match). */
  confidence: number;
}

/**
 * Definition structure for a heuristic prompt injection detection rule.
 */
export interface InjectionPatternDefinition {
  /** Unique identifier for the rule. */
  id: string;
  /** High-level OWASP attack category. */
  category: InjectionCategory;
  /** Assigned severity tier. */
  severity: SeverityLevel;
  /** Confidence score assigned when this pattern matches (0.0 to 1.0). */
  confidence: number;
  /** Compiled regular expression pattern. */
  regex: RegExp;
}

/**
 * Options for customizing prompt injection scanner behavior.
 */
export interface InjectionScannerOptions {
  /** Specific attack categories to evaluate. Defaults to all categories. */
  enabledCategories?: InjectionCategory[];
  /** Minimum confidence threshold to report an injection finding (0.0 to 1.0). Defaults to 0.7. */
  confidenceThreshold?: number;
  /** Optional custom injection patterns to evaluate alongside built-in heuristics. */
  customPatterns?: InjectionPatternDefinition[];
}

/**
 * Standard chat message representation compatible with OpenAI, Anthropic, and LangChain message schemas.
 */
export interface ChatMessage {
  /** The role of the message author in the conversation thread. */
  role: 'system' | 'user' | 'assistant' | 'tool' | (string & {});
  /** The string content of the message. */
  content: string;
  [key: string]: unknown;
}

/**
 * Configuration options for inspecting and safeguarding multi-turn conversation message arrays.
 */
export interface ProtectMessagesOptions extends FirewallOptions {
  /** The firewall enforcement mode to apply ('redact' | 'block' | 'warn'). Defaults to 'redact'. */
  mode?: FirewallMode;
  /** Conversation message roles that should be scanned. Defaults to ['user', 'system']. */
  rolesToScan?: string[];
  /** Optional callback executed when messages are blocked due to security violations. */
  onBlock?: (result: ScanResult) => void;
  /** Optional callback executed when security findings are detected in warn mode. */
  onWarn?: (result: ScanResult) => void;
}

/**
 * Result payload returned from inspecting and protecting multi-turn message arrays.
 */
export interface ProtectMessagesResult {
  /** The sanitized array of chat messages safe for transmission to downstream LLM APIs. */
  safeMessages: ChatMessage[];
  /** Array of all security and prompt injection findings detected across inspected messages. */
  findings: Finding[];
  /** Boolean flag indicating whether policy violations triggered a block action. */
  blocked: boolean;
  /** Bidirectional mapping of synthetic placeholder tokens to original values across all messages. */
  tokenMap: VaultTokenMap[];
  /** Restores LLM response strings containing synthetic tokens back to original values. */
  restore: (llmResponse: string) => string;
}

/**
 * Options for scanning and sanitizing downstream LLM output completions.
 */
export interface OutputScanOptions extends FirewallOptions {
  /** Optional token map or restore closure used to restore synthetic tokens before scanning. */
  tokenMap?: VaultTokenMap[];
  /** If true and tokenMap is provided, restores tokens before scanning for residual raw secrets. Defaults to true. */
  restoreBeforeScan?: boolean;
}

/**
 * Result payload from scanning downstream LLM output completions.
 */
export interface OutputScanResult extends ScanResult {
  /** Indicates whether residual raw secrets or PII were leaked in the LLM generation. */
  hasLeaks: boolean;
}
