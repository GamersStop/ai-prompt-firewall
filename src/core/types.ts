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
    /** A dictionary of custom regular expression patterns to evaluate alongside built-in rules. */
    customPatterns?: Record<string, RegExp>;
    /** Optional custom redactor callback function to dynamically format replacement tokens for matched snippets. */
    redactor?: (type: string, match: string) => string;
}