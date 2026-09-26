/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Defines custom typed error hierarchy (FirewallError, PromptBlockedError, PromptValidationError) for structured exception handling in backend pipelines.
 * Author Name: Mayuresh Pandit
 */

import { ScanResult, InjectionFinding } from './types.js';

/**
 * Base custom error class for all AI Prompt Firewall exceptions.
 * Extends the native Error class and properly sets the prototype for clean instanceof checks.
 */
export class FirewallError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FirewallError';
    // Ensure proper prototype chain maintenance for custom error classes in TypeScript/ES6
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a prompt violates security policies while the firewall is operating in 'block' mode.
 * Automatically extracts violation finding types and attaches the full ScanResult payload for debugging/auditing.
 */
export class PromptBlockedError extends FirewallError {
  constructor(public readonly result: ScanResult) {
    const findingTypes = result.findings.map((f) => f.type).join(', ');
    super(`[AI Prompt Firewall] Request blocked due to security violations: ${findingTypes}`);
    this.name = 'PromptBlockedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Helper getter to verify whether any detected violations represent prompt injection attacks.
   */
  public get hasInjectionViolations(): boolean {
    return this.result.findings.some((f) => 'category' in f);
  }
}

/**
 * Thrown when prompt input validation fails (e.g., empty strings, null values, or invalid non-string payloads).
 */
export class PromptValidationError extends FirewallError {
  constructor(message: string) {
    super(`[AI Prompt Firewall] Validation Error: ${message}`);
    this.name = 'PromptValidationError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a prompt contains adversarial prompt injection, jailbreak attempts, or unauthorized instruction escapes.
 */
export class PromptInjectionError extends FirewallError {
  constructor(
    public readonly findings: InjectionFinding[],
    message?: string
  ) {
    const categories = Array.from(new Set(findings.map((f) => f.category))).join(', ');
    super(message ?? `[AI Prompt Firewall] Prompt injection attack detected: ${categories}`);
    this.name = 'PromptInjectionError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
