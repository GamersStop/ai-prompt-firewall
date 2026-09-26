/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Zero-dependency bidirectional tokenization engine for context-preserving anonymization and transparent restoration.
 * Author Name: Mayuresh Pandit
 */

import { Finding, VaultOptions, VaultState, VaultTokenMap } from './types.js';

/**
 * Escapes special regular expression characters within a string.
 */
export function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Default entity category aliases for synthetic token formatting.
 */
export const DEFAULT_ENTITY_MAPPING: Record<string, string> = {
  EMAIL: 'EMAIL',
  PHONE_NUMBER: 'PHONE',
  IPV4_ADDRESS: 'IP',
  USER_NAME_CONTEXT: 'PERSON',
  OPENAI_KEY: 'OPENAI_KEY',
  ANTHROPIC_KEY: 'ANTHROPIC_KEY',
  AWS_KEY: 'AWS_KEY',
  AWS_SECRET: 'AWS_SECRET',
  STRIPE_KEY: 'STRIPE_KEY',
  GITHUB_TOKEN: 'GITHUB_TOKEN',
  GOOGLE_API_KEY: 'GOOGLE_API_KEY',
  SLACK_TOKEN: 'SLACK_TOKEN',
  PRIVATE_KEY: 'PRIVATE_KEY',
  BEARER_TOKEN: 'BEARER_TOKEN',
  US_SSN: 'SSN',
  CREDIT_CARD: 'CARD',
  IBAN: 'IBAN',
};

/**
 * Bidirectional Tokenization Vault managing synthetic placeholder generation,
 * entity deduplication, and inverted string restoration.
 */
export class TokenVault {
  private originalToToken = new Map<string, VaultTokenMap>();
  private tokenToOriginal = new Map<string, VaultTokenMap>();
  private counters = new Map<string, number>();
  private options: VaultOptions;

  constructor(options?: VaultOptions, existingTokens?: VaultTokenMap[]) {
    this.options = options || {};

    if (existingTokens && Array.isArray(existingTokens)) {
      for (const item of existingTokens) {
        this.registerToken(item);
      }
    }
  }

  /**
   * Registers a pre-existing token into the internal maps and updates counters.
   */
  public registerToken(item: VaultTokenMap): void {
    this.originalToToken.set(item.original, item);
    this.tokenToOriginal.set(item.token.toUpperCase(), item);

    // Parse index counter from token (e.g. "<EMAIL_2>" -> type "EMAIL", count 2)
    const match = /<?\[?([A-Z_]+)_(\d+)\]?>?/i.exec(item.token);
    if (match && match[1] && match[2]) {
      const type = match[1].toUpperCase();
      const count = parseInt(match[2], 10);
      const current = this.counters.get(type) ?? 0;
      if (count > current) {
        this.counters.set(type, count);
      }
    }
  }

  /**
   * Retrieves an existing token for an identical sensitive value or generates a new deterministic token.
   */
  public getOrCreateToken(originalValue: string, rawType: string): VaultTokenMap {
    const existing = this.originalToToken.get(originalValue);
    if (existing) {
      return existing;
    }

    const entityName = (
      this.options.entityNameMapping?.[rawType] ??
      DEFAULT_ENTITY_MAPPING[rawType] ??
      rawType
    ).toUpperCase();

    const count = (this.counters.get(entityName) ?? 0) + 1;
    this.counters.set(entityName, count);

    const token =
      this.options.prefixFormat === 'bracket'
        ? `[${entityName}_${count}]`
        : `<${entityName}_${count}>`;

    const tokenMap: VaultTokenMap = {
      token,
      original: originalValue,
      type: rawType,
    };

    this.originalToToken.set(originalValue, tokenMap);
    this.tokenToOriginal.set(token.toUpperCase(), tokenMap);

    return tokenMap;
  }

  /**
   * Replaces sensitive findings in the prompt with synthetic tokens from end-to-beginning,
   * returning the safe prompt and a closure to restore LLM completions.
   */
  public anonymize(
    prompt: string,
    findings: Finding[]
  ): {
    safePrompt: string;
    tokenMap: VaultTokenMap[];
    restore: (llmResponse: string) => string;
  } {
    // Filter and sanitize valid findings with character coordinate bounds
    const validFindings = findings
      .filter(
        (f) =>
          typeof f.startIndex === 'number' &&
          typeof f.endIndex === 'number' &&
          f.startIndex >= 0 &&
          f.endIndex > f.startIndex
      )
      .map((f) => ({
        ...f,
        startIndex: Math.max(0, f.startIndex as number),
        endIndex: Math.min(prompt.length, f.endIndex as number),
      }))
      .filter((f) => f.endIndex > f.startIndex);

    // Sort findings by startIndex ascending to resolve overlaps
    validFindings.sort((a, b) => a.startIndex - b.startIndex);

    // Remove overlapping spans (retain the first non-overlapping span)
    const nonOverlapping: Array<
      Finding & {
        startIndex: number;
        endIndex: number;
        entityText: string;
        replaceStart: number;
        replaceEnd: number;
        tokenMap?: VaultTokenMap;
      }
    > = [];

    let lastEnd = -1;
    for (const finding of validFindings) {
      if (finding.startIndex >= lastEnd) {
        const rawSnippet = prompt.substring(finding.startIndex, finding.endIndex);
        let entityText = rawSnippet;
        let replaceStart = finding.startIndex;
        const replaceEnd = finding.endIndex;

        // Handle conversational introduction patterns to preserve grammar ("my name is Alice" -> "my name is <PERSON_1>")
        if (finding.type === 'USER_NAME_CONTEXT') {
          const nameMatch = /(?:my name is|i am|call me)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/i.exec(
            rawSnippet
          );
          if (nameMatch && nameMatch[1]) {
            entityText = nameMatch[1];
            const nameOffset = rawSnippet.lastIndexOf(entityText);
            replaceStart = finding.startIndex + nameOffset;
          }
        }

        nonOverlapping.push({
          ...finding,
          entityText,
          replaceStart,
          replaceEnd,
        });
        lastEnd = finding.endIndex;
      }
    }

    // Track tokens that were registered prior to this anonymization call
    const previouslyRegistered = new Set(this.tokenToOriginal.keys());

    // Step 1: Assign or retrieve tokens in forward reading order (left-to-right)
    for (const item of nonOverlapping) {
      item.tokenMap = this.getOrCreateToken(item.entityText, item.type);
    }

    // Step 2: Sort descending by replaceStart for in-place reverse substitution
    nonOverlapping.sort((a, b) => b.replaceStart - a.replaceStart);

    let workingPrompt = prompt;
    // Disarm any untrusted pre-existing synthetic tokens to prevent token spoofing / confused deputy attacks
    if (this.options.sanitizePreexistingTokens !== false) {
      workingPrompt = workingPrompt.replace(
        /(<|\[)([A-Z0-9_]+_\d+)(>|\])/g,
        (fullMatch, _open, inner) => {
          if (previouslyRegistered.has(fullMatch.toUpperCase())) {
            return fullMatch;
          }
          return `(${inner})`;
        }
      );
    }

    let safePrompt = workingPrompt;
    for (const item of nonOverlapping) {
      if (item.tokenMap) {
        safePrompt =
          safePrompt.substring(0, item.replaceStart) +
          item.tokenMap.token +
          safePrompt.substring(item.replaceEnd);
      }
    }

    const currentTokenList = this.getAllTokens();
    const restoreFn = (llmResponse: string): string => this.restore(llmResponse);

    return {
      safePrompt,
      tokenMap: currentTokenList,
      restore: restoreFn,
    };
  }

  /**
   * Transparently restores an LLM-generated string containing synthetic tokens
   * back to the original sensitive values.
   */
  public restore(llmResponse: string): string {
    if (!llmResponse || typeof llmResponse !== 'string') {
      return '';
    }

    const tokens = this.getAllTokens();
    if (tokens.length === 0) {
      return llmResponse;
    }

    // Sort tokens descending by token string length to prevent prefix collisions (<EMAIL_10> before <EMAIL_1>)
    const sortedTokens = [...tokens].sort((a, b) => b.token.length - a.token.length);

    // Build single combined regex alternation for O(N) performance
    const pattern = new RegExp(sortedTokens.map((t) => escapeRegExp(t.token)).join('|'), 'gi');

    return llmResponse.replace(pattern, (matchedToken) => {
      const found = this.tokenToOriginal.get(matchedToken.toUpperCase());
      return found ? found.original : matchedToken;
    });
  }

  /**
   * Returns all active token-to-original mappings.
   */
  public getAllTokens(): VaultTokenMap[] {
    return Array.from(this.originalToToken.values());
  }

  /**
   * Exports serializable state snapshot for distributed persistence or cache storage.
   */
  public exportState(): VaultState {
    const countersRecord: Record<string, number> = {};
    for (const [key, count] of this.counters.entries()) {
      countersRecord[key] = count;
    }
    return {
      tokens: this.getAllTokens(),
      counters: countersRecord,
    };
  }

  /**
   * Rehydrates a TokenVault from a serialized state snapshot.
   */
  public static fromState(state: VaultState, options?: VaultOptions): TokenVault {
    const vault = new TokenVault(options, state?.tokens);
    if (state?.counters && typeof state.counters === 'object') {
      for (const [key, count] of Object.entries(state.counters)) {
        if (typeof count === 'number') {
          vault.counters.set(key, count);
        }
      }
    }
    return vault;
  }

  /**
   * Clears all stored tokens and resets counters.
   */
  public clear(): void {
    this.originalToToken.clear();
    this.tokenToOriginal.clear();
    this.counters.clear();
  }
}

/**
 * Functional convenience helper to anonymize a prompt with an ephemeral vault instance.
 */
export function anonymizePrompt(
  prompt: string,
  findings: Finding[],
  options?: VaultOptions,
  existingTokens?: VaultTokenMap[]
): {
  safePrompt: string;
  tokenMap: VaultTokenMap[];
  restore: (llmResponse: string) => string;
} {
  const vault = new TokenVault(options, existingTokens);
  return vault.anonymize(prompt, findings);
}
