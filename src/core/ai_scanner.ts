/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Core scanning engine implementing stateless security evaluation, multi-tenant caching, and SIEM metadata extraction.
 * Author Name: Mayuresh Pandit
 */

import { PATTERNS } from './patterns.js';
import {
  FirewallMode,
  ScanResult,
  Finding,
  FirewallOptions,
  AnonymizeResult,
  SessionOptions,
  VaultOptions,
  OutputScanOptions,
  OutputScanResult,
} from './types.js';
import { validatePrompt, isValidFirewallMode, validateCustomPattern } from './validators.js';
import { detectPromptInjection } from './injection_scanner.js';
import { anonymizePrompt, TokenVault } from './vault.js';
import { FirewallSession, createSession } from './session.js';

export type {
  FirewallMode,
  ScanResult,
  Finding,
  FirewallOptions,
  AnonymizeResult,
  OutputScanOptions,
  OutputScanResult,
};

/**
 * Scans a prompt string for security violations, secrets, or PII.
 * Operates statelessly with zero side-effects to ensure high safety in concurrent backend environments.
 */
export function scan(
  prompt: string,
  mode: FirewallMode = 'redact',
  options?: FirewallOptions
): ScanResult {
  const cleanPrompt = validatePrompt(prompt);

  if (!isValidFirewallMode(mode)) {
    throw new TypeError(`Invalid firewall mode: "${mode}". Expected 'redact', 'block', or 'warn'.`);
  }

  let safePrompt = cleanPrompt;
  const findings: Finding[] = [];

  // 1. Run heuristic prompt injection detection first if enabled (OWASP LLM01)
  if (options?.detectInjections) {
    const injectionFindings = detectPromptInjection(cleanPrompt, options.injectionOptions);
    if (injectionFindings.length > 0) {
      findings.push(...injectionFindings);

      // In block mode, immediately halt and reject the request upon detecting injection attacks
      if (mode === 'block') {
        return {
          safePrompt: '',
          findings,
          blocked: true,
        };
      }
    }
  }

  // Safely validate and compile any per-scan custom patterns supplied via options
  const customPatterns = options?.customPatterns || {};
  for (const [name, regex] of Object.entries(customPatterns)) {
    validateCustomPattern(name, regex);
  }

  const activePatterns = { ...PATTERNS, ...customPatterns };

  // Execute pattern scans using regex execution loops to extract exact character coordinates for SIEM audit logs
  for (const [key, regex] of Object.entries(activePatterns) as [string, RegExp][]) {
    const activeRegex = new RegExp(
      regex.source,
      regex.flags.includes('g') ? regex.flags : regex.flags + 'g'
    );
    activeRegex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = activeRegex.exec(cleanPrompt)) !== null) {
      findings.push({
        type: key,
        severity: 'CRITICAL',
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        matchedSnippetLength: match[0].length,
      });

      // Prevent infinite loops on zero-length matches
      if (match.index === activeRegex.lastIndex) {
        activeRegex.lastIndex++;
      }
    }
  }

  // Handle 'block' mode: instantly reject execution by returning an empty safe prompt payload
  if (mode === 'block' && findings.length > 0) {
    return {
      safePrompt: '',
      findings,
      blocked: true,
    };
  }

  // Handle 'redact' mode: scrub sensitive snippets using vault tokens or default/custom callback templates
  if (mode === 'redact' && findings.length > 0) {
    if (options?.enableVault) {
      const vaultResult = anonymizePrompt(cleanPrompt, findings, options.vaultOptions);
      return {
        safePrompt: vaultResult.safePrompt,
        findings,
        blocked: false,
      };
    }

    for (const [key, regex] of Object.entries(activePatterns) as [string, RegExp][]) {
      const activeRegex = new RegExp(
        regex.source,
        regex.flags.includes('g') ? regex.flags : regex.flags + 'g'
      );

      safePrompt = safePrompt.replace(activeRegex, (matchedText) => {
        if (options?.redactor) {
          return options.redactor(key, matchedText);
        }
        return `[${key}_REDACTED]`;
      });
    }

    return {
      safePrompt,
      findings,
      blocked: false,
    };
  }

  // Default return ('warn' mode or clean prompt): pass through unmutated while retaining findings for monitoring
  return {
    safePrompt: cleanPrompt,
    findings,
    blocked: false,
  };
}

/**
 * Scans a prompt string and performs reversible tokenization with synthetic placeholders (<TYPE_n>).
 * Also performs prompt injection defense if detectInjections is enabled.
 */
export function anonymize(prompt: string, options?: FirewallOptions): AnonymizeResult {
  const cleanPrompt = validatePrompt(prompt);
  const activeOptions: FirewallOptions = {
    ...options,
    enableVault: true,
  };

  const findings: Finding[] = [];

  // Check for prompt injections if enabled
  if (activeOptions.detectInjections) {
    const injectionFindings = detectPromptInjection(cleanPrompt, activeOptions.injectionOptions);
    if (injectionFindings.length > 0) {
      findings.push(...injectionFindings);
    }
  }

  // Scan for secrets and PII (in warn mode so we get all findings without destroying coordinates)
  const scanResult = scan(cleanPrompt, 'warn', {
    ...activeOptions,
    detectInjections: false,
  });

  for (const f of scanResult.findings) {
    if (
      !findings.some(
        (existing) =>
          existing.startIndex === f.startIndex &&
          existing.endIndex === f.endIndex &&
          existing.type === f.type
      )
    ) {
      findings.push(f);
    }
  }

  // If prompt injection was found and detectInjections was enabled, block execution unless explicitly in warn mode
  const isAttackBlocked = activeOptions.detectInjections && findings.some((f) => 'category' in f);

  if (isAttackBlocked) {
    return {
      safePrompt: '',
      findings,
      blocked: true,
      tokenMap: [],
      restore: (llmResponse: string) => llmResponse,
    };
  }

  // Execute reversible tokenization
  const vaultResult = anonymizePrompt(cleanPrompt, findings, activeOptions.vaultOptions);

  return {
    safePrompt: vaultResult.safePrompt,
    findings,
    blocked: false,
    tokenMap: vaultResult.tokenMap,
    restore: vaultResult.restore,
  };
}

/**
 * Scans, validates, and secures output completions generated by downstream LLMs before delivering to clients.
 * Optionally restores synthetic tokens first, and detects residual leaked secrets (e.g. model training memorization or tool leaks).
 */
export function scanOutput(
  output: string,
  mode: FirewallMode = 'redact',
  options?: OutputScanOptions
): OutputScanResult {
  const cleanOutput = validatePrompt(output);

  // 1. Scan the output for any raw secrets or PII leaked by the model
  const scanResult = scan(cleanOutput, mode, options);

  // 2. If tokenMap is provided and restoreBeforeScan is not disabled, restore synthetic tokens in the safe output
  let finalSafePrompt = scanResult.safePrompt;
  if (
    !scanResult.blocked &&
    options?.tokenMap &&
    options.tokenMap.length > 0 &&
    options.restoreBeforeScan !== false
  ) {
    const vault = new TokenVault(options.vaultOptions, options.tokenMap);
    finalSafePrompt = vault.restore(finalSafePrompt);
  }

  return {
    safePrompt: finalSafePrompt,
    findings: scanResult.findings,
    blocked: scanResult.blocked,
    hasLeaks: scanResult.findings.length > 0,
  };
}

/**
 * High-performance instance wrapper for multi-tenant applications
 * that pre-compiles custom rules once upon tenant configuration load to eliminate regex compilation overhead.
 */
export class PromptFirewall {
  private compiledCustomPatterns: Record<string, RegExp>;
  private defaultOptions?: FirewallOptions;

  constructor(defaultOptions?: FirewallOptions) {
    this.defaultOptions = defaultOptions;
    this.compiledCustomPatterns = {};

    if (defaultOptions?.customPatterns) {
      for (const [name, regex] of Object.entries(defaultOptions.customPatterns)) {
        validateCustomPattern(name, regex);
        this.compiledCustomPatterns[name] = new RegExp(
          regex.source,
          regex.flags.includes('g') ? regex.flags : regex.flags + 'g'
        );
      }
    }
  }

  public scan(
    prompt: string,
    mode: FirewallMode = 'redact',
    overrideOptions?: FirewallOptions
  ): ScanResult {
    return scan(prompt, mode, {
      ...this.defaultOptions,
      ...overrideOptions,
      customPatterns: {
        ...this.compiledCustomPatterns,
        ...(overrideOptions?.customPatterns || {}),
      },
    });
  }

  public anonymize(prompt: string, overrideOptions?: FirewallOptions): AnonymizeResult {
    return anonymize(prompt, {
      ...this.defaultOptions,
      ...overrideOptions,
      customPatterns: {
        ...this.compiledCustomPatterns,
        ...(overrideOptions?.customPatterns || {}),
      },
    });
  }

  public scanOutput(
    output: string,
    mode: FirewallMode = 'redact',
    overrideOptions?: OutputScanOptions
  ): OutputScanResult {
    return scanOutput(output, mode, {
      ...this.defaultOptions,
      ...overrideOptions,
      customPatterns: {
        ...this.compiledCustomPatterns,
        ...(overrideOptions?.customPatterns || {}),
      },
    });
  }

  public createSession(
    sessionOptions?: SessionOptions & {
      vaultOptions?: VaultOptions;
      firewallOptions?: FirewallOptions;
    }
  ): FirewallSession {
    const combinedFirewallOptions: FirewallOptions = {
      ...this.defaultOptions,
      ...sessionOptions?.firewallOptions,
      customPatterns: {
        ...this.compiledCustomPatterns,
        ...(sessionOptions?.firewallOptions?.customPatterns || {}),
      },
    };

    return createSession(
      {
        ...sessionOptions,
        firewallOptions: combinedFirewallOptions,
      },
      (p, m, o) => this.scan(p, m, o)
    );
  }
}

/**
 * Factory helper function to instantiate a pre-compiled multi-tenant firewall context.
 */
export function createFirewall(options?: FirewallOptions): PromptFirewall {
  return new PromptFirewall(options);
}
