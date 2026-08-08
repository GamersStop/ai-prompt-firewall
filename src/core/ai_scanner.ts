/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Core scanning engine implementing stateless security evaluation, multi-tenant caching, and SIEM metadata extraction.
 * Author Name: Mayuresh Pandit
 */

import { PATTERNS } from './patterns.js';
import { FirewallMode, ScanResult, Finding, FirewallOptions } from './types.js';
import { validatePrompt, isValidFirewallMode, validateCustomPattern } from './validators.js';

export type { FirewallMode, ScanResult, Finding, FirewallOptions };

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
                matchedSnippetLength: match[0].length
            });

            // Prevent infinite loops on zero-length matches
            if (match.index === activeRegex.lastIndex) {
                activeRegex.lastIndex++;
            }
        }
    }

    // Handle 'redact' mode: scrub sensitive snippets using default or custom callback templates
    if (mode === 'redact' && findings.length > 0) {
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

    // Handle 'block' mode: instantly reject execution by returning an empty safe prompt payload
    if (mode === 'block' && findings.length > 0) {
        return {
            safePrompt: '',
            findings,
            blocked: true,
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

    public scan(prompt: string, mode: FirewallMode = 'redact', overrideOptions?: FirewallOptions): ScanResult {
        return scan(prompt, mode, {
            ...this.defaultOptions,
            ...overrideOptions,
            customPatterns: {
                ...this.compiledCustomPatterns,
                ...(overrideOptions?.customPatterns || {})
            }
        });
    }
}

/**
 * Factory helper function to instantiate a pre-compiled multi-tenant firewall context.
 */
export function createFirewall(options?: FirewallOptions): PromptFirewall {
    return new PromptFirewall(options);
}