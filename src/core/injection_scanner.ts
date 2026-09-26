/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Fast, zero-dependency heuristic prompt injection analyzer detecting adversarial inputs under OWASP LLM01.
 * Author Name: Mayuresh Pandit
 */

import { INJECTION_PATTERNS } from './injection_patterns.js';
import { InjectionFinding, InjectionScannerOptions } from './types.js';
import { validatePrompt } from './validators.js';

/**
 * Normalizes input text to defeat homoglyph and zero-width obfuscation bypasses.
 */
function normalizeForAnalysis(input: string): string {
  // Strip zero-width and invisible formatting characters
  const stripped = input.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '');
  // Apply Unicode NFKC normalization to standard forms
  return stripped.normalize('NFKC');
}

/**
 * Evaluates a prompt against OWASP LLM01 prompt injection and jailbreak heuristic rules.
 * Runs statelessly with zero external dependencies and sub-millisecond execution (<0.2ms).
 *
 * @param prompt - The input text payload to analyze.
 * @param options - Configuration options for category filtering and confidence thresholding.
 * @returns Array of detected injection findings.
 */
export function detectPromptInjection(
  prompt: string,
  options?: InjectionScannerOptions
): InjectionFinding[] {
  const cleanPrompt = validatePrompt(prompt);
  const normalized = normalizeForAnalysis(cleanPrompt);

  const confidenceThreshold = options?.confidenceThreshold ?? 0.7;
  const enabledCategories = options?.enabledCategories;
  const customPatterns = options?.customPatterns || [];

  const allPatterns = [...INJECTION_PATTERNS, ...customPatterns];
  const findings: InjectionFinding[] = [];

  for (const pattern of allPatterns) {
    // Check if category is enabled
    if (enabledCategories && !enabledCategories.includes(pattern.category)) {
      continue;
    }

    // Skip patterns below minimum confidence threshold
    if (pattern.confidence < confidenceThreshold) {
      continue;
    }

    const regex = new RegExp(
      pattern.regex.source,
      pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g'
    );
    regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = regex.exec(normalized)) !== null) {
      findings.push({
        type: pattern.id,
        category: pattern.category,
        severity: pattern.severity,
        confidence: pattern.confidence,
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        matchedSnippetLength: match[0].length,
      });

      // Avoid infinite loops on zero-length matches
      if (match.index === regex.lastIndex) {
        regex.lastIndex++;
      }
    }
  }

  return findings;
}
