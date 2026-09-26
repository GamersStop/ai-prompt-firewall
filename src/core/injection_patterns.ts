/**
 * Project Name: ai-prompt-firewall
 * File Purpose: High-precision, ReDoS-safe heuristic pattern catalog for detecting OWASP LLM01 Prompt Injections & Jailbreaks.
 * Author Name: Mayuresh Pandit
 */

import { InjectionPatternDefinition } from './types.js';

export const INJECTION_PATTERNS: InjectionPatternDefinition[] = [
  // =========================================================================
  // 1. INSTRUCTION OVERRIDE & CONTEXT RESET
  // =========================================================================
  {
    id: 'OVERRIDE_IGNORE_PREVIOUS',
    category: 'INSTRUCTION_OVERRIDE',
    severity: 'CRITICAL',
    confidence: 0.95,
    regex:
      /\b(?:ignore|disregard|skip|bypass)\s+(?:all\s+)?(?:previous|prior|above|existing|system|developer)\s+(?:instructions?|directives?|rules?|constraints?|prompts?)\b/gi,
  },
  {
    id: 'OVERRIDE_FORGET_CONSTRAINTS',
    category: 'INSTRUCTION_OVERRIDE',
    severity: 'CRITICAL',
    confidence: 0.95,
    regex:
      /\b(?:forget|clear|reset)\s+(?:all\s+)?(?:system|developer|prior|previous|existing)\s+(?:instructions?|directives?|constraints?|context|rules?)\b/gi,
  },
  {
    id: 'OVERRIDE_PERSONA_SWITCH',
    category: 'INSTRUCTION_OVERRIDE',
    severity: 'HIGH',
    confidence: 0.85,
    regex:
      /\b(?:from now on|new instructions?|new persona starts now)\b[\s\S]{0,60}?\b(?:you (?:are|will)|act as|behave as)\b/gi,
  },
  {
    id: 'OVERRIDE_BYPASS_SAFETY',
    category: 'INSTRUCTION_OVERRIDE',
    severity: 'CRITICAL',
    confidence: 0.95,
    regex:
      /\b(?:override|bypass|disable)\s+(?:all\s+)?(?:safety|security|system|content)\s+(?:rules?|filters?|guidelines?|protocols?|safeguards?)\b/gi,
  },
  {
    id: 'OVERRIDE_DO_NOT_FOLLOW',
    category: 'INSTRUCTION_OVERRIDE',
    severity: 'CRITICAL',
    confidence: 0.9,
    regex:
      /\bdo not follow (?:any\s+)?(?:prior|previous|above|system)\s+(?:instructions?|directives?|rules?)\b/gi,
  },

  // =========================================================================
  // 2. SYSTEM PROMPT & GUARDRAIL EXTRACTION (PROMPT LEAK)
  // =========================================================================
  {
    id: 'PROMPT_LEAK_VERBATIM',
    category: 'PROMPT_LEAK',
    severity: 'CRITICAL',
    confidence: 0.95,
    regex:
      /\b(?:repeat|print|output|display|show|reveal|echo)\s+(?:your\s+)?(?:system|initial|base|developer|original)?\s*(?:prompt|instructions?|directives?|rules?)\s+(?:verbatim|word for word|in full|completely)\b/gi,
  },
  {
    id: 'PROMPT_LEAK_OUTPUT_ABOVE',
    category: 'PROMPT_LEAK',
    severity: 'CRITICAL',
    confidence: 0.95,
    regex:
      /\b(?:output|print|show|repeat)\s+(?:everything|all text)\s+above\s+(?:this line|the prompt|here)\b/gi,
  },
  {
    id: 'PROMPT_LEAK_INITIALIZATION',
    category: 'PROMPT_LEAK',
    severity: 'HIGH',
    confidence: 0.9,
    regex:
      /\b(?:what (?:are|were)|print|show)\s+(?:your\s+)?(?:exact\s+)?(?:system|initialization|developer|initial)\s+(?:instructions?|prompt|message)\b/gi,
  },
  {
    id: 'PROMPT_LEAK_SYSTEM_PROMPT_DIRECT',
    category: 'PROMPT_LEAK',
    severity: 'HIGH',
    confidence: 0.9,
    regex:
      /\b(?:tell me|give me|reveal)\s+(?:your\s+)?(?:complete\s+)?(?:system prompt|secret instructions?)\b/gi,
  },

  // =========================================================================
  // 3. ROLEPLAY JAILBREAKS & PERSONA HIJACKING
  // =========================================================================
  {
    id: 'JAILBREAK_DAN_MODE',
    category: 'ROLEPLAY_JAILBREAK',
    severity: 'CRITICAL',
    confidence: 1.0,
    regex: /\b(?:DAN\s+mode|do anything now)\s+(?:activated|enabled|is on|starts now)\b/gi,
  },
  {
    id: 'JAILBREAK_UNFILTERED_ASSISTANT',
    category: 'ROLEPLAY_JAILBREAK',
    severity: 'CRITICAL',
    confidence: 0.95,
    regex:
      /\b(?:you are|act as)\s+(?:an?|the)?\s*(?:always compliant assistant|unfiltered ai|jailbroken ai|evil confidant|chaos gpt)\b/gi,
  },
  {
    id: 'JAILBREAK_NO_ETHICS',
    category: 'ROLEPLAY_JAILBREAK',
    severity: 'CRITICAL',
    confidence: 0.95,
    regex:
      /\byou (?:have|possess|operate with)\s+no\s+(?:ethics|filters|moral compass|limitations|restrictions|rules|boundaries)\b/gi,
  },
  {
    id: 'JAILBREAK_DEVELOPER_MODE',
    category: 'ROLEPLAY_JAILBREAK',
    severity: 'HIGH',
    confidence: 0.9,
    regex: /\b(?:in )?developer mode\s+(?:is\s+)?(?:enabled|activated|on|output)\b/gi,
  },
  {
    id: 'JAILBREAK_HYPOTHETICAL_UNFILTERED',
    category: 'ROLEPLAY_JAILBREAK',
    severity: 'HIGH',
    confidence: 0.85,
    regex:
      /\b(?:hypothetically|for a fictional story|in an alternate universe),\s*(?:you are|act as)\s+(?:an?\s+)?(?:unfiltered|unrestricted|amoral)\b/gi,
  },

  // =========================================================================
  // 4. DELIMITER & TAG INJECTION EXPLOITS
  // =========================================================================
  {
    id: 'DELIMITER_SYSTEM_CLOSE_TAG',
    category: 'DELIMITER_INJECTION',
    severity: 'CRITICAL',
    confidence: 1.0,
    regex: /<\/(?:system|SYS|prompt|instructions?|context)>/gi,
  },
  {
    id: 'DELIMITER_SPECIAL_TOKENS',
    category: 'DELIMITER_INJECTION',
    severity: 'CRITICAL',
    confidence: 1.0,
    regex: /(?:<<\/?SYS>>|<\|(?:im_start|im_end|endoftext)\|)/gi,
  },
  {
    id: 'DELIMITER_BRACKETED_DIRECTIVES',
    category: 'DELIMITER_INJECTION',
    severity: 'CRITICAL',
    confidence: 0.95,
    regex: /\[\/?(?:SYSTEM|SYS|INST|SYSTEM INSTRUCTION)\]/gi,
  },
  {
    id: 'DELIMITER_PROMPT_COMMENT',
    category: 'DELIMITER_INJECTION',
    severity: 'CRITICAL',
    confidence: 1.0,
    regex: /<!--\s*(?:end of prompt|system prompt|instructions)\s*-->/gi,
  },
  {
    id: 'DELIMITER_MARKDOWN_HEADER_INJECTION',
    category: 'DELIMITER_INJECTION',
    severity: 'HIGH',
    confidence: 0.9,
    regex: /###\s*(?:System|Instruction|Assistant|Human):/gi,
  },

  // =========================================================================
  // 5. OBFUSCATION & ENCODING TRAPS
  // =========================================================================
  {
    id: 'OBFUSCATION_BASE64_EXEC',
    category: 'OBFUSCATION_TRAP',
    severity: 'HIGH',
    confidence: 0.9,
    regex:
      /\b(?:decode|execute|run|eval)\s+(?:the following\s+)?(?:base64|b64)(?:\s*(?:encoded)?\s*(?:string|payload|command|prompt))?:\s*[A-Za-z0-9+/]{20,}={0,2}\b/gi,
  },
  {
    id: 'OBFUSCATION_HEX_PAYLOAD',
    category: 'OBFUSCATION_TRAP',
    severity: 'MEDIUM',
    confidence: 0.85,
    regex: /(?:\\x[0-9a-fA-F]{2}){4,}/g,
  },
  {
    id: 'OBFUSCATION_CIPHER_DIRECTIVE',
    category: 'OBFUSCATION_TRAP',
    severity: 'MEDIUM',
    confidence: 0.8,
    regex: /\b(?:rot13|caesar cipher|decode hex)\s*:\s*[a-zA-Z0-9+/=\s]{10,}\b/gi,
  },
];
