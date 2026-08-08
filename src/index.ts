/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Primary public entry point and export aggregator for the package, exposing core scanning APIs, multi-tenant factories, typed errors, provider middleware wrappers, and TypeScript definitions.
 * Author Name: Mayuresh Pandit
 */

// Core scanning engine, multi-tenant factory class, and factory creator function
export { scan, createFirewall, PromptFirewall } from './core/ai_scanner.js';

// Built-in regular expression security pattern dictionary
export { PATTERNS } from './core/patterns.js';

// Structured exception classes for robust error handling
export { FirewallError, PromptBlockedError, PromptValidationError } from './core/errors.js';

// Provider-specific security middleware wrappers
export { protectOpenAIPrompt } from './middleware/openai.js';
export { protectAnthropicPrompt } from './middleware/anthropic.js';
export { protectLangChainPrompt } from './middleware/langchain.js';

// Public TypeScript type definitions and interface contracts
export type {
    FirewallMode,
    ScanResult,
    Finding,
    SeverityLevel,
    FirewallOptions
} from './core/types.js';