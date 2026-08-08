/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Repository of optimized, high-performance regular expression patterns designed for real-time detection of API secrets, cryptographic tokens, PII, and conversational context leaks.
 * Author Name: Mayuresh Pandit
 */

export const PATTERNS = {
    // --- AI & CLOUD API KEYS ---
    // Matches OpenAI project and legacy keys while explicitly negative-looking ahead to prevent Anthropic false positives.
    OPENAI_KEY: /sk-(?!ant)[a-zA-Z0-9\-]{32,}/g,

    // Matches Anthropic Claude production and test API keys.
    ANTHROPIC_KEY: /sk-ant-api03-[a-zA-Z0-9\-_]{90,}/g,

    // Matches standard AWS Access Key IDs.
    AWS_KEY: /\bAKIA[0-9A-Z]{16}\b/g,

    // Matches 40-character base64-encoded AWS Secret Access Keys with strict boundary assertions to avoid false matches.
    AWS_SECRET: /\b(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])\b/g,

    // Matches Stripe live/test secret and restricted keys.
    STRIPE_KEY: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,

    // Matches GitHub Personal Access Tokens (classic and fine-grained).
    GITHUB_TOKEN: /\bghp_[a-zA-Z0-9]{36,}\b/g,

    // Matches Google Cloud API & Generative AI keys.
    GOOGLE_API_KEY: /\bAIza[0-9A-Za-z\-_]{35}\b/g,

    // Matches Slack bot, user, and app tokens.
    SLACK_TOKEN: /\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g,

    // --- CRYPTOGRAPHIC SECRETS ---
    // Matches PEM-encoded private key blocks (RSA, OpenSSH, Generic Private Keys) using non-greedy multiline matching.
    PRIVATE_KEY: /-----BEGIN\s+(?:RSA|OPENSSH|PRIVATE)\s+KEY-----[\s\S]+?-----END\s+(?:RSA|OPENSSH|PRIVATE)\s+KEY-----/g,

    // Matches HTTP Authorization Bearer tokens.
    BEARER_TOKEN: /Bearer\s+[a-zA-Z0-9-._~+/]+=*/g,

    // --- PII & CONTACT DATA ---
    // Matches standard RFC-compliant email address structures.
    EMAIL: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,

    // Matches international and domestic phone number formats with optional country/area codes.
    PHONE_NUMBER: /\b(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b/g,

    // Matches standard IPv4 addresses with precise 0-255 octet range validations to minimize false positives.
    IPV4_ADDRESS: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,

    // Matches conversational introductions where a user leaks their personal name context.
    USER_NAME_CONTEXT: /(?:my name is|i am|call me)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/gi
};