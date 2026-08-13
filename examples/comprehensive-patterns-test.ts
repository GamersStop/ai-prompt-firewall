/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Comprehensive integration example validating all built-in security patterns, runtime custom regex options, multi-tenant pre-compiled firewalls, and SIEM metadata offsets.
 * Author Name: Mayuresh Pandit
 */

import { scan, PATTERNS, createFirewall, PromptBlockedError, PromptValidationError } from '../dist/index.js';
import type { FirewallMode } from '../dist/index.js';

console.log('==================================================');
console.log('   AI PROMPT FIREWALL: COMPREHENSIVE PATTERN TEST ');
console.log('==================================================\n');

// 1. Generate test samples for every single pattern in PATTERNS (sanitized to prevent false-positive secret scanning blocks)
const samplePayloads: Record<keyof typeof PATTERNS, string> = {
    OPENAI_KEY: "Here is my secret key: sk-proj-TESTKEY00000000000000000000000000000000",
    ANTHROPIC_KEY: "Use this anthropic key: sk-ant-api03-TESTKEY000000000000000000000000000000000000000000000000000000000000000000000000-ZZZZZZ",
    AWS_KEY: "My AWS access key is AKIAIOSFODNN7EXAMPLE",
    AWS_SECRET: "And my secret is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    STRIPE_KEY: "Stripe live key: sk_live_TEST_KEY_NOT_REAL_1234567890",
    GITHUB_TOKEN: "GitHub token: ghp_TESTTOKEN0000000000000000000000000000",
    GOOGLE_API_KEY: "Google token: AIzaSy_TEST_KEY_NOT_REAL_1234567890abcdef",
    SLACK_TOKEN: "Slack token: xoxb-TEST-TOKEN-NOT-REAL-123456",
    PRIVATE_KEY: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
    BEARER_TOKEN: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    EMAIL: "Contact support at security@example.com for details.",
    PHONE_NUMBER: "Call us at +1-800-555-0199 or text 555-123-4567.",
    IPV4_ADDRESS: "Server internal IP is 192.168.1.100 for deployment.",
    USER_NAME_CONTEXT: "my name is John Doe and i am testing this system."
};

const modes: FirewallMode[] = ['redact', 'block', 'warn'];

// 2. Loop through every pattern and test across all firewall modes
for (const [patternName, sampleText] of Object.entries(samplePayloads)) {
    console.log(`--------------------------------------------------`);
    console.log(`[PATTERN TEST]: ${patternName}`);
    console.log(`Sample Input: "${sampleText}"`);
    console.log(`--------------------------------------------------`);

    for (const mode of modes) {
        try {
            const result = scan(sampleText, mode);
            console.log(`  Mode [${mode.toUpperCase()}]:`);
            console.log(`    - Blocked     : ${result.blocked}`);
            console.log(`    - Findings    : ${result.findings.map(f => f.type).join(', ')}`);
            console.log(`    - Safe Output : "${result.safePrompt}"`);
        } catch (err: unknown) {
            const error = err as Error;
            console.error(`  Mode [${mode.toUpperCase()}] Error:`, error.message);
        }
    }
    console.log();
}

// 3. Test Custom Pattern Integration across modes using options
console.log(`--------------------------------------------------`);
console.log(`[PATTERN TEST]: CUSTOM_PATTERN (RUNTIME OPTIONS)`);
console.log(`--------------------------------------------------`);

const customPatterns = {
    INTERNAL_SECRET_CODE: /SECRET-[A-Z]{3}-\d{4}/g
};

const customSample = "Confidential project uses code SECRET-XYZ-9876 for access.";
for (const mode of modes) {
    const result = scan(customSample, mode, { customPatterns });
    console.log(`  Mode [${mode.toUpperCase()}]:`);
    console.log(`    - Blocked     : ${result.blocked}`);
    console.log(`    - Findings    : ${result.findings.map(f => f.type).join(', ')}`);
    console.log(`    - Safe Output : "${result.safePrompt}"`);
}
console.log();

// 4. Test Multi-Tenant Instance (createFirewall / PromptFirewall)
console.log(`--------------------------------------------------`);
console.log(`[FEATURE TEST]: MULTI-TENANT PRE-COMPILED FIREWALL`);
console.log(`--------------------------------------------------`);
const tenantFirewall = createFirewall({
    customPatterns: {
        TENANT_BADGE: /BADGE-\d{5}/g
    }
});

const tenantResult = tenantFirewall.scan("Employee badge is BADGE-99887 access granted.", "redact");
console.log(`  - Multi-Tenant Blocked     : ${tenantResult.blocked}`);
console.log(`  - Multi-Tenant Findings    : ${tenantResult.findings.map(f => f.type).join(', ')}`);
console.log(`  - Multi-Tenant Safe Output : "${tenantResult.safePrompt}"`);
console.log();

// 5. Test SIEM Finding Offsets & Metadata
console.log(`--------------------------------------------------`);
console.log(`[FEATURE TEST]: SIEM FINDING METADATA & OFFSETS`);
console.log(`--------------------------------------------------`);
const offsetSample = "My AWS access key is AKIAIOSFODNN7EXAMPLE for deployment.";
const offsetResult = scan(offsetSample, "warn");
for (const finding of offsetResult.findings) {
    console.log(`  - Finding Type : ${finding.type}`);
    console.log(`  - Start Index  : ${finding.startIndex}`);
    console.log(`  - End Index    : ${finding.endIndex}`);
    console.log(`  - Length       : ${finding.matchedSnippetLength}`);
}
console.log();

// 6. Test Typed Error Hierarchy
console.log(`--------------------------------------------------`);
console.log(`[FEATURE TEST]: TYPED ERROR CLASSES`);
console.log(`--------------------------------------------------`);
try {
    scan("", "redact");
} catch (err: unknown) {
    if (err instanceof PromptValidationError) {
        console.log(`  - Caught Expected Validation Error : ${err.message}`);
    }
}

try {
    const blockCheck = scan("sk-proj-TESTKEY00000000000000000000000000000000", "block");
    if (blockCheck.blocked) {
        throw new PromptBlockedError(blockCheck);
    }
} catch (err: unknown) {
    if (err instanceof PromptBlockedError) {
        console.log(`  - Caught Expected Blocked Error    : ${err.message}`);
    }
}

console.log('\n==================================================');
console.log('   ALL PATTERN & FEATURE COMBINATIONS TESTED     ');
console.log('==================================================');