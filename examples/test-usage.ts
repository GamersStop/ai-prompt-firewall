import { scan, addCustomPattern, PATTERNS } from '../dist/index.js';
import type { FirewallMode } from '../dist/index.js';

console.log('=== RUNNING AI PROMPT FIREWALL COMPREHENSIVE TESTS ===\n');

// --- TEST 1: Default 'redact' mode with built-in patterns ---
const unsafePrompt = "Hello, my OpenAI key is sk-proj-1234567890abcdef1234567890abcdef and my email is test@example.com.";
const redactResult = scan(unsafePrompt, 'redact');
console.log('Test 1 [Redact Mode]:');
console.log('  Safe Prompt:', redactResult.safePrompt);
console.log('  Findings Count:', redactResult.findings.length);
console.log('  Blocked:', redactResult.blocked);
console.log('-------------------------------------------');

// --- TEST 2: 'block' mode ---
const blockResult = scan("Contact me at admin@company.com", 'block');
console.log('Test 2 [Block Mode]:');
console.log('  Blocked:', blockResult.blocked);
console.log('  Safe Prompt (should be empty):', JSON.stringify(blockResult.safePrompt));
console.log('  Findings:', blockResult.findings);
console.log('-------------------------------------------');

// --- TEST 3: 'warn' mode (should return clean prompt even if findings exist) ---
const warnResult = scan("My AWS key is AKIA1234567890ABCDEF", 'warn');
console.log('Test 3 [Warn Mode]:');
console.log('  Safe Prompt (unchanged):', warnResult.safePrompt);
console.log('  Findings Detected:', warnResult.findings);
console.log('  Blocked:', warnResult.blocked);
console.log('-------------------------------------------');

// --- TEST 4: Custom Pattern Registration & Validation ---
try {
    // Add a valid custom pattern
    addCustomPattern('INTERNAL_PROJECT', /PROJ-[0-9]{3}/g);
    const customResult = scan("We are working on PROJ-404 secret backend.", 'redact');
    console.log('Test 4 [Custom Pattern Success]:');
    console.log('  Safe Prompt:', customResult.safePrompt);
    console.log('  Findings:', customResult.findings);
} catch (error) {
    console.error('Test 4 Failed:', error);
}
console.log('-------------------------------------------');

// --- TEST 5: Error Handling (Invalid Inputs) ---
console.log('Test 5 [Input Validation Errors]:');
try {
    // Empty prompt check
    scan("", 'redact');
} catch (error: any) {
    console.log('  Caught empty prompt error successfully:', error.message);
}

try {
    // Invalid type check
    scan(123 as any, 'redact');
} catch (error: any) {
    console.log('  Caught invalid type error successfully:', error.message);
}

try {
    // Invalid firewall mode check
    scan("Clean text", "invalid_mode" as FirewallMode);
} catch (error: any) {
    console.log('  Caught invalid mode error successfully:', error.message);
}

try {
    // Invalid custom pattern check (not a RegExp)
    addCustomPattern('BAD_PATTERN', "not-a-regex" as any);
} catch (error: any) {
    console.log('  Caught invalid custom pattern error successfully:', error.message);
}

console.log('\n=== ALL TESTS COMPLETED SUCCESSFULLY ===');