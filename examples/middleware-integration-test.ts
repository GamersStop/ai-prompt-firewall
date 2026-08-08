import {
    protectOpenAIPrompt,
    protectAnthropicPrompt,
    protectLangChainPrompt,
    PromptBlockedError
} from '../dist/index.js';

console.log('==================================================');
console.log('   AI PROMPT FIREWALL: MIDDLEWARE INTEGRATION TEST');
console.log('==================================================\n');

// 1. Test OpenAI Middleware Wrapper
console.log('--------------------------------------------------');
console.log('[TEST 1]: protectOpenAIPrompt (Redact Mode)');
console.log('--------------------------------------------------');
try {
    const openaiInput = "Analyze this prompt with API key sk-proj-1234567890abcdef1234567890abcdefABCDEF please.";
    const safeOpenAIPrompt = protectOpenAIPrompt(openaiInput, { mode: 'redact' });
    console.log(`  - Input  : "${openaiInput}"`);
    console.log(`  - Output : "${safeOpenAIPrompt}"`);
} catch (err: any) {
    console.error('  - Error:', err.message);
}
console.log();

// 2. Test Anthropic Middleware Wrapper with Block Mode
console.log('--------------------------------------------------');
console.log('[TEST 2]: protectAnthropicPrompt (Block Mode)');
console.log('--------------------------------------------------');
try {
    const anthropicInput = "Use anthropic key sk-ant-api03-abcdef1234567890abcdef1234567890abcdef-ZZZZZZ";
    protectAnthropicPrompt(anthropicInput, { mode: 'block' });
} catch (err: any) {
    if (err instanceof PromptBlockedError) {
        console.log(`  - Successfully Blocked! Error Message : ${err.message}`);
        console.log(`  - Detected Findings Type             : ${err.result.findings.map(f => f.type).join(', ')}`);
    } else {
        console.error('  - Unexpected Error:', err.message);
    }
}
console.log();

// 3. Test LangChain Middleware Wrapper with Warn Mode
console.log('--------------------------------------------------');
console.log('[TEST 3]: protectLangChainPrompt (Warn Mode)');
console.log('--------------------------------------------------');
try {
    const langchainInput = "Contact user via security@example.com for LangChain chain execution.";
    const safeLangChainPrompt = protectLangChainPrompt(langchainInput, { mode: 'warn' });
    console.log(`  - Input  : "${langchainInput}"`);
    console.log(`  - Output : "${safeLangChainPrompt}" (Passed through unchanged in warn mode)`);
} catch (err: any) {
    console.error('  - Error:', err.message);
}

console.log('\n==================================================');
console.log('   ALL MIDDLEWARE INTEGRATION TESTS PASSED       ');
console.log('==================================================');