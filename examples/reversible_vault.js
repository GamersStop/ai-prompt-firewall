/**
 * Example: Reversible Tokenization Vault (Pillar 1)
 *
 * Demonstrates zero-dependency, bi-directional tokenization that swaps
 * sensitive PII and secrets with context-preserving synthetic entities (<TYPE_n>),
 * allows cloud LLMs to process the task safely, and transparently restores
 * the original values in the LLM's response.
 *
 * Run with: node examples/reversible_vault.js
 */

import { anonymize, scan, TokenVault } from '../dist/index.js';

console.log('=== Pillar 1: Reversible Tokenization Vault Demo ===\n');

// 1. Raw prompt containing sensitive PII and secrets
const rawPrompt =
  'Please draft an employment contract for Alice Smith (email: alice@acme.com, ' +
  'phone: +1 (555) 234-5678). Also provision access with OpenAI key ' +
  'sk-proj-1234567890abcdef1234567890abcdef and server IP 192.168.1.10.';

console.log('1. Raw Prompt (with sensitive data):');
console.log(`   "${rawPrompt}"\n`);

// 2. Anonymize the prompt using the Reversible Vault
const result = anonymize(rawPrompt);

console.log('2. Protected Prompt (safe to send to Cloud LLM):');
console.log(`   "${result.safePrompt}"\n`);

console.log('3. Token Mapping Table:');
console.table(
  result.tokenMap.map((entry) => ({
    Token: entry.token,
    'Original Value': entry.original,
    Type: entry.type,
  }))
);

// 4. Simulate a completion from OpenAI / Anthropic / Claude using the synthetic tokens
const simulatedLLMResponse = `
# Employment Agreement & System Access

This Agreement is entered into by Acme Corp and <PERSON_1>.

- **Contact Email**: <EMAIL_1>
- **Phone**: <PHONE_1>
- **Internal Server Target**: \`<IPV4_ADDRESS_1>\`

### Configuration Instructions
Configure your local environment with your provisioned API key:
\`\`\`bash
export OPENAI_API_KEY="<OPENAI_KEY_1>"
curl -X POST "http://<IPV4_ADDRESS_1>:8080/v1/auth" \\
  -H "Authorization: Bearer <OPENAI_KEY_1>"
\`\`\`

Welcome to the team, <PERSON_1>!
`.trim();

console.log('\n4. LLM Generated Output (contains synthetic tokens):');
console.log('--------------------------------------------------');
console.log(simulatedLLMResponse);
console.log('--------------------------------------------------\n');

// 5. Restore the original values seamlessly
const restoredOutput = result.restore(simulatedLLMResponse);

console.log('5. Restored Final Output (original sensitive data restored):');
console.log('==================================================');
console.log(restoredOutput);
console.log('==================================================\n');

// 6. Deduplication Demonstration: Identical entities resolve to the same token
console.log('6. Entity Deduplication Demo:');
const duplicatePrompt =
  'Send billing receipt to finance@acme.com and CC finance@acme.com or alerts@acme.com.';
const dedupResult = anonymize(duplicatePrompt);
console.log('   Original:', duplicatePrompt);
console.log('   Protected:', dedupResult.safePrompt);
console.log('   Notice that finance@acme.com is mapped once to <EMAIL_1>, alerts@acme.com to <EMAIL_2>.\n');

console.log('✅ Reversible Tokenization Vault demo completed successfully.');
