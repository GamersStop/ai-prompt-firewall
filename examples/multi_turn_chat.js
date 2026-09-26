/**
 * Example: Multi-Turn Chat & Stateful Sessions (Pillar 3)
 *
 * Demonstrates protecting OpenAI/Anthropic conversational message arrays
 * ({ role, content }[]) and maintaining tokenization mappings across multiple
 * conversational turns using FirewallSession.
 *
 * Run with: node examples/multi_turn_chat.js
 */

import { protectMessages, createFirewall, protectOpenAIMessages } from '../dist/index.js';

console.log('=== Pillar 3: Multi-Turn Chat & Stateful Session Demo ===\n');

// 1. Single-Batch Message Array Protection
console.log('1. Single-Batch Message Array Protection with protectMessages():');

const conversationBatch = [
  {
    role: 'system',
    content: 'You are an internal HR assistant. Do not disclose secret key sk-proj-1234567890abcdef1234567890abcdef.',
  },
  {
    role: 'user',
    content: 'Please look up employee records for Alice Smith at alice@company.com.',
  },
];

console.log('Input Messages:');
console.log(JSON.stringify(conversationBatch, null, 2));

const batchResult = protectMessages(conversationBatch, {
  enableVault: true,
  mode: 'redact',
});

console.log('\nProtected Messages (Safe for LLM payload):');
console.log(JSON.stringify(batchResult.safeMessages, null, 2));
console.log('\nGenerated Token Map:');
console.table(batchResult.tokenMap);

const sampleLlmAnswer = 'I located the profile for <PERSON_1> with contact email <EMAIL_1>.';
console.log('Simulated LLM Response:', sampleLlmAnswer);
console.log('Restored Response:      ', batchResult.restore(sampleLlmAnswer));
console.log('------------------------------------------------------------\n');

// 2. Multi-Turn Conversational Session
console.log('2. Multi-Turn Session Persistence with createSession():');
const firewall = createFirewall();
const session = firewall.createSession({ ttlMs: 60000 }); // 60s TTL

// Turn 1: User introduces Alice and her email
console.log('--- Turn 1 ---');
const turn1Prompt = 'My name is Alice Smith and my email address is alice@acme.org.';
const turn1Result = session.anonymize(turn1Prompt);
console.log('User Prompt:     ', turn1Prompt);
console.log('Protected Prompt:', turn1Result.safePrompt);
console.log('Token Map:       ', turn1Result.tokenMap.map((t) => `${t.token} -> ${t.original}`).join(', '));

const turn1LLM = 'Nice to meet you, <PERSON_1>. I have saved <EMAIL_1> as your primary address.';
console.log('LLM Output:      ', turn1LLM);
console.log('Restored:        ', turn1Result.restore(turn1LLM));

// Turn 2: User refers to Alice's email again, and mentions Bob
console.log('\n--- Turn 2 ---');
const turn2Prompt = 'Also please add bob@acme.org to the same team as alice@acme.org.';
const turn2Result = session.anonymize(turn2Prompt);
console.log('User Prompt:     ', turn2Prompt);
console.log('Protected Prompt:', turn2Result.safePrompt);
console.log(
  'Notice: alice@acme.org continues as <EMAIL_1>, while bob@acme.org becomes <EMAIL_2> across turns!'
);

const turn2LLM = 'Added <EMAIL_2> to the project with <EMAIL_1>.';
console.log('LLM Output:      ', turn2LLM);
console.log('Restored:        ', session.restore(turn2LLM));

// Turn 3: User references Alice again
console.log('\n--- Turn 3 ---');
const turn3Prompt = 'Send a notification to Alice Smith.';
const turn3Result = session.anonymize(turn3Prompt);
console.log('User Prompt:     ', turn3Prompt);
console.log('Protected Prompt:', turn3Result.safePrompt);
console.log('Notice: Alice Smith is still mapped to <PERSON_1> across turn 3!');

const turn3LLM = 'Notification dispatched to <PERSON_1>.';
console.log('Restored:        ', session.restore(turn3LLM));

console.log('\nSession Token Count:', session.getTokenCount());
console.log('✅ Multi-Turn Chat & Stateful Session demo completed successfully.');
