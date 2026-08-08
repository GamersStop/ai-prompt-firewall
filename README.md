# 🛡️ AI Prompt Firewall (`ai-prompt-firewall`)

[![npm version](https://img.shields.io/npm/v/ai-prompt-firewall.svg?style=flat-square&color=007acc)](https://www.npmjs.com/package/ai-prompt-firewall)
[![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](./LICENSE)
[![build](https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square)](#)
[![dependencies](https://img.shields.io/badge/dependencies-0--runtime-success.svg?style=flat-square)](#)
[![types](https://img.shields.io/badge/types-TypeScript-informational.svg?style=flat-square)](#)

> **Lightweight, developer-first AI prompt security middleware for real-time detection, remediation, and redaction of sensitive secrets and PII before reaching Large Language Models.**

---

## 📐 Architecture Overview

```
+---------------------+      +-------------------------------------------------+      +------------------------+
|  Untrusted User     | ---> |           AI PROMPT FIREWALL ENGINE             | ---> |  Downstream LLM        |
|  Input / Prompt     |      |                                                 |      |  (OpenAI / Anthropic / |
+---------------------+      |  - Pattern Matching (Secrets, PII, Tokens)      |      |   LangChain / Bedrock) |
                             |  - Multi-Tenant Rule Registry                   |      +------------------------+
                             |  - Custom Redactor Callbacks                    |
                             +-------------------------------------------------+
                                      |              |              |
                                 [REDACT]         [BLOCK]        [WARN]
                                    |                |              |
                             Sanitizes prompt  Throws Error   Logs SIEM offsets
                             with placeholders  & stops execution & passes through
```

---

## ✨ Core Features

* **📦 Zero Dependencies:** Zero third-party runtime dependencies. Zero supply-chain attack surface.
* **⚡ Dual-API Ergonomics:** Use stateless `scan()` for zero-setup calls, or `createFirewall()` pre-compiled instances for high-throughput multi-tenant backends.
* **🛡️ Built-in Secret & PII Scanner:** Detects OpenAI keys, Anthropic keys, AWS credentials, Stripe keys, GitHub tokens, Slack tokens, private SSH/RSA keys, Bearer tokens, emails, phone numbers, and IPv4 addresses out of the box.
* **📊 Enterprise SIEM Offsets:** Returns exact character coordinates (`startIndex`, `endIndex`, `matchedSnippetLength`) for security logging without leaking raw sensitive strings.
* **🚨 Typed Error Taxonomy:** Extends standard error classes with `PromptBlockedError` and `PromptValidationError` for programmatic exception handling.
* **🔌 Drop-in Provider Middleware:** Helper wrappers for **OpenAI**, **Anthropic**, and **LangChain** pipelines.
* **🖥️ CLI Executable:** Out-of-the-box CLI tool (`npx ai-prompt-firewall`) for local prompt scanning and build pipeline scripts.

---

## 📦 Installation

```bash
npm install ai-prompt-firewall
```

---

## 🚀 Quick Start & Usage Examples

### 1. Stateless Prompt Scanning & Redaction

```typescript
import { scan } from 'ai-prompt-firewall';

const prompt = "Please review my AWS key AKIAIOSFODNN7EXAMPLE and email me at dev@company.com.";

// Modes: 'redact' | 'block' | 'warn'
const result = scan(prompt, 'redact');

console.log(result.safePrompt);
// => "Please review my AWS key [AWS_KEY_REDACTED] and email me at [EMAIL_REDACTED]."

console.log(result.findings);
/*
[
  { type: 'AWS_KEY', severity: 'CRITICAL', startIndex: 22, endIndex: 42, matchedSnippetLength: 20 },
  { type: 'EMAIL', severity: 'CRITICAL', startIndex: 59, endIndex: 74, matchedSnippetLength: 15 }
]
*/
```

---

### 2. High-Performance Multi-Tenant Factory (`createFirewall`)

Pre-compile tenant-specific regex patterns once during initialization to maximize request throughput in multi-tenant SaaS environments:

```typescript
import { createFirewall } from 'ai-prompt-firewall';

// Initialize pre-compiled tenant instance
const tenantAFirewall = createFirewall({
  customPatterns: {
    TENANT_INTERNAL_ID: /TENANT-A-[0-9]{5}/g,
  },
  redactor: (type, match) => `[REDACTED_${type}]`
});

// High-frequency request path
const result = tenantAFirewall.scan("User requested TENANT-A-99887 access.");
console.log(result.safePrompt);
// => "User requested [REDACTED_TENANT_INTERNAL_ID] access."
```

---

### 3. Provider Middleware Wrappers (OpenAI / Anthropic / LangChain)

#### OpenAI Integration
```typescript
import { protectOpenAIPrompt, PromptBlockedError } from 'ai-prompt-firewall';

try {
  const safePrompt = protectOpenAIPrompt(userInput, {
    mode: 'block',
    onBlock: (result) => console.error('Violation blocked:', result.findings)
  });
  
  // Send safePrompt to OpenAI API...
} catch (err) {
  if (err instanceof PromptBlockedError) {
    // Handle security policy violation
  }
}
```

#### Anthropic Integration
```typescript
import { protectAnthropicPrompt } from 'ai-prompt-firewall';

const sanitizedClaudePrompt = protectAnthropicPrompt(userInput, { mode: 'redact' });
```

#### LangChain Integration
```typescript
import { protectLangChainPrompt } from 'ai-prompt-firewall';

const sanitizedChainInput = protectLangChainPrompt(userInput, { mode: 'redact' });
```

---

### 4. Command Line Interface (CLI)

Scan prompts directly from your terminal or CI/CD scripts:

```bash
# Redact mode (default)
npx ai-prompt-firewall "My OpenAI key is sk-proj-1234567890abcdef1234567890abcdef"

# Block mode (exits with status 1 if secrets found)
npx ai-prompt-firewall "Contact me at admin@company.com" --mode=block
```

---

## 🔍 Built-in Security Pattern Matrix

| Category | Pattern Type | Description / Format | Example Match |
| :--- | :--- | :--- | :--- |
| **AI & Cloud** | `OPENAI_KEY` | OpenAI Project & Secret API Keys (`sk-...`) | `sk-proj-1234567890abcdef...` |
| **AI & Cloud** | `ANTHROPIC_KEY` | Anthropic Claude API Keys (`sk-ant-api03-...`) | `sk-ant-api03-abcdef12345...` |
| **AI & Cloud** | `AWS_KEY` | Amazon Web Services Access Key IDs | `AKIAIOSFODNN7EXAMPLE` |
| **AI & Cloud** | `AWS_SECRET` | Amazon Web Services Secret Keys (40-char) | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| **Payment** | `STRIPE_KEY` | Stripe Live & Test Secret/Restricted Keys | `sk_live_51M0123456789abcdef...` |
| **Developer** | `GITHUB_TOKEN` | GitHub Personal Access Tokens | `ghp_1234567890abcdefghijklmnopqrst` |
| **Cloud API** | `GOOGLE_API_KEY` | Google Cloud API Keys | `AIzaSyA1234567890abcdefghijklmnopqrst` |
| **Messaging** | `SLACK_TOKEN` | Slack Bot & User Tokens | `xoxb-your-slack-bot-token-here` |
| **Crypto** | `PRIVATE_KEY` | RSA, OpenSSH, & Private Key Blocks | `-----BEGIN RSA PRIVATE KEY-----...` |
| **Auth** | `BEARER_TOKEN` | HTTP Authorization Bearer Tokens | `Bearer eyJhbGciOiJIUzI1Ni...` |
| **PII** | `EMAIL` | Standard Email Addresses | `user@company.com` |
| **PII** | `PHONE_NUMBER` | US & International Phone Numbers | `+1 (555) 019-2834` |
| **Network** | `IPV4_ADDRESS` | IPv4 Network Addresses | `192.168.1.1` |
| **PII Context** | `USER_NAME_CONTEXT` | Conversational Name Context Identifiers | `"my name is Alice"` |

---

## 🛠️ Development & Testing

```bash
# Clone the repository
git clone https://github.com/GamersStop/ai-prompt-firewall.git
cd ai-prompt-firewall

# Install dependencies
npm install

# Run build
npm run build

# Run unit tests
npm test
```

---

## 💖 Support & Sponsorship

If `ai-prompt-firewall` helps secure your production AI infrastructure, consider supporting the ongoing maintenance of the project:

[![Support on Ko-fi](https://img.shields.io/badge/Support%20on-Ko--fi-ff5e5b?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/dreainno)
[![Sponsor on Patreon](https://img.shields.io/badge/Sponsor%20on-Patreon-f96854?style=for-the-badge&logo=patreon&logoColor=white)](https://www.patreon.com/cw/dreainno)

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](./LICENSE) for details.

Copyright (c) 2026 Mayuresh Pandit.
