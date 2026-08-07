# AI Prompt Firewall (`ai-prompt-firewall`)

> Stop accidental data leaks before they reach the LLM.

`ai-prompt-firewall` is a lightweight, high-performance security middleware designed for AI application developers. It intercepts prompt traffic in real-time to detect and remediate sensitive data—such as API keys, cryptographic tokens, and PII—before it is transmitted to LLM providers like OpenAI, Anthropic, or Gemini.

---

## 🚀 The Problem

Modern AI applications are prone to accidental data leakage. Developers and users often paste sensitive information into prompts for debugging or summarization. Once sent, this data can be persisted by AI providers, posing severe risks to intellectual property, security, and compliance (GDPR, HIPAA, PCI-DSS).

---

## 🛡️ The Solution

Instead of scanning your codebase at rest, `ai-prompt-firewall` scans your prompts in flight. It acts as a transparent security layer that sits between your application and the AI API.

### Key Features

- **Real-time Detection:** Regex-based identification of API keys, JWTs, SSH keys, and internal credentials.
- **PII Sanitization:** Algorithmic detection and redaction of sensitive identifiers (Credit Cards, Phone Numbers, etc.).
- **Configurable Policy:** Choose between `block`, `warn`, or `redact` modes.
- **Zero-Dependency Core:** High-performance, isomorphic TypeScript engine (runs on Node.js and Browser).
- **SDK Wrappers:** Drop-in integration for `openai`, `@anthropic-ai/sdk`, and `langchain`.

---

## ⚡ Quick Start

### Installation

```bash
npm install ai-prompt-firewall
```

### Simple Usage

```typescript
import { wrapOpenAI } from 'ai-prompt-firewall';
import OpenAI from 'openai';

// Automatically scan every request sent to OpenAI
const openai = wrapOpenAI(new OpenAI(), { mode: 'redact' });

await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: userPrompt }]
});
```

---

## 🏗️ Architecture

The firewall operates with a sub-5ms latency overhead, ensuring your AI-powered applications remain responsive while staying secure.

- **Core Engine:** Pure TypeScript, zero-dependency.
- **Middleware Layer:** Adapter-based wrappers for popular AI SDKs.
- **Audit-Ready:** Structured findings report for SIEM integration.

---

## 🤝 Contributing

We welcome contributions to expand our rule library (Aadhaar, PAN, Passport patterns, etc.). Please check the [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 💖 Support & Contributions

If you find this project valuable, consider supporting the development and maintenance of these security tools:

[![Support via Ko-fi](https://img.shields.org/badge/Support%20via-Ko--fi-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/dreainno)

---

## ⚖️ License

This project is licensed under the [MIT License](LICENSE).
