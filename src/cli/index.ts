#!/usr/bin/env node
/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Command-Line Interface (CLI) entry point for evaluating prompts against security policies.
 * Author Name: Mayuresh Pandit
 */

import { scan } from '../core/ai_scanner.js';
import type { FirewallMode } from '../core/types.js';

/**
 * Parses command-line arguments to extract the firewall mode and target prompt string.
 * Supports both flag formats: `--mode=block` and `--mode block`.
 */
function parseArguments(): { mode: FirewallMode; prompt: string } {
    const args = process.argv.slice(2);
    let mode: FirewallMode = 'redact';
    let promptParts: string[] = [];

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (!arg) continue;

        if (arg.startsWith('--mode=')) {
            const splitMode = arg.split('=')[1];
            if (splitMode) {
                mode = splitMode as FirewallMode;
            }
        } else if (arg === '--mode') {
            const nextArg = args[i + 1];
            if (nextArg) {
                mode = nextArg as FirewallMode;
                i++; // Skip the next argument since it was consumed as the mode value
            }
        } else if (!arg.startsWith('--')) {
            promptParts.push(arg);
        }
    }

    return { mode, prompt: promptParts.join(' ') };
}

/**
 * Displays the CLI usage manual when no prompt is provided.
 */
function printUsageHelp(): void {
    console.log(`
🛡️  AI Prompt Firewall CLI

Usage:
  ai-prompt-firewall "Your AI prompt here" [--mode=redact|block|warn]

Examples:
  ai-prompt-firewall "My AWS key is AKIAIOSFODNN7EXAMPLE"
  ai-prompt-firewall "sk-1234567890abcdef1234567890abcdef" --mode=block
  `);
}

/**
 * Main execution routine for the CLI binary wrapper.
 */
function main(): void {
    const { mode, prompt } = parseArguments();

    if (!prompt) {
        printUsageHelp();
        process.exit(0);
    }

    try {
        const result = scan(prompt, mode);
        console.log(JSON.stringify(result, null, 2));

        // Enforce exit code 1 if the firewall policy blocks the request
        if (result.blocked) {
            process.exit(1);
        }

        process.exit(0);
    } catch (error) {
        console.error('❌ Error executing ai-prompt-firewall:', error);
        process.exit(1);
    }
}

main();