#!/usr/bin/env node
/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Command-Line Interface (CLI) entry point for evaluating prompts against security policies, prompt injection defense, and reversible vaulting.
 * Author Name: Mayuresh Pandit
 */

import { scan, anonymize } from '../core/ai_scanner.js';
import { TokenVault } from '../core/vault.js';
import type { FirewallMode, VaultTokenMap } from '../core/types.js';

export interface CliArgs {
  mode: FirewallMode;
  prompt: string;
  detectInjections: boolean;
  vault: boolean;
  restoreText?: string;
  tokenMapJson?: string;
  help: boolean;
}

/**
 * Parses command-line arguments to extract firewall mode, flags, and target prompt.
 */
export function parseArguments(rawArgs: string[] = process.argv.slice(2)): CliArgs {
  let mode: FirewallMode = 'redact';
  let detectInjections = false;
  let vault = false;
  let restoreText: string | undefined;
  let tokenMapJson: string | undefined;
  let help = false;
  const promptParts: string[] = [];

  for (let i = 0; i < rawArgs.length; i++) {
    const arg = rawArgs[i];
    if (!arg) continue;

    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg.startsWith('--mode=')) {
      const splitMode = arg.split('=')[1];
      if (splitMode) {
        mode = splitMode as FirewallMode;
      }
    } else if (arg === '--mode') {
      const nextArg = rawArgs[i + 1];
      if (nextArg && !nextArg.startsWith('--')) {
        mode = nextArg as FirewallMode;
        i++;
      }
    } else if (arg === '--detect-injections' || arg === '-d') {
      detectInjections = true;
    } else if (arg === '--vault' || arg === '-v') {
      vault = true;
    } else if (arg.startsWith('--restore=')) {
      restoreText = arg.slice('--restore='.length);
    } else if (arg === '--restore') {
      const nextArg = rawArgs[i + 1];
      if (nextArg && !nextArg.startsWith('--')) {
        restoreText = nextArg;
        i++;
      }
    } else if (arg.startsWith('--map=')) {
      tokenMapJson = arg.slice('--map='.length);
    } else if (arg === '--map' || arg === '--token-map') {
      const nextArg = rawArgs[i + 1];
      if (nextArg) {
        tokenMapJson = nextArg;
        i++;
      }
    } else if (!arg.startsWith('--')) {
      promptParts.push(arg);
    }
  }

  return {
    mode,
    prompt: promptParts.join(' '),
    detectInjections,
    vault,
    restoreText,
    tokenMapJson,
    help,
  };
}

/**
 * Displays the CLI usage manual when no prompt is provided or --help is passed.
 */
export function printUsageHelp(): string {
  const helpText = `
🛡️  AI Prompt Firewall CLI

Usage:
  ai-prompt-firewall "Your AI prompt here" [options]

Options:
  --mode=redact|block|warn   Firewall evaluation mode (default: redact)
  --detect-injections, -d    Enable OWASP LLM01 heuristic prompt injection defense
  --vault, -v                Enable reversible synthetic tokenization (<TYPE_n>)
  --restore="<LLM text>"     Restore synthetic tokens in an LLM completion
  --map='[...]'              Serialized JSON token map for use with --restore
  --help, -h                 Display this usage manual

Examples:
  # Scan & redact sensitive PII/secrets:
  ai-prompt-firewall "My AWS key is AKIAIOSFODNN7EXAMPLE"

  # Zero-trust blocking on prompt injection and leaks:
  ai-prompt-firewall "Ignore all previous rules" --detect-injections --mode=block

  # Reversible tokenization vault:
  ai-prompt-firewall "Send contract to alice@acme.com" --vault

  # Restore synthetic tokens in an LLM answer:
  ai-prompt-firewall --restore="Sent to <EMAIL_1>" --map='[{"token":"<EMAIL_1>","original":"alice@acme.com","type":"EMAIL"}]'
`;
  console.log(helpText);
  return helpText;
}

/**
 * Core CLI execution handler.
 */
export function executeCli(args: CliArgs): { output: unknown; exitCode: number } {
  if (args.help || (!args.prompt && !args.restoreText)) {
    printUsageHelp();
    return { output: null, exitCode: 0 };
  }

  // Handle --restore mode
  if (args.restoreText) {
    if (!args.tokenMapJson) {
      console.error(
        '❌ Error: --map=\'[{"token":"...","original":"..."}]\' is required when using --restore.'
      );
      return { output: null, exitCode: 1 };
    }

    try {
      const tokens = JSON.parse(args.tokenMapJson) as VaultTokenMap[];
      const vault = new TokenVault({}, tokens);
      const restored = vault.restore(args.restoreText);
      const result = {
        restored,
        original: args.restoreText,
        tokensRestored: tokens.length,
      };
      console.log(JSON.stringify(result, null, 2));
      return { output: result, exitCode: 0 };
    } catch (e) {
      console.error('❌ Error parsing token map JSON:', e);
      return { output: null, exitCode: 1 };
    }
  }

  // Handle --vault mode
  if (args.vault) {
    const result = anonymize(args.prompt, {
      mode: args.mode,
      detectInjections: args.detectInjections,
    });
    console.log(
      JSON.stringify(
        {
          safePrompt: result.safePrompt,
          blocked: result.blocked,
          findings: result.findings,
          tokenMap: result.tokenMap,
        },
        null,
        2
      )
    );
    return { output: result, exitCode: result.blocked ? 1 : 0 };
  }

  // Standard scan mode
  const result = scan(args.prompt, args.mode, {
    detectInjections: args.detectInjections,
  });
  console.log(JSON.stringify(result, null, 2));
  return { output: result, exitCode: result.blocked ? 1 : 0 };
}

function main(): void {
  const args = parseArguments();
  try {
    const { exitCode } = executeCli(args);
    if (exitCode !== 0) {
      process.exit(exitCode);
    }
  } catch (error) {
    console.error('❌ Error executing ai-prompt-firewall:', error);
    process.exit(1);
  }
}

// Only invoke main when run directly as CLI binary
if (
  process.argv[1] &&
  (process.argv[1].endsWith('index.js') || process.argv[1].endsWith('index.ts'))
) {
  main();
}
