/**
 * Project Name: ai-prompt-firewall
 * File Purpose: Multi-turn conversational session store maintaining cross-turn entity token consistency and TTL expiration.
 * Author Name: Mayuresh Pandit
 */

import { TokenVault } from './vault.js';
import { FirewallError } from './errors.js';
import {
  AnonymizeResult,
  Finding,
  FirewallMode,
  FirewallOptions,
  ScanResult,
  SessionOptions,
  SessionState,
  VaultOptions,
  VaultTokenMap,
} from './types.js';

export type ScannerFunction = (
  prompt: string,
  mode?: FirewallMode,
  options?: FirewallOptions
) => ScanResult;

/**
 * Stateful firewall session maintaining consistent synthetic tokens across multi-turn LLM conversations.
 * Includes configurable TTL, zero external dependencies, and in-memory LRU bounds.
 */
export class FirewallSession {
  public readonly sessionId: string;
  public readonly tenantId?: string;
  public readonly userId?: string;
  public readonly createdAt: number;
  public lastAccessedAt: number;

  private vault: TokenVault;
  private ttlMs: number;
  private maxEntries: number;
  private scanner?: ScannerFunction;
  private defaultFirewallOptions?: FirewallOptions;

  constructor(
    options?: SessionOptions & {
      sessionId?: string;
      vaultOptions?: VaultOptions;
      firewallOptions?: FirewallOptions;
    },
    scanner?: ScannerFunction
  ) {
    this.sessionId =
      options?.sessionId ?? `session_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
    this.tenantId = options?.tenantId;
    this.userId = options?.userId;
    this.createdAt = Date.now();
    this.lastAccessedAt = Date.now();
    this.ttlMs = options?.ttlMs ?? 1000 * 60 * 30; // Default 30-minute TTL
    this.maxEntries = options?.maxEntries ?? 1000;
    this.vault = new TokenVault(options?.vaultOptions);
    this.scanner = scanner;
    this.defaultFirewallOptions = options?.firewallOptions;
  }

  /**
   * Checks if the session has exceeded its configured time-to-live.
   */
  public isExpired(): boolean {
    return Date.now() - this.lastAccessedAt > this.ttlMs;
  }

  /**
   * Refreshes the last accessed timestamp of the session.
   */
  public touch(): void {
    if (this.isExpired()) {
      this.clear();
    }
    this.lastAccessedAt = Date.now();
  }

  /**
   * Anonymizes a prompt within this session context. Reuses existing entity mappings
   * so that identical entities receive consistent synthetic tokens across turns.
   */
  public anonymize(
    prompt: string,
    overrideOptions?: FirewallOptions,
    externalFindings?: Finding[]
  ): AnonymizeResult {
    this.touch();

    let findings: Finding[] = externalFindings || [];
    let blocked = false;

    // If scanner is configured and no external findings were provided, execute scan
    if (this.scanner && (!externalFindings || externalFindings.length === 0)) {
      const scanOpts = { ...this.defaultFirewallOptions, ...overrideOptions };
      const scanResult = this.scanner(prompt, 'warn', scanOpts);
      findings = scanResult.findings;
      blocked = scanResult.blocked;
    }

    const { safePrompt, tokenMap, restore } = this.vault.anonymize(prompt, findings);

    // Enforce LRU entry limit by clearing oldest tokens if threshold is exceeded
    if (this.vault.getAllTokens().length > this.maxEntries) {
      this.clear();
    }

    return {
      safePrompt,
      findings,
      blocked,
      tokenMap,
      restore,
    };
  }

  /**
   * Restores an LLM response containing synthetic tokens back to original values
   * using the accumulated session token map.
   */
  public restore(llmResponse: string): string {
    this.touch();
    return this.vault.restore(llmResponse);
  }

  /**
   * Returns all active token-to-original mappings stored within this session.
   */
  public getTokenMap(): VaultTokenMap[] {
    return this.vault.getAllTokens();
  }

  /**
   * Returns the count of active unique token mappings stored within this session.
   */
  public getTokenCount(): number {
    return this.vault.getAllTokens().length;
  }

  /**
   * Exports full serializable state of this session for distributed caching (e.g. Redis, DynamoDB).
   */
  public exportState(): SessionState {
    this.touch();
    return {
      sessionId: this.sessionId,
      tenantId: this.tenantId,
      userId: this.userId,
      createdAt: this.createdAt,
      lastAccessedAt: this.lastAccessedAt,
      vaultState: this.vault.exportState(),
    };
  }

  /**
   * Rehydrates a FirewallSession from a serialized state snapshot.
   */
  public static fromState(
    state: SessionState,
    options?: SessionOptions & {
      vaultOptions?: VaultOptions;
      firewallOptions?: FirewallOptions;
    },
    scanner?: ScannerFunction
  ): FirewallSession {
    const session = new FirewallSession(
      {
        ...options,
        sessionId: state.sessionId,
        tenantId: state.tenantId,
        userId: state.userId,
      },
      scanner
    );

    (session as unknown as { createdAt: number }).createdAt = state.createdAt;
    session.lastAccessedAt = state.lastAccessedAt;
    (session as unknown as { vault: TokenVault }).vault = TokenVault.fromState(
      state.vaultState,
      options?.vaultOptions
    );

    return session;
  }

  /**
   * Resets all session tokens and updates timestamp.
   */
  public clear(): void {
    this.vault.clear();
    this.lastAccessedAt = Date.now();
  }
}

/**
 * In-memory registry for managing multi-tenant sessions with active cleanup and TTL eviction.
 */
export class SessionStore {
  private sessions = new Map<string, FirewallSession>();
  private defaultOptions?: SessionOptions & {
    vaultOptions?: VaultOptions;
    firewallOptions?: FirewallOptions;
  };
  private scanner?: ScannerFunction;

  constructor(
    defaultOptions?: SessionOptions & {
      vaultOptions?: VaultOptions;
      firewallOptions?: FirewallOptions;
    },
    scanner?: ScannerFunction
  ) {
    this.defaultOptions = defaultOptions;
    this.scanner = scanner;
  }

  /**
   * Retrieves an existing session or creates a new isolated session.
   * Enforces tenant and user scope isolation.
   */
  public getOrCreate(
    sessionId: string,
    options?: SessionOptions & {
      vaultOptions?: VaultOptions;
      firewallOptions?: FirewallOptions;
    }
  ): FirewallSession {
    let session = this.sessions.get(sessionId);
    if (!session || session.isExpired()) {
      session = new FirewallSession(
        {
          ...this.defaultOptions,
          ...options,
          sessionId,
        },
        this.scanner
      );
      this.sessions.set(sessionId, session);
    } else {
      // Validate tenant and user isolation
      if (options?.tenantId && session.tenantId && session.tenantId !== options.tenantId) {
        throw new FirewallError(
          `Security violation: Session "${sessionId}" belongs to tenant "${session.tenantId}", not "${options.tenantId}".`
        );
      }
      if (options?.userId && session.userId && session.userId !== options.userId) {
        throw new FirewallError(
          `Security violation: Session "${sessionId}" belongs to user "${session.userId}", not "${options.userId}".`
        );
      }
      session.touch();
    }
    return session;
  }

  /**
   * Actively prunes all expired sessions from memory to prevent memory bloat in long-running services.
   * @returns The count of pruned expired sessions.
   */
  public pruneExpiredSessions(): number {
    let pruned = 0;
    for (const [id, session] of this.sessions.entries()) {
      if (session.isExpired()) {
        this.sessions.delete(id);
        pruned++;
      }
    }
    return pruned;
  }

  /**
   * Returns current active session count.
   */
  public getActiveCount(): number {
    return this.sessions.size;
  }

  /**
   * Clears all sessions in the store.
   */
  public clear(): void {
    this.sessions.clear();
  }
}

/**
 * Factory creator to initialize a new isolated conversation session.
 */
export function createSession(
  options?: SessionOptions & {
    vaultOptions?: VaultOptions;
    firewallOptions?: FirewallOptions;
  },
  scanner?: ScannerFunction
): FirewallSession {
  return new FirewallSession(options, scanner);
}

/**
 * Factory creator to initialize a multi-tenant session store with proactive pruning.
 */
export function createSessionStore(
  defaultOptions?: SessionOptions & {
    vaultOptions?: VaultOptions;
    firewallOptions?: FirewallOptions;
  },
  scanner?: ScannerFunction
): SessionStore {
  return new SessionStore(defaultOptions, scanner);
}
