import { createHash, randomBytes, randomInt, randomUUID } from "node:crypto";

/** @import { Step, Transcript } from './checks.js' */
/** @import { LinkedUser } from './exchange.js' */

/**
 * @typedef {object} AttemptRecord
 * @property {number} requestId
 * @property {string} state
 * @property {string} codeVerifier
 * @property {string} codeChallenge
 * @property {Date} createdAt
 * @property {'awaiting' | 'completed'} status
 * @property {Date} [completedAt]
 * @property {string} [origin]
 * @property {Step[]} steps
 * @property {Transcript[]} transcripts
 * @property {LinkedUser | null} user
 * @property {string | null} rejection
 */

const MAX_ATTEMPTS = 200;

/** In-memory store of authorization attempts; a restart clears it. */
export class Store {
  constructor() {
    /** @type {Map<number, AttemptRecord>} */
    this.attempts = new Map();
  }

  /** @returns {AttemptRecord} */
  create() {
    const codeVerifier = base64url(randomBytes(32));
    const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest());
    let requestId = randomInt(1, 1e9);
    while (this.attempts.has(requestId)) requestId = randomInt(1, 1e9);
    /** @type {AttemptRecord} */
    const attempt = {
      requestId,
      state: randomUUID(),
      codeVerifier,
      codeChallenge,
      createdAt: new Date(),
      status: "awaiting",
      steps: [],
      transcripts: [],
      user: null,
      rejection: null,
    };
    this.attempts.set(requestId, attempt);
    this.prune();
    return attempt;
  }

  /** @param {number} requestId */
  get(requestId) {
    return this.attempts.get(requestId) ?? null;
  }

  /** Newest first. */
  list() {
    return [...this.attempts.values()].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  prune() {
    if (this.attempts.size <= MAX_ATTEMPTS) return;
    for (const attempt of this.list().slice(MAX_ATTEMPTS)) {
      this.attempts.delete(attempt.requestId);
    }
  }
}

/** @param {Buffer} buf */
function base64url(buf) {
  return buf.toString("base64url");
}
