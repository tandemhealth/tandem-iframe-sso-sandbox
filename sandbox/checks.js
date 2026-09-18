/**
 * @typedef {'fail' | 'warn' | 'info'} Severity
 *
 * @typedef {object} Check
 * @property {string} id
 * @property {string} description
 * @property {boolean} passed
 * @property {Severity} severity  `fail`: violates the contract; `warn`: tolerated but should be fixed; `info`: informational.
 * @property {string} [detail]
 *
 * @typedef {object} Step
 * @property {string} id
 * @property {string} title
 * @property {Check[]} checks
 *
 * @typedef {object} Transcript
 * @property {string} method
 * @property {string} url
 * @property {Record<string, string>} requestHeaders
 * @property {string} [requestBody]
 * @property {number} [status]
 * @property {Record<string, string>} [responseHeaders]
 * @property {string} [responseBody]
 * @property {string} [error]
 */

export class Checker {
  /** @param {Step} step */
  constructor(step) {
    this.step = step;
  }

  /**
   * @param {string} id
   * @param {string} description
   * @param {boolean} passed
   * @param {{ severity?: Severity, detail?: string }} [opts]
   */
  check(id, description, passed, opts = {}) {
    this.step.checks.push({
      id,
      description,
      passed,
      severity: opts.severity ?? "fail",
      detail: opts.detail,
    });
    return passed;
  }

  /**
   * @param {string} id
   * @param {string} description
   * @param {string} [detail]
   */
  info(id, description, detail) {
    this.step.checks.push({ id, description, passed: true, severity: "info", detail });
  }
}

/**
 * @param {string} id
 * @param {string} title
 * @returns {Step}
 */
export function newStep(id, title) {
  return { id, title, checks: [] };
}

/** @param {Step} step */
export function stepStatus(step) {
  if (step.checks.some((c) => !c.passed && c.severity === "fail")) return "failed";
  if (step.checks.some((c) => !c.passed && c.severity === "warn")) return "warning";
  return "passed";
}

/** @param {Step[]} steps */
export function overallStatus(steps) {
  const statuses = steps.map(stepStatus);
  if (statuses.includes("failed")) return "failed";
  if (statuses.includes("warning")) return "warning";
  return "passed";
}
