/** The time source for signature and credential validity. Replaceable only by tests. */

let source = () => Date.now();

export const nowMs = () => source();

/** Tests only: evaluate time-bound vectors at their pinned instant. `null` restores real time. */
export function setClockForTests(fn) {
  source = fn ?? (() => Date.now());
}
