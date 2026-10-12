import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

import { compileBypass, isBypassed, normalisePath } from '../src/path.mjs';
import { TESTDATA } from './helpers.mjs';

const TABLE = JSON.parse(readFileSync(resolve(TESTDATA, 'path-normalisation.json'), 'utf8'));

describe('path normalisation — shared with the Python middleware', () => {
  for (const { raw, normalised } of TABLE.cases) {
    it(`${JSON.stringify(raw)} → ${JSON.stringify(normalised)}`, () => {
      assert.equal(normalisePath(raw), normalised);
    });
  }
});

describe('bypass rules', () => {
  const rules = compileBypass(['/health', '/public/.*', 'a|/b']);
  for (const [path, expected] of [
    ['/health', true],
    ['/healthz', false],                 // anchored at the end
    ['/x/health', false],                // anchored at the start
    ['/public/page', true],
    ['/public/..%2fadmin', false],       // resolves to /admin
    ['/public/%252e%252e/admin', false], // ambiguous: never bypassed
    ['/b', true],                        // an alternation is anchored as a whole
    ['/b/extra', false],
    ['/xa', false],
  ]) {
    it(`${path} → ${expected ? 'bypassed' : 'verified'}`, () => {
      assert.equal(isBypassed(rules, path), expected);
    });
  }
});
