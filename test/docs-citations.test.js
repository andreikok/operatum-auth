/**
 * docs-citations.test.js — keep the docs honest.
 *
 * README.md and ARCHITECTURE.md cite this repo's source as
 * `src/<file>.js:<line>` (or `:<start>-<end>`). Those citations are
 * load-bearing — they are how a reader verifies each claim — but they
 * rot silently when code moves. This test parses every such citation
 * out of the docs and asserts the file exists and the line (range) is
 * in bounds, so a stale reference fails CI instead of misleading a
 * reader.
 *
 * Scope is deliberately THIS repo only: the pattern requires a `src/`
 * prefix, so cross-repo references (which this repo intentionally does
 * NOT cite by file/line) are neither required nor validated here.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
// README cites by symbol name (it's a user guide); ARCHITECTURE.md is the
// line-cited doc. Both are validated for any citation they DO carry, but
// only the citation-dense doc must be non-empty.
const DOCS = [
  { file: 'README.md', requireCitations: false },
  { file: 'ARCHITECTURE.md', requireCitations: true },
];

// `src/foo.js:12`, `src/foo/bar.js:12-34`, or `package.json:2-6`.
// Backticks around the citation in markdown are not captured — the
// regex anchors on the `<repo-file>:<line>` shape itself. The path is
// kept to files this repo actually owns, so cross-repo references (which
// this repo intentionally does not cite by file/line) are not matched.
const CITATION_RE = /\b(?:src\/[A-Za-z0-9_./-]+\.js|package\.json):(\d+)(?:-(\d+))?/g;

const lineCountCache = new Map();
function lineCount(absPath) {
  if (!lineCountCache.has(absPath)) {
    lineCountCache.set(absPath, readFileSync(absPath, 'utf8').split('\n').length);
  }
  return lineCountCache.get(absPath);
}

for (const { file: doc, requireCitations } of DOCS) {
  test(`${doc}: every src/…:line citation resolves to a real, in-range line`, () => {
    const text = readFileSync(join(repoRoot, doc), 'utf8');
    const seen = [];
    for (const m of text.matchAll(CITATION_RE)) {
      const [cite] = m;
      const start = Number(m[1]);
      const end = m[2] !== undefined ? Number(m[2]) : start;
      const relPath = cite.slice(0, cite.lastIndexOf(':'));
      const absPath = join(repoRoot, relPath);

      assert.ok(existsSync(absPath), `${doc} cites missing file: ${relPath}`);
      const n = lineCount(absPath);
      assert.ok(start >= 1 && start <= n,
        `${doc} cite ${cite}: start line ${start} out of range (1..${n})`);
      assert.ok(end >= start && end <= n,
        `${doc} cite ${cite}: end line ${end} out of range (${start}..${n})`);
      seen.push(cite);
    }
    // Sanity: the line-cited doc is supposed to be densely cited. If this
    // drops to zero the regex broke or the docs lost their citations.
    if (requireCitations) {
      assert.ok(seen.length > 0, `${doc}: expected at least one src/…:line citation`);
    }
  });
}
