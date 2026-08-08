import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  validateProtocolCrossLanguageVectorPack,
} from '../server/src/protocol_fixtures.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const vectorPath = path.join(root, 'fixtures/protocol/cross-language-vectors.v1.json');
const vectorPack = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));

const result = validateProtocolCrossLanguageVectorPack(vectorPack);
assert.equal(result.ok, true);
assert.deepEqual(result.targetLanguages, ['go', 'nodejs', 'python']);
assert.equal(result.vectorCount, 5);
assert.equal(result.negativeVectorCount, 8);

console.log('protocol cross-language node self-test ok');
