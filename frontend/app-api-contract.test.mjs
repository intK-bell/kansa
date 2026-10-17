import assert from 'node:assert/strict';
import test from 'node:test';
import { APP_API_METHODS, assertAppApi } from './app-api-contract.js';

test('accepts an adapter implementing every operation', () => {
  const adapter = Object.fromEntries(APP_API_METHODS.map((method) => [method, () => undefined]));
  assert.equal(assertAppApi(adapter), adapter);
});

test('reports missing adapter operations', () => {
  assert.throws(() => assertAppApi({}), /getCurrentUser/);
  assert.throws(() => assertAppApi(null), /must be an object/);
});
