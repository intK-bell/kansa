import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const landingHtml = await readFile(new URL('./landing.html', import.meta.url), 'utf8');
const landingJs = await readFile(new URL('./landing.js', import.meta.url), 'utf8');

test('landing page exposes the market switcher', () => {
  assert.match(landingHtml, /id="landing-market-select"/);
  assert.match(landingHtml, /<option value="port">港湾版<\/option>/);
  assert.match(landingHtml, /<option value="rental">賃貸デモ<\/option>/);
});

test('landing page carries the selected market into app and demo links', () => {
  assert.match(landingJs, /landing-market-select/);
  assert.match(landingJs, /searchParams\.set\("market", market\)/);
  assert.match(landingJs, /index\.html/);
  assert.match(landingJs, /demo\.html/);
});
