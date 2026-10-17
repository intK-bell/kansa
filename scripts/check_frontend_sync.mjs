import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { pageConfigs, renderPage } from './generate_frontend_pages.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const frontendDir = path.resolve(scriptDir, '..', 'frontend');
let failed = false;
const renderedPages = new Map();

for (const config of Object.values(pageConfigs)) {
  const expected = await renderPage(config);
  const actual = await readFile(path.join(frontendDir, config.output), 'utf8');
  renderedPages.set(config.output, actual);
  if (actual !== expected) {
    failed = true;
    console.error(`${config.output} is out of sync with app-shell.template.html`);
  }
}

for (const [fileName, html] of renderedPages) {
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length) {
    failed = true;
    console.error(`${fileName} has duplicate IDs: ${[...new Set(duplicates)].join(', ')}`);
  }
}

const indexIds = new Set([...renderedPages.get('index.html').matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]));
const demoIds = new Set([...renderedPages.get('demo.html').matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]));
const allowedIndexOnlyIds = new Set([
  'developer-dashboard-btn',
  'developer-modal',
  'developer-close-btn',
  'developer-summary',
]);
const unexpectedIndexOnly = [...indexIds].filter((id) => !demoIds.has(id) && !allowedIndexOnlyIds.has(id));
const unexpectedDemoOnly = [...demoIds].filter((id) => !indexIds.has(id));
if (unexpectedIndexOnly.length || unexpectedDemoOnly.length) {
  failed = true;
  console.error(`Unexpected page ID differences: index-only=[${unexpectedIndexOnly}], demo-only=[${unexpectedDemoOnly}]`);
}

if (failed) {
  console.error('Run: node scripts/generate_frontend_pages.mjs');
  process.exitCode = 1;
} else {
  console.log('Frontend HTML is in sync.');
}
