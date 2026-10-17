import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');
const frontendDir = path.join(repoRoot, 'frontend');
const templatePath = path.join(frontendDir, 'app-shell.template.html');

const developerMenuButton =
  '                <button id="developer-dashboard-btn" type="button" class="hidden" data-i18n="開発者">開発者</button>';

const developerModal = `    <div id="developer-modal" class="modal hidden" role="dialog" aria-modal="true" aria-label="開発者ダッシュボード" data-i18n-attr="aria-label:開発者ダッシュボード">
      <div class="modal-card developer-card">
        <div class="modal-header">
          <h3 style="margin:0;" data-i18n="開発者ダッシュボード">開発者ダッシュボード</h3>
          <button id="developer-close-btn" type="button" class="danger" data-i18n="閉じる">閉じる</button>
        </div>
        <div id="developer-summary" class="developer-summary">
          <p class="muted" data-i18n="読み込み中...">読み込み中...</p>
        </div>
      </div>
    </div>
`;

export const pageConfigs = {
  index: {
    output: 'index.html',
    PAGE_TITLE: 'Cong | Container Log',
    FAVICON_HREF: './img/cong-favicon.png?v=20260606-add3',
    LOGO_HREF: './img/cong-logo.png?v=20260606-add3',
    DEVELOPER_MENU_BUTTON: developerMenuButton,
    DEVELOPER_MODAL: developerModal,
    CONFIG_SCRIPT: '    <script src="./config.js?v=20260606-add4"></script>',
    APP_SCRIPT: './main.js?v=20260606-add4',
  },
  demo: {
    output: 'demo.html',
    PAGE_TITLE: 'Cong | Container Log デモ',
    FAVICON_HREF: './img/cong-favicon.png',
    LOGO_HREF: './img/cong-logo.png',
    DEVELOPER_MENU_BUTTON: '',
    DEVELOPER_MODAL: '',
    CONFIG_SCRIPT: '',
    APP_SCRIPT: './demo.js?v=20260607-cong-i18n1',
  },
};

export async function renderPage(config) {
  let source = await readFile(templatePath, 'utf8');
  for (const [key, value] of Object.entries(config)) {
    if (key === 'output') continue;
    const token = `{{${key}}}`;
    if (!source.includes(token)) throw new Error(`Template token is missing: ${token}`);
    source = source.replaceAll(token, value);
  }
  const unresolved = source.match(/{{[A-Z0-9_]+}}/g);
  if (unresolved) throw new Error(`Unresolved template token: ${unresolved[0]}`);
  return source;
}

export async function generateFrontendPages() {
  for (const config of Object.values(pageConfigs)) {
    const output = await renderPage(config);
    await writeFile(path.join(frontendDir, config.output), output, 'utf8');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateFrontendPages();
}
