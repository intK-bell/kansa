const path = require('path');
const fs = require('fs');
const { PDFDocument, StandardFonts, rgb } = require('../backend/src/node_modules/pdf-lib');
const fontkit = require('../backend/src/node_modules/@pdf-lib/fontkit');
const { buildExportPresentation, resolveExportSlideLayout, PALETTE } = require('../backend/src/ppt-layout');
const { createExportI18n, normalizeLanguage } = require('../backend/src/export-i18n');

const PDF_PAGE_WIDTH = 960;
const PDF_PAGE_HEIGHT = 540;
const PPT_TO_PDF_SCALE = 72;
const PDF_FONT_PATH = path.resolve(__dirname, '../backend/src/fonts/NotoSansCJKjp-Regular.otf');

function pptUnit(value) {
  return Number(value || 0) * PPT_TO_PDF_SCALE;
}

function hexToRgbColor(hex) {
  const value = String(hex || '000000').replace('#', '').trim();
  const normalized = value.length === 3 ? value.split('').map((ch) => ch + ch).join('') : value.padStart(6, '0');
  const int = parseInt(normalized, 16);
  return rgb(((int >> 16) & 255) / 255, ((int >> 8) & 255) / 255, (int & 255) / 255);
}

function isPdfLatinChar(ch) {
  const code = String(ch || '').codePointAt(0);
  return Number.isFinite(code) && code >= 0x20 && code <= 0x7e;
}

function splitPdfTextRuns(text) {
  const runs = [];
  let currentType = null;
  let currentText = '';
  for (const ch of Array.from(String(text || ''))) {
    const nextType = isPdfLatinChar(ch) ? 'latin' : 'jp';
    if (currentType && nextType !== currentType) {
      runs.push({ type: currentType, text: currentText });
      currentText = '';
    }
    currentType = nextType;
    currentText += ch;
  }
  if (currentText) runs.push({ type: currentType || 'jp', text: currentText });
  return runs;
}

function measurePdfTextWidth(text, size, jpFont, latinFont) {
  return splitPdfTextRuns(text).reduce((sum, run) => {
    const font = run.type === 'latin' ? latinFont : jpFont;
    return sum + font.widthOfTextAtSize(run.text, size);
  }, 0);
}

function drawMixedPdfText(page, text, options) {
  const { x, y, size, jpFont, latinFont, color } = options;
  let cursorX = x;
  for (const run of splitPdfTextRuns(text)) {
    const font = run.type === 'latin' ? latinFont : jpFont;
    page.drawText(run.text, { x: cursorX, y, size, font, color });
    cursorX += font.widthOfTextAtSize(run.text, size);
  }
}

function wrapPdfText(text, maxWidth, size, jpFont, latinFont) {
  const raw = String(text || '').trim();
  if (!raw) return [];
  const lines = [];
  for (const block of raw.split('\n')) {
    const source = block.trimEnd();
    if (!source) {
      lines.push('');
      continue;
    }
    let current = '';
    for (const ch of Array.from(source)) {
      const candidate = current + ch;
      if (current && measurePdfTextWidth(candidate, size, jpFont, latinFont) > maxWidth) {
        lines.push(current);
        current = ch;
        continue;
      }
      current = candidate;
    }
    if (current) lines.push(current);
  }
  return lines;
}

function toneSet(seedText) {
  const presets = [
    ['7baf6a', 'dff0d8'],
    ['5f79a9', 'dbe7f7'],
    ['d85a6a', 'f6e6ea'],
    ['a86f22', 'f4dfbe'],
    ['2f8f83', 'cdeef6'],
  ];
  const source = Array.from(String(seedText || 'demo'));
  const hash = source.reduce((sum, ch) => sum + ch.codePointAt(0), 0);
  return presets[hash % presets.length];
}

function drawDemoImagePlaceholder(page, photo, box, jpFont, latinFont, i18n) {
  const [toneA, toneB] = toneSet(photo.fileName || photo.photoCode || photo.photoId);
  const x = pptUnit(box.x);
  const y = PDF_PAGE_HEIGHT - pptUnit(box.y + box.h);
  const w = pptUnit(box.w);
  const h = pptUnit(box.h);
  page.drawRectangle({ x, y, width: w, height: h, color: hexToRgbColor(toneA) });
  page.drawRectangle({ x: x + 16, y: y + 16, width: w - 32, height: h - 32, color: hexToRgbColor(toneB), opacity: 0.9 });
  page.drawCircle({ x: x + w - 70, y: y + h - 62, size: 28, color: rgb(1, 1, 1), opacity: 0.22 });
  page.drawRectangle({ x: x + 26, y: y + h - 50, width: 180, height: 16, color: rgb(1, 1, 1), opacity: 0.34 });
  page.drawRectangle({ x: x + 26, y: y + h - 76, width: 128, height: 10, color: rgb(1, 1, 1), opacity: 0.26 });
  page.drawRectangle({ x: x + 26, y: y + 26, width: w - 52, height: 74, color: rgb(1, 1, 1), opacity: 0.14 });
  drawMixedPdfText(page, photo.fileName || photo.photoCode || i18n.t('デモ画像'), {
    x: x + 28,
    y: y + 48,
    size: 20,
    jpFont,
    latinFont,
    color: rgb(1, 1, 1),
  });
}

async function buildDemoPdf(options) {
  const { folder, photos, currentPlan, usageBytes, capacityBytes, i18n: inputI18n } = options;
  const i18n = inputI18n || createExportI18n('ja');
  const pdfDoc = await PDFDocument.create();
  pdfDoc.registerFontkit(fontkit);
  const jpFont = await pdfDoc.embedFont(fs.readFileSync(PDF_FONT_PATH), { subset: false });
  const latinFont = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const exportAt = new Date();
  const footerSummary = `${i18n.t('形式')}: PDF / ${i18n.t('プラン')}: ${currentPlan} / ${i18n.t('使用量')}: ${Math.round(usageBytes / (1024 * 1024))}MB / ${i18n.t('上限')}: ${Math.round(
    capacityBytes / (1024 * 1024)
  )}MB / ${i18n.t('出力')}: ${formatJstDisplayDateTime(exportAt.toISOString(), i18n)}`;

  for (let index = 0; index < photos.length; index += 1) {
    const photo = photos[index];
    const page = pdfDoc.addPage([PDF_PAGE_WIDTH, PDF_PAGE_HEIGHT]);
    const layout = resolveExportSlideLayout({ width: 640, height: 480 });
    const comments = Array.isArray(photo.comments) ? photo.comments : [];
    const commentLines = comments.map((comment, lineIndex) => {
      const stampedBy = `${formatJstDisplayDateTime(comment.createdAt, i18n)} ${comment.createdByName || comment.createdBy || 'unknown'}`;
      return `${lineIndex + 1}. ${comment.text}\n${stampedBy}`;
    });

    page.drawRectangle({ x: 0, y: 0, width: PDF_PAGE_WIDTH, height: PDF_PAGE_HEIGHT, color: hexToRgbColor(PALETTE.bg) });
    page.drawRectangle({
      x: pptUnit(0.55),
      y: PDF_PAGE_HEIGHT - pptUnit(0.72),
      width: pptUnit(1.9),
      height: pptUnit(0.34),
      color: hexToRgbColor(PALETTE.brandSoft),
      borderColor: hexToRgbColor('BFD2B7'),
      borderWidth: 1,
    });
    page.drawText(i18n.t('監査レポート'), {
      x: pptUnit(0.82),
      y: PDF_PAGE_HEIGHT - pptUnit(0.58),
      size: 10,
      font: jpFont,
      color: hexToRgbColor(PALETTE.brandText),
    });
    drawMixedPdfText(page, `${folder.folderCode || 'F000'} ${folder.title}`, {
      x: pptUnit(0.55),
      y: PDF_PAGE_HEIGHT - pptUnit(1.18),
      size: 21,
      jpFont,
      latinFont,
      color: hexToRgbColor(PALETTE.ink),
    });
    drawMixedPdfText(page, `${photo.photoCode || '-'} ${photo.fileName || photo.photoId}`, {
      x: pptUnit(0.55),
      y: PDF_PAGE_HEIGHT - pptUnit(1.44),
      size: 11,
      jpFont,
      latinFont,
      color: hexToRgbColor(PALETTE.muted),
    });

    page.drawRectangle({
      x: pptUnit(layout.image.x),
      y: PDF_PAGE_HEIGHT - pptUnit(layout.image.y + layout.image.h),
      width: pptUnit(layout.image.w),
      height: pptUnit(layout.image.h),
      color: hexToRgbColor(PALETTE.card),
      borderColor: hexToRgbColor(PALETTE.line),
      borderWidth: 1,
    });
    drawDemoImagePlaceholder(page, photo, layout.image, jpFont, latinFont, i18n);

    page.drawRectangle({
      x: pptUnit(layout.comments.x),
      y: PDF_PAGE_HEIGHT - pptUnit(layout.comments.y + layout.comments.h),
      width: pptUnit(layout.comments.w),
      height: pptUnit(layout.comments.h),
      color: hexToRgbColor(PALETTE.card),
      borderColor: hexToRgbColor(PALETTE.line),
      borderWidth: 1,
    });
    page.drawText(i18n.t('コメント'), {
      x: pptUnit(layout.comments.x + 0.2),
      y: PDF_PAGE_HEIGHT - pptUnit(layout.comments.y + 0.28),
      size: 11,
      font: jpFont,
      color: hexToRgbColor(PALETTE.brandText),
    });
    const wrappedCommentLines = wrapPdfText(
      commentLines.length ? commentLines.join('\n\n') : i18n.t('コメントなし'),
      pptUnit(layout.comments.w - 0.4),
      10,
      jpFont,
      latinFont
    );
    let cursorY = PDF_PAGE_HEIGHT - pptUnit(layout.comments.y + 0.52);
    for (const line of wrappedCommentLines) {
      if (cursorY < PDF_PAGE_HEIGHT - pptUnit(layout.comments.y + layout.comments.h - 0.2)) break;
      drawMixedPdfText(page, line || ' ', {
        x: pptUnit(layout.comments.x + 0.2),
        y: cursorY,
        size: 10,
        jpFont,
        latinFont,
        color: hexToRgbColor('333333'),
      });
      cursorY -= 13;
    }
    drawMixedPdfText(page, `${footerSummary} / ${index + 1}/${photos.length}`, {
      x: pptUnit(0.58),
      y: PDF_PAGE_HEIGHT - pptUnit(7.02),
      size: 8,
      jpFont,
      latinFont,
      color: hexToRgbColor(PALETTE.muted),
    });
  }

  return Buffer.from(await pdfDoc.save());
}

function formatJstCompactTimestamp(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(date);
  const get = (type) => parts.find((part) => part.type === type)?.value || '';
  return `${get('year')}${get('month')}${get('day')}${get('hour')}${get('minute')}`;
}

function formatJstDisplayDateTime(value, i18n = createExportI18n('ja')) {
  if (!value) return i18n.t('日時不明');
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return i18n.t('日時不明');
  const parts = new Intl.DateTimeFormat(i18n.locale, {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(date);
  const get = (type) => parts.find((part) => part.type === type)?.value || '';
  return `${get('year')}/${get('month')}/${get('day')} ${get('hour')}:${get('minute')} JST`;
}

function sanitizeDownloadFileName(value, fallback = 'folder') {
  const normalized = String(value || '')
    .normalize('NFKC')
    .replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[. ]+$/g, '');
  return normalized || fallback;
}

function normalizeImageData(uri) {
  const value = String(uri || '');
  if (!value.startsWith('data:image/svg+xml')) return value;
  const commaIndex = value.indexOf(',');
  if (commaIndex < 0) return value;
  const payload = value.slice(commaIndex + 1);
  const svgText = decodeURIComponent(payload);
  return `data:image/svg+xml;base64,${Buffer.from(svgText, 'utf8').toString('base64')}`;
}

function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--room') result.roomId = argv[i + 1];
    if (arg === '--folder') result.folderId = argv[i + 1];
    if (arg === '--out') result.out = argv[i + 1];
    if (arg === '--format') result.format = argv[i + 1];
    if (arg === '--language') result.language = argv[i + 1];
  }
  return result;
}

async function main() {
  const { createDemoStore, DEMO_PLAN_BYTES } = await import(path.resolve(__dirname, './demo-seed.mjs'));
  const args = parseArgs(process.argv.slice(2));
  const language = normalizeLanguage(args.language || process.env.KANSA_LANGUAGE || 'ja');
  const i18n = createExportI18n(language);
  const store = createDemoStore();
  const roomId = args.roomId || store.activeRoomId || store.rooms[0]?.roomId;
  const room = store.rooms.find((item) => item.roomId === roomId);
  if (!room) throw new Error(`room not found: ${roomId}`);
  const folderId = args.folderId || room.folders[0]?.folderId;
  const folder = room.folders.find((item) => item.folderId === folderId);
  if (!folder) throw new Error(`folder not found: ${folderId}`);

  const currentPlan = String(room.subscriptionPlan || 'FREE').toUpperCase();
  const isFreePlan = currentPlan === 'FREE';
  const exportAt = new Date();
  const exportStamp = formatJstCompactTimestamp(exportAt);
  const format = String(args.format || 'pptx_high').toLowerCase();
  const languageSuffix = language === 'ja' ? '' : `-${language.toLowerCase()}`;
  const defaultOut =
    format === 'pdf'
      ? path.resolve(__dirname, `./demo-assets/demo-export-sample${languageSuffix}.pdf`)
      : format === 'pptx_light'
        ? path.resolve(__dirname, `./demo-assets/demo-export-light-sample${languageSuffix}.pptx`)
        : path.resolve(__dirname, `./demo-assets/demo-export-high-sample${languageSuffix}.pptx`);
  const outPath = args.out ? path.resolve(process.cwd(), args.out) : defaultOut;
  if (format === 'pdf') {
    const pdfBuffer = await buildDemoPdf({
      folder,
      photos: folder.photos,
      currentPlan,
      usageBytes: room.billing?.usageBytes || 0,
      capacityBytes: DEMO_PLAN_BYTES[currentPlan] || DEMO_PLAN_BYTES.FREE,
      i18n,
    });
    fs.writeFileSync(outPath, pdfBuffer);
  } else {
    const pptx = await buildExportPresentation({
      folder,
      photos: folder.photos,
      isFreePlanExport: isFreePlan,
      resolveImage: async (photo) => ({
        data: normalizeImageData(photo.previewUrl || photo.viewUrl),
        dimensions: { width: 640, height: 480 },
      }),
      resolveCommentLines: async (photo) => {
        const comments = Array.isArray(photo.comments) ? photo.comments : [];
        return comments.map((comment, index) => {
          const stampedBy = `${formatJstDisplayDateTime(comment.createdAt, i18n)} ${comment.createdByName || comment.createdBy || 'unknown'}`;
          return `${index + 1}. ${comment.text}\n${stampedBy}`;
        });
      },
      buildFooterText: (_photo, index, total) =>
        `${i18n.t('プラン')}: ${currentPlan} / ${i18n.t('使用量')}: ${Math.round((room.billing?.usageBytes || 0) / (1024 * 1024))}MB / ${i18n.t('上限')}: ${Math.round((DEMO_PLAN_BYTES[currentPlan] || DEMO_PLAN_BYTES.FREE) / (1024 * 1024))}MB / ${index + 1}/${total}`,
      i18n,
    });
    await pptx.writeFile({ fileName: outPath });
  }
  const safeTitle = sanitizeDownloadFileName(folder.title, 'folder');
  console.log(`generated: ${outPath}`);
  console.log(`suggested-name: ${safeTitle}_${exportStamp}.${format === 'pdf' ? 'pdf' : 'pptx'}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
