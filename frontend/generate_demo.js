const path = require('path');
const PptxGenJS = require('../backend/src/node_modules/pptxgenjs');

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

function formatJstDisplayDateTime(value) {
  if (!value) return '日時不明';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '日時不明';
  const parts = new Intl.DateTimeFormat('ja-JP', {
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

function resolveExportSlideLayout(dimensions) {
  const width = Number(dimensions?.width || 0);
  const height = Number(dimensions?.height || 0);
  const isPortrait = width > 0 && height > width;
  if (isPortrait) {
    return {
      image: { x: 0.6, y: 1.15, w: 5.1, h: 5.75 },
      comments: { x: 5.95, y: 1.15, w: 6.75, h: 5.75 },
    };
  }
  return {
    image: { x: 0.5, y: 1.15, w: 8.3, h: 5.2 },
    comments: { x: 9.0, y: 1.15, w: 3.8, h: 5.2 },
  };
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

function addFreePlanWatermarks(slide, imageBox) {
  for (let row = 0; row < 2; row += 1) {
    for (let col = 0; col < 3; col += 1) {
      slide.addText('FREE', {
        x: imageBox.x + col * (imageBox.w / 3) + 0.35,
        y: imageBox.y + row * (imageBox.h / 2) + 0.9,
        w: 1.1,
        h: 0.25,
        fontFace: 'Yu Gothic',
        fontSize: 18,
        bold: true,
        color: 'FFFFFF',
        transparency: 55,
        rotate: 330,
        align: 'center',
      });
    }
  }
}

function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--room') result.roomId = argv[i + 1];
    if (arg === '--folder') result.folderId = argv[i + 1];
    if (arg === '--out') result.out = argv[i + 1];
  }
  return result;
}

async function main() {
  const { createDemoStore, DEMO_PLAN_BYTES } = await import(path.resolve(__dirname, './demo-seed.mjs'));
  const args = parseArgs(process.argv.slice(2));
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
  const defaultOut = path.resolve(__dirname, './demo-assets/demo-export-sample.pptx');
  const outPath = args.out ? path.resolve(process.cwd(), args.out) : defaultOut;

  const pptx = new PptxGenJS();
  pptx.layout = 'LAYOUT_WIDE';
  pptx.author = 'generate_demo.js';
  pptx.company = 'Photo Hub for 監査';
  pptx.subject = 'Demo export';
  pptx.title = `${folder.title} demo export`;
  pptx.lang = 'ja-JP';

  for (const photo of folder.photos) {
    const slide = pptx.addSlide();
    slide.background = { color: 'F8FBF6' };
    slide.addText(`${folder.folderCode || 'F000'} ${folder.title}`, {
      x: 0.5,
      y: 0.2,
      w: 12,
      h: 0.4,
      fontFace: 'Yu Gothic',
      fontSize: 16,
      bold: true,
      color: '1F2937',
    });
    slide.addText(`${photo.photoCode || '-'} ${photo.fileName || photo.photoId}`, {
      x: 0.5,
      y: 0.7,
      w: 12,
      h: 0.3,
      fontFace: 'Yu Gothic',
      fontSize: 11,
      color: '4B5563',
    });

    const layout = resolveExportSlideLayout({ width: 640, height: 480 });
    slide.addShape(pptx.ShapeType.roundRect, {
      x: layout.image.x,
      y: layout.image.y,
      w: layout.image.w,
      h: layout.image.h,
      rectRadius: 0.04,
      line: { color: 'D8E0D2', pt: 1 },
      fill: { color: 'FFFFFF' },
    });
    slide.addImage({
      data: normalizeImageData(photo.previewUrl || photo.viewUrl),
      x: layout.image.x,
      y: layout.image.y,
      w: layout.image.w,
      h: layout.image.h,
      sizing: { type: 'contain', x: layout.image.x, y: layout.image.y, w: layout.image.w, h: layout.image.h },
    });
    if (isFreePlan) {
      addFreePlanWatermarks(slide, layout.image);
    }

    const comments = Array.isArray(photo.comments) ? photo.comments : [];
    const commentLines = comments.map((comment, index) => {
      const stampedBy = `${formatJstDisplayDateTime(comment.createdAt)} ${comment.createdByName || comment.createdBy || 'unknown'}`;
      return `${index + 1}. ${comment.text}\n${stampedBy}`;
    });

    slide.addShape(pptx.ShapeType.roundRect, {
      x: layout.comments.x,
      y: layout.comments.y,
      w: layout.comments.w,
      h: layout.comments.h,
      rectRadius: 0.04,
      line: { color: 'D8E0D2', pt: 1 },
      fill: { color: 'FFFFFF' },
    });
    slide.addText(commentLines.length ? commentLines.join('\n\n') : 'コメントなし', {
      x: layout.comments.x + 0.16,
      y: layout.comments.y + 0.16,
      w: layout.comments.w - 0.32,
      h: layout.comments.h - 0.32,
      fontFace: 'Yu Gothic',
      fontSize: 10,
      valign: 'top',
      color: '333333',
      breakLine: false,
      margin: 0,
    });
    slide.addText(`プラン: ${currentPlan} / 使用量: ${Math.round((room.billing?.usageBytes || 0) / (1024 * 1024))}MB / 上限: ${Math.round((DEMO_PLAN_BYTES[currentPlan] || DEMO_PLAN_BYTES.FREE) / (1024 * 1024))}MB`, {
      x: 0.5,
      y: 6.65,
      w: 6.8,
      h: 0.2,
      fontFace: 'Yu Gothic',
      fontSize: 8,
      color: '6B7280',
    });
  }

  await pptx.writeFile({ fileName: outPath });
  const safeTitle = sanitizeDownloadFileName(folder.title, 'folder');
  console.log(`generated: ${outPath}`);
  console.log(`suggested-name: ${safeTitle}_${exportStamp}.pptx`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
