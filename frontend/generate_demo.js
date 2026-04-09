const path = require('path');
const { buildExportPresentation } = require('../backend/src/ppt-layout');

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
        const stampedBy = `${formatJstDisplayDateTime(comment.createdAt)} ${comment.createdByName || comment.createdBy || 'unknown'}`;
        return `${index + 1}. ${comment.text}\n${stampedBy}`;
      });
    },
    buildFooterText: (_photo, index, total) =>
      `プラン: ${currentPlan} / 使用量: ${Math.round((room.billing?.usageBytes || 0) / (1024 * 1024))}MB / 上限: ${Math.round((DEMO_PLAN_BYTES[currentPlan] || DEMO_PLAN_BYTES.FREE) / (1024 * 1024))}MB / ${index + 1}/${total}`,
  });

  await pptx.writeFile({ fileName: outPath });
  const safeTitle = sanitizeDownloadFileName(folder.title, 'folder');
  console.log(`generated: ${outPath}`);
  console.log(`suggested-name: ${safeTitle}_${exportStamp}.pptx`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
