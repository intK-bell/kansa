const path = require('node:path');
const PptxGenJS = require('pptxgenjs');
const { createExportI18n } = require('./export-i18n');

const PPT_WATERMARK_PATH = path.resolve(__dirname, 'favicon.png');

const PALETTE = {
  bg: 'F8FBF6',
  card: 'FFFFFF',
  soft: 'EEF5EA',
  line: 'D8E0D2',
  brand: '7BAF6A',
  brandSoft: 'E8F2E2',
  brandText: '5F8D52',
  ink: '1F2937',
  muted: '6B7280',
};

function resolveExportSlideLayout(dimensions) {
  const width = Number(dimensions?.width || 0);
  const height = Number(dimensions?.height || 0);
  const isPortrait = width > 0 && height > width;
  if (isPortrait) {
    return {
      image: { x: 0.6, y: 1.55, w: 4.9, h: 5.2 },
      comments: { x: 5.8, y: 1.55, w: 6.45, h: 5.2 },
    };
  }
  return {
    image: { x: 0.55, y: 1.55, w: 7.6, h: 4.9 },
    comments: { x: 8.45, y: 1.55, w: 3.85, h: 4.9 },
  };
}

function addFreePlanWatermarks(slide, imageBox) {
  const cols = 3;
  const rows = 2;
  const cellW = imageBox.w / cols;
  const cellH = imageBox.h / rows;
  const markW = Math.min(1.35, cellW * 0.68);
  const markH = Math.min(1.35, cellH * 0.68);
  for (let row = 0; row < rows; row += 1) {
    for (let col = 0; col < cols; col += 1) {
      const centerX = imageBox.x + cellW * col + cellW / 2;
      const centerY = imageBox.y + cellH * row + cellH / 2;
      slide.addImage({
        path: PPT_WATERMARK_PATH,
        x: centerX - markW / 2,
        y: centerY - markH / 2,
        w: markW,
        h: markH,
        transparency: 72,
      });
    }
  }
}

function createPresentation(i18n = createExportI18n('ja')) {
  const pptx = new PptxGenJS();
  pptx.layout = 'LAYOUT_WIDE';
  pptx.author = i18n.t('Photo Hub for 監査');
  pptx.company = i18n.t('Photo Hub for 監査');
  pptx.subject = 'Folder export';
  pptx.lang = i18n.locale;
  return pptx;
}

async function addExportPhotoSlide(pptx, options) {
  const {
    folder,
    photo,
    isFreePlanExport,
    resolveImage,
    resolveCommentLines,
    footerText,
    i18n = createExportI18n('ja'),
  } = options;
  const slide = pptx.addSlide();
  slide.background = { color: PALETTE.bg };

  slide.addShape(pptx.ShapeType.roundRect, {
    x: 0.55,
    y: 0.38,
    w: 1.9,
    h: 0.34,
    rectRadius: 0.08,
    fill: { color: PALETTE.brandSoft },
    line: { color: 'BFD2B7', pt: 1 },
  });
  slide.addText(i18n.t('監査レポート'), {
    x: 0.82,
    y: 0.45,
    w: 1.35,
    h: 0.12,
    fontFace: 'Yu Gothic',
    fontSize: 10,
    bold: true,
    color: PALETTE.brandText,
  });

  slide.addText(`${folder.folderCode || 'F000'} ${folder.title}`, {
    x: 0.55,
    y: 0.9,
    w: 8.2,
    h: 0.34,
    fontFace: 'Yu Gothic',
    fontSize: 21,
    bold: true,
    color: PALETTE.ink,
  });
  slide.addText(`${photo.photoCode || '-'} ${photo.fileName || photo.photoId}`, {
    x: 0.55,
    y: 1.23,
    w: 7.8,
    h: 0.22,
    fontFace: 'Yu Gothic',
    fontSize: 11,
    color: PALETTE.muted,
  });

  const image = await resolveImage(photo);
  const layout = resolveExportSlideLayout(image?.dimensions || null);

  slide.addShape(pptx.ShapeType.roundRect, {
    x: layout.image.x,
    y: layout.image.y,
    w: layout.image.w,
    h: layout.image.h,
    rectRadius: 0.05,
    fill: { color: PALETTE.card },
    line: { color: PALETTE.line, pt: 1 },
  });
  slide.addImage({
    ...(image?.path ? { path: image.path } : {}),
    ...(image?.data ? { data: image.data } : {}),
    x: layout.image.x,
    y: layout.image.y,
    w: layout.image.w,
    h: layout.image.h,
    sizing: { type: 'contain', x: layout.image.x, y: layout.image.y, w: layout.image.w, h: layout.image.h },
  });
  if (isFreePlanExport) {
    addFreePlanWatermarks(slide, layout.image);
  }

  slide.addShape(pptx.ShapeType.roundRect, {
    x: layout.comments.x,
    y: layout.comments.y,
    w: layout.comments.w,
    h: layout.comments.h,
    rectRadius: 0.05,
    fill: { color: PALETTE.card },
    line: { color: PALETTE.line, pt: 1 },
  });
  slide.addText(i18n.t('コメント'), {
    x: layout.comments.x + 0.2,
    y: layout.comments.y + 0.16,
    w: 1.3,
    h: 0.16,
    fontFace: 'Yu Gothic',
    fontSize: 11,
    bold: true,
    color: PALETTE.brandText,
  });

  const lines = await resolveCommentLines(photo);
  slide.addText(lines.length ? lines.join('\n\n') : i18n.t('コメントなし'), {
    x: layout.comments.x + 0.2,
    y: layout.comments.y + 0.46,
    w: layout.comments.w - 0.4,
    h: layout.comments.h - 0.78,
    fontFace: 'Yu Gothic',
    fontSize: 10,
    color: '333333',
    valign: 'top',
    margin: 0,
    breakLine: false,
  });

  slide.addShape(pptx.ShapeType.line, {
    x: 0.55,
    y: 6.82,
    w: 11.2,
    h: 0,
    line: { color: PALETTE.line, pt: 1 },
  });
  slide.addText(footerText || '', {
    x: 0.58,
    y: 6.88,
    w: 10.8,
    h: 0.16,
    fontFace: 'Yu Gothic',
    fontSize: 8,
    color: PALETTE.muted,
  });
}

async function buildExportPresentation(options) {
  const {
    folder,
    photos,
    isFreePlanExport,
    resolveImage,
    resolveCommentLines,
    buildFooterText,
    i18n: inputI18n,
  } = options;
  const i18n = inputI18n || createExportI18n('ja');
  const pptx = createPresentation(i18n);
  for (let index = 0; index < photos.length; index += 1) {
    const photo = photos[index];
    await addExportPhotoSlide(pptx, {
      folder,
      photo,
      isFreePlanExport,
      resolveImage,
      resolveCommentLines,
      footerText: typeof buildFooterText === 'function' ? buildFooterText(photo, index, photos.length) : '',
      i18n,
    });
  }
  return pptx;
}

module.exports = {
  PALETTE,
  PPT_WATERMARK_PATH,
  buildExportPresentation,
  resolveExportSlideLayout,
  addFreePlanWatermarks,
};
