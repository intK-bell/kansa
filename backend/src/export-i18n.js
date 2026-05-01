const LANGUAGE_ALIASES = {
  en: 'en',
  ja: 'ja',
  vi: 'vi',
  zh: 'zh-CN',
  'zh-cn': 'zh-CN',
  'zh-hans': 'zh-CN',
  'zh-sg': 'zh-CN',
};

const TRANSLATIONS = {
  en: {
    'Photo Hub for 監査': 'Photo Hub for Audit',
    監査レポート: 'Audit report',
    コメント: 'Comments',
    コメントなし: 'No comments',
    デモ画像: 'Demo image',
    日時不明: 'Unknown date/time',
    軽量PPT: 'Light PPT',
    高画質PPT: 'High-quality PPT',
    形式: 'Format',
    プラン: 'Plan',
    使用量: 'Used',
    上限: 'Limit',
    出力: 'Exported',
  },
  'zh-CN': {
    'Photo Hub for 監査': '审计 Photo Hub',
    監査レポート: '审计报告',
    コメント: '评论',
    コメントなし: '无评论',
    デモ画像: '演示图片',
    日時不明: '日期时间不明',
    軽量PPT: '轻量 PPT',
    高画質PPT: '高画质 PPT',
    形式: '格式',
    プラン: '计划',
    使用量: '已用',
    上限: '上限',
    出力: '导出',
  },
  vi: {
    'Photo Hub for 監査': 'Photo Hub cho kiểm toán',
    監査レポート: 'Báo cáo kiểm toán',
    コメント: 'Bình luận',
    コメントなし: 'Không có bình luận',
    デモ画像: 'Ảnh demo',
    日時不明: 'Không rõ ngày giờ',
    軽量PPT: 'PPT nhẹ',
    高画質PPT: 'PPT chất lượng cao',
    形式: 'Định dạng',
    プラン: 'Gói',
    使用量: 'Đã dùng',
    上限: 'Giới hạn',
    出力: 'Đã xuất',
  },
};

function normalizeLanguage(value) {
  const raw = String(value || '').trim();
  if (!raw) return 'ja';
  const parts = raw
    .split(',')
    .map((part) => part.split(';')[0].trim())
    .filter(Boolean);
  for (const part of parts) {
    const exact = LANGUAGE_ALIASES[part.toLowerCase()];
    if (exact) return exact;
    const base = part.split('-')[0].toLowerCase();
    if (LANGUAGE_ALIASES[base]) return LANGUAGE_ALIASES[base];
  }
  return 'ja';
}

function languageFromHeaders(headers = {}) {
  const custom = headers['x-kansa-language'] || headers['X-Kansa-Language'];
  if (custom) return normalizeLanguage(custom);
  return normalizeLanguage(headers['accept-language'] || headers['Accept-Language']);
}

function localeForLanguage(language) {
  if (language === 'en') return 'en-US';
  if (language === 'zh-CN') return 'zh-CN';
  if (language === 'vi') return 'vi-VN';
  return 'ja-JP';
}

function createExportI18n(languageInput) {
  const language = normalizeLanguage(languageInput);
  const dictionary = TRANSLATIONS[language] || {};
  return {
    language,
    locale: localeForLanguage(language),
    t(key) {
      return dictionary[key] || key;
    },
  };
}

module.exports = {
  createExportI18n,
  languageFromHeaders,
  normalizeLanguage,
};
