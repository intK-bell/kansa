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
    'フリープランへの切り替えは、以下を満たす必要があります。': 'To switch to the Free plan, these requirements must be met.',
    '・容量が512MB未満': '- Storage must be under 512 MB',
    '・フォルダの数が2つ以下': '- Folder count must be 2 or less',
    '・現在の容量: {bytes} bytes': '- Current storage: {bytes} bytes',
    '・現在のフォルダ数: {count}': '- Current folder count: {count}',
    '課金停止の確認に失敗したため、お部屋を削除できませんでした。時間をおいて再度お試しください。':
      'Could not delete the room because billing cancellation could not be confirmed. Please try again later.',
    'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
      'The Free plan allows up to 2 folders. Paid plans allow unlimited folders.',
    '30日を過ぎた写真はアーカイブ済みのため、フリープランではPPT出力できません。':
      'Photos older than 30 days are archived, so PPT export is not available on the Free plan.',
    出力できる写真がありません: 'There are no photos available for export.',
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
    'フリープランへの切り替えは、以下を満たす必要があります。': '切换到免费计划需要满足以下条件。',
    '・容量が512MB未満': '- 容量必须小于 512 MB',
    '・フォルダの数が2つ以下': '- 文件夹数量必须不超过 2 个',
    '・現在の容量: {bytes} bytes': '- 当前容量：{bytes} bytes',
    '・現在のフォルダ数: {count}': '- 当前文件夹数：{count}',
    '課金停止の確認に失敗したため、お部屋を削除できませんでした。時間をおいて再度お試しください。':
      '由于无法确认计费停止，未能删除房间。请稍后重试。',
    'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
      '免费计划最多可创建 2 个文件夹。付费计划可无限创建。',
    '30日を過ぎた写真はアーカイブ済みのため、フリープランではPPT出力できません。':
      '超过 30 天的照片已归档，免费计划无法导出 PPT。',
    出力できる写真がありません: '没有可导出的照片。',
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
    'フリープランへの切り替えは、以下を満たす必要があります。':
      'Để chuyển sang gói miễn phí, cần đáp ứng các điều kiện sau.',
    '・容量が512MB未満': '- Dung lượng phải dưới 512 MB',
    '・フォルダの数が2つ以下': '- Số thư mục phải từ 2 trở xuống',
    '・現在の容量: {bytes} bytes': '- Dung lượng hiện tại: {bytes} bytes',
    '・現在のフォルダ数: {count}': '- Số thư mục hiện tại: {count}',
    '課金停止の確認に失敗したため、お部屋を削除できませんでした。時間をおいて再度お試しください。':
      'Không thể xóa phòng vì chưa xác nhận được việc dừng thanh toán. Vui lòng thử lại sau.',
    'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
      'Gói miễn phí cho phép tối đa 2 thư mục. Gói trả phí không giới hạn thư mục.',
    '30日を過ぎた写真はアーカイブ済みのため、フリープランではPPT出力できません。':
      'Ảnh quá 30 ngày đã được lưu trữ, nên gói miễn phí không thể xuất PPT.',
    出力できる写真がありません: 'Không có ảnh nào có thể xuất.',
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
    format(key, values = {}) {
      return (dictionary[key] || key).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) =>
        Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : match
      );
    },
  };
}

module.exports = {
  createExportI18n,
  languageFromHeaders,
  normalizeLanguage,
};
