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
    フォトスマ: 'Cong',
    フォトスマレポート: 'Cong report',
    Congレポート: 'Cong report',
    'Cong Report': 'Cong Report',
    コンテナ番号: 'Container number',
    タグ: 'Tag',
    搬入: 'Gate in',
    搬出: 'Gate out',
    シール: 'Seal',
    損傷: 'Damage',
    その他: 'Other',
    クエスト: 'Quest',
    港湾デモ管理者: 'Port demo admin',
    ゲート担当: 'Gate staff',
    シール確認担当: 'Seal checker',
    損傷確認担当: 'Damage checker',
    ヤード担当: 'Yard staff',
    事務所確認者: 'Office checker',
    'コンテナ番号を確認済み。': 'Container number confirmed.',
    'ゲート受付時の番号照合OK。': 'Number check at gate reception OK.',
    '搬入時の外観を記録済み。': 'Exterior at gate-in recorded.',
    'シール番号の視認性問題なし。': 'Seal number is clearly visible.',
    '右側面に擦過あり。搬入時点の証跡として保存。': 'Scratch on right side. Saved as gate-in evidence.',
    '搬出前の外観を確認済み。': 'Exterior before gate-out confirmed.',
    'ドライバー連絡用の補足写真。': 'Supplementary photo for driver communication.',
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
    '・フォルダの数が2つ以下': '- Container count must be 2 or less',
    '・コンテナの数が2つ以下': '- Container count must be 2 or less',
    '・現在の容量: {bytes} bytes': '- Current storage: {bytes} bytes',
    '・現在のフォルダ数: {count}': '- Current container count: {count}',
    '・現在のコンテナ数: {count}': '- Current container count: {count}',
    '課金停止の確認に失敗したため、お部屋を削除できませんでした。時間をおいて再度お試しください。':
      'Could not delete the room because billing cancellation could not be confirmed. Please try again later.',
    'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
      'The Free plan allows up to 2 containers. Paid plans allow unlimited containers.',
    'フリープランではコンテナは2つまでです。有料プランで無制限になります。':
      'The Free plan allows up to 2 containers. Paid plans allow unlimited containers.',
    '30日を過ぎた写真はアーカイブ済みのため、フリープランではPPT出力できません。':
      'Photos older than 30 days are archived, so PPT export is not available on the Free plan.',
    出力できる写真がありません: 'There are no photos available for export.',
  },
  'zh-CN': {
    フォトスマ: 'Cong',
    フォトスマレポート: 'Cong 报告',
    Congレポート: 'Cong 报告',
    'Cong Report': 'Cong 报告',
    コンテナ番号: '集装箱编号',
    タグ: '标签',
    搬入: '进场',
    搬出: '出场',
    シール: '封条',
    損傷: '损伤',
    その他: '其他',
    クエスト: '任务',
    港湾デモ管理者: '港口演示管理员',
    ゲート担当: '闸口担当',
    シール確認担当: '封条确认担当',
    損傷確認担当: '损伤确认担当',
    ヤード担当: '堆场担当',
    事務所確認者: '办公室确认者',
    'コンテナ番号を確認済み。': '集装箱编号已确认。',
    'ゲート受付時の番号照合OK。': '闸口受理时编号核对 OK。',
    '搬入時の外観を記録済み。': '进场时外观已记录。',
    'シール番号の視認性問題なし。': '封条编号可视性无问题。',
    '右側面に擦過あり。搬入時点の証跡として保存。': '右侧面有擦痕。已作为进场时证据保存。',
    '搬出前の外観を確認済み。': '出场前外观已确认。',
    'ドライバー連絡用の補足写真。': '用于司机联系的补充照片。',
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
    '・フォルダの数が2つ以下': '- 集装箱数量必须不超过 2 个',
    '・コンテナの数が2つ以下': '- 集装箱数量必须不超过 2 个',
    '・現在の容量: {bytes} bytes': '- 当前容量：{bytes} bytes',
    '・現在のフォルダ数: {count}': '- 当前集装箱数：{count}',
    '・現在のコンテナ数: {count}': '- 当前集装箱数：{count}',
    '課金停止の確認に失敗したため、お部屋を削除できませんでした。時間をおいて再度お試しください。':
      '由于无法确认计费停止，未能删除房间。请稍后重试。',
    'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
      '免费计划最多可创建 2 个集装箱。付费计划可无限创建。',
    'フリープランではコンテナは2つまでです。有料プランで無制限になります。':
      '免费计划最多可创建 2 个集装箱。付费计划可无限创建。',
    '30日を過ぎた写真はアーカイブ済みのため、フリープランではPPT出力できません。':
      '超过 30 天的照片已归档，免费计划无法导出 PPT。',
    出力できる写真がありません: '没有可导出的照片。',
  },
  vi: {
    フォトスマ: 'Cong',
    フォトスマレポート: 'Báo cáo Cong',
    Congレポート: 'Báo cáo Cong',
    'Cong Report': 'Báo cáo Cong',
    コンテナ番号: 'Số container',
    タグ: 'Thẻ',
    搬入: 'Nhập bãi',
    搬出: 'Xuất bãi',
    シール: 'Seal',
    損傷: 'Hư hỏng',
    その他: 'Khác',
    クエスト: 'Quest',
    港湾デモ管理者: 'Quản trị demo cảng',
    ゲート担当: 'Nhân viên cổng',
    シール確認担当: 'Nhân viên kiểm tra seal',
    損傷確認担当: 'Nhân viên kiểm tra hư hỏng',
    ヤード担当: 'Nhân viên bãi',
    事務所確認者: 'Người kiểm tra văn phòng',
    'コンテナ番号を確認済み。': 'Đã xác nhận số container.',
    'ゲート受付時の番号照合OK。': 'Đối chiếu số tại cổng OK.',
    '搬入時の外観を記録済み。': 'Đã ghi nhận ngoại quan khi nhập bãi.',
    'シール番号の視認性問題なし。': 'Số seal hiển thị rõ.',
    '右側面に擦過あり。搬入時点の証跡として保存。': 'Có vết xước ở mặt phải. Đã lưu làm bằng chứng khi nhập bãi.',
    '搬出前の外観を確認済み。': 'Đã xác nhận ngoại quan trước khi xuất bãi.',
    'ドライバー連絡用の補足写真。': 'Ảnh bổ sung để liên hệ tài xế.',
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
    '・フォルダの数が2つ以下': '- Số container phải từ 2 trở xuống',
    '・コンテナの数が2つ以下': '- Số container phải từ 2 trở xuống',
    '・現在の容量: {bytes} bytes': '- Dung lượng hiện tại: {bytes} bytes',
    '・現在のフォルダ数: {count}': '- Số container hiện tại: {count}',
    '・現在のコンテナ数: {count}': '- Số container hiện tại: {count}',
    '課金停止の確認に失敗したため、お部屋を削除できませんでした。時間をおいて再度お試しください。':
      'Không thể xóa phòng vì chưa xác nhận được việc dừng thanh toán. Vui lòng thử lại sau.',
    'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
      'Gói miễn phí cho phép tối đa 2 container. Gói trả phí không giới hạn container.',
    'フリープランではコンテナは2つまでです。有料プランで無制限になります。':
      'Gói miễn phí cho phép tối đa 2 container. Gói trả phí không giới hạn container.',
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
