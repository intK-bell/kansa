export const DEMO_USER_KEY = 'demo-user';

export const DEMO_PLAN_BYTES = {
  FREE: 512 * 1024 * 1024,
  BASIC: 1 * 1024 * 1024 * 1024,
  PLUS: 5 * 1024 * 1024 * 1024,
  PRO: 10 * 1024 * 1024 * 1024,
};

export function demoNow(minutesAgo = 0) {
  return new Date(Date.now() - minutesAgo * 60 * 1000).toISOString();
}

export function demoSvg(label, toneA, toneB) {
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 480">
      <defs>
        <linearGradient id="g" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0%" stop-color="${toneA}" />
          <stop offset="100%" stop-color="${toneB}" />
        </linearGradient>
      </defs>
      <rect width="640" height="480" rx="32" fill="url(#g)" />
      <circle cx="510" cy="110" r="48" fill="rgba(255,255,255,0.34)" />
      <rect x="54" y="66" width="220" height="26" rx="13" fill="rgba(255,255,255,0.52)" />
      <rect x="54" y="104" width="168" height="18" rx="9" fill="rgba(255,255,255,0.42)" />
      <rect x="54" y="316" width="532" height="94" rx="24" fill="rgba(255,255,255,0.2)" />
      <text x="54" y="372" fill="#ffffff" font-size="38" font-family="'Zen Kaku Gothic New', sans-serif" font-weight="700">${label}</text>
    </svg>
  `;
  return `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(svg)}`;
}

export function createDemoPhoto(seed) {
  return {
    photoId: seed.photoId,
    photoCode: seed.photoCode,
    fileName: seed.fileName,
    createdBy: seed.createdBy || DEMO_USER_KEY,
    createdByName: seed.createdByName || '港湾デモ管理者',
    viewUrl: seed.viewUrl,
    previewUrl: seed.viewUrl,
    originalName: seed.originalName || seed.fileName,
    logTag: seed.logTag || 'container_number',
    questId: seed.questId || null,
    questText: seed.questText || '',
    questCode: seed.questCode || null,
    sizeBytes: seed.sizeBytes || 8 * 1024 * 1024,
    createdAt: seed.createdAt || demoNow(180),
    comments: (seed.comments || []).map((comment) => ({
      commentId: comment.commentId,
      text: comment.text,
      createdAt: comment.createdAt,
      updatedAt: comment.updatedAt || null,
      createdBy: comment.createdBy,
      createdByName: comment.createdByName,
    })),
  };
}

export function createDemoStore() {
  return {
    me: { userKey: DEMO_USER_KEY, displayName: '港湾デモ管理者' },
    activeRoomId: 'room-demo-1',
    inviteCounter: 1,
    roomCounter: 3,
    folderCounter: 5,
    photoCounter: 10,
    commentCounter: 10,
    questCounter: 2,
    questCommentCounter: 2,
    rooms: [
      {
        roomId: 'room-demo-1',
        roomName: '〇〇港運株式会社',
        currentUserRole: 'admin',
        memberStatus: 'active',
        subscriptionPlan: 'BASIC',
        inviteToken: null,
        members: [
          { userKey: DEMO_USER_KEY, displayName: '港湾デモ管理者', role: 'admin', status: 'active', folderScope: 'all' },
          { userKey: 'user-gate', displayName: 'ゲート担当', role: 'member', status: 'active', folderScope: 'all' },
          { userKey: 'user-yard', displayName: 'ヤード担当', role: 'member', status: 'active', folderScope: 'own' },
          { userKey: 'user-seal', displayName: 'シール確認担当', role: 'member', status: 'active', folderScope: 'invited', folderIds: ['folder-demo-1'] },
          { userKey: 'user-damage', displayName: '損傷確認担当', role: 'member', status: 'active', folderScope: 'invited', folderIds: ['folder-demo-1'] },
          { userKey: 'user-office', displayName: '事務所確認者', role: 'member', status: 'active', folderScope: 'invited', folderIds: ['folder-demo-1', 'folder-demo-4'] },
          { userKey: 'user-forwarder', displayName: '乙仲担当', role: 'member', status: 'active', folderScope: 'invited', folderIds: ['folder-demo-4'] },
        ],
        folders: [
          {
            folderId: 'folder-demo-4',
            folderCode: 'F-103',
            title: 'MSCU7654321',
            mode: 'quest',
            createdBy: DEMO_USER_KEY,
            createdByName: '港湾デモ管理者',
            hasPassword: false,
            password: '',
            quests: [
              {
                questId: 'quest-demo-1',
                questCode: 'F-103-Q001',
                folderId: 'folder-demo-4',
                folderCode: 'F-103',
                text: 'シール番号が読める写真を撮ってきて',
                status: 'done',
                createdBy: DEMO_USER_KEY,
                createdByName: '港湾デモ管理者',
                createdAt: demoNow(80),
                updatedAt: demoNow(40),
                comments: [
                  {
                    commentId: 'quest-comment-demo-1',
                    text: '扉まわりも少し入れてください。',
                    createdAt: demoNow(60),
                    createdBy: 'user-office',
                    createdByName: '事務所確認者',
                  },
                ],
              },
              {
                questId: 'quest-demo-2',
                questCode: 'F-103-Q002',
                folderId: 'folder-demo-4',
                folderCode: 'F-103',
                text: '右側面の損傷箇所が分かる写真を撮ってきて',
                status: 'open',
                createdBy: 'user-office',
                createdByName: '事務所確認者',
                createdAt: demoNow(25),
                updatedAt: demoNow(25),
                comments: [],
              },
            ],
            photos: [
              createDemoPhoto({
                photoId: 'photo-demo-8',
                photoCode: 'P-008',
                fileName: 'MSCU7654321_シール_001',
                logTag: 'seal',
                viewUrl: demoSvg('シール確認', '#7C4DFF', '#e7ddff'),
                sizeBytes: 8 * 1024 * 1024,
                questId: 'quest-demo-1',
                questText: 'シール番号が読める写真を撮ってきて',
                questCode: 'F-103-Q001',
                comments: [],
              }),
            ],
          },
          {
            folderId: 'folder-demo-1',
            folderCode: 'F-101',
            title: 'TCLU1234567',
            createdBy: DEMO_USER_KEY,
            createdByName: '港湾デモ管理者',
            hasPassword: false,
            password: '',
            photos: [
              createDemoPhoto({
                photoId: 'photo-demo-1',
                photoCode: 'P-001',
                fileName: 'TCLU1234567_コンテナ番号_001',
                logTag: 'container_number',
                viewUrl: demoSvg('コンテナ番号', '#06224A', '#dcecff'),
                sizeBytes: 14 * 1024 * 1024,
                comments: [
                  {
                    commentId: 'comment-demo-1',
                    text: 'コンテナ番号を確認済み。',
                    createdAt: demoNow(140),
                    createdBy: DEMO_USER_KEY,
                    createdByName: '港湾デモ管理者',
                  },
                  {
                    commentId: 'comment-demo-2',
                    text: 'ゲート受付時の番号照合OK。',
                    createdAt: demoNow(110),
                    createdBy: 'user-gate',
                    createdByName: 'ゲート担当',
                  },
                ],
              }),
              createDemoPhoto({
                photoId: 'photo-demo-2',
                photoCode: 'P-002',
                fileName: 'TCLU1234567_搬入_002',
                logTag: 'inbound',
                viewUrl: demoSvg('搬入記録', '#1E90FF', '#dcecff'),
                sizeBytes: 11 * 1024 * 1024,
                comments: [
                  {
                    commentId: 'comment-demo-3',
                    text: '搬入時の外観を記録済み。',
                    createdAt: demoNow(90),
                    createdBy: DEMO_USER_KEY,
                    createdByName: '港湾デモ管理者',
                  },
                ],
              }),
              createDemoPhoto({
                photoId: 'photo-demo-3',
                photoCode: 'P-003',
                fileName: 'TCLU1234567_シール_003',
                logTag: 'seal',
                viewUrl: demoSvg('シール確認', '#7C4DFF', '#e7ddff'),
                sizeBytes: 10 * 1024 * 1024,
                createdBy: 'user-seal',
                createdByName: 'シール確認担当',
                comments: [
                  {
                    commentId: 'comment-demo-4',
                    text: 'シール番号の視認性問題なし。',
                    createdAt: demoNow(70),
                    createdBy: 'user-seal',
                    createdByName: 'シール確認担当',
                  },
                ],
              }),
              createDemoPhoto({
                photoId: 'photo-demo-4',
                photoCode: 'P-004',
                fileName: 'TCLU1234567_損傷_004',
                logTag: 'damage',
                viewUrl: demoSvg('損傷確認', '#E53935', '#ffe0de'),
                sizeBytes: 9 * 1024 * 1024,
                createdBy: 'user-damage',
                createdByName: '損傷確認担当',
                comments: [
                  {
                    commentId: 'comment-demo-6',
                    text: '右側面に擦過あり。搬入時点の証跡として保存。',
                    createdAt: demoNow(55),
                    createdBy: 'user-damage',
                    createdByName: '損傷確認担当',
                  },
                ],
              }),
              createDemoPhoto({
                photoId: 'photo-demo-6',
                photoCode: 'P-005',
                fileName: 'TCLU1234567_搬出_005',
                logTag: 'outbound',
                viewUrl: demoSvg('搬出記録', '#2E7D32', '#d9f0df'),
                sizeBytes: 12 * 1024 * 1024,
                createdBy: 'user-yard',
                createdByName: 'ヤード担当',
                comments: [
                  {
                    commentId: 'comment-demo-7',
                    text: '搬出前の外観を確認済み。',
                    createdAt: demoNow(35),
                    createdBy: 'user-yard',
                    createdByName: 'ヤード担当',
                  },
                ],
              }),
              createDemoPhoto({
                photoId: 'photo-demo-7',
                photoCode: 'P-006',
                fileName: 'TCLU1234567_その他_006',
                logTag: 'other',
                viewUrl: demoSvg('その他記録', '#607D8B', '#dfe7eb'),
                sizeBytes: 6 * 1024 * 1024,
                createdBy: 'user-office',
                createdByName: '事務所確認者',
                comments: [
                  {
                    commentId: 'comment-demo-8',
                    text: 'ドライバー連絡用の補足写真。',
                    createdAt: demoNow(20),
                    createdBy: 'user-office',
                    createdByName: '事務所確認者',
                  },
                ],
              }),
            ],
          },
        ],
      },
      {
        roomId: 'room-demo-2',
        roomName: '△△コンテナ株式会社',
        currentUserRole: 'member',
        memberStatus: 'active',
        subscriptionPlan: 'FREE',
        inviteToken: null,
        members: [
          { userKey: 'user-moji-admin', displayName: '△△CY管理者', role: 'admin', status: 'active', folderScope: 'all' },
          { userKey: DEMO_USER_KEY, displayName: '港湾デモ管理者', role: 'member', status: 'active', folderScope: 'all' },
        ],
        folders: [
          {
            folderId: 'folder-demo-3',
            folderCode: 'F-201',
            title: 'NYKU2468101',
            createdBy: 'user-moji-admin',
            createdByName: '△△CY管理者',
            hasPassword: false,
            password: '',
            photos: [
              createDemoPhoto({
                photoId: 'photo-demo-5',
                photoCode: 'P-101',
                fileName: 'NYKU2468101_搬出_001',
                logTag: 'outbound',
                viewUrl: demoSvg('搬出記録', '#2E7D32', '#d9f0df'),
                sizeBytes: 7 * 1024 * 1024,
                createdBy: 'user-moji-admin',
                createdByName: '△△CY管理者',
                comments: [
                  {
                    commentId: 'comment-demo-5',
                    text: '搬出前の状態を記録済み。',
                    createdAt: demoNow(240),
                    createdBy: 'user-moji-admin',
                    createdByName: '△△CY管理者',
                  },
                ],
              }),
            ],
          },
        ],
      },
    ],
  };
}
