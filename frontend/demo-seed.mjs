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
    createdByName: seed.createdByName || 'デモ利用者',
    viewUrl: seed.viewUrl,
    previewUrl: seed.viewUrl,
    originalName: seed.originalName || seed.fileName,
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
    me: { userKey: DEMO_USER_KEY, displayName: 'デモ利用者' },
    activeRoomId: 'room-demo-1',
    inviteCounter: 1,
    roomCounter: 3,
    folderCounter: 5,
    photoCounter: 10,
    commentCounter: 10,
    rooms: [
      {
        roomId: 'room-demo-1',
        roomName: '〇〇工場 監査チーム',
        currentUserRole: 'admin',
        memberStatus: 'active',
        subscriptionPlan: 'BASIC',
        inviteToken: null,
        members: [
          { userKey: DEMO_USER_KEY, displayName: 'デモ利用者', role: 'admin', status: 'active', folderScope: 'all' },
          { userKey: 'user-sato', displayName: '佐藤', role: 'member', status: 'active', folderScope: 'all' },
          { userKey: 'user-suzuki', displayName: '鈴木', role: 'member', status: 'active', folderScope: 'own' },
        ],
        folders: [
          {
            folderId: 'folder-demo-1',
            folderCode: 'F-101',
            title: '2026年4月 定期巡回',
            createdBy: DEMO_USER_KEY,
            createdByName: 'デモ利用者',
            hasPassword: false,
            password: '',
            photos: [
              createDemoPhoto({
                photoId: 'photo-demo-1',
                photoCode: 'P-001',
                fileName: '配管まわり',
                viewUrl: demoSvg('配管まわり', '#7baf6a', '#dff0d8'),
                sizeBytes: 14 * 1024 * 1024,
                comments: [
                  {
                    commentId: 'comment-demo-1',
                    text: '配管接続部に軽微なにじみあり。次回点検で再確認。',
                    createdAt: demoNow(140),
                    createdBy: DEMO_USER_KEY,
                    createdByName: 'デモ利用者',
                  },
                  {
                    commentId: 'comment-demo-2',
                    text: '応急処置は不要。報告書には経過観察で記載予定。',
                    createdAt: demoNow(110),
                    createdBy: 'user-sato',
                    createdByName: '佐藤',
                  },
                ],
              }),
              createDemoPhoto({
                photoId: 'photo-demo-2',
                photoCode: 'P-002',
                fileName: '計器表示',
                viewUrl: demoSvg('計器表示', '#5f79a9', '#dbe7f7'),
                sizeBytes: 11 * 1024 * 1024,
                comments: [
                  {
                    commentId: 'comment-demo-3',
                    text: '計器表示は正常範囲。今回は記録のみ。',
                    createdAt: demoNow(90),
                    createdBy: DEMO_USER_KEY,
                    createdByName: 'デモ利用者',
                  },
                ],
              }),
              createDemoPhoto({
                photoId: 'photo-demo-3',
                photoCode: 'P-003',
                fileName: '床面状況',
                viewUrl: demoSvg('床面状況', '#d85a6a', '#f6e6ea'),
                sizeBytes: 9 * 1024 * 1024,
                comments: [],
              }),
            ],
          },
          {
            folderId: 'folder-demo-2',
            folderCode: 'F-102',
            title: '2026年3月 月次監査',
            createdBy: 'user-sato',
            createdByName: '佐藤',
            hasPassword: true,
            password: 'demo',
            photos: [
              createDemoPhoto({
                photoId: 'photo-demo-4',
                photoCode: 'P-004',
                fileName: '外観チェック',
                viewUrl: demoSvg('外観チェック', '#a86f22', '#f4dfbe'),
                sizeBytes: 12 * 1024 * 1024,
                createdBy: 'user-sato',
                createdByName: '佐藤',
                comments: [
                  {
                    commentId: 'comment-demo-4',
                    text: '外観に大きな異常なし。清掃後の状態良好。',
                    createdAt: demoNow(300),
                    createdBy: 'user-sato',
                    createdByName: '佐藤',
                  },
                ],
              }),
            ],
          },
        ],
      },
      {
        roomId: 'room-demo-2',
        roomName: '△△倉庫 点検チーム',
        currentUserRole: 'member',
        memberStatus: 'active',
        subscriptionPlan: 'FREE',
        inviteToken: null,
        members: [
          { userKey: 'user-tanaka', displayName: '田中', role: 'admin', status: 'active', folderScope: 'all' },
          { userKey: DEMO_USER_KEY, displayName: 'デモ利用者', role: 'member', status: 'active', folderScope: 'all' },
        ],
        folders: [
          {
            folderId: 'folder-demo-3',
            folderCode: 'F-201',
            title: '倉庫A 週次確認',
            createdBy: 'user-tanaka',
            createdByName: '田中',
            hasPassword: false,
            password: '',
            photos: [
              createDemoPhoto({
                photoId: 'photo-demo-5',
                photoCode: 'P-101',
                fileName: '荷台エリア',
                viewUrl: demoSvg('荷台エリア', '#2f8f83', '#cdeef6'),
                sizeBytes: 7 * 1024 * 1024,
                createdBy: 'user-tanaka',
                createdByName: '田中',
                comments: [
                  {
                    commentId: 'comment-demo-5',
                    text: '整理済み。通路確保できています。',
                    createdAt: demoNow(240),
                    createdBy: 'user-tanaka',
                    createdByName: '田中',
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
