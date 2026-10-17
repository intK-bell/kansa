# 本番・デモ画面 共通化計画

更新日: 2026-08-11  
対象: `frontend/index.html`, `frontend/demo.html`, `frontend/main.js`, `frontend/demo.js`

## 1. 目的

本番画面とデモ画面の表示・操作ロジックを一つの実装から提供し、機能追加時の二重修正と挙動ずれを防ぐ。

デモ固有のインメモリデータ、サンプル出力、本番固有のCognito認証・開発者画面は分離したまま維持する。

## 2. 現状

| 対象 | 本番 | デモ | 重複の状況 |
|---|---:|---:|---|
| HTML | 470行 | 456行 | 差分はタイトル、開発者UI、設定・起動スクリプトなどに限定 |
| JavaScript | 4,273行 | 4,961行 | 本番160関数のうち152関数名がデモにも存在 |
| CSS | `styles.css`を共有 | `styles.css`を共有 | 原則として共通化済み |

現在の主な問題:

- UI修正を`main.js`と`demo.js`へ個別反映する必要がある。
- `demo.js`が本番用認証・API処理を含み、後半でデモ実装へ上書きしている。
- `index.html`と`demo.html`のDOM差分が手作業で管理されている。
- 両画面の差分を機械的に検証する仕組みがない。

## 3. 守るべき境界

### 共通にするもの

- DOM参照、画面切替、モーダル、メニュー
- ルーム、コンテナ、写真、コメント、クエストの描画
- 入力検証、表示用フォーマット、i18n
- アップロード下書きUI、検索UI、課金表示UI
- イベント登録

### 分離して残すもの

- 本番: Cognito認証、HTTP API、Stripe遷移、開発者ダッシュボード
- デモ: `demo-seed.mjs`、インメモリAPI、サンプルPDF/PPT、デモ専用ダイアログ
- ページメタデータ: タイトル、favicon、読み込む起動モジュール

## 4. 目標構成

```text
frontend/
  app-shell.template.html     共通DOMテンプレート
  index.html                  生成物: 本番ページ
  demo.html                   生成物: デモページ
  app-core.js                 共通状態・UI・イベント
  api-live.js                 Cognito・HTTP API・Stripe
  api-demo.js                 インメモリAPI・デモ出力
  main.js                     本番依存を注入して起動
  demo.js                     デモ依存を注入して起動
scripts/
  generate_frontend_pages.mjs HTML生成
  check_frontend_sync.mjs     生成差分・境界違反の検査
```

## 5. 実施段階

### Phase 0 — ベースライン固定

- [x] HTML・JavaScriptの行数と差分を計測
- [x] 共通部分と環境固有部分を分類
- [x] 現在の主要ユーザーフローを回帰チェック項目として列挙

完了条件:

- 共通化前後で比較する対象が文書化されている。
- 本番固有・デモ固有の削除禁止領域が明確になっている。

### Phase 1 — HTML共通化

- [x] `app-shell.template.html`を作成
- [x] 本番・デモの差分を明示的なテンプレート変数へ限定
- [x] `index.html`と`demo.html`を生成するスクリプトを追加
- [x] 生成済みHTMLが手編集でずれていないか検査するコマンドを追加

完了条件:

- 2つのHTMLが単一テンプレートから再現できる。
- IDの重複や欠落がなく、既存JavaScriptのDOM参照を満たす。
- 生成前後の意味的なDOM差分が既知の差分だけである。

### Phase 2 — 共通UIモジュール抽出

- [x] 副作用の少ないユーティリティを`app-core.js`へ移す
- [x] 描画関数を機能単位で移す
- [x] DOM参照とイベント登録を共通化
- [x] 環境依存処理を引数またはadapterとして受け取る

移行順:

1. 日付・容量・エラー整形などの純粋関数
2. DOM生成・表示関数
3. モーダル・画面状態
4. 写真・コメント・クエストUI
5. 起動処理とイベント登録

完了条件:

- 共通関数を`main.js`と`demo.js`へコピーしない。
- 本番とデモで同じUI関数を呼び出す。
- 各移行単位で構文確認と主要フロー確認が通る。

### Phase 3 — データアクセス層分離

- [x] 共通UIが利用するAPIインターフェースを定義
- [x] 本番実装を`api-live.js`へ移す
- [x] デモ実装を`api-demo.js`へ移す
- [x] `demo.js`から本番認証・HTTP APIの死んだ定義を削除

完了条件:

- `api-live.js`だけがCognito設定と本番API URLを参照する。
- `api-demo.js`は外部APIへアクセスせずに主要操作を再現する。
- デモが本番関数を実行時に上書きしない。

### Phase 4 — 起動ファイル縮小

- [ ] `main.js`を本番adapter設定と起動だけにする
- [ ] `demo.js`をデモadapter設定と起動だけにする
- [ ] 開発者UIを本番のfeature flagとして注入
- [ ] デモ専用文言・出力処理をデモadapterへ閉じ込める

完了条件:

- 両起動ファイルに業務UIの重複実装がない。
- 環境差分がファイル先頭から把握できる。

### Phase 5 — 回帰確認と旧コード削除

- [x] 構文確認
- [x] HTML生成同期チェック
- [ ] DOM ID参照チェック
- [ ] 本番のログイン・ルーム・写真・検索・出力・課金フロー確認
- [ ] デモの初期表示・CRUD・検索・サンプル出力確認
- [ ] 未使用関数、旧上書き処理、旧ドキュメントを削除・更新

完了条件:

- 回帰チェックがすべて通る。
- `main.js`と`demo.js`の共通関数重複がゼロになる。
- 生成物とソースの責任範囲がREADMEに記載されている。

## 6. 検証コマンド

各Phaseで最低限、次を実行する。

```bash
node --check frontend/main.js
node --check frontend/demo.js
node --check frontend/demo-seed.mjs
node --check scripts/generate_frontend_pages.mjs
node --check scripts/check_frontend_sync.mjs
git diff --check
```

ブラウザ確認では、少なくとも次を対象にする。

- 本番: 未ログイン、ログイン復帰、ルーム切替、コンテナ選択、写真追加、検索、出力
- デモ: 初期データ、ルーム切替、写真追加・削除、コメント、検索、PDF/PPTサンプル
- 共通: メニュー、全モーダル、モバイル幅、`prefers-reduced-motion`

## 7. リスクと対策

| リスク | 対策 |
|---|---|
| 一度に分割して回帰箇所が特定できない | Phaseと機能単位で小さく移す |
| デモ固有挙動を共通化で失う | adapter境界とデモ回帰項目を先に固定 |
| 生成HTMLを直接編集して差分が再発する | 同期チェックを必須化し、編集元を明記 |
| ES Modules化で読み込み順が変わる | グローバル依存を棚卸し後に一つずつimportへ変更 |
| 本番APIへデモが接続する | デモadapterの外部通信禁止を検査する |

## 8. 進行ルール

- 各Phaseは独立して戻せる差分にする。
- 既存機能の仕様変更と共通化を同じ差分に混ぜない。
- 生成物は必ず生成スクリプトから更新する。
- 次Phaseへ進む前に、そのPhaseの完了条件を満たす。

## 9. 作業記録

### 2026-08-11 — Phase 0 / Phase 1

- 本番・デモのHTML差分とJavaScript関数重複を計測した。
- `app-shell.template.html`をHTML構造の編集元にした。
- `generate_frontend_pages.mjs`で本番・デモHTMLを生成できるようにした。
- `check_frontend_sync.mjs`へ生成同期、ID重複、許可済みID差分の検査を追加した。
- 結果: HTML同期検査、JavaScript構文検査、`git diff --check`が成功。

### 2026-08-11 — Phase 2 / Batch 1

- 副作用の少ない共通関数9個を`app-core.js`へ抽出した。
- 対象: Cognitoドメイン正規化、JWT解析、フォルダモード、容量表示、APIエラー解析、エラーメッセージ、プラン名・順位・容量。
- `main.js`と`demo.js`から同一定義を削除し、ES Modulesのimportへ変更した。
- `app-core.test.mjs`を追加し、正常系・不正値・プラン境界を検証する。
- 次の候補: DOM生成、ログタグ、日付整形など、環境依存が小さい共通処理。

### 2026-08-11 — Phase 2 / Batch 2

- 共通DOM生成ヘルパー`el`と、クエスト既読キー生成`questReadKey`を`app-core.js`へ抽出した。
- 認証関連ヘルパーは本番adapterへ移す予定のため、このBatchでは抽出対象から除外した。
- Batch 1・2合計で11関数、両ファイルから計188行の重複定義を削減した。
- 結果: 共通関数テスト6項目、両起動ファイルの構文確認、HTML同期検査、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 3

- ログタグの定数、既定値、正規化、メタデータ取得を`app-core.js`へ集約した。
- `Content-Disposition`からダウンロード名を取り出す処理を共通化した。
- 翻訳に依存するタグバッジ・select生成は、依存注入の設計が決まるまで各画面側へ残した。
- タグ異常値、UTF-8ファイル名、fallbackのテストを追加した。
- 結果: 共通関数テスト8項目、両起動ファイルの構文確認、HTML同期検査、差分検査が成功。
- 累計: 15関数・定数を共通モジュールへ移行した。

### 2026-08-11 — Phase 2 / Batch 4

- 本番・デモの`api(path, options)`呼び出しを棚卸しし、意味APIへ変換する契約を定義した。
- `app-api-contract.js`へ意味操作と完全性検査`assertAppApi`を追加した（Batch 8時点で38操作）。
- 経路対応、環境固有動作、移行規則を`frontend-api-contract.md`へ記録した。
- 開発者ダッシュボードは本番feature、デモのルーム横断検索はadapter内部実装として扱う判断にした。
- 次のBatchでは利用者・ルーム操作からlive/demo adapterへ移す。
- 結果: API契約テスト、共通関数テスト、構文確認、HTML同期検査、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 5

- `api-live.js`と`api-demo.js`を追加し、利用者・ルームの5操作を意味APIへ移した。
- 移行対象: 利用者取得、表示名保存、ルーム一覧、ルーム切替、ルーム作成。
- `main.js`と`demo.js`の移行済みUIから、対応するURL・HTTPメソッド・JSON生成を除去した。
- 段階移行中は既存の低レベル`api()`をrequest関数としてadapterへ注入する。デモ側のインメモリ実装移動後、この注入を撤去する。
- live/demo両adapterの経路、method、bodyを同一契約テストで検証する。
- 結果: adapter契約・経路テスト、共通関数テスト、全対象JavaScriptの構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 6

- コンテナ領域6操作をlive/demo adapterへ移した。
- 移行対象: 一覧、作成、削除、パスワード設定、メンバー一覧、招待メンバー解除。
- UIからフォルダ経路、HTTPメソッド、IDエンコード、JSON body、パスワードヘッダー生成を除去した。
- adapterへパスワードヘッダー取得関数を注入し、認証情報そのものはadapterが保持しない構成にした。
- 管理画面と通常画面に重複していたコンテナ操作は、同じ意味APIへ統一した。
- 結果: live/demoの経路・body・IDエンコード・パスワードヘッダーテスト、契約テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 7

- 写真の通常操作7項目をlive/demo adapterへ移した。
- 移行対象: 写真一覧、タグ更新、削除、コメント一覧・追加・更新・削除。
- 通常記録とクエスト内写真で重複していた削除処理を、同じ`deletePhoto`へ統一した。
- UIから写真・コメント経路、HTTPメソッド、JSON body、一覧取得時のパスワードヘッダーを除去した。
- アップロード署名URL取得、バイナリ送信、写真保存は意図的に次Batchへ残した。
- 結果: live/demo写真・コメント経路テスト、契約テスト、共通関数テスト、構文、HTML同期、差分検査が成功。
- 確認: UIに残る`/folders/:id/photos`直接呼び出しはアップロード完了後の保存2箇所だけ。

### 2026-08-11 — Phase 2 / Batch 8

- 共通UIのアップロード操作を`uploadPhoto`一つに統一した。
- 本番adapterは署名URL取得、原本PUT、プレビューPUT、メタデータ保存を担当する。
- デモadapterは外部アップロードを行わず、デモストアへ直接写真メタデータを保存する。
- 重複していた画像縮小処理を`resizeImageToJpeg`として`app-core.js`へ抽出した。
- UIから署名URL、S3キー、PUT通信、保存API経路を除去した。
- 本番の原本・プレビュー送信順序と保存body、デモの外部通信なしをテストする。
- 結果: upload adapterテスト、既存adapter・契約・共通関数テスト、構文、HTML同期、差分検査が成功。
- 確認: `main.js`と`demo.js`から`upload-url`、署名URL、写真保存APIの直接参照がゼロになった。

### 2026-08-11 — Phase 2 / Batch 9

- クエスト領域6操作をlive/demo adapterへ移した。
- 移行対象: 一覧、作成、状態更新、削除、コメント追加、コメント削除。
- UIからクエスト経路、HTTPメソッド、JSON body、パスワードヘッダーを除去した。
- 通常一覧取得と未読計算で重複していたクエスト取得を、同じ`listQuests`へ統一した。
- Batch 8の残課題として、実ブラウザからS3へのE2E送信はデプロイ環境で確認する必要があることを記録した。
- 結果: live/demoクエスト経路・body・ヘッダーテスト、全既存テスト、構文、HTML同期、差分検査が成功。
- 確認: `main.js`と`demo.js`からクエストAPI経路の直接参照がゼロになった。

### 2026-08-11 — Phase 2 / Batch 10

- 検索と出力を`searchPhotos`、`exportFolder`としてlive/demo adapterへ移した。
- 本番検索はルーム検索APIのquery生成をadapter内で行う。
- デモ検索は同じquery契約を受け、インメモリ写真をタグ・キーワード・新着順・件数で処理する。
- 本番出力はBackend生成URL、デモ出力は既存サンプルファイルURLを同じ戻り値で返す。
- UIから検索URL、query組み立て、出力URL、HTTP method、パスワードヘッダーを除去した。
- Batch 8の変更理由: 環境差が最大のアップロード処理をadapterへ閉じ込め、共通UIの条件分岐とデモからの外部送信リスクをなくすため。
- 結果: live/demo検索query・出力経路・ヘッダーテスト、全既存テスト、構文、HTML同期、差分検査が成功。
- 確認: UIから検索・出力API経路の直接参照がゼロになった。`demo.js`後半の出力経路はデモbackend実装として意図的に残る。

### 2026-08-11 — Phase 2 / Batch 11

- チーム、招待、課金、アカウント削除の12操作をlive/demo adapterへ移した。
- 移行対象: チーム取得、メンバー一覧・更新、退出・削除、アカウント削除、招待作成・承認・失効、課金取得・checkout・プラン変更。
- 契約棚卸しで不足していた`deleteAccount`を`APP_API_METHODS`へ追加した。
- UIからチーム・招待・課金・アカウント経路、HTTP method、IDエンコード、JSON bodyを除去した。
- ルーム招待とコンテナ招待を`createInvite(folderId?)`へ統一した。
- 結果: live/demoの全12操作経路・bodyテスト、全既存テスト、構文、HTML同期、差分検査が成功。
- 到達点: `main.js`の直接`api()`呼び出しは本番専用の開発者サマリー1箇所だけ。`demo.js`の共通UI領域から直接`api()`呼び出しはゼロになった。
- `demo.js`後半の`api`分岐はデモbackend実装として残っており、Phase 3で`api-demo.js`へ物理移動する。

### 2026-08-11 — Phase 3 / Batch 12

- 547行のデモbackend request実装を`demo.js`から`api-demo.js`へ物理移動した。
- `createDemoRequest(context)`を追加し、デモストア・変換関数・定数を明示的なcontext境界から受け取る構成にした。
- `demo.js`はbackendを直接実装せず、contextを組み立ててrequestを生成するだけになった。
- `demo.js`は4,698行から4,178行へ縮小した（Batch 12開始時点との比較）。
- `/me`、アカウント削除、未実装経路エラーを使い、移動後のrequest生成とcontext接続をテストする。
- 次Batchではcontext内のデモ変換関数とストア操作も`api-demo.js`へ寄せ、依存数を減らす。
- 結果: デモbackend境界テスト、全adapter・契約・共通関数テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 3 / Batch 13

- `demo.js`に残っていた旧`uploadFiles`上書きを削除し、Batch 8で定義した`appApi.uploadPhoto`をデモ実行時にも使う構成へ統一した。
- 旧上書きは同じ保存処理を二重実装し、adapterのアップロード境界を迂回していたため削除した。デモは引き続き外部S3へ送信せず、`api-demo.js`内のデモbackendへ直接保存する。
- backend専用のclone、HTTP風error生成、ルーム内写真検索を`createDemoRequest`内へ移し、`demo.js`から3 helperとcontext引数を除去した。
- 参照されていなかった`demoCanAccessFolder`を削除した。
- `demo.js`は4,178行から4,069行へ縮小し、`createDemoRequest`のcontext依存は25項目から22項目になった。
- UI側による低レベルrequest・アップロード処理の再上書きを検知する構造テストを追加した。
- 次Batchではfind・summary・recalculateを含むストア操作群をbackend objectへまとめ、context境界をさらに細くする。
- 結果: adapter・契約・共通関数テスト、全対象JavaScriptの構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 3 / Batch 14

手順:

1. `demo.js`にあるストア検索、再計算、レスポンス整形の参照元を棚卸しした。
2. ストアを所有する`createDemoBackend` factoryを`api-demo.js`へ追加した。
3. find 3件、再計算1件、summary 5件、active room取得1件をfactory内へ移した。
4. UIが直接必要とする`getActiveRoom`と`recalculate`だけをbackend objectから参照する形にした。
5. `createDemoRequest`へ渡していた個別helperを`demoBackend`一つに置き換えた。
6. 検索・再計算・summaryと、UI/backend境界をテストしてから全体検査を実行した。

判断と結果:

- データと操作を同じobjectにまとめ、`demoStore`を多数の独立関数が外側から操作する構造を解消した。
- `createDemoRequest`のcontext依存は22項目から12項目へ減った。
- `demo.js`は4,069行から3,911行へ縮小した。移動先を含む2ファイル合計も4,763行から4,758行へ5行減った。
- factory単体テストと、旧helperがUIへ戻らないための構造テストを追加した。
- 次Batchでは残る12依存のうち、デモ表示素材・時刻・写真生成などをbackend設定へ統合できるか確認する。翻訳や共通正規化は無理に閉じ込めず、責務を見て判断する。
- 結果: adapter・backend・契約・共通関数テスト、全対象JavaScriptの構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 3 / Batch 15

手順:

1. `createDemoRequest`に残る12依存を、デモデータ設定・共通ルール・UI副作用に分類した。
2. 利用者ID、容量表、時刻、写真生成、デモ画像、出力URL、プラン比較、翻訳、既定タグ、正規化を`createDemoBackend`の構成値へ移した。
3. request側ではbackend objectから必要な設定と操作を取得し、個別値をcontextで受け取らない形にした。
4. UI通知を消す`clearError`はbackendのデータ責務ではないため、request lifecycle callbackとして境界に残した。
5. 写真タグ更新経路を実行する回帰テストを加え、構文・同期・差分を含む全体検査を行った。

判断と結果:

- `createDemoRequest`のcontext依存は12項目から`demoBackend`と`clearError`の2項目へ減った。
- 翻訳・正規化関数そのものは共通モジュールに残し、デモbackendは注入されたルールを利用する。これにより共通仕様を複製せず、backendの設定境界だけを明確にした。
- `clearError`は画面表示への副作用なのでbackendへ取り込まなかった。データ操作とUI状態を混在させないための意図的な2依存である。
- 棚卸し中、写真タグ更新が`api-demo.js`内で未注入の`DEFAULT_LOG_TAG`を参照する潜在不具合を発見した。既定タグをbackend設定へ追加して修正し、無効タグ更新時に既存タグを保持するテストを追加した。
- `demo.js`は3,911行から3,908行へ縮小した。設定を明示したため2ファイル合計は7行増えたが、暗黙依存をなくすための意図的な増加である。
- 次Batchでは`createDemoRequest`内部の長い経路分岐を領域別handlerへ分割し、単一関数の大きさと変更衝突を減らす。
- 結果: adapter・backend・回帰・契約・共通関数テスト、全対象JavaScriptの構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 3 / Batch 16

- `createDemoRequest`の経路分岐から、検索・アカウント・招待／課金を領域別handlerへ抽出した。
- `UNHANDLED` sentinelとhandler dispatcherを導入し、正常な`undefined`戻り値と未処理経路を区別できる構成にした。
- 表示名変更時のデモストア同期、ルーム横断検索、招待作成・失効、プラン変更の既存処理は各handlerへそのまま移し、API契約を変更していない。
- handler名とdispatcher登録を構造テストで固定し、巨大な単一分岐へ戻る退行を検知できるようにした。
- 次Batchでは残るルーム／チーム、フォルダ／クエスト、写真／コメント領域を同じdispatcherへ順次移す。
- 結果: adapter・backend・契約・共通関数テスト、全対象JavaScriptの構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 3 / Batch 17

- ルーム／チーム領域8経路を`handleRoomTeamRequest`へ抽出し、Batch 16のdispatcherへ登録した。
- 移行対象: チーム情報、所属ルーム一覧、ルーム切替・作成、チーム退出、メンバー一覧・更新、チーム削除。
- ルーム切替時の参加状態検査、所有ルーム作成制限、退出・削除後のactive room fallbackをhandler内に維持した。
- backend factoryを使う回帰テストへ所属ルーム一覧とチーム情報の実行確認を追加した。
- `createDemoRequest`本体に残る分岐はフォルダ／クエスト、写真／コメント領域になった。次Batchでフォルダ／クエストを抽出する。
- 結果: adapter・backend・契約・共通関数テスト、構文、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 18

- Phase順序を戻し、描画関数の共通化を再開した。
- ログタグbadge、ログタグselect、タグ別件数summaryのDOM生成を`app-core.js`へ抽出した。
- `createLogTagUi(translate)`で翻訳関数を注入し、本番・デモが同じ描画実装を利用する構成にした。
- `main.js`と`demo.js`からbadge・selectの重複定義を削除し、summaryは画面状態から対象DOMと写真を渡す薄いwrapperだけにした。
- DOM stubを使ったテストで、翻訳、色、選択値、異常タグの`other`集計を検証した。
- 「描画関数を機能単位で移す」は他の描画領域が残るため未チェックを維持する。次Batchではモーダルまたはストレージ表示の共通描画を抽出する。
- 結果: 共通DOM描画テスト、adapter・backend・契約テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 19

- `collectAppElements`を`app-core.js`へ追加し、HTML内のIDをcamelCaseのDOM参照へ変換する共通factoryを実装した。
- `main.js`と`demo.js`に重複していた約150項目ずつの`els`定義を削除し、両画面を同じDOM参照生成へ切り替えた。本番専用developer要素はHTMLに存在するときだけ収集される。
- `bindGlobalAppEvents`を追加し、未処理Promise、window error、resize、グローバルメニュー、accordion排他制御のイベント登録を共通化した。
- DOM ID変換と、window／document／menu／accordionへのイベント登録をstubで検証するテストを追加した。
- `main.js`は3,984行から3,793行、`demo.js`は3,908行から3,721行へ縮小した（Batch 17終了時との比較）。
- DOM参照の移行は完了したが、画面操作イベントが残るため「DOM参照とイベント登録を共通化」は未チェックを維持する。次Batchでタブ・検索・ルーム／フォルダ選択イベントを共通registrarへ移す。
- 結果: 共通DOM・イベントテスト、adapter・backend・契約テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 20

- 共通描画として容量統計、ルーム見出し、フォルダmode panel、容量graphを`app-core.js`へ抽出した。
- 本番のi18n文言はlabel formatterを注入し、デモの既存表示と同じ共通描画関数を利用する。
- `bindAppControlEvents`を追加し、ルーム／フォルダ選択、record／search tab、検索範囲、検索実行、タグ変更、キーワードEnterの登録先とevent種別を共通化した。
- 共通描画の表示状態・割合・文言と、control keyからのevent登録をテストした。
- 棚卸し結果、主要な重複描画（ルーム一覧、フォルダ、写真、クエスト等）と静的イベント登録が残るため、Phase 2の2項目は未チェックを維持する。
- 次Batchではルーム一覧・select描画を共通化し、モーダルclose／backdropイベントを共通registrarへ移す。
- 結果: 共通描画・イベントテスト、adapter・backend・契約テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 21

- 所属ルーム一覧とヘッダーのルームselect描画を`renderMyRoomsInto`、`renderRoomSelectInto`として共通化した。
- active／disabled／left状態、管理者表示、切替callbackを引数化し、本番・デモの薄いwrapperから同じDOM描画を呼ぶ構成にした。
- `bindModalDismissEvents`を追加し、ルーム作成、フォルダ作成・鍵、ヘルプ、写真preview、容量警告、出力選択、本番developer modalのclose button／backdrop登録を共通化した。
- ルーム状態別のDOMと切替callback、モーダルbutton／backdropのdismiss条件をテストした。
- `main.js`は3,793行から3,601行、`demo.js`は3,721行から3,536行へ縮小した（Batch 19終了時との比較、Batch 20を含む）。
- 写真・クエスト・フォルダ等の主要描画とその他の静的イベントが残るため、Phase 2の2項目は未チェックを維持する。
- 次Batchではフォルダ一覧または検索結果描画を共通化し、出力操作イベント群を共通registrarへ移す。
- 結果: 共通ルーム描画・モーダルイベントテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 22

- フォルダselect描画を`renderFolderSelectInto`へ抽出し、空状態、選択状態、mode、鍵、未読表示を共通化した。
- 検索結果カード描画を`renderSearchResultsInto`へ抽出し、タグ、画像keyboard操作、コンテナ・投稿者表示、preview callbackを共通化した。
- 本番の「フォト」とデモの「通常」という既存表示差は`photoModeLabel`で明示的に注入した。
- `bindExportControlEvents`を追加し、loading close、download、別tab、link copy、高画質PPT、軽量PPT、PDFの7操作を共通registrarへ移した。
- フォルダ状態、検索カードpreview、出力control mappingをDOM stubでテストした。
- 写真・クエスト本体、アップロード下書き等の描画と、アカウント・管理操作イベントが残るためPhase 2の2項目は未チェックを維持する。
- 次Batchでは写真／クエスト内の共通カード部品を抽出し、認証・ルーム・フォルダ管理イベントをregistrar単位へまとめる。
- 結果: 共通描画・イベントテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 23

- 賃貸向け搬入／搬出比較を`renderRentalComparisonInto`へ抽出し、タグ集計、時系列表示、空状態、keyboard previewを共通化した。
- `bindAuthControlEvents`を追加し、ログイン、新規登録、表示名変更、ログアウトの静的イベント登録を共通registrarへ移した。
- 本番・デモの通知文言と、デモだけのtheme modal closeはcallback内部の環境差として維持した。
- 比較列・preview callbackと、認証control mappingをDOM stubでテストした。
- `demo.js`末尾にあるデモ専用login／logout等の実行時上書きは既存挙動を維持するため残した。Phase 3の旧上書き削除でadapter注入へ置き換える。
- 写真・クエスト・アップロード下書きの主要描画と管理操作イベントが残るため、Phase 2の2項目は未チェックを維持する。
- 次Batchではアップロード下書きのカード部品、または写真／クエスト共通画像tileを抽出し、ルーム・フォルダ管理イベント登録を共通化する。
- 結果: 共通描画・認証イベントテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 24

- 写真アーカイブ案内を`renderPhotoArchiveNoteInto`へ抽出し、表示条件、既定保存日数、環境別format callbackを共通化した。
- 検索範囲button、タグfilter、keywordの表示同期を`syncSearchControlsInto`へ移した。
- `bindManagementControlEvents`を追加し、ルーム一覧更新、ルーム／フォルダ作成・鍵modal、ヘルプ、本番developer dashboardのイベント登録を共通化した。
- アーカイブ表示・非表示、検索control state、管理control mappingをテストした。
- 写真・クエスト・アップロード下書きの主要描画と、作成submit・削除・課金等の操作イベントが残るためPhase 2の2項目は未チェックを維持する。
- 次Batchではクエスト／写真で共有できる画像preview tileと状態表示を抽出し、作成・削除系controlをregistrarへ移す。
- 結果: 共通描画・管理イベントテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 25

- クエストの状態／日時順sortと状態文言を`sortQuests`、`questStatusText`として共通化した。
- クエストcardのcode、状態、本文、投稿情報、管理者完了、削除actionを`createQuestCardHeader`へ抽出した。
- 本番・デモの`renderQuests`は共通cardへAPI callbackと確認処理を注入し、写真strip・コメント領域の描画に集中する形へ縮小した。
- 作成・upload・export・削除系の静的controlをまとめる`bindMutationControlEvents`を追加した。個別登録の置換は次Batchで行う。
- status sort、日時sort、完了callback、mutation control mappingをテストした。
- クエスト写真・コメント、通常写真、upload下書きの描画とmutation control移行が残るためPhase 2の2項目は未チェックを維持する。
- 次Batchでは`bindMutationControlEvents`へ既存登録を接続し、クエスト／写真で重複するpreview tileを抽出する。
- 結果: 共通クエスト描画・control mappingテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 26

- `bindMutationControlEvents`へ写真upload、クエスト作成、フォルダ出力を接続し、個別の`onclick`登録を削除した。
- `createPhotoPreviewImage`を追加し、クエスト写真tileと通常写真cardの画像属性、preview callback、keyboard操作を共通化した。
- 本番だけの翻訳済みaria-labelと、クエストtileの既存click-only挙動はoptionで維持した。
- mutation registrarの接続、画像URL・role、click／Enter previewをテストした。
- 写真・クエストのコメント領域、upload下書き全体の描画と、残る削除・課金・管理イベントがあるためPhase 2の2項目は未チェックを維持する。
- 次Batchではコメント表示・編集actionの共通部品を抽出し、フォルダ削除・鍵設定・チーム管理イベントをregistrarへ接続する。
- 結果: 共通画像描画・mutationイベントテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 27

- 写真コメントのmetadata、本文、編集form、保存・取消・削除actionを`createPhotoCommentRow`へ抽出した。
- 本番・デモの`renderPhotos`は権限判定とAPI callbackを共通コメント行へ注入し、重複するDOM生成を削除した。
- チーム管理open／backを`bindManagementControlEvents`へ接続した。
- フォルダ削除と鍵設定を`bindMutationControlEvents`へ接続し、個別`onclick`登録を削除した。
- コメント編集値・削除callbackと、既存registrarのイベントmappingをテストした。
- 通常写真card・クエスト残部・upload下書きの描画と、課金・チーム／アカウント削除等のイベントが残るためPhase 2の2項目は未チェックを維持する。
- 次Batchでは写真cardのmetadata・action shellを抽出し、課金controlを共通registrarへ移す。
- 結果: 共通コメント描画・管理mutationイベントテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 28

- 写真cardのcode、タグbadge、preview画像、投稿者、タグ編集・削除button、編集slotを`createPhotoCardShell`へ抽出した。
- 本番・デモの`renderPhotos`は未読・accordion・コメント処理を共通shellへ追加する構成になり、card基本DOMの重複を削除した。
- `bindBillingControlEvents`を追加し、BASIC／PLUS／PRO／FREE変更と容量不足時のプラン選択を共通registrarへ移した。
- 写真card構造・編集actionと、課金control mappingをDOM stubでテストした。
- 写真accordion・クエストコメント・upload下書きの描画と、チーム／アカウント削除等のイベントが残るためPhase 2の2項目は未チェックを維持する。
- 次Batchでは写真accordion shellとコメント追加行を抽出し、チーム・アカウント削除イベントをmutation registrarへ接続する。
- 結果: 共通写真card・課金イベントテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 29

- 写真コメントの`details`、summary、未読badge、遅延読込表示、追加入力欄・buttonを`createPhotoCommentsAccordion`へ抽出した。
- Batch 19で共通化済みのメニューaccordion排他制御とは別に残っていた、写真card内accordionの基本DOMを共通化した。
- チーム削除とアカウント削除の静的イベント登録を`bindMutationControlEvents`へ接続した。
- accordion構造、未読表示、入力属性と、mutation registrar経由の削除control mappingを検証した。
- accordionのtoggle時データ読込ロジック、クエストコメント、upload下書き描画、残るinput/changeイベントがあるためPhase 2の2項目は未チェックを維持する。
- 次Batchではaccordion toggle lifecycleを共通helperへ移し、upload下書きのcard rowを抽出する。
- 結果: 共通accordion・削除イベントテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 30

- 写真コメントaccordionのtoggle lifecycleを`bindPhotoCommentsAccordionLifecycle`へ抽出した。
- 初回open時だけのコメント取得、loading表示、件数更新、最新受信日時、既読化、未読badge除去、open state更新、フォルダ未読再計算を共通化した。
- 本番のi18n件数formatはcallbackで注入し、デモと同じlifecycleを利用する。
- 初回load、描画callback、既読callback、badge除去、後処理の実行順を非同期テストで検証した。
- 写真accordionの基本DOMとlifecycleは共通化済み。クエストコメント、upload下書き描画、file input等の残存イベントがあるためPhase 2の2項目は未チェックを維持する。
- 次Batchではupload下書きrowのDOM生成を抽出し、file input・bulk comment・cancel等のuploadイベントを共通registrarへ移す。
- 結果: 共通accordion lifecycleテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 31

- upload下書きrowの番号・ファイル名、容量、除外button、preview、タグselect、初回コメント入力を`createUploadDraftRow`へ抽出した。
- 除外時cleanup、preview callback、タグ正規化、コメント50文字同期をcallbackと共通event handlerで扱う構成にした。
- `bindUploadControlEvents`を追加し、file選択、フォルダ名input、クエストsort、コメント一括反映、下書き取消の5イベントを共通registrarへ移した。
- 下書き除外、タグ・コメント同期とupload control mappingをDOM stubでテストした。
- upload下書きrowは共通化済み。クエストコメント・管理panel描画と一部submit／動的イベントが残るためPhase 2の2項目は未チェックを維持する。
- 次Batchではupload下書きcontainer状態とvalidationを共通化し、残存する静的イベント登録を棚卸しする。
- 結果: 共通upload描画・eventテスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 32

- upload下書きcontainerの表示／非表示、件数、bulk操作表示、row追加を`renderUploadDraftContainerInto`へ抽出した。
- DOM rowからのタグ・コメント同期を`syncUploadDraftsFromRows`、タグ・50文字validationを`validateUploadDraftItems`へ共通化した。
- Batch 31の機械的抽出範囲が隣接するvalidation loopへ掛かり、`renderUploadDrafts`を欠落させていた実行時退行を棚卸しで発見した。両entryのvalidation／render wrapperを復元し、今回の共通helperへ正しく接続した。
- 同種退行を構文検査だけに頼らず検知するため、両entryにvalidationとrender wrapperが存在し共通helperを呼ぶ構造テストを追加した。
- container空状態、件数、DOM同期、validation文言と全既存テストを実行した。
- 静的な`els`直接イベント登録は両entry合計18件まで減少した。主要描画ではクエストコメント・管理panel等が残るためPhase 2の2項目は未チェックを維持する。
- 次Batchでは残る18件の静的イベントを分類・共通registrarへ移し、DOM参照／イベント項目の完了判定を行う。
- 結果: upload container・validation・wrapper構造テスト、全既存テスト、構文、HTML同期、差分検査が成功。

### 2026-08-11 — Phase 2 / Batch 33

- 招待URLのコピー・発行・失効を`bindInviteControlEvents`へ移し、ルーム脱退とルーム／コンテナ作成は既存のmanagement／mutation registrarへ接続した。
- デモ固有のログイン・登録・ログアウト・アカウント削除挙動は、後から安全に差し替えられるよう`bindAuthControlEvents`の代入方式を明示した。
- 両entryの静的な`els`直接イベント登録を18件から0件へ削減した。`collectAppElements`によるDOM参照と合わせ、「DOM参照とイベント登録を共通化」を完了としてチェックした。
- 共通registrarのmapping／上書きテストと、両entryへ直接イベント登録が再流入しない構造テストを追加した。
- 「描画関数を機能単位で移す」はクエストコメント・管理panel等が残るため未チェックを維持する。
- 次Batchでは残存描画関数を棚卸しし、クエストコメントまたは管理panelのまとまりを共通化する。

### 2026-08-11 — Phase 2 / Batch 34

- クエストコメントの一覧、投稿者・日時、削除操作、コメント追加フォームを`createQuestCommentsSection`へ抽出した。
- 本番／デモの翻訳差分、削除可否、削除・追加処理はcallbackとして注入し、APIや画面状態を共通UIから分離した。
- コメント表示、削除callback、空文字を除くtrim済み追加callbackをDOM stubでテストした。
- クエストcard本体には写真strip・アップロード入力が残り、管理panel描画も未抽出のため「描画関数を機能単位で移す」は未チェックを維持する。
- 次Batchではクエスト写真stripとアップロード入口を共通化する。

### 2026-08-11 — Phase 2 / Batch 35

- クエスト写真strip、タグbadge、空表示、削除button、file input、upload slotを`appendQuestPhotoArea`へ抽出した。
- preview、削除可否・削除処理、選択ファイルの下書き化をcallbackとして受け取り、本番／デモ固有処理を共通UIから分離した。
- 写真DOM、削除callback、file change時のファイル列とquest受け渡しをDOM stubでテストした。
- `renderQuests`は共通のheader・写真領域・コメント領域を組み立てる薄い調整層になった。管理panelなどの描画が残るためPhase 2描画項目は未チェックを維持する。
- 次Batchでは管理panelのメンバー行描画から共通化する。

### 2026-08-11 — Phase 2 / Batch 36

- お部屋管理のメンバー一覧、権限select、コンテナ招待表示、削除buttonを`renderTeamMembersInto`へ抽出した。
- owner／adminの操作制限、権限変更、メンバー削除は引数とcallbackへ分離し、本番／デモの確認・API処理を維持した。
- 一覧初期化、権限変更値、削除対象の受け渡しをDOM stubでテストした。
- 管理panelのコンテナpicker・招待・メンバー管理描画が残るため「描画関数を機能単位で移す」は未チェックを維持する。
- 次Batchでは管理コンテナpickerと概要headerを共通化する。

### 2026-08-11 — Phase 2 / Batch 37

- 管理コンテナの選択肢、モード・鍵表示、件数、未選択表示、作成者・容量headerを`createFolderAdminOverview`へ抽出した。
- 選択変更、件数と概要文言のformatはcallbackとして注入し、本番／デモの表示契約を維持した。
- 選択肢label、概要header、選択callbackをDOM stubでテストした。
- 管理コンテナの招待・パスワード・削除操作と配下メンバー描画が残るためPhase 2描画項目は未チェックを維持する。
- 次Batchでは管理コンテナの操作行を共通化する。

### 2026-08-11 — Phase 2 / Batch 38

- 管理コンテナの招待URL発行・失効・コピー、パスワード設定／解除、削除の3操作行を`appendFolderAdminActions`へ抽出した。
- 入力DOMと失効buttonをcallbackへ渡し、URL反映・表示切替・API処理を各entry側で従来どおり実行できる構成にした。
- 操作行数、招待control参照、パスワードtrim、削除callbackをDOM stubでテストした。
- 管理コンテナ配下メンバー描画と写真cardの残部があるためPhase 2描画項目は未チェックを維持する。
- 次Batchでは管理コンテナ配下メンバー一覧を共通化する。

### 2026-08-11 — Phase 2 / Batch 39

- 管理コンテナ配下のメンバー一覧、アクセス理由・状態、招待メンバー解除buttonを`renderFolderMembersInto`へ抽出した。
- 解除対象はcallbackでentryへ返し、確認・API更新・再読込を従来どおり環境側に保持した。
- 見出し、アクセス理由label、解除対象callbackをDOM stubでテストした。
- 管理panelの主要DOM生成は共通化済み。写真card編集領域や補助的な表示wrapperを再棚卸しするため、Phase 2描画項目は現時点では未チェックを維持する。
- 次Batchでは両entryの残存描画差分を一覧化し、写真card編集領域を共通化する。

### 2026-08-11 — Phase 2 / Batch 40

- 写真cardのタグ編集展開、保存・取消、写真削除のevent接続を`bindPhotoCardEditing`へ抽出した。
- コメントaccordionと未読状態表示の追加を`appendPhotoCardComments`へ共通化した。
- 編集値の正規化、保存・削除callback、未読文言をDOM stubでテストした。
- 本番／デモの主要な写真・コメント・クエスト・管理panel DOM生成は共通helperへ移行した。次Batchで薄いwrapperと環境固有描画を分類し、Phase 2描画項目の完了判定を行う。

### 2026-08-11 — Phase 2 / Batch 41

- 上部容量グラフの比率・使用量・残量・補助情報・表示切替を`renderTopStorageGraphInto`へ抽出した。
- 課金ステータスバーのプラン・作成者／参加者・容量不足・無料枠・管理者表示を`renderBillingBarInto`へ抽出した。
- 本番側の翻訳formatとデモ側の既定文言を引数で吸収し、entryの`renderTopStorageGraph`／`renderBillingBar`を薄いwrapperにした。
- 容量比率、補助label、課金ステータス文言をDOM stubでテストした。
- プラン選択buttonの状態描画が重複して残るためPhase 2描画項目は未チェックを維持する。
- 次Batchではsubscription plan button描画を共通化し、完了判定を行う。

### 2026-08-11 — Phase 2 / Batch 42

- subscription plan buttonのラベル、現在選択、`aria-pressed`、使用量超過時のダウングレード制限を`syncSubscriptionPlanButtonsInto`へ抽出した。
- FREE／BASIC／PLUS／PROの状態描画と警告titleをDOM stubでテストした。
- 写真・コメント・クエスト・upload・ルーム／コンテナ・管理panel・容量／課金の主要描画が、両entryから機能単位の共通helperへ移行済みであることを構造テストで固定した。
- entryに残る`render*`は共通helperを束ねる状態／API調整wrapper、または本番専用の開発者ダッシュボードであり、production/demo間の重複描画には該当しないと判定した。
- Phase 2の「描画関数を機能単位で移す」を完了としてチェックした。これによりPhase 2の全チェック項目が完了した。
- 次はPhase 3の未完了項目を確認し、環境差分の注入方式へ進む。

### 2026-08-11 — Phase 3 / Batch 1

- 本番HTTP transportを`createLiveRequest`として`api-live.js`へ抽出した。
- API base結合、method別header合成、fetch、JSON decode、network error、401、active room不在の処理を注入可能な本番requestへ集約した。
- `main.js`は認証状態・画面遷移callbackとfolder password headerを注入して`createLiveApi`を構成する形に変更した。
- request URL・header合成・JSON応答・401 error bodyをadapterテストで確認した。
- Cognito設定・認証処理が`main.js`に残るため「本番実装を`api-live.js`へ移す」は未チェックを維持する。
- 次BatchではCognito認証clientを`api-live.js`へ抽出する。

### 2026-08-11 — Phase 3 / Batch 2

- 本番環境設定の解決を`resolveLiveEnvironment`、Cognito Hosted UI・PKCE・callback token交換・logout URLを`createCognitoClient`として`api-live.js`へ抽出した。
- `main.js`からCognito URL、PKCE helper、token fetch、callback query cleanupを削除し、認証clientの呼び出しだけを残した。
- localStorage優先設定、Cognito domain正規化、login／logout URLをadapterテストで確認した。
- `main.js`にCognito hostや直接HTTP request実装が再流入しない構造テストを追加した。
- Phase 3の「本番実装を`api-live.js`へ移す」を完了としてチェックした。
- `demo.js`には本番認証・HTTPの旧定義と実行時上書きが残るため、最後の項目は未チェックを維持する。
- 次Batchではデモの死んだ本番定義を削除し、上書きなしでデモ依存を初期注入する。

### 2026-08-11 — Phase 3 / Batch 3

- `demo.js`からAPI base・Cognito設定、PKCE、Hosted UI、token交換、production header／fetch requestを削除した。
- デモ用login／signup、subscription切替、`initUser`を最初からデモ実装として定義し、末尾の関数上書きを廃止した。
- `createDemoRequest`は`demoBackend`生成後に`demoRequest`依存へ注入し、`createDemoApi`のinterfaceを維持した。
- デモのアカウント削除は認証registrarのデモ案内だけに統一し、本番用削除listenerの重複登録を除去した。
- Cognito／本番API設定・HTTP transport・実行時関数上書きが`demo.js`へ再流入しない構造テストを追加した。
- Phase 3の最後の項目をチェックし、Phase 3の全項目を完了した。

### 2026-08-11 — Phase 4 / Batch 1

- 共通runtimeの最初の境界として、アプリ初期stateを`createInitialAppState`へ抽出した。
- ユーザー別の既読storage、最新incoming comment、未読判定、既読更新を`createReadTracker`へ抽出した。
- 本番／デモのstate shapeを共通化し、配列・Setがinstance間で共有されないこととユーザー別既読をテストした。
- entry縮小は開始段階のためPhase 4のチェック項目は未チェックを維持する。
- 次Batchではモーダル／画面表示制御を共通runtime controllerへ移す。

### 2026-08-11 — Phase 4 / Batch 2

- メニュー、管理panel、ルーム／コンテナ作成、パスワード、ヘルプ、容量警告、出力optionsのclose処理を`createAppViewController`へ抽出した。
- 本番専用developer modalとデモ専用theme modalもoptional elementとして同じcontrollerへ注入した。
- 管理panel終了時のmode同期とパスワード対象名resetをcontrollerの契約としてテストした。
- 棚卸し中にデモから参照される`closeThemeModal`のローカル定義欠落を発見し、共通controller提供により実行時エラーを解消した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではexport loading UI state controllerを共通runtimeへ移す。

### 2026-08-11 — Phase 4 / Batch 3

- export loadingのtimer、疑似進捗、download進捗、60%準備、100%完了、resetを`createExportProgressController`へ抽出した。
- 両entryから`exportLoadingTimer`と重複する進捗計算・interval cleanupを削除した。
- timer起動、進捗率、準備／完了状態、timer解除をfake windowとbarでテストした。
- export結果actionと文言描画はentryに残るためPhase 4項目は未チェックを維持する。
- 次Batchではexport result action controllerを共通runtimeへ移す。

### 2026-08-11 — Phase 4 / Batch 4

- export結果の保持、完了表示、object URL download、通常URL遷移、別タブ、リンクコピー、URL解放を`createExportResultController`へ抽出した。
- 本番のi18n文言とデモ既定文言はformatter／callbackとしてcontrollerへ注入した。
- download anchor、別タブURL、clipboard、object URL cleanupをbrowser stubでテストした。
- 両entryから`exportResult` stateと重複browser action実装を削除した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは写真previewと基本画面遷移controllerを共通runtimeへ移す。

### 2026-08-11 — Phase 4 / Batch 5

- 写真previewの画像URL、alt、title、modal open／close、src cleanupを`createPhotoPreviewController`へ抽出した。
- 本番のタグ＋写真code表示とデモのファイル名表示を`titleFor`／`altFor` formatterとして注入した。
- preview表示・終了・label差し替えをDOM stubでテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではauth／room setup／appの基本画面表示を共通controllerへ移す。

### 2026-08-11 — Phase 4 / Batch 6

- 認証setup、ルームsetup、アプリ本体の表示切替を`createScreenController`へ抽出した。
- 認証済みルームsetup時のglobal menu／logout表示と、アプリ表示時のユーザー名反映を共通化した。
- 各screenのhidden状態、認証済み操作、ユーザー名をDOM stubでテストした。
- entryにはデータ読込・menu action・環境固有modal cleanupだけを残した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom context resetと初期化flowの共通runtime化を進める。

### 2026-08-11 — Phase 4 / Batch 7

- room-scoped stateの初期値復元を`resetRoomState`へ抽出し、本番／デモのreset差分を共通state shapeへ統一した。
- 起動時のasync初期化とerror捕捉を`startAppInitialization`へ抽出し、各entryは環境固有`initUser`と表示callbackを注入する構成にした。
- user stateを維持したroom reset、配列・Set・検索状態の復元、初期化成功／失敗をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは共通のroom／folder data-loading orchestrationをruntimeへ移す。

### 2026-08-11 — Phase 4 / Batch 8

- team／room context取得とstate反映・失敗時resetを`loadTeamState`へ抽出した。
- 入室可能room一覧の取得・left除外を`loadRoomListState`へ抽出した。
- folder一覧取得・未読更新・失敗時空配列化を`loadFolderListState`へ抽出した。
- 成功時のstate反映・filter・未読callbackと、team／folder失敗時resetをテストした。
- entryには読込中／error文言と描画呼出だけを残した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom切替とfolder content読込の共通orchestrationを進める。

### 2026-08-11 — Phase 4 / Batch 9

- room切替API、旧context cleanup、新room state反映、app再表示を`switchRoomState`へ抽出した。
- folder modeによるphoto／quest state初期化とload分岐、mode再描画、デモの検索tab再実行を`loadFolderContentState`へ抽出した。
- room切替順序・state resetと、quest modeのarchive／load／render／search順序をテストした。
- entryには確認・表示callbackと環境差分だけを注入する構成にした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではphoto／quest loadと検索state orchestrationを共通runtimeへ移す。

### 2026-08-11 — Phase 4 / Batch 10

- photo一覧とarchive情報の正規化・state反映を`loadPhotoState`へ抽出した。
- quest一覧の取得・state反映を`loadQuestState`へ抽出した。
- folder／room検索条件、検索結果、pagination tokenの更新を`runPhotoSearchState`へ抽出した。
- entryには検索control同期、描画、未読・team再取得など画面固有の後処理だけを残した。
- Phase 3分離後に残っていた開発者サマリーの旧`api`参照を`liveRequest`へ修正した。
- photo／quest取得とfolder／room検索state更新をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではupload処理の共通orchestrationをruntimeへ移す。

### 2026-08-11 — Phase 4 / Batch 11

- upload draftの同期・検証、多重実行防止、逐次upload、重複集計、loading解除を`runUploadBatch`へ抽出した。
- 本番のpreview生成と部分draft削除、デモのファイル名生成と全draft cleanupはcallbackとして注入した。
- upload成功・重複・検証失敗の集計とloading遷移をテストした。
- entryには環境固有のupload payload、容量不足処理、完了・重複文言だけを残した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではupload draft lifecycleとloading UIの共通化を進める。

### 2026-08-11 — Phase 4 / Batch 12

- upload draftのpreview URL破棄、再構築、部分削除、全消去を`createUploadDraftController`へ抽出した。
- upload中のstate、button／file input／一括操作／loading表示切替を`createUploadLoadingController`へ抽出した。
- 本番だけのquest file input無効化と翻訳済みbutton文言はcontroller optionとして注入した。
- draft target・preview lifecycleとloading UI遷移をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではupload draft編集・一括操作の共通orchestrationを進める。

### 2026-08-11 — Phase 4 / Batch 13

- draft行のDOM同期・検証を`createUploadDraftEditor`へ集約した。
- 先頭コメントの取得・50文字制限・全draft反映と、draft破棄確認を共通化した。
- 本番／デモで異なるvalidation文言とalert／confirmはcallbackとして注入した。
- 検証、一括反映、空コメントguard、キャンセル処理をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder detail tabと検索controlのstate／UI同期を共通化する。

### 2026-08-11 — Phase 4 / Batch 14

- record／search tabのstate、ARIA選択状態、panel表示切替を`createFolderDetailController`へ抽出した。
- folder／room検索範囲のstate更新、folder復帰時のpagination reset、検索control描画を同controllerへ集約した。
- entryのtab／scope event handlerはcontroller更新後に検索を実行するだけの構成にした。
- tab表示・ARIA・mode再描画と検索範囲・pagination・criteria同期をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder選択時の検索state resetとdetail表示orchestrationを共通化する。

### 2026-08-11 — Phase 4 / Batch 15

- folder選択確定後のselected stateと検索条件・結果・pagination初期化を`selectFolderState`へ抽出した。
- folder selector再描画、detail表示、record tab復帰、title設定、content loadの順序を共通化した。
- 鍵入力・不一致処理と本番／デモで異なるmode labelはentry callbackとして維持した。
- デモもfolder切替時にscope／tag／keywordを確実に初期化するよう統一した。
- 選択state初期化とdetail表示順序をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder未選択・読込失敗時のdetail cleanupを共通化する。

### 2026-08-11 — Phase 4 / Batch 16

- folder未選択、一覧空、鍵不一致、folder削除後のcleanupを`clearFolderSelectionState`へ抽出した。
- selected folder／archive、photo／quest／検索結果、tab／scope／criteria／paginationを一括初期化するよう統一した。
- draft cleanup、detail非表示、archive・folder再描画は用途別callbackとして注入した。
- cleanup stateとcallback実行順序をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder password prompt・不一致処理の共通orchestrationを進める。

### 2026-08-11 — Phase 4 / Batch 17

- 鍵付きfolderの入力要否判定、prompt cancel／空入力guard、trim済みpassword保存を`ensureFolderPasswordState`へ抽出した。
- 403鍵不一致判定後の保存済みpassword破棄、folder cleanup、error通知を`handleInvalidFolderPassword`へ抽出した。
- prompt・error判定・翻訳文言はentry callbackとして維持した。
- password保存・再prompt抑止・cancel・不一致cleanupをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder一覧の空状態と選択維持orchestrationを共通化する。

### 2026-08-11 — Phase 4 / Batch 18

- folder一覧・未読map・選択IDの描画入力を`renderFolderListState`へ集約した。
- 空一覧と、選択中folderが更新後の一覧から消えた状態を検知して共通cleanupするようにした。
- デモ専用のphoto mode labelは描画callback内の環境差として維持した。
- 選択維持用context、選択消失、空一覧の分岐をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder未読集計とstate反映の共通orchestrationを進める。

### 2026-08-11 — Phase 4 / Batch 19

- 全folder／指定folderの対象選択、並列未読取得、取得失敗時fallbackを`refreshFolderUnreadState`へ抽出した。
- mode別未読値のboolean正規化と`folderModeUnreadMap`／`folderUnreadMap`反映を共通化した。
- photo／quest個別の未読算出は既存`computeFolderUnread` callbackとして注入した。
- 対象filter、失敗fallback、mode別・総合未読state反映をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではphoto／quest個別のfolder未読算出をruntimeへ移す。

### 2026-08-11 — Phase 4 / Batch 20

- folder modeに応じたphoto／quest取得と最新incoming comment判定を`computeFolderUnreadState`へ抽出した。
- photo ID／quest read keyの既読照合と、最初の未読検知時の短絡を共通化した。
- password未入力の鍵付きfolderはAPI取得せず未読なしとするguardを共通化した。
- mode正規化・既読判定・quest key生成は既存helperをcallback注入した。
- photo／quest未読算出と鍵付きfolder skipをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではcomment取得・既読反映後のfolder未読更新を共通化する。

### 2026-08-11 — Phase 4 / Batch 21

- photo comment取得、最新incoming算出、未読判定、既読保存を`createCommentReadController`へ集約した。
- accordion開閉後に選択中folderだけ未読を再集計し、folder一覧を再描画する処理を同controllerへ移した。
- quest描画時の既読保存も共通controller経由へ統一した。
- comment取得・既読保存・選択folder更新と、未選択時skipをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではphoto／quest作成中stateとcontrol無効化を共通化する。

### 2026-08-11 — Phase 4 / Batch 22

- quest作成の多重実行・folder未選択・空文字guardを`runQuestCreation`へ抽出した。
- 作成中の`isCreatingQuest`、button／textarea無効化、成功時入力消去、finally復元を共通化した。
- API呼出と作成後のquest再読込はentry callbackとして注入した。
- photo uploadの既存`runUploadBatch`／`createUploadLoadingController`と同じruntime管理パターンへ揃えた。
- 成功時state・control遷移、失敗時復元、各guardをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは共通mutation actionのloading／error boundaryを整理する。

### 2026-08-11 — Phase 4 / Batch 23

- mutation event共通のerror消去、async実行、例外捕捉、表示、loggingを`createActionBoundary`へ抽出した。
- 本番／デモの`safeAction`は共通boundaryへ委譲し、翻訳済みlabel・messageだけを注入する構成にした。
- upload／questのloadingと`finally`復元はdomain runtimeに、event全体のerror表示はaction boundaryに責務分離した。
- 成功値の返却と、失敗時のformat・表示・log・例外吸収をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは初期化・room切替・folder選択のerror boundaryを共通action構成へ揃える。

### 2026-08-11 — Phase 4 / Batch 24

- domain error handlerが処理済みを返した場合だけ例外を吸収する`runActionWithHandledErrors`を追加した。
- 初期化errorは同boundary経由で専用表示callbackへ渡し、従来どおり成功／失敗booleanを返す構成にした。
- folder選択の鍵不一致はdomain側で処理済みにし、それ以外は共通action boundaryへ再throwするよう整理した。
- room切替失敗はselect表示を戻してから再throwし、共通`safeAction`で表示する責務順に揃えた。
- 成功値、handled error吸収、unhandled error再throwをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom changeのvalidation・confirm・切替orchestrationを共通化する。

### 2026-08-11 — Phase 4 / Batch 25

- room選択値の正規化、空値・同一room guard、一覧存在・disabled判定を`runRoomChange`へ抽出した。
- 切替確認、cancel時selector復元、切替実行、失敗時selector復元と再throwを共通化した。
- 両entryの`onRoomChange`は共通action boundaryで`runRoomChange`を呼ぶだけの構成にした。
- unchanged／unavailable／cancelled／switchedと、失敗時復元をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder change eventと選択ID解決を共通化する。

### 2026-08-11 — Phase 4 / Batch 26

- folder選択値の正規化、空値時cleanup、state一覧からのID解決を`runFolderChange`へ抽出した。
- 存在しないfolder IDのguardと、解決済みfolderによる選択実行を共通化した。
- event changeとfolder作成後の自動選択が同じ`selectFolderById`／runtime経路を通る構成にした。
- 両entryのfolder change handlerは共通action boundaryへの一行接続に縮小した。
- cleared／missing／selectedの各分岐と解決済みobject受渡しをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではentryに残る重複runtime wrapperを棚卸しし、Phase 4チェック可否を再評価する。

### 2026-08-11 — Phase 4 / Batch 27

- 両entryの関数一覧を棚卸しし、upload／comment／folder detail周辺のruntime委譲だけを行うwrapperを特定した。
- loading、draft clear／rebuild／sync、一括反映／cancel、comment load、tab／検索control同期の9 wrapperを直接alias接続へ縮小した。
- wrapper削除に伴う初期化時TDZを避けるため、upload editorのclear callbackはcontrollerを遅延参照する構成にした。
- 描画・課金・管理UIの業務実装が両entryに残るため、Phase 4の4チェック項目は未チェックを維持する。
- 次Batchでは重複の大きいsubscription／billing UI orchestrationを共通runtimeへ移す。

### 2026-08-11 — Phase 4 / Batch 28

- billing mode・現在plan・rank比較とcheckout／unchanged／upgrade／downgrade分岐を`runSubscriptionPlanChange`へ抽出した。
- confirm cancel、subscription変更、team／admin再読込、変更後通知の順序を共通化した。
- 本番のStripe遷移とデモstore更新は`startCheckout` callbackとして環境側に維持した。
- checkout、upgrade、同一plan、cancel、不正planをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではplan表示・変更確認・成功文言の共通UI formatterを抽出する。

### 2026-08-11 — Phase 4 / Batch 29

- plan表示名、checkout／upgrade／downgrade確認文、変更成功文を`createSubscriptionPlanUi`へ抽出した。
- 本番／デモの重複formatterを削除し、同じ`translate`／`formatMessage`注入経路へ統一した。
- subscription変更後の通知も共通formatterから生成する構成にした。
- plan labelとcheckout・upgrade・downgrade・成功文をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではフリープラン変更の確認・制約error・再読込orchestrationを共通化する。

### 2026-08-11 — Phase 4 / Batch 30

- フリープラン変更の確認、API実行、成功後再読込・通知を`runFreePlanChange`へ抽出した。
- `FREE_PLAN_REQUIREMENTS_NOT_MET`だけをdomain errorとして吸収し、制約表示へ渡す構成を共通化した。
- その他errorは共通action boundaryへ再throwする挙動を維持した。
- cancel、成功、要件未達、未知errorをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではフリープラン案内・制約・確認・成功文言formatterを共通化する。

### 2026-08-11 — Phase 4 / Batch 31

- フリープラン／有料プラン案内、要件未達制約、変更確認、成功文を`createFreePlanUi`へ抽出した。
- 本番／デモの重複4 formatterを削除し、翻訳・message format・容量formatを注入する構成にした。
- billing案内とフリープラン変更flowが同じformatter instanceを利用するよう統一した。
- 案内、容量・folder数制約、確認、成功文をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではlow storage modalの判定・表示orchestrationを共通化する。

### 2026-08-11 — Phase 4 / Batch 32

- low storageのadmin／billing guard、100MB・15%閾値、upload blocked判定を`createLowStorageController`へ抽出した。
- room別の表示済み記録、重複表示抑止、容量回復時の記録解除、modal message・表示を共通化した。
- 容量追加actionのadmin panel誘導と、使用量によるBASIC／PLUS／PRO推奨を同controllerへ移した。
- 初回表示・再表示抑止・回復・推奨plan actionをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではbilling status・storage graph描画orchestrationを共通化する。

### 2026-08-12 — Phase 4 / Batch 33

- billing有無によるstatus／guide／archive note描画と空状態cleanupを`renderBillingAdminState`へ抽出した。
- storage graph描画、low storage判定、subscription button同期の実行順序を共通化した。
- billing status・archive文言は翻訳差分を保つcallbackとしてentryに残した。
- billing描画と空状態cleanup、callback順序をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではbilling status・folder usage文言formatterを共通化する。

### 2026-08-12 — Phase 4 / Batch 34

- billing mode・planに基づくfolder上限と使用数表示を`createBillingStatusUi`へ抽出した。
- 使用量、plan／無料容量、残量、folder summary、plan名を組み立てるbilling status formatterを共通化した。
- Batch 33でentryに残した大きなstatus callbackを共通formatter呼出へ縮小した。
- free／subscriptionのfolder上限・usage・capacity・plan表示をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではtop／admin storage graph wrapperとwidth同期を共通化する。

### 2026-08-12 — Phase 4 / Batch 35

- header幅からtop storage graph幅を同期する処理を`createStorageGraphController`へ抽出した。
- top／admin graphのelement map組立とbilling・active・folder usage option注入を同controllerへ集約した。
- 本番の翻訳済みused／remaining labelだけをcontroller optionとして維持した。
- 両entryからtop／admin graph wrapper本体を削除し、controller aliasへ縮小した。
- width同期とtop／admin描画callback入力をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではbilling bar描画とadmin visibility orchestrationを共通化する。

### 2026-08-12 — Phase 4 / Batch 36

- top graph描画後のbilling bar element・state option組立を`createBillingUiController`へ抽出した。
- admin権限による4管理button表示、admin panel非表示、low storage／folder password modal cleanupを共通化した。
- 本番だけの翻訳済みplan表記は`formatPlan` optionとして維持した。
- 両entryのbilling bar／admin visibility wrapper本体を削除しcontroller aliasへ縮小した。
- billing bar optionと非admin時のvisibility・cleanupをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin panel open／closeとteam admin mode同期を共通化する。

### 2026-08-12 — Phase 4 / Batch 37

- team admin panelのopen／close／toggleとpanel再読込を`createTeamAdminController`へ抽出した。
- admin mode中のheader controls・room static・folder detail表示同期とroom header再描画を共通化した。
- menu操作、Stripe return、low storage誘導が同じcontroller経路を使う構成に揃えた。
- open／close／toggle、mode表示、menu close、panel loadをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin panelのmember／folder data load orchestrationを共通化する。

### 2026-08-12 — Phase 4 / Batch 38

- admin権限・panel表示guardとteam member／folder一覧取得を`loadAdminPanelState`へ抽出した。
- left member除外、空配列正規化、選択中admin folderの存在確認・resetを共通化した。
- member／folder取得errorを独立保持し、一方の失敗で他方の描画を止めない構成にした。
- entryには成功／失敗時のDOM描画と各管理actionだけを残した。
- 正常取得、left除外、選択整合性、独立error、guardをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは選択admin folderのmember取得・失敗処理を共通化する。

### 2026-08-12 — Phase 4 / Batch 39

- 選択中admin folderのmember取得と空配列正規化を`loadAdminFolderMembers`へ抽出した。
- panel全体を待たせない非同期更新を維持しつつ、成功／失敗callbackの呼び分けを共通化した。
- 両entryから直接の`listFolderMembers`呼出とPromise error分岐を削除した。
- member取得成功・失敗とcallback入力をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin panelのteam member更新・削除actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 40

- team memberの更新確認、API更新、成功通知、panel再読込を`runTeamMemberUpdate`へ抽出した。
- 閲覧権限変更のキャンセル時にselectを元の値へ戻す処理を共通actionのcallbackへ統合した。
- member削除を同じ更新actionへ揃え、entryには確認・成功文言だけを残した。
- 更新時の処理順序とキャンセル時にAPIを呼ばないことをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin folderの選択・招待URL発行／失効actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 41

- admin folder選択時のstate更新とpanel再読込を`selectAdminFolder`へ抽出した。
- folder招待の発行、token検証・保存、URL生成、表示更新を`createAdminFolderInvite`へ集約した。
- folder招待のtokenなし・確認キャンセル・失効・state cleanupを`revokeAdminFolderInvite`へ集約した。
- 選択、発行、失効、キャンセル、tokenなし、発行応答tokenなしをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin folderのpassword設定・解除actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 42

- admin folderのpassword設定／解除に伴う確認とAPI更新を`runFolderPasswordUpdate`へ抽出した。
- password cacheの追加／削除、成功通知、folder一覧／admin panel再読込の順序を共通化した。
- entryにはfolder名を含む確認文言、成功文言、input cleanupだけを残した。
- 設定、解除、キャンセル、更新後のcallback順序をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin folder削除actionと関連state cleanupを共通化する。

### 2026-08-12 — Phase 4 / Batch 43

- admin folder削除の確認とAPI呼出を`runAdminFolderDelete`へ抽出した。
- 削除後のadmin選択解除、招待token／password cache削除を共通化した。
- 成功通知、folder一覧、team情報、admin panel再読込の順序を共通化した。
- 削除成功、関連state cleanup、callback順序、キャンセルをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin folder member解除actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 44

- admin folder member解除の確認とAPI呼出を`runAdminFolderMemberRemove`へ抽出した。
- 解除後の成功通知とadmin panel再読込の順序を共通化した。
- entryにはmember名を含む確認文言と成功文言だけを残した。
- 解除成功、callback順序、キャンセル時にAPIを呼ばないことをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin panel全体のDOM描画error boundaryを共通化する。

### 2026-08-12 — Phase 4 / Batch 45

- admin panelのmember／folderセクション描画を`renderAdminPanelSection`の独立error boundaryへ移した。
- API取得errorとDOM描画中errorを同じsection別fallbackへ流す構成に統一した。
- 一方のsection失敗が他方の描画とbilling描画を止めない従来挙動を維持した。
- 正常描画、取得error、描画errorとfallback callbackをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin member／folder sectionの描画wrapperを共通controllerへ集約する。

### 2026-08-12 — Phase 4 / Batch 46

- admin data取得、member／folder独立描画、billing描画を`renderAdminPanel`へ集約した。
- admin権限・panel表示guardから描画完了までの実行順序を共通controllerで管理する構成にした。
- 両entryの`loadAdminPanel`はsection別DOM callbackと文言注入だけを持つ形へ縮小した。
- folder側が失敗してもmember・billing描画が続くこととguard時skipをテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin member sectionのDOM描画設定を共通factoryへ移す。

### 2026-08-12 — Phase 4 / Batch 47

- admin member rendererへ渡すowner、翻訳、権限変更／削除handler設定を`createAdminMemberSection`へ抽出した。
- safe action境界と`runTeamMemberUpdate`の結線、権限変更キャンセル時のselect復元をfactoryへ集約した。
- entryには確認・成功・error文言と対象DOMだけを残した。
- renderer option、翻訳、権限キャンセル、member削除の処理順序をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin folder sectionのoverview描画設定を共通factoryへ移す。

### 2026-08-12 — Phase 4 / Batch 48

- admin folderの空状態、overview生成、picker／empty／選択済みwrap配置を`createAdminFolderSection`へ抽出した。
- 選択ID更新とpanel再読込を行うsafe actionの結線を同factoryへ集約した。
- entryにはfolder header文言、選択済みfolderの管理UI、error文言だけを残した。
- overview option、DOM配置順、folder選択、空状態と選択解除をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは選択済みadmin folderのaction／member描画設定を共通factoryへ移す。

### 2026-08-12 — Phase 4 / Batch 49

- 選択済みadmin folderの招待、password、削除action設定を`createAdminSelectedFolderRenderer`へ抽出した。
- member loading box配置、member取得、一覧描画、解除handler、取得error反映を同factoryへ集約した。
- entryには確認・通知・error文言、URL生成、DOM生成callbackだけを残した。
- action handler生成、members box配置、member取得・renderer option結線をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin panel callback群を起動時に生成し、`loadAdminPanel`を薄い呼出へ縮小する。

### 2026-08-12 — Phase 4 / Batch 50

- admin member／folder／billing callback群を`adminPanelOptions`としてentry起動時に一度だけ生成する構成へ変更した。
- panel再読込ごとのfactory再生成をなくし、`loadAdminPanel`を`renderAdminPanel`の薄い呼出へ縮小した。
- 本番／デモ双方が同じoptions生成・controller呼出境界を持つことを構造テストへ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin panel固有文言callback群を共通UI formatterへ移す。

### 2026-08-12 — Phase 4 / Batch 51

- admin panelのmember／folder確認、成功、空状態、取得失敗文言を`createAdminPanelUi`へ抽出した。
- folder件数・作成者・容量header、招待／password／削除／member解除文言を共通formatterへ集約した。
- billing archive注記も同formatterへ移し、本番の翻訳・format経路をoption注入で維持した。
- member／folder名、容量、設定／解除分岐、error整形をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではadmin panel optionsの共通composer化を検討し、Phase 4 checklist判定を更新する。

### 2026-08-12 — Phase 4 / Batch 52

- member、folder overview、selected-folder、billing設定の合成を`createAdminPanelOptions`へ抽出した。
- entryは環境依存DOM・dialog callbackをsection別optionとして注入し、factory階層を直接組み立てない構成にした。
- composerが全section callbackとvisibility／billing callbackを公開することをテストした。
- 構造契約を共通composer境界へ更新した。
- Phase 4 checklistを再監査したが、entryにはadmin以外の業務UI／mutationがまだ残るため4項目とも未チェックを維持する。
- 次Batchでは共通化済みfolder password更新を通常管理buttonにも適用する。

### 2026-08-12 — Phase 4 / Batch 53

- 通常のfolder password modalも`runFolderPasswordUpdate`を使う経路へ統一した。
- entryから直接のpassword API呼出とpassword cache追加／削除を除去した。
- input cleanup、modal close、toastは環境依存callbackとして維持し、folder再読込を共通actionへ委譲した。
- 本番／デモ双方の通常password handlerが共通actionを使うことを構造テストへ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは通常folder削除actionをadmin削除actionと共通化する。

### 2026-08-12 — Phase 4 / Batch 54

- folder削除の確認、API呼出、招待token／password cache cleanup、再読込を汎用`runFolderDelete`へ統合した。
- admin削除actionは同じ関数のaliasとし、通常管理buttonも同じ削除経路へ移した。
- 通常画面固有のalertと選択folder UI cleanupは`onDeleted` callbackとして維持した。
- 本番／デモ双方の通常削除handlerが共通actionを使うことを構造テストへ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom削除actionの確認・cleanup・画面遷移を共通化する。

### 2026-08-12 — Phase 4 / Batch 55

- room削除の二段階確認、API呼出、成功通知、context reset、setup画面遷移を`runRoomDelete`へ抽出した。
- 初回確認と最終確認それぞれのキャンセル状態を明示し、APIを呼ばない境界を共通化した。
- entryには削除確認・成功文言と既存UI callbackだけを残した。
- 削除後の処理順序と二段階のキャンセルをテストし、両entryの共通action利用を構造契約へ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではaccount削除のowner guard・二段階確認・error分岐を共通化する。

### 2026-08-12 — Phase 4 / Batch 56

- account削除の全room owner guard、二段階確認、API呼出、削除後cleanupを`runAccountDelete`へ抽出した。
- API側owner競合を判定callbackで処理し、案内とmenu close後に安全終了する分岐を共通化した。
- 成功時の通知、menu close、room reset、auth clear、認証画面遷移の順序を共通化した。
- 成功、事前owner block、API owner conflictをテストした。
- デモentryには自己account削除機能がないため、存在する本番経路のみを置換した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom脱退actionのadmin guard・確認・local cleanupを共通化する。

### 2026-08-12 — Phase 4 / Batch 57

- room脱退のadmin guard、事前案内、確認、API呼出、local cleanupを`runRoomLeave`へ抽出した。
- team情報取得失敗時も確認へ進み、leave API失敗時もlocal脱退を完了する従来fallbackを共通化した。
- room reset、menu close、setup画面遷移、room一覧再読込の順序を統一した。
- 成功、admin block、guard失敗後のキャンセル、leave API失敗をテストした。
- 本番／デモ双方の脱退handlerが共通actionを使うことを構造契約へ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom作成・初期room作成のvalidation／409 error処理を共通化する。

### 2026-08-12 — Phase 4 / Batch 58

- 通常／初期room作成の入力trim・validation、API呼出、room state反映を`runRoomCreation`へ抽出した。
- 作成後のadmin close、room reset、app表示、成功通知の順序を共通化した。
- 409を既存room保有／room名重複へ分類し、その他errorと合わせて表示callbackへ委譲した。
- entryから`createRoomAndEnter`重複wrapperを削除した。
- validation、成功、2種類の409、一般errorをテストし、両entryの通常／初期作成経路を構造契約へ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder作成のvalidation・plan制約error・成功後選択を共通化する。

### 2026-08-12 — Phase 4 / Batch 59

- folder作成のtitle trim・validation、mode正規化、password trim、API呼出を`runFolderCreation`へ抽出した。
- 無料plan folder上限errorの判定と案内をcallback境界へ統一した。
- 作成後の入力cleanup・modal close・toast、folder一覧再読込、自動選択の順序を共通化した。
- 空入力、正規化済みAPI入力、成功後callback順序、plan上限をテストした。
- 本番／デモ双方のfolder作成handlerが共通actionを使うことを構造契約へ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは通常／folder招待URLの発行・失効・copy処理をさらに統合する。

### 2026-08-12 — Phase 4 / Batch 60

- room／folder招待のAPI発行、token検証・保存、URL生成を`createInviteToken`へ統合した。
- tokenなし、確認キャンセル、API失効、token cleanup、成功通知を`revokeInviteToken`へ統合した。
- clipboard成功、prompt fallback、未入力、copy拒否を`copyInviteText`へ抽出した。
- 既存のadmin folder invite helperは汎用actionを利用するwrapperへ縮小した。
- 発行・失効・copy・fallback・未入力をテストし、両entryの共通action利用を構造契約へ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder list取得error分類と表示処理を共通化する。

### 2026-08-12 — Phase 4 / Batch 61

- folder一覧取得errorのmessage正規化とnetwork／一般分類を`handleFolderListError`へ抽出した。
- `Failed to fetch`／`Type error`をnetwork・CORS案内へ流す既存判定を共通化した。
- entryには翻訳済みnetwork案内と一般error表示callbackだけを残した。
- network errorと一般errorの分類・callback入力をテストした。
- 本番／デモ双方のfolder loaderが共通error handlerを使うことを構造契約へ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは通常／初期room作成の文言formatterを共通UIへ移す。

### 2026-08-12 — Phase 4 / Batch 62

- room作成の入力不足、成功、既存room、名前重複、一般error文言を`createRoomCreationUi`へ抽出した。
- 通常modalと初期room画面が同じformatterを使い、alert／error表示先だけをentry callbackとして維持した。
- 本番の翻訳・format・error message経路をoption注入で維持し、デモも同じ経路へ揃えた。
- validation、成功、2種類の競合、一般error文言をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder作成のvalidation・plan上限・成功文言formatterを共通UIへ移す。

### 2026-08-12 — Phase 4 / Batch 63

- folder作成の入力不足、無料plan上限、登録成功文言を`createFolderCreationUi`へ抽出した。
- API error bodyの個別messageを優先し、ない場合の無料plan既定案内を共通化した。
- 本番／デモのtitle error、alert、toastが同じformatter経路を使う構成に揃えた。
- validation、既定／API指定plan上限、成功文言をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom削除・脱退・account削除の確認／成功文言formatterを共通UIへ移す。

### 2026-08-12 — Phase 4 / Batch 64

- room削除、room脱退、account削除の確認・警告・成功文言を`createManagementUi`へ抽出した。
- account owner競合案内と二段階確認文言も同formatterへ集約した。
- entryはdialog種別と画面固有callbackだけを持ち、文言生成を共通UIへ委譲した。
- room削除、脱退、account削除の全formatter出力をテストした。
- デモにないaccount削除文言も共通formatter内で一元管理した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは通常folder削除・password更新・invite操作の文言formatterを共通UIへ移す。

### 2026-08-12 — Phase 4 / Batch 65

- 通常folder削除・password更新とroom招待操作の文言を`createFolderManagementUi`へ抽出した。
- invite発行token不足、失効token不足、失効確認・成功、copy成功・未入力・prompt・拒否案内を集約した。
- 本番／デモのalert・toast・prompt・error表示が同じformatterを使う構成に揃えた。
- folder管理とinvite操作の全formatter出力をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder一覧取得error文言と初期化／global error文言を共通formatterへ移す。

### 2026-08-12 — Phase 4 / Batch 66

- folder一覧のnetwork／一般error、初期化error、未処理Promise、global実行error文言を`createAppErrorUi`へ抽出した。
- error message正規化とformat処理を共通formatterへ集約した。
- entryにはconsole記録と`showError`表示先だけを残した。
- folder network／一般、初期化、未処理Promise、実行error文言をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom／folder mutation handler option群を起動時に生成し、event登録をさらに薄くする。

### 2026-08-12 — Phase 4 / Batch 67

- room／folder作成actionをevent handler化する`createRoomCreationHandler`／`createFolderCreationHandler`を追加した。
- room handlerは事前cleanupと入力取得、folder handlerは入力snapshot取得と共通action option合成を担当する。
- handler再利用時も各入力を実行時に取得する構成にした。
- room／folder handlerの生成、実行結果、callback結線をテストした。
- entryへのfactory適用は次Batchで行うため、Phase 4 checklistは未チェックを維持する。
- 次Batchでは両entryのinline作成handlerを生成済みhandlerへ置換する。

### 2026-08-12 — Phase 4 / Batch 68

- 通常room、初期room、folder作成optionを起動時にfactoryへ渡し、生成済みhandlerとして保持する構成にした。
- mutation event登録を`createRoomHandler`／`createInitialRoomHandler`／`createFolderHandler`参照だけへ縮小した。
- 初期room作成の`clearError`はhandlerの`before` callbackへ移した。
- 両entryがhandler factoryを生成し、event registrarへ直接渡すことを構造契約へ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではroom削除・脱退・account削除handlerも起動時factory生成へ移す。

### 2026-08-12 — Phase 4 / Batch 69

- room脱退、room削除、account削除の共通action wrapper factoryを追加した。
- 両entryで脱退／room削除handlerを起動時生成し、本番ではaccount削除handlerも同様に生成した。
- event登録を生成済みhandlerへの`safeAction`適用だけへ縮小した。
- 3種類のhandler生成と主要な早期終了状態をテストし、構造契約をfactory境界へ更新した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder削除・password更新・invite handlerを起動時factory生成へ移す。

### 2026-08-12 — Phase 4 / Batch 70

- 選択folder取得を含む`createFolderDeleteHandler`／`createFolderPasswordHandler`を追加した。
- copy・発行・失効を一組で生成する`createInviteHandlers`を追加した。
- folder未選択時の安全終了と、invite値を実行時に取得する構成を共通化した。
- folder／invite handlerの生成、missing guard、copy・発行・失効結線をテストした。
- entryへのfactory適用は次Batchで行うため、Phase 4 checklistは未チェックを維持する。
- 次Batchでは両entryのinline folder／invite handlerを生成済みhandlerへ置換する。

### 2026-08-12 — Phase 4 / Batch 71

- room inviteのcopy・発行・失効optionを起動時に`createInviteHandlers`へ渡す構成にした。
- 通常folder削除・password更新も起動時に共通factoryでhandler生成する構成へ移した。
- invite／mutation event登録を生成済みhandlerへの`safeAction`適用だけへ縮小した。
- 両entryの構造契約をhandler factory境界へ更新した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは未使用になった直接action import／薄いinvite wrapperを監査・整理する。

### 2026-08-12 — Phase 4 / Batch 72

- 両entryのruntime symbol使用数を監査し、factory適用後に未使用となったinvite発行／失効・folder削除／password直接action importを削除した。
- `setInviteUrlText`はURL欄反映＋自動copy、`copyInviteUrlFromInput`はadmin folder入力値のcopy adapterとして利用中のため維持した。
- 2つの薄いinvite wrapperが共通`copyInviteUrl`へ委譲することを構造契約へ追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではentryの残存直接API mutationを再監査し、次の共通化対象を決める。

### 2026-08-12 — Phase 4 / Batch 73

- 両entryの直接API mutationを再監査し、quest／photo card内CRUDが最大の残存重複と確認した。
- quest完了のstatus更新・quest再読込と、削除確認・API削除・folder再読込を`createQuestMutationActions`へ抽出した。
- quest card rendererには生成済みcomplete／remove actionを`safeAction`経由で渡す構成にした。
- 完了・削除のAPI引数、再読込順序、削除キャンセルをテストした。
- 残存mutation監査結果を記録し、次候補をquest photo／comment CRUDとした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではquest card内photo削除actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 74

- photo削除の確認・API呼び出し・再読込を`createPhotoMutationActions`へ抽出した。
- quest card内と通常photo一覧の4か所（本番・デモ）を同じremove actionへ統合した。
- 呼び出し元の表示単位に応じてfolder全体またはphoto一覧の再読込処理を注入する構成にした。
- 削除成功時の呼出順序とキャンセル時にAPIを呼ばないことをテストした。
- 両entryから直接`deletePhoto`を呼ばない構造契約を追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではquest commentの追加・削除actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 75

- quest commentの追加・削除とquest再読込を`createQuestCommentMutationActions`へ抽出した。
- 削除確認をactionへ含め、キャンセル時にはAPIも再読込も実行しない構成にした。
- 両entryのquest comment描画は生成済みadd／remove actionを`safeAction`へ渡すだけに縮小した。
- comment追加・削除のAPI引数と処理順序、削除キャンセルをテストした。
- 両entryからquest comment APIを直接呼ばない構造契約を追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは通常photo commentの編集・削除actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 76

- photo commentの編集・削除とphoto一覧再読込を`createPhotoCommentMutationActions`へ抽出した。
- 編集前の表示位置保持と削除確認を注入可能な共通action境界に揃えた。
- 両entryのcomment rowには生成済みedit／remove actionを直接渡す構成にした。
- 編集・削除のAPI引数と処理順序、削除キャンセルをテストした。
- 両entryからphoto comment更新・削除APIを直接呼ばない構造契約を追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではphoto comment追加中stateと作成actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 77

- photo comment追加中state、空入力guard、control無効化、API作成、再読込を`createPhotoCommentAddHandler`へ抽出した。
- 追加前のaccordion維持・scroll位置保存を注入し、失敗時にはcontrolと再試行可能stateを復帰する構成にした。
- 両entryの追加ボタンは共通handlerを生成して登録するだけに縮小した。
- 空入力、二重送信、成功時の処理順序、失敗後のcontrol復帰と再試行をテストした。
- 両entryからphoto comment作成APIを直接呼ばない構造契約を追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではphoto log tag更新actionを共通化する。

### 2026-08-12 — Phase 4 / Batch 78

- photoのlog tag更新を既存の`createPhotoMutationActions`へ統合した。
- 更新前の表示位置保持、API更新、photo一覧再読込をphoto単位の共通actionに揃えた。
- 両entryのphoto card編集callbackは次のtagを共通actionへ渡すだけに縮小した。
- 更新payloadと処理順序を削除actionと合わせてテストした。
- 両entryからphoto更新APIを直接呼ばない構造契約を追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは残存する直接API mutationを再監査する。

### 2026-08-12 — Phase 4 / Batch 79

- 両entryの直接API呼び出しを再監査し、共通runtimeへ注入済みのadapter callbackと、entry内に残るmutationを分類した。
- 所有room削除ガードの現在room判定・切替確認・API切替・context reset・画面復帰を`runOwnerRoomSwitch`へ抽出した。
- 現在room、確認キャンセル、切替成功と処理順序をテストした。
- 両entryから所有roomへの直接`switchRoom`呼び出しを除去する構造契約を追加した。
- upload・quest作成・subscription変更のAPI参照は共通runtimeへ渡すadapter callbackとして残ることを確認した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは表示名取得・保存と初回設定flowを共通化する。

### 2026-08-12 — Phase 4 / Batch 80

- current user取得・既存表示名反映・初回入力loopを`ensureUserDisplayName`へ抽出した。
- 表示名のtrim検証・API保存・state反映を`saveUserDisplayName`へ共通化し、メニューからの名前変更にも適用した。
- 本番固有のdeveloper属性反映はuser取得後callbackとして注入し、共通flowから環境差分を分離した。
- cancel後の再入力、空値、保存成功、既存名、単独保存のinvalidをテストした。
- 両entryからcurrent user取得・表示名保存APIの直接呼び出しを除去する構造契約を追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchでは表示名変更時のprompt・validation・UI更新handlerを共通化する。

### 2026-08-12 — Phase 4 / Batch 81

- 表示名変更のprompt・キャンセル・validation・保存・完了通知を`createDisplayNameChangeHandler`へ抽出した。
- 保存成功時の表示名DOM反映・storage graph更新・成功文言はcallbackとして注入した。
- 両entryの認証eventには生成済みhandlerを`safeAction`経由で渡す構成にした。
- 保存成功、空値、キャンセルと完了status通知をテストした。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではfolder export要求・結果処理の共通化範囲を監査する。

### 2026-08-12 — Phase 4 / Batch 82

- folder exportの選択検証・確認・API要求・PDF stream読込・fallback・結果通知を`runFolderExport`へ抽出した。
- fetch・Blob・object URL・画面遷移・翻訳文言をbrowser adapter callbackとして注入した。
- 両entryに重複していた約80行のexport flowをruntime呼び出しへ置換した。
- PPT、streamed PDF、folder未選択、確認キャンセル、download fallback、API失敗をテストした。
- 両entryからfolder export APIを直接呼ばない構造契約を追加した。
- Phase 4のentry縮小は継続中のためチェック項目は未チェックを維持する。
- 次Batchではmenu action visibilityとdeveloper UI注入境界を共通化する。
