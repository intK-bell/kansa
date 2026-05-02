# i18n対応実装メモ (2026-05-02)

## 概要
- ブラウザまたはユーザー設定の言語に合わせて、フロントエンド表示を切り替える仕組みを追加した。
- 対応言語は日本語、英語、中国語、ベトナム語。
- 既存文言を辞書キー化し、静的HTMLは `data-i18n` 属性で翻訳できるようにした。

## 対象ファイル
- `frontend/i18n.js`
  - 新規追加。
  - `window.KANSA_I18N` として `t`, `format`, `setLanguage`, `getLanguage` を公開。
  - `navigator.languages`、`localStorage.kansa_language`、`window.KANSA_CONFIG.language` から言語を判定。
  - `ja`, `en`, `zh-CN`, `vi` をサポート。
  - `data-i18n`, `data-i18n-html`, `data-i18n-attr` に対応。
  - 動的に追加されたDOMも `MutationObserver` で翻訳対象にする。
- `frontend/index.html`
  - `i18n.js` を `main.js` より前に読み込むよう追加。
  - アプリ本体上部、メニュー、部屋作成画面、管理パネル、アップロード操作の静的文言を `data-i18n` 化。
  - ダイアログ/モーダル内の見出し、ボタン、説明文、placeholder、`aria-label` を `data-i18n` / `data-i18n-attr` 化。
- `frontend/main.js`
  - 動的生成文言、ダイアログ文言、日時表示、エラー/トースト文言を `t()` / `format()` 経由に変更。
- `frontend/demo.html`
  - `i18n.js` を `demo.js` より前に読み込むよう追加。
  - アプリ本体上部、メニュー、部屋作成画面、管理パネル、アップロード操作の静的文言を `data-i18n` 化。
  - ダイアログ/モーダル内の見出し、ボタン、説明文、placeholder、`aria-label` を `data-i18n` / `data-i18n-attr` 化。
- `frontend/demo.js`
  - デモ用の動的文言、ダイアログ、日時表示を翻訳対象化。
  - alert/confirm/prompt の可変文言を `t()` / `format()` 経由に揃え、本番側と同じ辞書キーを使うようにした。
  - デモ出力サンプルは現在言語に応じて言語別ファイルを参照する。
- `frontend/generate_demo.js`
  - `--language ja|en|zh-CN|vi` を追加。
  - デモPDF/PPTサンプル内の固定文言を言語別に生成できるようにした。
- `backend/src/export-i18n.js`
  - PDF/PPTなど生成物向けの軽量辞書を追加。
  - APIから画面へ返る一部の日本語エラーメッセージも言語別に返せるようにした。
- `backend/src/ppt-layout.js`
  - PPT出力内のタイトル、コメント見出し、空コメント文言、メタ情報を言語別に変更。
- `backend/src/api.js`
  - `x-kansa-language` / `Accept-Language` から出力言語を判定。
  - PDF/PPT出力の固定文言、フッター、日時表示を言語別に変更。
  - フリープラン制約、フォルダ上限、出力対象なし、課金停止確認失敗のAPIメッセージを言語別に変更。
- `backend/template.yaml`
  - CORS許可ヘッダーに `x-kansa-language` を追加。
- `frontend/landing.html`
  - LP本文、料金表、申込導線、CTA、会社情報を `data-i18n` 化。
- `frontend/legal.html`
  - 特定商取引法に基づく表記、利用規約、プライバシーポリシー本文を `data-i18n` 化。
- `docs/user-guide.md`
  - 現在のUIに合わせて利用者ガイドを更新。
- `docs/user-guide.en.md`, `docs/user-guide.zh-CN.md`, `docs/user-guide.vi.md`
  - 利用者ガイドの英語・中国語・ベトナム語版を追加。
- `frontend/manuals/README.md`
  - HTML版マニュアル、レガシーPDF、Markdown版ガイドの扱いを記録。
- `frontend/manuals/kansa-manual.html`
  - PDFに代わるアプリ内マニュアルとして追加。
  - `data-i18n` と `frontend/i18n.js` で日本語、英語、中国語、ベトナム語へ切り替え。

## 言語判定
優先順:

1. `window.KANSA_CONFIG.language`
2. `localStorage.kansa_language`
3. `navigator.languages` / `navigator.language`
4. どれにも一致しない場合は日本語

中国語は `zh`, `zh-CN`, `zh-Hans`, `zh-SG` を `zh-CN` に寄せる。

## 静的HTMLの翻訳方式
- 通常テキスト: `data-i18n="辞書キー"`
- HTMLを含む文言: `data-i18n-html="辞書キー"`
- 属性翻訳: `data-i18n-attr="aria-label:辞書キー;title:辞書キー"`

HTMLを含む翻訳は、既存の固定文言に限定して使う。ユーザー入力値や外部入力値は `data-i18n-html` に入れない。

## 検証結果
実行済み:

```bash
node --check frontend/i18n.js
node --check frontend/main.js
node --check frontend/demo.js
node --check frontend/generate_demo.js
node --check backend/src/export-i18n.js
node --check backend/src/ppt-layout.js
node --check backend/src/api.js
```

`landing.html` と `legal.html` の `data-i18n`, `data-i18n-html`, `data-i18n-attr` について、英語・中国語・ベトナム語の辞書キー欠けがないことを確認済み。
`index.html`, `demo.html`, `main.js`, `demo.js` のダイアログ/モーダル関連キーも同様に確認済み。

確認時点の結果:

```text
en missing 0
zh-CN missing 0
vi missing 0
```

デモ出力サンプル生成:

```bash
node frontend/generate_demo.js --format pdf --language ja
node frontend/generate_demo.js --format pptx_light --language ja
node frontend/generate_demo.js --format pptx_high --language ja
node frontend/generate_demo.js --format pdf --language en
node frontend/generate_demo.js --format pptx_light --language en
node frontend/generate_demo.js --format pptx_high --language en
node frontend/generate_demo.js --format pdf --language zh-CN
node frontend/generate_demo.js --format pptx_light --language zh-CN
node frontend/generate_demo.js --format pptx_high --language zh-CN
node frontend/generate_demo.js --format pdf --language vi
node frontend/generate_demo.js --format pptx_light --language vi
node frontend/generate_demo.js --format pptx_high --language vi
```

## 残対応候補
- バックエンド生成物の翻訳
  - PDF/PPT出力の主要固定文言は対応済み。
  - APIエラーメッセージは引き続きフロント側辞書での表示変換が中心。
- 画像内テキスト
  - デモ画像や説明画像に日本語が埋め込まれている場合は、画像差し替えか言語別画像が必要。
- マニュアル
  - アプリ内マニュアルは `frontend/manuals/kansa-manual.html` に移行済み。
  - HTML版は `data-i18n` と `frontend/i18n.js` を使い、システム/アプリ言語に追従する。
  - `frontend/manuals/kansa-manual.pdf` はレガシー参照として残している。PDF自体の多言語化が必要な場合はHTMLまたはMarkdown版から再生成する。
- 翻訳品質レビュー
  - 英語、中国語、ベトナム語は実装用の初期翻訳。公開前にネイティブ確認するのが望ましい。
- 言語切替UI
  - 現状はシステム言語および設定値に追従する実装。画面上で手動切替したい場合は、メニューや設定画面にUI追加が必要。
- SEO/メタ情報
  - `title` は辞書化済み。`meta description`, OGP, canonical/hreflang まで多言語対応する場合は別対応。
- テスト自動化
  - 辞書キー欠けチェックは手元コマンドで確認済み。CIで継続チェックするなら専用スクリプト化が必要。

## 注意
- `data-i18n-html` は `innerHTML` を更新するため、辞書キーと翻訳値はアプリ管理下の固定値だけを使う。
- 長文の法務文書は原文の意味を保つよう翻訳しているが、法的な正式訳としてはレビューが必要。
