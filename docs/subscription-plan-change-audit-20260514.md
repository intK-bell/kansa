# サブスクプラン変更 調査記録

調査日: 2026-05-14

## 調査目的

- `¥980` の `BASIC` から `¥1,980` の `PLUS` へ月途中で変更した場合の請求挙動を確認する。
- `¥1,980` の `PLUS` から `¥980` の `BASIC` へ下げた場合の反映タイミングと差額扱いを確認する。
- 実装上、画面導線から仕様どおりの変更APIが呼ばれているか確認する。

## 結論

### 1. バックエンドの変更API上の挙動

`POST /team/subscription/change` を正しく使う前提では、仕様どおり。

- 上位プラン変更:
  - 即時反映。
  - Stripe Subscription item の price を更新する。
  - `proration_behavior=always_invoice` を指定しており、残期間分の差額を即時請求する。
  - `¥980 -> ¥1,980` の場合、ユーザーが払うのは固定の `¥1,000` ではなく、残り期間に応じた差額。
- 下位プラン変更:
  - 即時反映しない。
  - `pendingPlan` に変更先を保存し、次回請求境界で反映する。
  - Stripe 更新時は `proration_behavior=none` を指定しており、日割り返金や差額返金は発生しない想定。
  - 変更先プラン上限を現在使用量が超えている場合は、ダウングレード予約を拒否する。

根拠:

- 仕様: `docs/billing-subscription-spec.md`
  - 上位変更は即時反映、当月は差額のみ請求。
  - 下位変更は次月反映。
  - 期中アップグレードは proration を即時請求。
- 実装: `backend/src/api.js`
  - `stripeUpdateSubscriptionPlan(..., 'always_invoice')` でアップグレード。
  - `pendingPlan` でダウングレード予約。
  - 反映時に `stripeUpdateSubscriptionPlan(..., 'none')`。

### 2. 画面導線上の現状

現フロントの有料プランボタンは、既存サブスクの `upgrade` / `downgrade` API を呼んでいない。

- `1GB / 5GB / 10GB` ボタンはすべて `startSubscriptionCheckout(plan)` を呼ぶ。
- `startSubscriptionCheckout(plan)` は `POST /team/subscription/checkout` を呼ぶ。
- `/team/subscription/checkout` は Stripe Checkout の `mode=subscription` セッションを新規作成する。
- 既存契約中かどうかを見て `/team/subscription/change` に切り替える分岐は見つからなかった。
- `/team/subscription/change` を直接呼んでいる画面導線は、確認範囲では `free` のみ。

根拠:

- `frontend/main.js`
  - `syncSubscriptionPlanButtons()` は現在プランのボタンだけ無効化するが、上位/下位ボタンは Checkout 導線のまま。
  - `subscribeBasicBtn` / `subscribePlusBtn` / `subscribeProBtn` は `startSubscriptionCheckout(...)` を呼ぶ。
  - `startSubscriptionCheckout(...)` は `/team/subscription/checkout` を呼ぶ。
- `backend/src/api.js`
  - `/team/subscription/checkout` は `mode=subscription` の Checkout Session を作成する。
  - Checkout 作成時に既存 `stripeSubscriptionId` の有無を見て拒否・変更APIへ誘導する処理はない。

### 3. リスク

画面から既存有料ユーザーが別の有料プランボタンを押した場合、仕様どおりのプラン変更ではなく、新規 Subscription Checkout が作られる可能性がある。

想定される問題:

- 既存 Stripe Subscription が残ったまま、新しい Subscription が作成される可能性がある。
- Webhook は新しい `stripeSubscriptionId` を部屋の billing meta に上書きするため、アプリ上は新プランに見える可能性がある。
- 旧 Subscription を自動停止する実装は確認できなかった。
- その結果、Stripe 上で二重課金になるリスクがある。

### 4. デモと確認スクリプト

- `frontend/demo.js` はデモ内でプラン状態を直接切り替えるため、本番の Stripe 変更挙動の検証には使えない。
- `scripts/run_subscription_checks.sh` は `/team/subscription/change` の `upgrade` / `downgrade` を叩くチェックを持つが、`RUN_CHANGE=1` のときだけ実行される。
- 同スクリプトは画面導線が `/team/subscription/change` を使っているかまでは検証しない。

## 回答としての整理

仕様・バックエンド変更APIとしては次の回答で正しい。

- `¥980 -> ¥1,980`: 残期間分の差額だけを即時請求する。
- `¥1,980 -> ¥980`: 当月は返金なし。次回請求期間から `¥980` に下がる。

ただし、現画面導線では既存契約の有料プラン変更に `/team/subscription/change` を使っていないため、このままだと実ユーザー操作が上記仕様どおりにならない可能性がある。

## 要対応候補

コード変更は本調査では実施していない。

対応する場合の方向性:

- 既存サブスク中に有料プランボタンを押したら、現在プランとの rank 比較で `/team/subscription/change` を呼ぶ。
  - 上位: `{ action: 'upgrade', targetPlan }`
  - 下位: `{ action: 'downgrade', targetPlan }`
- 無料/未契約から有料へ入る場合だけ `/team/subscription/checkout` を使う。
- バックエンド側でも `/team/subscription/checkout` に既存 `stripeSubscriptionId` ガードを追加し、既存契約中の新規 Checkout 作成を防ぐ。
- 上位/下位変更、Checkout新規契約、フリープラン戻しの画面操作テストを追加する。

## 4プラン間の変更リスク一覧

前提:

- プランは `FREE`, `BASIC(¥980)`, `PLUS(¥1,980)`, `PRO(¥2,980)` の4つ。
- 画面の有料プランボタンは、現在プラン以外では `/team/subscription/checkout` を呼ぶ。
- 画面のフリープランボタンだけは `/team/subscription/change` の `{ action: 'free' }` を呼ぶ。
- バックエンドには `{ action: 'upgrade' }` / `{ action: 'downgrade' }` が実装済みだが、現画面導線からは使われていない。

### FREE からの変更

| 変更 | 期待仕様 | 現画面導線 | リスク |
|---|---|---|---|
| `FREE -> BASIC` | 新規サブスク契約 | Checkout 新規作成 | 低。未契約からの新規契約なので導線と仕様が一致する。 |
| `FREE -> PLUS` | 新規サブスク契約 | Checkout 新規作成 | 低。未契約からの新規契約なので導線と仕様が一致する。 |
| `FREE -> PRO` | 新規サブスク契約 | Checkout 新規作成 | 低。未契約からの新規契約なので導線と仕様が一致する。 |

### BASIC(¥980) からの変更

| 変更 | 期待仕様 | 現画面導線 | リスク |
|---|---|---|---|
| `BASIC -> FREE` | 条件を満たせばフリープランへ戻す。Stripe Subscription は即時キャンセル。 | `/team/subscription/change` の `free` | 中。導線は専用APIを使うが、即時キャンセルなので当月残期間の返金はない。条件未達なら拒否される。 |
| `BASIC -> PLUS` | 上位変更。即時反映し、残期間分の差額を即時請求。 | Checkout 新規作成 | 高。既存 Subscription を更新せず、新しい Subscription が作成される可能性がある。二重課金リスク。 |
| `BASIC -> PRO` | 上位変更。即時反映し、残期間分の差額を即時請求。 | Checkout 新規作成 | 高。既存 Subscription を更新せず、新しい Subscription が作成される可能性がある。二重課金リスク。 |

### PLUS(¥1,980) からの変更

| 変更 | 期待仕様 | 現画面導線 | リスク |
|---|---|---|---|
| `PLUS -> FREE` | 条件を満たせばフリープランへ戻す。Stripe Subscription は即時キャンセル。 | `/team/subscription/change` の `free` | 中。導線は専用APIを使うが、仕様書上の「下位変更は次月反映」ではなく、フリー戻しは即時キャンセルとして実装されている。当月残期間の返金はない想定。 |
| `PLUS -> BASIC` | 下位変更。次回請求期間から反映。差額返金なし。 | Checkout 新規作成 | 高。既存 Subscription を更新せず、BASIC の新規 Subscription が作成される可能性がある。旧 PLUS が残ると二重課金リスク。期待される `pendingPlan` 予約も作られない。 |
| `PLUS -> PRO` | 上位変更。即時反映し、残期間分の差額を即時請求。 | Checkout 新規作成 | 高。既存 Subscription を更新せず、新しい Subscription が作成される可能性がある。二重課金リスク。 |

### PRO(¥2,980) からの変更

| 変更 | 期待仕様 | 現画面導線 | リスク |
|---|---|---|---|
| `PRO -> FREE` | 条件を満たせばフリープランへ戻す。Stripe Subscription は即時キャンセル。 | `/team/subscription/change` の `free` | 中。導線は専用APIを使うが、即時キャンセルなので当月残期間の返金はない。条件未達なら拒否される。 |
| `PRO -> BASIC` | 下位変更。次回請求期間から反映。差額返金なし。 | Checkout 新規作成 | 高。既存 Subscription を更新せず、BASIC の新規 Subscription が作成される可能性がある。旧 PRO が残ると二重課金リスク。期待される `pendingPlan` 予約も作られない。 |
| `PRO -> PLUS` | 下位変更。次回請求期間から反映。差額返金なし。 | Checkout 新規作成 | 高。既存 Subscription を更新せず、PLUS の新規 Subscription が作成される可能性がある。旧 PRO が残ると二重課金リスク。期待される `pendingPlan` 予約も作られない。 |

### リスク分類まとめ

| 分類 | 対象 | 内容 |
|---|---|---|
| 低 | `FREE -> 有料` | 新規 Checkout が正しい導線。 |
| 中 | `有料 -> FREE` | 専用APIを使うため二重契約リスクは低いが、即時キャンセル・返金なし・条件チェックあり。仕様説明と画面文言の整合確認が必要。 |
| 高 | `有料 -> 別の有料` | 本来は既存 Subscription の price 更新または `pendingPlan` 予約にすべきだが、画面は新規 Checkout を作る。二重課金リスクがある。 |

### 特に注意するケース

- `BASIC -> PLUS`, `BASIC -> PRO`
  - 本来は差額請求だけで済むべきだが、現画面導線では新規サブスクが作られる可能性がある。
- `PLUS -> BASIC`, `PRO -> BASIC`, `PRO -> PLUS`
  - 本来は次回請求期間からの予約変更で、返金なし。
  - 現画面導線では予約ではなく新規サブスク作成になり得る。
- `PLUS -> FREE`, `PRO -> FREE`, `BASIC -> FREE`
  - 現実装では即時キャンセル。
  - 「下位変更は次月反映」と説明する場合、フリー戻しだけ別扱いであることを明記しないとユーザー認識とズレる。

## 対応記録

対応日: 2026-05-14

### 対応した高リスク

有料プランから別の有料プランへ変更するときに、新規 Stripe Checkout を作成して二重課金になり得るリスクを対策した。

変更内容:

- `frontend/main.js`
  - 有料プランボタンの押下処理を `changeSubscriptionPlan()` に変更。
  - 現在が `FREE` または未契約の場合だけ `/team/subscription/checkout` を使う。
  - 現在が有料サブスクの場合は rank 比較で `/team/subscription/change` を呼ぶ。
    - 上位変更: `{ action: 'upgrade', targetPlan }`
    - 下位変更: `{ action: 'downgrade', targetPlan }`
  - 容量不足モーダルからの推奨プラン変更も同じ分岐を使う。
- `backend/src/api.js`
  - `/team/subscription/checkout` に既存サブスクガードを追加。
  - `billingMode=subscription` かつ有効な既存 Subscription がある場合は `409 SUBSCRIPTION_ALREADY_EXISTS` を返し、新規 Checkout 作成を拒否する。
  - 拒否時は監査ログに `existing_subscription` として記録する。
- `frontend/demo.js`
  - デモ画面も本番と同じ有料間変更導線に合わせた。
- `frontend/i18n.js`
  - プラン変更時の通知文言を英語・中国語・ベトナム語にも追加。

### 対応後の4プラン間リスク

| 分類 | 対象 | 対応後の状態 |
|---|---|---|
| 低 | `FREE -> 有料` | 従来どおり新規 Checkout。仕様どおり。 |
| 中 | `有料 -> FREE` | 従来どおり専用API。即時キャンセル・返金なし・条件チェックあり。 |
| 低 | `有料 -> 上位有料` | 画面は変更APIを呼ぶ。バックエンドは既存 Subscription の price を更新し、差額を即時請求する。 |
| 低 | `有料 -> 下位有料` | 画面は変更APIを呼ぶ。バックエンドは `pendingPlan` に予約し、次回請求境界で反映する。 |

### 残る確認事項

- Stripe の実環境で、`BASIC -> PLUS` などの上位変更時に差額請求 invoice が即時作成されることを確認する。
- Stripe の実環境で、`PLUS -> BASIC` などの下位変更時に追加請求・返金が発生せず、次回境界で price が変わることを確認する。
- `有料 -> FREE` は即時キャンセル扱いのため、ユーザー向け文言で「下位変更」と混同しないように説明する。

## 中リスク対応記録

対応日: 2026-05-14

### 対応した中リスク

`有料 -> FREE` の操作について、課金ロジックは変更せず、ユーザーが誤認しやすい点を確認・成功メッセージに明記した。

変更内容:

- `frontend/main.js`
  - フリープランへ戻す確認ダイアログで以下を明示。
    - Stripe の定期課金は今すぐ停止する。
    - 当月の残り期間分の返金はない。
    - フリープランへ戻すには容量512MB未満・フォルダ2個以下が必要。
  - 成功ダイアログで以下を明示。
    - フリープランに戻った。
    - Stripe の定期課金は停止した。
    - 当月の残り期間分の返金はない。
    - 現在の上限は容量512MB未満・フォルダ2個まで。
- `frontend/demo.js`
  - デモ画面も同じ確認・成功メッセージに合わせた。
- `frontend/i18n.js`
  - 追加文言を英語・中国語・ベトナム語にも追加。

### 対応後の中リスク状態

- `有料 -> FREE` の実装挙動は従来どおり。
  - 条件を満たす場合は即時フリープラン化。
  - Stripe Subscription は即時キャンセル。
  - 当月残期間の返金はなし。
  - 条件未達の場合は拒否。
- 画面上で上記を事前確認できるため、ユーザー認識とのズレは低減した。
