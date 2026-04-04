# 部屋削除時のStripeサブスク停止 要件整理

更新日: 2026-04-04

## 目的

- 作成者が `お部屋削除（全データ）` を実行した時、Stripe のサブスク請求が残り続ける事故を防ぐ
- アプリ内データ削除と外部課金停止を同じ操作で完結させる
- 削除失敗時に `アプリだけ消えた / Stripeだけ残った` という不整合を減らす

## 現状の問題

- 現行の `POST /team/delete` は、部屋データ・メンバー情報・課金情報を削除する
- ただし、Stripe の Subscription 解約処理は呼んでいない
- そのため、部屋削除後も Stripe 側で定期課金が継続する可能性がある
- さらに、部屋削除で `ROOM#<roomId>` 配下の課金メタを先に消すため、後続の Stripe Webhook で状態同期しづらくなる

## あるべき挙動

- 作成者が部屋削除を実行した場合、対象部屋に紐づく Stripe Subscription が存在すれば、削除処理の中で停止する
- Stripe 側の停止成功を確認してから、アプリ側の部屋データ削除に進む
- すでに解約済み、または Stripe 上で対象 Subscription が存在しない場合は、冪等に成功扱いとする
- 部屋削除完了後は、追加請求が発生しない状態にする

## 対象

- API: `POST /team/delete`
- Backend: `backend/src/api.js`
- Stripe連携: `backend/src/stripe-webhook.js`
- 課金メタ: `ROOM#<roomId> / META#BILLING`

## 機能要件

### 1. 部屋削除時のサブスク停止

- `teamDelete` 開始時に、対象部屋の `billing_meta` を読む
- `billingMode=subscription` かつ `stripeSubscriptionId` がある場合、Stripe の Subscription 停止APIを呼ぶ
- 停止方法は `即時解約` とする
- Stripe 応答が `canceled` または実質的に終了状態であれば、削除継続可とする
- Stripe 上に対象 Subscription が見つからない場合は、警告ログを残したうえで削除継続可とする

### 2. 実行順序

- 順序は以下を基本とする
- `1. Stripe停止`
- `2. アプリ内データ削除`
- `3. 作成者制約解除`
- Stripe 停止に失敗した場合は、アプリ内データ削除へ進まない
- 中途半端な削除を避けるため、`Stripe停止失敗 = 部屋削除失敗` とする

### 3. 冪等性

- 同じ部屋削除操作が再試行されても、二重解約や不要な失敗にならないこと
- すでに Subscription が削除済みの場合は成功扱いに寄せる
- Webhook の `customer.subscription.deleted` が後から届いても、削除済み部屋のため致命エラーにしない

### 4. ログ・監査

- `team.delete` の監査ログに、Stripe停止の成否を含める
- 例: `stripeSubscriptionId`, `stripeCancellationAttempted`, `stripeCancellationResult`
- Stripe 停止失敗時は、部屋ID・Subscription ID・エラー種別を必ず残す

### 5. ユーザー向け挙動

- 部屋削除確認ダイアログの文言は、`課金停止` を含む表現へ更新する
- 確認ダイアログの文言例は以下とする

`このお部屋を削除すると、フォルダ/写真/コメント/課金情報が全て削除され、Stripeの定期課金も即時停止されます。よかですか？`

- Stripe 停止失敗で部屋削除できない場合、ユーザー向けメッセージは以下の推奨文言とする

`課金停止の確認に失敗したため、お部屋を削除できませんでした。時間をおいて再度お試しください。`

- 解決しない場合の補足文言が必要なら、以下を利用可とする

`解決しない場合は運用担当へお問い合わせください。`

- ユーザー向け画面では Stripe の内部エラー詳細は表示しない

## 非機能要件

- Stripe API失敗時に、削除処理全体が無言で成功しないこと
- 外部API失敗時でも、原因追跡できるログが残ること
- 既存の `action=free` によるサブスク停止ロジックと責務が重複しすぎないこと
- 既存の無料プラン部屋、未課金部屋、過去課金済みだが現在無料の部屋には影響を出さないこと

## 例外ケース

- `billingMode=subscription` だが `stripeSubscriptionId` が欠落している場合
- Stripe 上では `canceled` 済みだが、アプリ内には `subscription` として残っている場合
- Webhook 未反映のまま部屋削除が先に走る場合
- Stripe API の一時障害やタイムアウトが起きる場合

## 実装方針案

- 既存の `stripeCancelSubscriptionNow` を `teamDelete` から再利用できるようにする
- `teamDelete` の早い段階で `billing_meta` を読んで、解約要否を判定する
- Stripe 解約成功後に DynamoDB / S3 削除へ進む
- Webhook 側は、削除済み部屋に対する `customer.subscription.deleted` を無害化する
- 必要なら `STRIPE_SUB#<subscriptionId>` の逆引きレコード削除タイミングも整理する

## 受け入れ条件

- 有料プラン部屋を削除した時、Stripe 上の Subscription も停止する
- 部屋削除後に、同 Subscription に対する追加請求が発生しない
- Stripe 停止失敗時は、部屋データが消えず、ユーザーへ失敗が返る
- 無料プラン部屋の削除挙動は従来通りである
- Webhook が削除後に到着しても、致命エラーや不要な再作成が起きない

## 対応効果

- 退会・部屋削除まわりの課金事故を防げる
- ユーザーから見て `部屋を消したのに請求が続く` という不信を避けられる
- 運用側の返金対応、問い合わせ対応、Stripe手動調査の工数を減らせる
- アプリ内状態とStripe状態の整合性が上がる

## 要確認事項

- `使い方・料金` 画面にも、部屋削除時は Stripe の定期課金が即時停止されることを追記するか
- Stripe停止失敗時の補足文言を、常時表示にするか、必要時のみ表示にするか
