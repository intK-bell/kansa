# 部屋削除時のStripeサブスク停止 実装タスク

更新日: 2026-04-04

元要件: [docs/team-delete-subscription-requirements.md](/Users/aokikensaku/Documents/Devapps/kansa/docs/team-delete-subscription-requirements.md)

## 目的

- `POST /team/delete` 実行時に、部屋に紐づく Stripe Subscription を即時解約してから部屋データを削除する
- 部屋削除後の継続課金事故を防ぐ
- Stripe停止失敗時に中途半端な削除を起こさない

## 実装方針

- `teamDelete` の先頭付近で `billing_meta` を確認する
- `billingMode=subscription` かつ `stripeSubscriptionId` がある場合だけ Stripe 即時解約を試みる
- 解約成功後にのみ、既存の部屋削除処理へ進む
- 解約失敗時は部屋削除を中断し、ユーザーへ推奨文言を返す
- Webhook は削除済み部屋への後着イベントを無害化する

## フェーズ1: 事前整理

- [ ] `teamDelete` の現在の削除順序を確定する
- [ ] `changeTeamSubscription(action=free)` で使っている `stripeCancelSubscriptionNow` の再利用条件を確認する
- [ ] `customer.subscription.deleted` 到着時に、削除済み部屋で何が起きるかを確認する
- [ ] 監査ログに追加したい項目を整理する

完了条件:
- 実装着手前に、再利用する関数と差分責務が明確になっている

## フェーズ2: Backend API 修正

対象:
- `backend/src/api.js`

タスク:
- [ ] `teamDelete` の先頭で `ROOM#<roomId> / META#BILLING` を取得する
- [ ] `billingMode=subscription` かつ `stripeSubscriptionId` ありの場合、Stripe即時解約を実行する
- [ ] Stripe が `canceled` または終了済みなら削除継続とする
- [ ] Stripe 停止失敗時は `teamDelete` を失敗で返す
- [ ] ユーザー向け失敗文言を以下に統一する

`課金停止の確認に失敗したため、お部屋を削除できませんでした。時間をおいて再度お試しください。`

- [ ] Stripe停止成功後だけ、既存のフォルダ/写真/メンバー/課金情報削除に進む
- [ ] 監査ログへ `stripeSubscriptionId`, `stripeCancellationAttempted`, `stripeCancellationResult` を追加する

完了条件:
- 有料部屋で `teamDelete` 実行時、部屋削除前に Stripe 停止が必ず走る
- Stripe停止失敗時、部屋データは削除されない

## フェーズ3: Webhook 安全化

対象:
- `backend/src/stripe-webhook.js`

タスク:
- [ ] 削除済み部屋に対して `customer.subscription.deleted` が到着した場合の更新挙動を見直す
- [ ] 課金メタ未存在時でも致命エラーにしないようにする
- [ ] 必要なら `subscription_room_not_found` や `billing not found` を成功寄りに扱う分岐を追加する
- [ ] ログ上で「削除済み部屋への後着Webhook」と判別できるようにする

完了条件:
- 部屋削除後にWebhookが届いても、Lambdaが不要に失敗しない

## フェーズ4: Frontend 文言修正

対象:
- `frontend/main.js`

タスク:
- [ ] 部屋削除確認ダイアログ文言を更新する
- [ ] 更新文言は以下を基準とする

`このお部屋を削除すると、フォルダ/写真/コメント/課金情報が全て削除され、Stripeの定期課金も即時停止されます。よかですか？`

- [ ] API失敗時に返るメッセージが、そのまま利用者に違和感なく見えるか確認する

完了条件:
- 管理者が部屋削除前に `定期課金も停止される` ことを認識できる

## フェーズ5: ガイド・説明文更新

対象候補:
- `docs/user-guide.md`
- 使い方・料金ページに相当する画面/文言定義箇所

タスク:
- [ ] `お部屋削除（全データ）` の説明に `Stripeの定期課金も即時停止` を追記する
- [ ] 必要なら管理者向けの注意書きとして「削除失敗時は再試行してください」を追加する
- [ ] `使い方・料金` メニュー内の案内文にも同趣旨を追記する場所を特定する

完了条件:
- 画面上の説明と実際の挙動が一致する

## フェーズ6: テスト・確認

### API観点

- [ ] 無料部屋を削除して従来通り削除できる
- [ ] 有料部屋を削除すると Stripe停止後に削除される
- [ ] Stripe停止失敗時は部屋削除が失敗し、データが残る
- [ ] すでにStripe上で解約済みの部屋でも削除できる

### Webhook観点

- [ ] 部屋削除後に `customer.subscription.deleted` が到着しても致命エラーにならない

### UI観点

- [ ] 部屋削除ダイアログに `Stripeの定期課金も即時停止` が表示される
- [ ] 失敗時に推奨文言が表示される

完了条件:
- 主要ケースで課金事故と削除中断の両方を確認できる

## 実装順（推奨）

1. フェーズ1で再利用ポイントと失敗条件を確認
2. フェーズ2で `teamDelete` にStripe停止を追加
3. フェーズ3でWebhook後着を安全化
4. フェーズ4で削除ダイアログ文言を更新
5. フェーズ5でガイド・使い方説明を更新
6. フェーズ6で確認

## 補足

- 本件は `アカウント削除` 仕様変更ではなく、まず `部屋削除の責務を正しく閉じる` ための対応とする
- 追加で `有料部屋が残っている作成者のアカウント削除制約` を見直す場合は、別要件として切り出す
