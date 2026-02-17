# サブスク移行 実装計画（実装順）

対象: `kansa` の課金方式をプリペイドから Stripe サブスクへ段階移行する。  
方針: 既存運用を止めず、後方互換を保ちながら小さく切り替える。

## フェーズ1: 土台（互換維持）
- [x] `backend/src/billing.js` にサブスク用プラン定義を追加
  - `FREE/BASIC/PLUS/PRO`
  - 上限Bytes定義
- [x] `billing_meta` にサブスク関連フィールドを持てるようにする（既存データはそのまま）
  - 例: `billingMode`, `currentPlan`, `pendingPlan`, `cancelAtPeriodEnd`
- [x] アップロード停止判定を「課金モード別」に切替
  - プリペイド: 現行ロジック維持
  - サブスク: `usageBytes > currentPlanLimit`
- [x] `team/me` 返却の `billing` にサブスク状態を同梱（フロント表示準備）

完了条件:
- 現行プリペイド挙動が変わらない
- サブスクモードの計算関数がテスト可能な形で利用可能

## フェーズ2: サブスクAPI（Backend）
- [x] サブスク状態取得API
  - 例: `GET /team/subscription`
- [x] 変更API
  - 例: `POST /team/subscription/change`（upgrade/downgrade/cancel）
- [x] 下位変更ガード
  - `usageBytes <= targetPlanLimit` の時のみ受付
- [x] 毎月1日反映ジョブ（または起動時反映）
  - `pendingPlan` / `cancelAtPeriodEnd` を反映
  - 実装は `requireActiveMember` 通過時の境界時刻チェックで反映（常駐ジョブ未導入）

完了条件:
- 管理者が API 経由でプラン変更予約できる
- 反映時に超過再チェックが効く

## フェーズ3: Stripeサブスク連携
- [x] Checkout（subscription mode）作成API
- [x] Customer/Subscription ID をルームに紐付け
- [x] Webhook実装
  - `invoice.paid`
  - `invoice.payment_failed`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
- [ ] 冪等処理（event id / invoice id）

完了条件:
- Stripeイベントだけで課金状態が正しく反映される
- リダイレクト結果に依存しない

## フェーズ4: 管理画面（Frontend）
- [ ] 現在プラン/上限/使用量/次回更新日の表示
- [ ] 上位変更（即時差額）導線
- [ ] 下位変更（次月反映）予約導線
- [ ] 解約予約導線
- [ ] エラー表示（下位変更不可、支払い失敗など）

完了条件:
- 管理画面から全運用操作が可能
- 画面文言が運用ルールと一致

## フェーズ5: 移行と廃止
- [x] 既存プリペイド導線を無効化（段階フラグ）
- [ ] `docs/billing-spec.md` をアーカイブ扱いへ
- [ ] 運用Runbook更新（障害対応・再送・返金方針）

完了条件:
- サブスク単独運用
- 旧プリペイドAPIに依存しない

## 実装順（推奨）
1. フェーズ1（今回着手）
2. フェーズ2
3. フェーズ3
4. フェーズ4
5. フェーズ5
