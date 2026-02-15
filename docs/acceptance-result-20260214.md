# 受け入れ試験 実施結果 (2026-02-14)

## 実施者
- Codex (API自動試験)

## 対象
- API: `https://0nhz8sat7j.execute-api.ap-northeast-1.amazonaws.com`
- Script: `/Users/aokikensaku/Documents/Devapps/kansa/scripts/run_api_acceptance.sh`

## 実施結果サマリ
- OK: 15
- NG: 0

## OK項目
1. フォルダ作成
2. フォルダ採番 (`F001`)
3. アップロードURL発行
4. S3アップロード
5. 写真登録
6. 写真採番 (`F001-P001`)
7. 写真名リネーム(本人)
8. 写真名リネーム(他人拒否)
9. コメント追加
10. コメント修正(本人)
11. コメント修正(他人拒否)
12. コメント削除(他人拒否)
13. コメント削除(本人)
14. 写真削除(他人拒否)
15. 写真削除(本人)

## 未実施(手動確認が必要)
- 初回ニックネーム登録UI
- 未読バッジの表示/既読化
- コメントアコーディオン表示 (`▶` 回転)
- モバイル表示崩れ確認
- PowerPoint出力の実ファイル見た目

## 補足
- 当初NGだった項目は再デプロイで解消済み。
- 実施時点のスタック更新完了: `kansa-backend` (ap-northeast-1)
