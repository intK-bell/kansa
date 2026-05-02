(function () {
  const SUPPORTED_LANGUAGES = ['ja', 'en', 'zh-CN', 'vi'];
  const LANGUAGE_ALIASES = {
    zh: 'zh-CN',
    'zh-cn': 'zh-CN',
    'zh-hans': 'zh-CN',
    'zh-sg': 'zh-CN',
    en: 'en',
    ja: 'ja',
    vi: 'vi',
  };

  const TRANSLATIONS = {
    en: {
      'Photo Hub for 監査': 'Photo Hub for Audit',
      'Photo Hub for 監査 | デモ': 'Photo Hub for Audit | Demo',
      'Photo Hub for 監査 | プロダクトランディングページ': 'Photo Hub for Audit | Product Landing Page',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー | Photo Hub for 監査':
        'Legal Notice, Terms of Use, and Privacy Policy | Photo Hub for Audit',
      監査写真コメントアプリ: 'Audit photo comment app',
      '監査のあと、<br />会社に戻って報告書を作っていませんか？':
        'After an audit,<br />are you going back to the office to create the report?',
      '現場で終わるはずの仕事を、<br />その場で完結させる。':
        'Finish work on site<br />that should not have to wait until later.',
      無料で試す: 'Try for free',
      少し触ってみる: 'Try the demo',
      '説明より先に、「今のやり方がしんどい」と感じた方のためのページです。':
        'This page is for people who already feel the current workflow is too painful.',
      現場起点: 'Field-first',
      '写真もコメントも、その場で記録': 'Record photos and comments on site',
      報告まで一気通貫: 'Straight through to reporting',
      あとでPCに戻って整理し直さない: 'No re-sorting later on a PC',
      導入が軽い: 'Light to adopt',
      '高機能すぎず、現場で使われる作り': 'Focused enough to actually be used in the field',
      'こんな運用、続いていませんか？': 'Is this workflow still continuing?',
      現場ではこう動いている: 'How work happens on site',
      写真はスマホで撮る: 'Photos are taken on a phone',
      '共有はLINEやGoogle Drive': 'Sharing happens through LINE or Google Drive',
      報告はExcelやPowerPoint: 'Reports are made in Excel or PowerPoint',
      その結果: 'The result',
      '帰社後に1時間〜2時間の作業': '1-2 hours of work after returning to the office',
      同じ人が二度手間: 'The same person does the work twice',
      毎回なんとなく非効率: 'Every time feels vaguely inefficient',
      '原因は「ツールの分断」です。': 'The cause is fragmented tools.',
      '記録と共有と報告が別々やけん、移動・再整理・二重作業が当たり前になっとる状態です。':
        'Because recording, sharing, and reporting are separate, moving data, re-sorting it, and duplicate work become normal.',
      記録: 'Record',
      スマホ: 'Phone',
      共有: 'Share',
      クラウド: 'Cloud',
      報告: 'Report',
      PC: 'PC',
      'この分断によって、<span class="accent">移動・再整理・二重作業</span>が発生しています。':
        'This fragmentation creates <span class="accent">moving, re-sorting, and duplicate work</span>.',
      'すべて一体化したツールを使えばいい？': 'Should you just use an all-in-one tool?',
      'でも現実は、そこがいちばん難しかところです。': 'In practice, that is the hardest part.',
      高い: 'Expensive',
      '1人数千円かかると、現場全員に広げにくい。':
        'When it costs several thousand yen per person, it is hard to roll out to the whole field team.',
      設定が難しい: 'Hard to configure',
      '最初の設計や運用ルールづくりで止まりやすい。':
        'Initial setup and operating rules can easily slow adoption.',
      使われない: 'Not used',
      '覚えることが多いと、結局いつものExcelに戻る。':
        'If there is too much to learn, teams end up going back to Excel.',
      '本サービスは、この「分断」と「導入負荷」の間を埋めます。':
        'This service bridges fragmented tools and adoption burden.',
      '写真・コメント・報告書を<br /><strong>一つの流れで完結。</strong>':
        'Photos, comments, and reports<br /><strong>completed in one flow.</strong>',
      '現場で撮って、<br />そのまま報告まで。': 'Take photos on site,<br />then continue straight to the report.',
      撮る: 'Capture',
      現場で写真を残す: 'Keep photos from the site',
      書く: 'Write',
      その場でコメントを添える: 'Add comments on the spot',
      出す: 'Output',
      報告の形までつなげる: 'Turn it into a report',
      'だから現場で使われる。': 'That is why teams use it on site.',
      '監査業務に特化しとるけん、必要以上に重たくなっていません。':
        'Because it is focused on audit work, it does not become heavier than necessary.',
      機能を絞っている: 'Focused features',
      'やることが見えやすく、迷わず使える。': 'The next action is clear, so people can use it without hesitation.',
      スマホで直感操作: 'Intuitive phone operation',
      '現場の流れを止めずに記録できる。': 'Record without stopping the field workflow.',
      設定不要: 'No setup required',
      '導入時の説明や初期調整に時間を取られにくい。':
        'Less time is spent on onboarding explanations and initial adjustment.',
      '「帰ってからやる」が、「現場で終わる」に変わります。':
        '"Do it after returning" changes into "finish it on site."',
      '現場 → 帰社 → PC作業 → 報告': 'Site -> office -> PC work -> report',
      '仕事が終わったあとに、もう一度まとめ直す流れ。':
        'A flow where work is organized again after the job is done.',
      現場で完結: 'Completed on site',
      '撮る・書く・報告するが、一つの作業としてつながる流れ。':
        'Capturing, writing, and reporting connect as one task.',
      '料金プラン（税込・月額）': 'Pricing plans (tax included, monthly)',
      'まずは無料で試して、運用に合えばそのまま広げられます。':
        'Start for free, then expand if it fits your workflow.',
      '1GBプラン': '1 GB plan',
      '5GBプラン': '5 GB plan',
      '10GBプラン': '10 GB plan',
      ' / 月': ' / month',
      'まず試したい方向け。無料枠（512MB）でお試し利用できます。':
        'For teams that want to try first. Use the free 512 MB allowance.',
      '小規模チーム向け。まず運用を始めるための基本プラン。':
        'A basic plan for small teams starting operation.',
      '運用が安定して写真点数が増えてきたチーム向け。':
        'For teams whose workflow is stable and photo volume is growing.',
      '複数案件・複数拠点で継続運用するチーム向け。':
        'For teams running multiple projects or sites continuously.',
      '料金プラン比較表': 'Pricing plan comparison',
      項目: 'Item',
      フリープラン: 'Free plan',
      '1GB〜10GBプラン': '1 GB-10 GB plan',
      フォルダ数: 'Folder count',
      '2個まで': 'Up to 2',
      無制限: 'Unlimited',
      保存期間: 'Retention period',
      '30日保存<sup>※2</sup>': '30-day storage<sup>*2</sup>',
      '3年保存': '3-year storage',
      PPT出力: 'PPT export',
      透かしあり: 'With watermark',
      透かしなし: 'No watermark',
      '※1 容量にアーカイブが含まれます。<br />※2 保存期間後はアーカイブ(非表示)となります。':
        '*1 Storage includes archived data.<br />*2 After the retention period, data is archived and hidden.',
      申込方法: 'How to apply',
      '本ウェブサイトを通じてお申し込みいただきます。': 'Apply through this website.',
      '無料枠を超えて利用を続ける場合、管理者がサブスクプラン（1GB/5GB/10GB）を選択します。':
        'To continue beyond the free allowance, an admin selects a subscription plan (1 GB/5 GB/10 GB).',
      'クレジットカード（Stripeによる決済代行）で決済します。':
        'Pay by credit card through Stripe payment processing.',
      '初回は有料プラン申込時に決済、以後は有効期間中に毎月自動決済されます。':
        'The first payment is made when applying for a paid plan, then charged automatically each month during the active period.',
      申込ページへ進む: 'Go to application page',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシーを見る':
        'View Legal Notice, Terms of Use, and Privacy Policy',
      '帰ってから整理する監査を、ここで終わらせる。': 'Stop audits that need sorting after returning.',
      'まず触ってみるか、先に運用イメージだけ確認するか。どちらからでも始められます。':
        'Start by trying it, or check the workflow first. Either path works.',
      '販売事業者:': 'Seller:',
      '商品名:': 'Product name:',
      '販売方法:': 'Sales method:',
      '本ウェブサイトを通じたご案内・お申し込み': 'Information and applications through this website',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー':
        'Legal Notice, Terms of Use, and Privacy Policy',
      商品画面に戻る: 'Back to product page',
      特定商取引法に基づく表記: 'Legal Notice under Japanese Specified Commercial Transactions Act',
      '最終更新日: 2026年2月20日': 'Last updated: February 20, 2026',
      法人名: 'Business name',
      住所: 'Address',
      '請求があった場合は遅滞なく開示します。': 'Disclosed without delay upon request.',
      電話番号: 'Phone number',
      '受付時間: 土日 10:00-18:00 / まずはメールでお問い合わせください。':
        'Hours: Sat-Sun 10:00-18:00 / Please contact us by email first.',
      メールアドレス: 'Email address',
      運営責任者: 'Operations manager',
      '事業内容・販売方法': 'Business activities and sales method',
      '事業内容: 業務効率化に関する助言・支援サービス':
        'Business activities: advisory and support services for operational efficiency',
      '販売方法: 本ウェブサイトを通じたご案内・お申し込み':
        'Sales method: information and applications through this website',
      追加手数料: 'Additional fees',
      '本サービスの利用にかかる通信費などについては、お客様のご負担となります。':
        'Customers are responsible for communication fees and similar costs related to using this service.',
      交換および返品に関するポリシー: 'Exchange and return policy',
      '＜お客様からの返品・交換＞ デジタルサービスの性質上、提供開始後の返品・返金はお受けできません。':
        '<Customer returns and exchanges> Due to the nature of digital services, returns and refunds cannot be accepted after service provision begins.',
      '＜不良品・サービスの返品・交換＞ 当方起因の不具合、重複請求、サービス提供不能が確認できた場合は、内容確認後に返金または是正対応を行います。':
        '<Defective service returns and exchanges> If a defect caused by us, duplicate billing, or inability to provide the service is confirmed, we will review the details and issue a refund or corrective response.',
      '有料プランの解約は管理画面からいつでも手続きできます。':
        'Paid plans can be canceled at any time from the management screen.',
      '解約手続き後は有料プランの提供を停止し、以後の定期請求は行いません。':
        'After cancellation, paid plan service stops and no further recurring charges are made.',
      '不審請求（チャージバック）対応方針': 'Suspicious charge (chargeback) response policy',
      '不審請求が発生した場合は、サービスの発注・提供記録・メール履歴に加え、本人確認記録およびアクセスログ等の証跡を提出し、適切に対応します。':
        'If a suspicious charge occurs, we will respond appropriately by submitting service order and provision records, email history, identity verification records, access logs, and other evidence.',
      サービス提供時期: 'Service provision timing',
      '決済完了後、通常は即時に反映します。システム都合で遅延する場合があります。':
        'After payment is completed, it is usually reflected immediately. Delays may occur due to system circumstances.',
      利用可能な決済手段: 'Available payment methods',
      'クレジットカードのみ（Stripeによる決済代行）': 'Credit card only (payment processing by Stripe)',
      決済期間: 'Payment period',
      '初回の有料プラン申込時に決済が直ちに行われます。':
        'Payment is made immediately when first applying for a paid plan.',
      'その後は有料プランが継続される期間中、Stripeの定期課金により毎月自動で決済されます。':
        'After that, payment is automatically charged monthly by Stripe while the paid plan continues.',
      価格: 'Price',
      '表示価格はすべて税込です。': 'All displayed prices include tax.',
      '無料枠（512MB）を超えて利用を続ける場合、管理者がサブスクプランを選択します。':
        'To continue using the service beyond the free allowance (512 MB), an admin selects a subscription plan.',
      動作環境: 'Operating environment',
      '本サービスは、インターネット接続環境下でブラウザから利用するクラウドサービスです。ご利用にあたっては、以下の環境を推奨します。':
        'This service is a cloud service used from a browser with an internet connection. We recommend the following environment.',
      '<strong>対応OS（最新版推奨）</strong><br>Windows / macOS / iOS / Android':
        '<strong>Supported OS (latest version recommended)</strong><br>Windows / macOS / iOS / Android',
      '<strong>対応ブラウザ（各最新版）</strong><br>Google Chrome / Microsoft Edge / Safari':
        '<strong>Supported browsers (latest versions)</strong><br>Google Chrome / Microsoft Edge / Safari',
      '<strong>インターネット接続</strong><br>常時接続の通信環境が必要です。回線状況により、表示速度やアップロード速度に影響が出る場合があります。':
        '<strong>Internet connection</strong><br>An always-on connection is required. Network conditions may affect display speed and upload speed.',
      '<strong>JavaScript・Cookie</strong><br>本サービスでは JavaScript および Cookie を使用します。ブラウザ設定で無効化されている場合、一部機能が正常に動作しないことがあります。':
        '<strong>JavaScript and cookies</strong><br>This service uses JavaScript and cookies. Some features may not work correctly if they are disabled in browser settings.',
      '<strong>その他</strong><br>画像アップロード・閲覧に必要な端末ストレージ空き容量を確保してください。推奨環境外では、表示崩れや一部機能が利用できない場合があります。':
        '<strong>Other</strong><br>Please ensure enough device storage for image upload and viewing. Outside the recommended environment, layout issues or unavailable features may occur.',
      '利用規約': 'Terms of Use',
      '制定日: 2025年2月24日 / 最終改定日: 2026年2月17日': 'Established: February 24, 2025 / Last revised: February 17, 2026',
      '本利用規約（以下「本規約」）は、あおき業務企画（以下「当方」）が提供する各種サービス（以下「本サービス」）の利用条件を定めるものです。利用者は、本規約に同意のうえ本サービスを利用するものとします。':
        'These Terms of Use define the conditions for using the services provided by Aoki Business Planning. Users shall use the services after agreeing to these terms.',
      '1. 適用範囲': '1. Scope',
      '本規約は、本サービスの利用に関する当方と利用者との一切の関係に適用されます。':
        'These terms apply to all relationships between us and users regarding use of the services.',
      '2. 同意': '2. Agreement',
      '利用者は、本サービスを利用した時点で本規約および当方のプライバシーポリシーに同意したものとみなされます。':
        'Users are deemed to have agreed to these terms and our Privacy Policy when they use the services.',
      '3. アカウント管理': '3. Account Management',
      '利用者は、自己の責任でアカウント情報を管理し、第三者への貸与・譲渡・共有を行わないものとします。':
        'Users shall manage account information at their own responsibility and shall not lend, transfer, or share it with third parties.',
      'アカウントの不正使用により生じた損害について、当方に故意または重過失がある場合を除き、当方は責任を負いません。':
        'We are not responsible for damages caused by unauthorized account use, except in cases of our intent or gross negligence.',
      '本規約における「非アクティブ」とは、無料プランのアカウントについて、最終ログイン日から365日間ログインが確認できない状態をいいます。':
        '"Inactive" in these terms means a free-plan account with no confirmed login for 365 days from the last login date.',
      '前項の非アクティブ状態が継続した場合、当方は、事前の通知なく、当該アカウントおよび関連データを自動的に削除するものとします。':
        'If the inactive state described above continues, we may automatically delete the account and related data without prior notice.',
      '削除の実施後、当該アカウントおよび関連データは復元できません。':
        'After deletion, the account and related data cannot be restored.',
      'ただし、法令遵守、不正利用防止、請求・監査対応等のため保存が必要な情報（請求履歴、決済関連記録、監査ログ等）については、法令上より長い保存義務がある場合を除き、削除実施日から3年間保持し、期間経過後に削除または匿名化します。':
        'However, information that must be retained for legal compliance, fraud prevention, billing, or audit response, such as billing history, payment records, and audit logs, will be retained for 3 years from deletion unless a longer legal retention period applies, then deleted or anonymized.',
      '前項にもとづく削除が実施された場合、当方に故意または重過失がある場合を除き、当該削除により利用者に生じた損害について当方は責任を負いません。':
        'If deletion is performed under the preceding paragraph, we are not responsible for damages caused to users by the deletion, except in cases of our intent or gross negligence.',
      '4. 禁止事項': '4. Prohibited Acts',
      '利用者は、以下の行為をしてはなりません。': 'Users must not engage in the following acts.',
      '・法令または公序良俗に違反する行為': '- Acts that violate laws or public order and morals',
      '・犯罪行為に関連する行為': '- Acts related to criminal activity',
      '・当方または第三者の知的財産権、名誉、プライバシーその他の権利利益を侵害する行為':
        '- Acts that infringe our or third parties\' intellectual property rights, reputation, privacy, or other rights and interests',
      '・不正アクセス、過度な負荷、脆弱性探索その他本サービスの運営を妨害する行為':
        '- Unauthorized access, excessive load, vulnerability probing, or other acts that interfere with operation of the services',
      '・本サービスを通じた無断の営業、宣伝、勧誘、スパム行為':
        '- Unauthorized sales, advertising, solicitation, or spam through the services',
      '・虚偽情報の登録または本人になりすます行為': '- Registering false information or impersonating another person',
      '・第三者のデータを権限なくアップロード、共有、公開する行為':
        '- Uploading, sharing, or publishing third-party data without authority',
      '・リバースエンジニアリング、解析、複製、改変、再配布その他当方が不適切と判断する行為':
        '- Reverse engineering, analysis, copying, modification, redistribution, or other acts we deem inappropriate',
      '5. 利用停止等': '5. Suspension of Use',
      '当方は、利用者が本規約に違反した場合、または本サービス運営上必要と判断した場合、事前通知なく利用停止、データ削除、アカウント停止等の措置を行うことがあります。':
        'If a user violates these terms or we deem it necessary for operation of the services, we may suspend use, delete data, suspend accounts, or take similar measures without prior notice.',
      '6. 知的財産権': '6. Intellectual Property Rights',
      '本サービスに関する著作権、商標権その他の知的財産権は、当方または正当な権利者に帰属します。利用者が本サービスにアップロードしたデータの権利は利用者または正当な権利者に留保されます。':
        'Copyrights, trademarks, and other intellectual property rights related to the services belong to us or legitimate rights holders. Rights to data uploaded by users remain with the users or legitimate rights holders.',
      '7. 免責および責任制限': '7. Disclaimer and Limitation of Liability',
      '当方は、本サービスの完全性、正確性、継続性、有用性、特定目的適合性を保証しません。通信障害、システム障害、外部サービス障害、不可抗力等により発生した損害について、当方は責任を負いません。':
        'We do not guarantee completeness, accuracy, continuity, usefulness, or fitness for a particular purpose of the services. We are not responsible for damages caused by communication failures, system failures, external service failures, force majeure, or similar events.',
      '当方の責任が認められる場合でも、当方に故意または重過失がある場合を除き、利用者が当方に直近3か月間に実際に支払った金額を上限として賠償責任を負うものとします。':
        'Even if our liability is recognized, except in cases of our intent or gross negligence, our liability is limited to the amount actually paid by the user to us in the most recent 3 months.',
      '8. 規約の変更': '8. Changes to Terms',
      '当方は、法令改正や運用上の必要に応じて本規約を変更することがあります。重要な変更は本ウェブサイト上で公表します。':
        'We may change these terms due to legal revisions or operational needs. Important changes will be announced on this website.',
      '9. 準拠法・管轄': '9. Governing Law and Jurisdiction',
      '本規約は日本法に準拠し、本サービスに関して紛争が生じた場合は、当方所在地を管轄する裁判所を第一審の専属的合意管轄裁判所とします。':
        'These terms are governed by Japanese law. Any dispute regarding the services shall be subject to the exclusive jurisdiction of the court having jurisdiction over our location as the court of first instance.',
      'プライバシーポリシー': 'Privacy Policy',
      'あおき業務企画（以下「当方」）は、当方が提供するサービスにおける利用者情報の取扱いについて、以下のとおりプライバシーポリシー（以下「本ポリシー」）を定めます。':
        'Aoki Business Planning establishes this Privacy Policy regarding the handling of user information in the services we provide.',
      '1. 取得する情報': '1. Information Collected',
      '当方は、サービス提供・運営のために、次の情報を取得することがあります。':
        'We may collect the following information to provide and operate the services.',
      'アカウント情報（メールアドレス、認証に必要な識別子）':
        'Account information (email address and identifiers required for authentication)',
      'プロフィール情報（表示名）': 'Profile information (display name)',
      'サービス利用情報（所属ルーム、操作履歴、アップロードデータ、コメント、課金状態）':
        'Service usage information (rooms, operation history, uploaded data, comments, billing status)',
      '技術情報（アクセスログ、エラー情報、端末・ブラウザ情報、Cookieまたはこれに類する技術）':
        'Technical information (access logs, error information, device and browser information, cookies or similar technologies)',
      '決済関連情報（Stripe上の顧客ID・サブスクリプション情報等。カード番号等は当方で保持しません）':
        'Payment-related information (customer IDs and subscription information on Stripe. We do not retain card numbers.)',
      '2. 利用目的': '2. Purposes of Use',
      '取得した情報は、次の目的で利用します。': 'Collected information is used for the following purposes.',
      'サービスの提供、本人確認、契約履行、アフターサポートのため':
        'To provide services, verify identity, perform contracts, and provide after-sales support',
      'お問い合わせへの回答、重要なご連絡のため': 'To respond to inquiries and send important notices',
      '請求・決済・返金対応および不正利用防止のため':
        'For billing, payment, refund handling, and prevention of unauthorized use',
      'サービス品質の向上、機能改善、利用状況分析のため':
        'To improve service quality, improve features, and analyze usage',
      '法令・規約等に基づく対応のため': 'To respond based on laws, regulations, and terms',
      '3. 第三者提供': '3. Provision to Third Parties',
      '当方は、法令で認められる場合を除き、本人の同意なく個人情報を第三者に提供しません。ただし、サービス運営に必要な範囲で、業務委託先（決済代行、インフラ、分析ツール等）へ取扱いを委託することがあります。この場合、必要かつ適切な監督を行います。':
        'Except where permitted by law, we do not provide personal information to third parties without the individual\'s consent. However, we may outsource handling to service providers such as payment processors, infrastructure providers, and analytics tools as necessary for service operation. In such cases, we provide necessary and appropriate supervision.',
      '4. 安全管理措置': '4. Security Management Measures',
      '当方は、個人情報への不正アクセス、漏えい、滅失、毀損等を防止するため、合理的な安全管理措置を講じます。なお、インターネット通信の性質上、完全な安全性を保証するものではありません。':
        'We take reasonable security management measures to prevent unauthorized access, leakage, loss, damage, and similar issues involving personal information. However, due to the nature of internet communication, complete security is not guaranteed.',
      '5. Cookie等の利用': '5. Use of Cookies',
      '当方ウェブサイトでは、利便性向上やアクセス解析のためCookie等を利用する場合があります。利用者はブラウザ設定によりCookieを無効化できますが、一部機能が利用できない場合があります。':
        'Our website may use cookies and similar technologies to improve convenience and analyze access. Users can disable cookies in browser settings, but some features may become unavailable.',
      '6. 保有個人データの開示等の請求': '6. Requests for Disclosure of Retained Personal Data',
      'ご本人から、保有個人データの開示、訂正、追加、削除、利用停止等の請求があった場合は、ご本人確認のうえ、法令に従って適切に対応します。':
        'If the individual requests disclosure, correction, addition, deletion, suspension of use, or similar handling of retained personal data, we will verify identity and respond appropriately in accordance with laws.',
      'アカウント削除後のデータは原則復元できません。ただし、法令遵守、不正利用防止、請求・監査対応のために必要な情報は、法令上より長い保存義務がある場合を除き、削除実施日から3年間保持し、期間経過後に削除または匿名化します。':
        'Data after account deletion generally cannot be restored. However, information needed for legal compliance, fraud prevention, billing, and audit response will be retained for 3 years from deletion unless a longer legal retention obligation applies, then deleted or anonymized.',
      '7. 返金・不審請求対応における情報利用': '7. Use of Information for Refunds and Suspicious Charge Responses',
      '返金・不審請求（チャージバック）対応のため、当方は、取引記録、請求・決済履歴、サブスクリプション変更履歴、監査ログ、認証・アクセスログ等を確認し、必要に応じて決済事業者または関係機関へ提出する場合があります。':
        'For refunds and suspicious charge (chargeback) responses, we may review transaction records, billing and payment history, subscription change history, audit logs, authentication and access logs, and may submit them to payment providers or relevant organizations as needed.',
      '8. ポリシーの改定': '8. Policy Revisions',
      '本ポリシーは、法令改正や運用上の必要に応じて改定することがあります。重要な変更がある場合は、当ウェブサイト上で公表します。':
        'This policy may be revised due to legal changes or operational needs. Important changes will be announced on this website.',
      '9. お問い合わせ窓口': '9. Contact',
      '本ポリシーに関するお問い合わせは、上記「特定商取引法に基づく表記」のお問い合わせ先をご参照ください。':
        'For inquiries about this policy, please refer to the contact information in the Legal Notice above.',
      '以上': 'End',
      menu: 'menu',
      お部屋: 'Rooms',
      管理: 'Manage',
      作成: 'Create',
      脱退: 'Leave',
      フォルダ: 'Folders',
      パスワード: 'Password',
      出力: 'Export',
      アカウント: 'Account',
      テーマ: 'Theme',
      開発者: 'Developer',
      名前変更: 'Change name',
      削除: 'Delete',
      ログアウト: 'Log out',
      '使い方・料金': 'Help and pricing',
      ログイン: 'Log in',
      新規登録: 'Sign up',
      使い方を見る: 'View help',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー': 'Legal notice, Terms, and Privacy Policy',
      '管理者はお部屋を作成、メンバーは招待URLから参加します。': 'Admins create rooms, and members join from an invitation URL.',
      新規作成: 'Create new',
      お部屋名: 'Room name',
      お部屋を作る: 'Create room',
      入室可能なお部屋: 'Available rooms',
      一覧更新: 'Refresh list',
      '読み込み中...': 'Loading...',
      '※ 「この部屋へ」で入室中のお部屋を切り替えられます。': 'Use "Enter this room" to switch your active room.',
      '利用者:': 'User:',
      'お部屋:': 'Room:',
      現在のお部屋: 'Current room',
      お部屋を選択してください: 'Select a room',
      現在のフォルダ: 'Current folder',
      フォルダを選択してください: 'Select a folder',
      ストレージ使用量: 'Storage usage',
      '使用量 0MB': 'Used 0 MB',
      '残り 0MB': 'Remaining 0 MB',
      '追加残り 0.00 GB・月 相当': 'Extra remaining: 0.00 GB-months',
      'お部屋管理（管理者）': 'Room management (admin)',
      '招待URLを発行（7日）': 'Issue invitation URL (7 days)',
      招待URLを失効: 'Revoke invitation URL',
      招待URL: 'Invitation URL',
      コピー: 'Copy',
      'お部屋を削除（全データ）': 'Delete room (all data)',
      '※ 削除は、アップロード画像に加え、サムネイル等の自動生成データも含みます。': 'Deletion includes uploaded images and generated data such as thumbnails.',
      容量: 'Storage',
      フリープランに戻る: 'Return to Free plan',
      '1GBプラン (¥980/月)': '1 GB plan (¥980/month)',
      '5GBプラン (¥1,980/月)': '5 GB plan (¥1,980/month)',
      '10GBプラン (¥2,980/月)': '10 GB plan (¥2,980/month)',
      '※ 本サービスの容量表示は2進単位です（1GB=1,024MB、5GB=5,120MB、10GB=10,240MB）。':
        'Storage is shown in binary units (1 GB=1,024 MB, 5 GB=5,120 MB, 10 GB=10,240 MB).',
      部屋に戻る: 'Back to room',
      '1つ目の写真名を連番で反映': 'Apply first photo name as sequence',
      '1つ目のコメントを全件に反映': 'Apply first comment to all',
      キャンセル: 'Cancel',
      アップロード: 'Upload',
      'アップロード中...': 'Uploading...',
      お部屋作成: 'Create room',
      閉じる: 'Close',
      '※ 1人1部屋です。作成済みの場合は作成できません。': 'Each user can create one room. You cannot create another if one already exists.',
      作成して入室: 'Create and enter',
      フォルダ作成: 'Create folder',
      '〇〇工場_yyyymmdd': 'Factory_yyyymmdd',
      'フォルダパスワード（任意）': 'Folder password (optional)',
      季節: 'Season',
      春: 'Spring',
      夏: 'Summer',
      秋: 'Autumn',
      冬: 'Winter',
      ダークモード: 'Dark mode',
      フォルダパスワード: 'Folder password',
      対象フォルダ: 'Target folder',
      '現在のフォルダに設定します。空で保存すると解除されます。': 'Applies to the current folder. Save empty to remove it.',
      'フォルダパスワード（空で解除）': 'Folder password (empty to remove)',
      '鍵を設定/解除': 'Set/remove lock',
      使い方: 'How to use',
      '新規登録後、ログイン（初回は表示名を設定）': 'Sign up, then log in. Set your display name the first time.',
      'ログイン後、お部屋を作成': 'Create a room after logging in.',
      'フォルダ作成 → 写真アップロード → コメント追加 → 出力': 'Create a folder, upload photos, add comments, then export.',
      'マニュアル：': 'Manual:',
      こちら: 'Open',
      'Photo Hub for 監査 使い方マニュアル': 'Photo Hub for Audit User Manual',
      '使い方マニュアル': 'User Manual',
      '作成日：': 'Created:',
      '2026年4月19日': 'April 19, 2026',
      '改訂日：': 'Revised:',
      '2026年4月30日': 'April 30, 2026',
      'はじめに': 'Introduction',
      '多くの企業の現場では監査や検品業務において、多くの手間と時間がかかっています。本アプリはこれらを効率化します。':
        'Many company work sites spend significant time and effort on audits and inspections. This app streamlines those tasks.',
      'ユーザー登録が必要': 'User registration is required',
      '管理者・お部屋メンバー・フォルダメンバーに分類': 'Users are grouped as admins, room members, and folder members',
      '3階層構造（お部屋・フォルダ・写真）': 'Three-level structure: rooms, folders, and photos',
      'PowerPoint出力可能': 'PowerPoint export is available',
      '権限管理あり': 'Permission management is available',
      'フリー／有料プラン': 'Free and paid plans',
      '1. ユーザー登録': '1. User registration',
      '1-1 新規登録': '1-1 Sign up',
      '新規ユーザーは登録を行います。': 'New users complete registration.',
      '1-2 ログイン': '1-2 Log in',
      '認証後利用可能。': 'Available after authentication.',
      '1-3 初回設定': '1-3 Initial setup',
      '表示名を設定。': 'Set a display name.',
      '2. ユーザー分類': '2. User categories',
      'ユーザーは管理者とメンバーに分類されます。': 'Users are categorized as admins or members.',
      '3. お部屋': '3. Rooms',
      '1ユーザー1部屋': 'One room per user',
      'URLで参加': 'Join by URL',
      '7日間有効': 'Valid for 7 days',
      '4. フォルダ': '4. Folders',
      'フリー：2つ': 'Free: 2 folders',
      '有料：無制限': 'Paid: unlimited',
      '5. 写真': '5. Photos',
      'カメラ / ライブラリ / ファイル': 'Camera / library / files',
      '単体 / 一括': 'Single / batch',
      '6. コメント': '6. Comments',
      '全員閲覧可能': 'Visible to everyone',
      '管理者は全編集可能': 'Admins can edit everything',
      '7. 出力': '7. Export',
      'PowerPoint出力': 'PowerPoint export',
      'フリー：透かしあり': 'Free: includes watermark',
      '有料：透かしなし': 'Paid: no watermark',
      '8. 権限管理': '8. Permission management',
      '全閲覧 / 自分のみ': 'Everyone / self only',
      '9. 料金プラン': '9. Pricing plans',
      'フリー：512MB / 30日': 'Free: 512 MB / 30 days',
      '1GB：¥980': '1 GB: ¥980',
      '5GB：¥1,980': '5 GB: ¥1,980',
      '10GB：¥2,980': '10 GB: ¥2,980',
      '権限表': 'Permission table',
      '機能': 'Feature',
      '可': 'Allowed',
      '不可': 'Not allowed',
      料金: 'Pricing',
      'ご利用料金は、当サービスにお預けいただくデータ量に応じて異なります。': 'Pricing depends on the amount of data stored in this service.',
      '無料枠を超えて利用を続ける場合、管理者がサブスクプランを選択します。': 'If usage exceeds the free allowance, an admin selects a subscription plan.',
      'サブスクプラン（1か月）:': 'Subscription plans (monthly):',
      '※ 料金操作は管理者メニュー（お部屋管理）から実行します。': 'Billing actions are available from the admin menu.',
      開発者ダッシュボード: 'Developer dashboard',
      容量不足のご案内: 'Low storage notice',
      '容量を追加しますか？': 'Add storage?',
      サブスクプランへ変更: 'Change to subscription plan',
      出力形式の選択: 'Select export format',
      出力形式を選択: 'Select export format',
      'PDF を最優先でおすすめします。': 'PDF is recommended first.',
      最も安定して閲覧できます: 'Most reliable for viewing',
      軽量PPT: 'Light PPT',
      'できるだけ軽量化したPPTです。携帯では見れない場合があります': 'A smaller PPT. It may not display on some phones.',
      高画質PPT: 'High-quality PPT',
      '高品質なPPTです。携帯では見れない場合があります': 'A high-quality PPT. It may not display on some phones.',
      PDFダウンロード中: 'Downloading PDF',
      出力中: 'Exporting',
      'ダウンロードを開始しています...': 'Starting download...',
      ダウンロードする: 'Download',
      別タブで開く: 'Open in new tab',
      リンクをコピー: 'Copy link',
      写真全体表示: 'Full photo view',
      写真プレビュー: 'Photo preview',
      生成完了: 'Export ready',
      'リンクをコピーしました。': 'Link copied.',
      '写真名': 'Photo name',
      '初回コメント（任意）': 'Initial comment (optional)',
      コメント: 'Comment',
      'まだフォルダがなかです': 'No folders yet',
      'Cognito設定が不足しています。config.jsを確認してください。': 'Cognito settings are missing. Check config.js.',
      'Cognito設定が不足しています。config.jsにdomain/clientId/regionを設定してください。':
        'Cognito settings are missing. Set domain, clientId, and region in config.js.',
      'Cognitoトークン取得失敗: {message}': 'Failed to get Cognito token: {message}',
      'Cognitoトークンが取得できませんでした。': 'Could not get the Cognito token.',
      'PDFをダウンロード中... {percent}%': 'Downloading PDF... {percent}%',
      'PDFをダウンロード中... {kb}KB': 'Downloading PDF... {kb} KB',
      'PDFのダウンロードを開始しています...': 'Starting PDF download...',
      'PDFダウンロード失敗({status})': 'PDF download failed ({status})',
      '{formatLabel} の生成が完了しました。操作を選んでください。': '{formatLabel} is ready. Choose an action.',
      '{formatLabel} のリンクをコピーしました。': 'Copied the {formatLabel} link.',
      '{formatLabel} を生成しています...': 'Generating {formatLabel}...',
      '{formatLabel}で出力します。よろしいですか？': 'Export as {formatLabel}?',
      '{label}失敗: {message}': '{label} failed: {message}',
      '{label}（現在のプラン）': '{label} (current plan)',
      '{name} を全体表示': 'View full image: {name}',
      '{product}プラン': '{product} plan',
      '{count}件': '{count} items',
      '{count}件 / 有料内 {paidPercent}% / 全体 {totalPercent}%':
        '{count} rooms / {paidPercent}% of paid / {totalPercent}% total',
      '{count}件の写真をアップロード対象に追加しています。': 'Added {count} photos for upload.',
      '{uploaded}/{total}件アップロード完了。': 'Uploaded {uploaded}/{total}.',
      '{uploaded}/{total}件アップロード完了。{duplicate}件は重複のためスキップしました。':
        'Uploaded {uploaded}/{total}. Skipped {duplicate} duplicates.',
      '{duplicate}件は重複のためスキップしました。': 'Skipped {duplicate} duplicates.',
      '{row}行目: 写真名は必須です。': 'Row {row}: Photo name is required.',
      '{row}行目: 写真名は20文字以内にしてください。': 'Row {row}: Photo name must be 20 characters or less.',
      '{row}行目: 初回コメントは50文字以内にしてください。': 'Row {row}: Initial comment must be 50 characters or less.',
      '先にフォルダを選択してください。': 'Select a folder first.',
      未選択: 'Not selected',
      '{roomName}（停止中）': '{roomName} (disabled)',
      '軽量PPT': 'Light PPT',
      '高画質PPT': 'High-quality PPT',
      'フォルダ {count} / 無制限': 'Folders {count} / unlimited',
      'フォルダ {count} / {limit}': 'Folders {count} / {limit}',
      '1GB〜10GBプラン: フォルダ無制限 / 3年保存 / PPT透かしなし':
        '1 GB-10 GB plans: unlimited folders / 3-year storage / no PPT watermark',
      'フリープラン: フォルダ2個 / 30日保存 / PPT透かしあり':
        'Free plan: 2 folders / 30-day storage / PPT watermark',
      'フリープランへの切り替えは、以下を満たす必要があります。':
        'To switch to the Free plan, these requirements must be met.',
      '・容量が512MB未満': '- Storage must be under 512 MB',
      '・フォルダの数が2つ以下': '- Folder count must be 2 or less',
      '・現在の容量: {size}': '- Current storage: {size}',
      '・現在のフォルダ数: {count}': '- Current folder count: {count}',
      '{count}件の写真は{days}日保存後にアーカイブされ、現在は非表示です。アーカイブ済みデータも容量に含まれます。有料プランにすると再表示されます。':
        '{count} photos were archived after {days} days and are currently hidden. Archived data counts toward storage. Upgrade to a paid plan to show them again.',
      '使用量 {size}': 'Used {size}',
      '残り {size}': 'Remaining {size}',
      'プラン:{plan}': 'Plan: {plan}',
      参加者: 'Member',
      'アップロード停止中（残量不足）': 'Upload paused (low storage)',
      無料枠で利用中: 'Using free allowance',
      'フリープランに戻る（現在のプラン）': 'Return to Free plan (current plan)',
      '容量を追加しますか？（現在の残り: {remain} / 現在プラン: {plan}）':
        'Add storage? (Remaining: {remain} / Current plan: {plan})',
      '表示名を入力してください。メニューからいつでも変更可能です。':
        'Enter your display name. You can change it anytime from the menu.',
      '表示名は必須です。': 'Display name is required.',
      '表示名を設定しました。': 'Display name set.',
      '初回コメント': 'Initial comment',
      'この写真を除外': 'Remove this photo',
      '1つ目のコメントを先に入力してください。': 'Enter the first comment first.',
      '1つ目のコメントを全件に反映してよかですか？既存入力は上書きされます。':
        'Apply the first comment to all photos? Existing input will be overwritten.',
      '1行目の写真名を先に入力してください。': 'Enter the first row photo name first.',
      '1つ目の写真名を連番で反映してよかですか？既存入力は上書きされます。':
        'Apply the first photo name as a sequence? Existing input will be overwritten.',
      '選択した写真と入力内容を破棄してよかですか？': 'Discard selected photos and entered content?',
      処理: 'Action',
      無料プラン: 'Free plan',
      不明: 'Unknown',
      'プランを{label}へ更新しました。': 'Updated plan to {label}.',
      '決済反映に少し時間がかかっとるばい。しばらくしてプラン表示ば確認してね。':
        'Payment may take a little time to apply. Check the plan display shortly.',
      'お部屋に参加しました。': 'Joined the room.',
      '招待URLの処理に失敗しました: {message}': 'Failed to process invitation URL: {message}',
      入室可能なお部屋がありません: 'No rooms available to enter',
      '（参加中）': '(joined)',
      '（停止中）': '(disabled)',
      '作成者: 自分': 'Owner: you',
      '作成者: 別ユーザ': 'Owner: another user',
      入室中: 'In room',
      停止中: 'Disabled',
      この部屋へ: 'Enter this room',
      お部屋がありません: 'No rooms',
      '作成者は先に「このお部屋を削除（全データ）」を実行してください。':
        'Owners must first run "Delete this room (all data)".',
      '作成者は先に「お部屋を削除（全データ）」を実行してください。\n「{roomName}」へ移動しますか？':
        'Owners must first run "Delete room (all data)".\nMove to "{roomName}"?',
      自分の部屋: 'My room',
      '「{roomName}」へ移動しました。': 'Moved to "{roomName}".',
      'ネットワークエラー: {message}': 'Network error: {message}',
      'チーム情報取得失敗: {message}（バックエンド/フロントのデプロイ差分やキャッシュの可能性）':
        'Failed to get team info: {message} (deployment mismatch or cache may be involved)',
      メンバーがおらんばい: 'No members',
      閲覧: 'Access',
      フォルダ招待: 'Folder invitation',
      自分のフォルダのみ: 'Own folders only',
      全フォルダ表示: 'Show all folders',
      'メンバー「{name}」の閲覧権限を変更してよかですか？': 'Change access permission for "{name}"?',
      '閲覧権限を更新しました。': 'Access permission updated.',
      'メンバー「{name}」をお部屋から削除してよかですか？（本人は入れんごとなります）':
        'Remove "{name}" from the room? They will no longer be able to enter.',
      'メンバーを削除しました。': 'Member removed.',
      'メンバー取得失敗: {message}': 'Failed to get members: {message}',
      フォルダがなかです: 'No folders',
      'フォルダ招待URL': 'Folder invitation URL',
      '招待URL発行（7日）': 'Issue invitation URL (7 days)',
      招待URL失効: 'Revoke invitation URL',
      '失効する招待URLがなかです（先に発行してください）': 'No invitation URL to revoke. Issue one first.',
      'フォルダ「{folder}」の招待URLを失効してよかですか？': 'Revoke the invitation URL for folder "{folder}"?',
      'フォルダ招待URLを失効しました。': 'Folder invitation URL revoked.',
      'メンバー読み込み中...': 'Loading members...',
      '設定/解除': 'Set/remove',
      'フォルダ「{folder}」のパスワードを設定してよかですか？': 'Set a password for folder "{folder}"?',
      'フォルダ「{folder}」のパスワードを解除してよかですか？': 'Remove the password for folder "{folder}"?',
      'フォルダのパスワードを設定しました。': 'Folder password set.',
      'フォルダのパスワードを解除しました。': 'Folder password removed.',
      'フォルダ「{folder}」を削除してよかですか？（写真とコメントも消えます）':
        'Delete folder "{folder}"? Photos and comments will also be deleted.',
      'フォルダを削除しました。': 'Folder deleted.',
      全フォルダ: 'All folders',
      権限: 'Permission',
      このフォルダから外す: 'Remove from this folder',
      'メンバー「{name}」をこのフォルダから外してよかですか？': 'Remove "{name}" from this folder?',
      'フォルダメンバーを外しました。': 'Folder member removed.',
      'フォルダ取得失敗: {message}': 'Failed to get folders: {message}',
      'プラン容量 {size}': 'Plan storage {size}',
      '無料 {size}': 'Free {size}',
      '使用量 {used} / {capacity}（残り {remain}） / {folderSummary} / プラン {plan}':
        'Used {used} / {capacity} (remaining {remain}) / {folderSummary} / Plan {plan}',
      '※ 30日保存後はアーカイブへ移動し、アーカイブは容量に含まれます。\n※ フリープランへ戻す際の容量判定にはアーカイブ済みデータも含みます。':
        'After 30 days, photos move to the archive and archived data counts toward storage.\nArchived data is also counted when checking Free plan requirements.',
      'コピーする招待URLがなかです（先に発行してください）': 'No invitation URL to copy. Issue one first.',
      '招待URLをコピーしました。': 'Invitation URL copied.',
      '招待URL（コピーしてください）': 'Invitation URL (copy this)',
      'ブラウザがコピー操作を許可しませんでした。URL欄からコピーしてください。':
        'The browser did not allow copying. Copy it from the URL field.',
      '招待トークンが取得できませんでした。': 'Could not get invitation token.',
      'この招待URLを失効してよかですか？': 'Revoke this invitation URL?',
      '招待URLを失効しました。': 'Invitation URL revoked.',
      'フォルダ取得失敗: ネットワーク/CORSエラーの可能性があります': 'Failed to get folders: possible network/CORS error',
      鍵: 'Lock',
      '●新着': 'New',
      'このフォルダは鍵付きです。パスワードを入力してください。': 'This folder is locked. Enter the password.',
      'フォルダパスワードが必要です。': 'Folder password is required.',
      'フォルダ: {folder}': 'Folder: {folder}',
      'フォルダパスワードが違います。': 'Folder password is incorrect.',
      '画像アップロード通信エラー: {message}': 'Image upload network error: {message}',
      '画像アップロード失敗({status})': 'Image upload failed ({status})',
      'リサイズ画像アップロード通信エラー: {message}': 'Resized image upload network error: {message}',
      'リサイズ画像アップロード失敗({status})': 'Resized image upload failed ({status})',
      '同じ写真は同じフォルダにアップロードできません（重複を検知しました）。':
        'The same photo cannot be uploaded to the same folder. Duplicate detected.',
      'すべて重複なのでアップロードができません。': 'All photos are duplicates, so upload cannot continue.',
      'アップロード停止中です（残量不足）。管理者が容量チケットを追加するか、写真を削除してください。':
        'Uploads are paused due to low storage. Ask an admin to add capacity or delete photos.',
      '表示中の写真はなかです。30日を過ぎた写真はアーカイブされとるばい。':
        'No photos are currently visible. Photos older than 30 days have been archived.',
      '写真はまだなかです。': 'No photos yet.',
      '投稿: {name}': 'Posted by: {name}',
      写真名修正: 'Edit photo name',
      写真削除: 'Delete photo',
      未読: 'Unread',
      開いたら読み込みます: 'Open to load',
      修正: 'Edited',
      投稿: 'Posted',
      コメント修正: 'Edit comment',
      コメント削除: 'Delete comment',
      保存: 'Save',
      取消: 'Cancel',
      'このコメントを削除してよかですか？': 'Delete this comment?',
      追加: 'Add',
      'コメント ({count})': 'Comments ({count})',
      入力を消去: 'Clear input',
      'この写真を削除してよかですか？': 'Delete this photo?',
      未読コメントがあります: 'Unread comments',
      未読コメントなし: 'No unread comments',
      '新しい表示名を入力してください。': 'Enter a new display name.',
      '表示名を更新しました。': 'Display name updated.',
      '管理者は脱退できません。お部屋管理から「お部屋を削除（全データ）」を実行してください。':
        'Admins cannot leave. Use room management to delete the room first.',
      'メンバーをやめると、このお部屋には招待URLなしでは再参加できません。':
        'If you leave, you cannot rejoin this room without an invitation URL.',
      '本当にメンバーをやめますか？': 'Really leave as a member?',
      'お部屋名を入力してください。': 'Enter a room name.',
      'お部屋：{roomName} が作成されました。': 'Room "{roomName}" was created.',
      'すでに自分のお部屋を作成済みです（自分の部屋は1人1部屋）。':
        'You have already created your own room. Each user can create one room.',
      '同じ部屋名は作成できません。別の部屋名にしてください。':
        'That room name already exists. Choose another name.',
      'お部屋作成失敗: {message}': 'Room creation failed: {message}',
      'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
        'The Free plan allows up to 2 folders. Paid plans allow unlimited folders.',
      'フォルダ：{title} を作成しました。': 'Folder "{title}" was created.',
      'Stripe決済URLが取得できませんでした。': 'Could not get the Stripe checkout URL.',
      'フリープランへ戻してよかですか？': 'Return to the Free plan?',
      'フリープランに戻りました。\n\n現在の上限は、容量512MB未満・フォルダ2個までです。':
        'Returned to the Free plan.\n\nCurrent limits are under 512 MB storage and up to 2 folders.',
      'このお部屋を削除すると、フォルダ/写真/コメント/課金情報が全て削除され、Stripeの定期課金も即時停止されます。よかですか？':
        'Deleting this room removes all folders, photos, comments, and billing info, and immediately stops Stripe subscriptions. Continue?',
      '本当によかですか？（取り消せません）': 'Are you sure? This cannot be undone.',
      'お部屋を削除しました。': 'Room deleted.',
      'アカウントを削除すると、このユーザーでは今後ログインできません。よかですか？':
        'Deleting this account prevents future login with this user. Continue?',
      '本当によかですか？（アカウント削除後は取り消せません）': 'Are you sure? Account deletion cannot be undone.',
      '作成者は先に「お部屋を削除（全データ）」を実行してください。':
        'Owners must first run "Delete room (all data)".',
      'アカウントを削除しました。': 'Account deleted.',
      'このフォルダを削除すると、写真とコメントも消えます。よかですか？':
        'Delete this folder? Photos and comments will also be deleted.',
      'フォルダの鍵を更新しました。': 'Folder lock updated.',
      '予期しないエラー: {message}': 'Unexpected error: {message}',
      '実行エラー: {message}': 'Runtime error: {message}',
      '現在のお部屋を切り替えます。よろしいですか？': 'Switch the current room?',
      '初期化失敗: {message}': 'Initialization failed: {message}',
      '更新: {datetime}': 'Updated: {datetime}',
      全ユーザー: 'All users',
      お部屋メンバー: 'Room members',
      フォルダメンバー: 'Folder members',
      総容量: 'Total storage',
      有料プラン内訳: 'Paid plan breakdown',
      '有料プランのお部屋はまだありません。': 'There are no paid-plan rooms yet.',
      お部屋と容量: 'Rooms and storage',
      メンバー: 'Members',
      'メンバー（合計）': 'Members (total)',
      'デモではログイン不要です。このまま画面を触ってみてください。':
        'No login is needed in the demo. You can use the screen as-is.',
      'デモでは新規登録不要です。気になる動きだけそのまま試せます。':
        'No signup is needed in the demo. Try the flows you want to check.',
      'デモではログイン不要です。': 'No login is needed in the demo.',
      'デモでは新規登録不要です。': 'No signup is needed in the demo.',
      'デモではアカウント削除は行いません。': 'Account deletion is disabled in the demo.',
      'デモでは {plan} に切り替えた状態を表示します。': 'The demo now shows the state switched to {plan}.',
      'フォルダが見つかりません。': 'Folder not found.',
      LPに戻る: 'Back to landing page',
      デモ中: 'Demo mode',
      登録不要: 'No signup needed',
      デモ画像: 'Demo image',
      監査レポート: 'Audit report',
      コメントなし: 'No comments',
      日時不明: 'Unknown date/time',
      デモ利用者: 'Demo user',
      新規写真: 'New photo',
      新規フォルダ: 'New folder',
      管理者: 'Admin',
      作成者: 'Owner',
      'お部屋がありません。': 'No rooms.',
      '取得失敗: {message}': 'Failed to fetch: {message}',
      '{folder}（作成:{creator} / 容量:{size}）': '{folder} (created by: {creator} / storage: {size})',
    },
    'zh-CN': {
      'Photo Hub for 監査': '审计 Photo Hub',
      'Photo Hub for 監査 | デモ': '审计 Photo Hub | 演示',
      'Photo Hub for 監査 | プロダクトランディングページ': '审计 Photo Hub | 产品落地页',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー | Photo Hub for 監査':
        '特定商业交易法标示、使用条款和隐私政策 | 审计 Photo Hub',
      監査写真コメントアプリ: '审计照片评论应用',
      '監査のあと、<br />会社に戻って報告書を作っていませんか？':
        '审计之后，<br />还要回公司制作报告吗？',
      '現場で終わるはずの仕事を、<br />その場で完結させる。': '把本应在现场完成的工作，<br />就在现场完成。',
      無料で試す: '免费试用',
      少し触ってみる: '试用演示',
      '説明より先に、「今のやり方がしんどい」と感じた方のためのページです。':
        '这是为已经觉得“现在的做法很辛苦”的人准备的页面。',
      現場起点: '以现场为起点',
      '写真もコメントも、その場で記録': '照片和评论都在现场记录',
      報告まで一気通貫: '一路连接到报告',
      あとでPCに戻って整理し直さない: '之后无需回到电脑重新整理',
      導入が軽い: '轻量导入',
      '高機能すぎず、現場で使われる作り': '功能不过度，适合现场使用',
      'こんな運用、続いていませんか？': '这样的运用方式还在继续吗？',
      現場ではこう動いている: '现场实际是这样运转的',
      写真はスマホで撮る: '用手机拍照',
      '共有はLINEやGoogle Drive': '通过 LINE 或 Google Drive 共享',
      報告はExcelやPowerPoint: '用 Excel 或 PowerPoint 做报告',
      その結果: '结果',
      '帰社後に1時間〜2時間の作業': '回公司后还要工作 1-2 小时',
      同じ人が二度手間: '同一个人重复处理',
      毎回なんとなく非効率: '每次都觉得有些低效',
      '原因は「ツールの分断」です。': '原因是“工具割裂”。',
      '記録と共有と報告が別々やけん、移動・再整理・二重作業が当たり前になっとる状態です。':
        '记录、共享和报告分别使用不同工具，因此移动数据、重新整理和重复作业变成了常态。',
      記録: '记录',
      スマホ: '手机',
      共有: '共享',
      クラウド: '云端',
      報告: '报告',
      PC: '电脑',
      'この分断によって、<span class="accent">移動・再整理・二重作業</span>が発生しています。':
        '这种割裂导致<span class="accent">移动、重新整理和重复作业</span>。',
      'すべて一体化したツールを使えばいい？': '只要使用一体化工具就可以吗？',
      'でも現実は、そこがいちばん難しかところです。': '但现实中，这正是最难的地方。',
      高い: '成本高',
      '1人数千円かかると、現場全員に広げにくい。':
        '如果每人需要数千日元，就很难推广到所有现场人员。',
      設定が難しい: '设置困难',
      '最初の設計や運用ルールづくりで止まりやすい。': '容易卡在初始设计和运用规则制定上。',
      使われない: '没人使用',
      '覚えることが多いと、結局いつものExcelに戻る。': '要记的东西太多，最后还是回到平时的 Excel。',
      '本サービスは、この「分断」と「導入負荷」の間を埋めます。':
        '本服务填补“工具割裂”和“导入负担”之间的空白。',
      '写真・コメント・報告書を<br /><strong>一つの流れで完結。</strong>':
        '照片、评论和报告<br /><strong>在一个流程中完成。</strong>',
      '現場で撮って、<br />そのまま報告まで。': '在现场拍摄，<br />直接连接到报告。',
      撮る: '拍摄',
      現場で写真を残す: '在现场留下照片',
      書く: '填写',
      その場でコメントを添える: '当场添加评论',
      出す: '输出',
      報告の形までつなげる: '连接到报告形式',
      'だから現場で使われる。': '所以现场愿意使用。',
      '監査業務に特化しとるけん、必要以上に重たくなっていません。':
        '因为专注于审计业务，不会变得过于沉重。',
      機能を絞っている: '功能聚焦',
      'やることが見えやすく、迷わず使える。': '要做的事清楚可见，可以不迷茫地使用。',
      スマホで直感操作: '手机直观操作',
      '現場の流れを止めずに記録できる。': '不打断现场流程即可记录。',
      設定不要: '无需设置',
      '導入時の説明や初期調整に時間を取られにくい。': '不容易在导入说明和初始调整上耗费时间。',
      '「帰ってからやる」が、「現場で終わる」に変わります。':
        '从“回去后再做”变成“现场完成”。',
      '現場 → 帰社 → PC作業 → 報告': '现场 -> 回公司 -> 电脑作业 -> 报告',
      '仕事が終わったあとに、もう一度まとめ直す流れ。': '工作结束后还要再整理一次的流程。',
      現場で完結: '现场完成',
      '撮る・書く・報告するが、一つの作業としてつながる流れ。':
        '拍摄、填写、报告作为一项工作连接起来。',
      '料金プラン（税込・月額）': '价格方案（含税・月付）',
      'まずは無料で試して、運用に合えばそのまま広げられます。':
        '先免费试用，如果适合运用，就可以直接扩展。',
      '1GBプラン': '1GB 方案',
      '5GBプラン': '5GB 方案',
      '10GBプラン': '10GB 方案',
      ' / 月': ' / 月',
      'まず試したい方向け。無料枠（512MB）でお試し利用できます。':
        '适合想先试用的人。可使用免费额度（512MB）体验。',
      '小規模チーム向け。まず運用を始めるための基本プラン。':
        '面向小规模团队。用于开始运用的基础方案。',
      '運用が安定して写真点数が増えてきたチーム向け。':
        '面向运用稳定、照片数量增加的团队。',
      '複数案件・複数拠点で継続運用するチーム向け。':
        '面向多个项目、多个据点持续运用的团队。',
      '料金プラン比較表': '价格方案比较表',
      項目: '项目',
      フリープラン: '免费方案',
      '1GB〜10GBプラン': '1GB-10GB 方案',
      フォルダ数: '文件夹数',
      '2個まで': '最多 2 个',
      無制限: '无限制',
      保存期間: '保存期间',
      '30日保存<sup>※2</sup>': '保存 30 天<sup>※2</sup>',
      '3年保存': '保存 3 年',
      PPT出力: 'PPT 导出',
      透かしあり: '有水印',
      透かしなし: '无水印',
      '※1 容量にアーカイブが含まれます。<br />※2 保存期間後はアーカイブ(非表示)となります。':
        '※1 容量包含归档数据。<br />※2 保存期间结束后会归档（隐藏）。',
      申込方法: '申请方法',
      '本ウェブサイトを通じてお申し込みいただきます。': '请通过本网站申请。',
      '無料枠を超えて利用を続ける場合、管理者がサブスクプラン（1GB/5GB/10GB）を選択します。':
        '如果超过免费额度继续使用，管理员选择订阅方案（1GB/5GB/10GB）。',
      'クレジットカード（Stripeによる決済代行）で決済します。':
        '通过信用卡付款（由 Stripe 代为处理）。',
      '初回は有料プラン申込時に決済、以後は有効期間中に毎月自動決済されます。':
        '首次在申请付费方案时付款，之后在有效期间内每月自动扣款。',
      申込ページへ進む: '前往申请页面',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシーを見る':
        '查看特定商业交易法标示、使用条款和隐私政策',
      '帰ってから整理する監査を、ここで終わらせる。': '让“回去后再整理”的审计在这里结束。',
      'まず触ってみるか、先に運用イメージだけ確認するか。どちらからでも始められます。':
        '可以先试用，也可以先确认运用方式。两种方式都能开始。',
      '販売事業者:': '销售方：',
      '商品名:': '商品名：',
      '販売方法:': '销售方式：',
      '本ウェブサイトを通じたご案内・お申し込み': '通过本网站进行介绍和申请',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー':
        '特定商业交易法标示、使用条款和隐私政策',
      商品画面に戻る: '返回商品页面',
      特定商取引法に基づく表記: '基于特定商业交易法的标示',
      '最終更新日: 2026年2月20日': '最后更新日：2026年2月20日',
      法人名: '法人名称',
      住所: '地址',
      '請求があった場合は遅滞なく開示します。': '如有请求，将及时披露。',
      電話番号: '电话号码',
      '受付時間: 土日 10:00-18:00 / まずはメールでお問い合わせください。':
        '受理时间：周六周日 10:00-18:00 / 请先通过邮件联系。',
      メールアドレス: '电子邮件地址',
      運営責任者: '运营负责人',
      '事業内容・販売方法': '业务内容和销售方式',
      '事業内容: 業務効率化に関する助言・支援サービス': '业务内容：业务效率化相关咨询与支持服务',
      '販売方法: 本ウェブサイトを通じたご案内・お申し込み': '销售方式：通过本网站进行介绍和申请',
      追加手数料: '附加费用',
      '本サービスの利用にかかる通信費などについては、お客様のご負担となります。':
        '使用本服务产生的通信费等由客户承担。',
      交換および返品に関するポリシー: '换货及退货政策',
      '＜お客様からの返品・交換＞ デジタルサービスの性質上、提供開始後の返品・返金はお受けできません。':
        '＜客户退货与换货＞ 因数字服务的性质，服务开始提供后不接受退货或退款。',
      '＜不良品・サービスの返品・交換＞ 当方起因の不具合、重複請求、サービス提供不能が確認できた場合は、内容確認後に返金または是正対応を行います。':
        '＜瑕疵服务的退货与换货＞ 如确认存在由我方原因导致的问题、重复扣款或无法提供服务，将在确认内容后进行退款或修正处理。',
      '有料プランの解約は管理画面からいつでも手続きできます。': '付费方案可随时从管理界面办理解约。',
      '解約手続き後は有料プランの提供を停止し、以後の定期請求は行いません。':
        '解约后将停止提供付费方案，并不再进行后续定期扣款。',
      '不審請求（チャージバック）対応方針': '可疑扣款（拒付）处理方针',
      '不審請求が発生した場合は、サービスの発注・提供記録・メール履歴に加え、本人確認記録およびアクセスログ等の証跡を提出し、適切に対応します。':
        '如发生可疑扣款，将提交服务订购和提供记录、邮件记录、身份确认记录及访问日志等证据，并妥善处理。',
      サービス提供時期: '服务提供时间',
      '決済完了後、通常は即時に反映します。システム都合で遅延する場合があります。':
        '付款完成后通常会立即反映。因系统原因可能会发生延迟。',
      利用可能な決済手段: '可用支付方式',
      'クレジットカードのみ（Stripeによる決済代行）': '仅支持信用卡（由 Stripe 代为处理付款）',
      決済期間: '付款期间',
      '初回の有料プラン申込時に決済が直ちに行われます。': '首次申请付费方案时会立即付款。',
      'その後は有料プランが継続される期間中、Stripeの定期課金により毎月自動で決済されます。':
        '之后在付费方案持续期间，将通过 Stripe 定期扣款每月自动付款。',
      価格: '价格',
      '表示価格はすべて税込です。': '显示价格均为含税价格。',
      '無料枠（512MB）を超えて利用を続ける場合、管理者がサブスクプランを選択します。':
        '若超过免费额度（512MB）继续使用，管理员需选择订阅方案。',
      動作環境: '运行环境',
      '本サービスは、インターネット接続環境下でブラウザから利用するクラウドサービスです。ご利用にあたっては、以下の環境を推奨します。':
        '本服务是在互联网连接环境下通过浏览器使用的云服务。建议在以下环境中使用。',
      '<strong>対応OS（最新版推奨）</strong><br>Windows / macOS / iOS / Android':
        '<strong>支持的 OS（建议最新版）</strong><br>Windows / macOS / iOS / Android',
      '<strong>対応ブラウザ（各最新版）</strong><br>Google Chrome / Microsoft Edge / Safari':
        '<strong>支持的浏览器（各最新版）</strong><br>Google Chrome / Microsoft Edge / Safari',
      '<strong>インターネット接続</strong><br>常時接続の通信環境が必要です。回線状況により、表示速度やアップロード速度に影響が出る場合があります。':
        '<strong>互联网连接</strong><br>需要持续连接的通信环境。根据线路状况，显示速度和上传速度可能受到影响。',
      '<strong>JavaScript・Cookie</strong><br>本サービスでは JavaScript および Cookie を使用します。ブラウザ設定で無効化されている場合、一部機能が正常に動作しないことがあります。':
        '<strong>JavaScript 和 Cookie</strong><br>本服务使用 JavaScript 和 Cookie。若在浏览器设置中禁用，部分功能可能无法正常运行。',
      '<strong>その他</strong><br>画像アップロード・閲覧に必要な端末ストレージ空き容量を確保してください。推奨環境外では、表示崩れや一部機能が利用できない場合があります。':
        '<strong>其他</strong><br>请确保设备有足够的存储空间用于图片上传和查看。在推荐环境之外，可能出现显示错位或部分功能不可用。',
      '利用規約': '使用条款',
      '制定日: 2025年2月24日 / 最終改定日: 2026年2月17日': '制定日：2025年2月24日 / 最后修订日：2026年2月17日',
      '本利用規約（以下「本規約」）は、あおき業務企画（以下「当方」）が提供する各種サービス（以下「本サービス」）の利用条件を定めるものです。利用者は、本規約に同意のうえ本サービスを利用するものとします。':
        '本使用条款规定あおき業務企画提供的各项服务的使用条件。用户应在同意本条款后使用本服务。',
      '1. 適用範囲': '1. 适用范围',
      '本規約は、本サービスの利用に関する当方と利用者との一切の関係に適用されます。':
        '本条款适用于我方与用户之间关于本服务使用的一切关系。',
      '2. 同意': '2. 同意',
      '利用者は、本サービスを利用した時点で本規約および当方のプライバシーポリシーに同意したものとみなされます。':
        '用户使用本服务时，即视为同意本条款及我方隐私政策。',
      '3. アカウント管理': '3. 账户管理',
      '利用者は、自己の責任でアカウント情報を管理し、第三者への貸与・譲渡・共有を行わないものとします。':
        '用户应自行负责管理账户信息，不得向第三方出借、转让或共享。',
      'アカウントの不正使用により生じた損害について、当方に故意または重過失がある場合を除き、当方は責任を負いません。':
        '除我方存在故意或重大过失外，我方不对因账户被不正当使用而产生的损害承担责任。',
      '本規約における「非アクティブ」とは、無料プランのアカウントについて、最終ログイン日から365日間ログインが確認できない状態をいいます。':
        '本条款中的“非活跃”是指免费方案账户自最后登录日起 365 天内未确认登录的状态。',
      '前項の非アクティブ状態が継続した場合、当方は、事前の通知なく、当該アカウントおよび関連データを自動的に削除するものとします。':
        '如前项非活跃状态持续，我方可在不事先通知的情况下自动删除该账户及相关数据。',
      '削除の実施後、当該アカウントおよび関連データは復元できません。':
        '删除执行后，该账户及相关数据无法恢复。',
      'ただし、法令遵守、不正利用防止、請求・監査対応等のため保存が必要な情報（請求履歴、決済関連記録、監査ログ等）については、法令上より長い保存義務がある場合を除き、削除実施日から3年間保持し、期間経過後に削除または匿名化します。':
        '但为遵守法律、防止不正当使用、处理账单和审计等需要保存的信息（账单记录、支付相关记录、审计日志等），除法律要求更长期限外，将自删除执行日起保存 3 年，期满后删除或匿名化。',
      '前項にもとづく削除が実施された場合、当方に故意または重過失がある場合を除き、当該削除により利用者に生じた損害について当方は責任を負いません。':
        '如根据前项执行删除，除我方存在故意或重大过失外，我方不对该删除给用户造成的损害承担责任。',
      '4. 禁止事項': '4. 禁止事项',
      '利用者は、以下の行為をしてはなりません。': '用户不得从事以下行为。',
      '・法令または公序良俗に違反する行為': '- 违反法律法规或公序良俗的行为',
      '・犯罪行為に関連する行為': '- 与犯罪行为相关的行为',
      '・当方または第三者の知的財産権、名誉、プライバシーその他の権利利益を侵害する行為':
        '- 侵害我方或第三方的知识产权、名誉、隐私或其他权利利益的行为',
      '・不正アクセス、過度な負荷、脆弱性探索その他本サービスの運営を妨害する行為':
        '- 不正当访问、过度负载、漏洞探测以及其他妨碍本服务运营的行为',
      '・本サービスを通じた無断の営業、宣伝、勧誘、スパム行為':
        '- 通过本服务进行未经授权的销售、宣传、招揽或垃圾信息行为',
      '・虚偽情報の登録または本人になりすます行為': '- 注册虚假信息或冒充他人的行为',
      '・第三者のデータを権限なくアップロード、共有、公開する行為':
        '- 未经授权上传、共享或公开第三方数据的行为',
      '・リバースエンジニアリング、解析、複製、改変、再配布その他当方が不適切と判断する行為':
        '- 逆向工程、解析、复制、修改、再分发以及其他我方认为不适当的行为',
      '5. 利用停止等': '5. 停止使用等',
      '当方は、利用者が本規約に違反した場合、または本サービス運営上必要と判断した場合、事前通知なく利用停止、データ削除、アカウント停止等の措置を行うことがあります。':
        '如用户违反本条款，或我方认为本服务运营上有必要，我方可在不事先通知的情况下采取停止使用、删除数据、暂停账户等措施。',
      '6. 知的財産権': '6. 知识产权',
      '本サービスに関する著作権、商標権その他の知的財産権は、当方または正当な権利者に帰属します。利用者が本サービスにアップロードしたデータの権利は利用者または正当な権利者に留保されます。':
        '与本服务相关的著作权、商标权及其他知识产权归我方或合法权利人所有。用户上传到本服务的数据权利保留给用户或合法权利人。',
      '7. 免責および責任制限': '7. 免责声明及责任限制',
      '当方は、本サービスの完全性、正確性、継続性、有用性、特定目的適合性を保証しません。通信障害、システム障害、外部サービス障害、不可抗力等により発生した損害について、当方は責任を負いません。':
        '我方不保证本服务的完整性、准确性、持续性、有用性或特定目的适合性。对于因通信故障、系统故障、外部服务故障、不可抗力等产生的损害，我方不承担责任。',
      '当方の責任が認められる場合でも、当方に故意または重過失がある場合を除き、利用者が当方に直近3か月間に実際に支払った金額を上限として賠償責任を負うものとします。':
        '即使认定我方承担责任，除我方存在故意或重大过失外，赔偿责任以上一最近 3 个月内用户实际向我方支付的金额为上限。',
      '8. 規約の変更': '8. 条款变更',
      '当方は、法令改正や運用上の必要に応じて本規約を変更することがあります。重要な変更は本ウェブサイト上で公表します。':
        '我方可根据法律修订或运营需要变更本条款。重要变更将在本网站上公布。',
      '9. 準拠法・管轄': '9. 准据法与管辖',
      '本規約は日本法に準拠し、本サービスに関して紛争が生じた場合は、当方所在地を管轄する裁判所を第一審の専属的合意管轄裁判所とします。':
        '本条款适用日本法。因本服务发生争议时，以管辖我方所在地的法院作为第一审专属合意管辖法院。',
      'プライバシーポリシー': '隐私政策',
      'あおき業務企画（以下「当方」）は、当方が提供するサービスにおける利用者情報の取扱いについて、以下のとおりプライバシーポリシー（以下「本ポリシー」）を定めます。':
        'あおき業務企画就我方提供的服务中用户信息的处理，制定如下隐私政策。',
      '1. 取得する情報': '1. 获取的信息',
      '当方は、サービス提供・運営のために、次の情報を取得することがあります。':
        '为提供和运营服务，我方可能获取以下信息。',
      'アカウント情報（メールアドレス、認証に必要な識別子）':
        '账户信息（电子邮件地址、认证所需识别符）',
      'プロフィール情報（表示名）': '个人资料信息（显示名称）',
      'サービス利用情報（所属ルーム、操作履歴、アップロードデータ、コメント、課金状態）':
        '服务使用信息（所属房间、操作历史、上传数据、评论、计费状态）',
      '技術情報（アクセスログ、エラー情報、端末・ブラウザ情報、Cookieまたはこれに類する技術）':
        '技术信息（访问日志、错误信息、设备和浏览器信息、Cookie 或类似技术）',
      '決済関連情報（Stripe上の顧客ID・サブスクリプション情報等。カード番号等は当方で保持しません）':
        '支付相关信息（Stripe 上的客户 ID、订阅信息等。我方不保存卡号等信息）',
      '2. 利用目的': '2. 使用目的',
      '取得した情報は、次の目的で利用します。': '获取的信息将用于以下目的。',
      'サービスの提供、本人確認、契約履行、アフターサポートのため':
        '用于提供服务、身份确认、履行合同和售后支持',
      'お問い合わせへの回答、重要なご連絡のため': '用于回复咨询和发送重要通知',
      '請求・決済・返金対応および不正利用防止のため':
        '用于账单、支付、退款处理以及防止不正当使用',
      'サービス品質の向上、機能改善、利用状況分析のため':
        '用于提升服务质量、改善功能和分析使用情况',
      '法令・規約等に基づく対応のため': '用于基于法律法规和条款等的处理',
      '3. 第三者提供': '3. 向第三方提供',
      '当方は、法令で認められる場合を除き、本人の同意なく個人情報を第三者に提供しません。ただし、サービス運営に必要な範囲で、業務委託先（決済代行、インフラ、分析ツール等）へ取扱いを委託することがあります。この場合、必要かつ適切な監督を行います。':
        '除法律允许的情形外，我方不会在未经本人同意的情况下向第三方提供个人信息。但在服务运营所需范围内，可能委托业务受托方（支付代行、基础设施、分析工具等）处理相关信息。此时我方将进行必要且适当的监督。',
      '4. 安全管理措置': '4. 安全管理措施',
      '当方は、個人情報への不正アクセス、漏えい、滅失、毀損等を防止するため、合理的な安全管理措置を講じます。なお、インターネット通信の性質上、完全な安全性を保証するものではありません。':
        '我方将采取合理的安全管理措施，防止个人信息被不正当访问、泄露、丢失、损坏等。但鉴于互联网通信的性质，不保证完全安全。',
      '5. Cookie等の利用': '5. Cookie 等的使用',
      '当方ウェブサイトでは、利便性向上やアクセス解析のためCookie等を利用する場合があります。利用者はブラウザ設定によりCookieを無効化できますが、一部機能が利用できない場合があります。':
        '我方网站可能为提高便利性和访问分析而使用 Cookie 等。用户可通过浏览器设置禁用 Cookie，但部分功能可能无法使用。',
      '6. 保有個人データの開示等の請求': '6. 保有个人数据的披露等请求',
      'ご本人から、保有個人データの開示、訂正、追加、削除、利用停止等の請求があった場合は、ご本人確認のうえ、法令に従って適切に対応します。':
        '如本人请求披露、更正、追加、删除、停止使用等保有个人数据，我方将在确认本人身份后依法妥善处理。',
      'アカウント削除後のデータは原則復元できません。ただし、法令遵守、不正利用防止、請求・監査対応のために必要な情報は、法令上より長い保存義務がある場合を除き、削除実施日から3年間保持し、期間経過後に削除または匿名化します。':
        '账户删除后的数据原则上无法恢复。但为遵守法律、防止不正当使用、处理账单和审计等所需信息，除法律要求更长期限外，将自删除执行日起保存 3 年，期满后删除或匿名化。',
      '7. 返金・不審請求対応における情報利用': '7. 退款和可疑扣款处理中信息的使用',
      '返金・不審請求（チャージバック）対応のため、当方は、取引記録、請求・決済履歴、サブスクリプション変更履歴、監査ログ、認証・アクセスログ等を確認し、必要に応じて決済事業者または関係機関へ提出する場合があります。':
        '为处理退款和可疑扣款（拒付），我方可能确认交易记录、账单和支付历史、订阅变更历史、审计日志、认证和访问日志等，并在必要时提交给支付服务商或相关机构。',
      '8. ポリシーの改定': '8. 政策修订',
      '本ポリシーは、法令改正や運用上の必要に応じて改定することがあります。重要な変更がある場合は、当ウェブサイト上で公表します。':
        '本政策可能根据法律修订或运营需要进行修订。如有重要变更，将在本网站上公布。',
      '9. お問い合わせ窓口': '9. 咨询窗口',
      '本ポリシーに関するお問い合わせは、上記「特定商取引法に基づく表記」のお問い合わせ先をご参照ください。':
        '关于本政策的咨询，请参照上方“基于特定商业交易法的标示”中的联系方式。',
      '以上': '以上',
      menu: '菜单',
      お部屋: '房间',
      管理: '管理',
      作成: '创建',
      脱退: '退出',
      フォルダ: '文件夹',
      パスワード: '密码',
      出力: '导出',
      アカウント: '账户',
      テーマ: '主题',
      開発者: '开发者',
      名前変更: '修改名称',
      削除: '删除',
      ログアウト: '退出登录',
      '使い方・料金': '使用方法和价格',
      ログイン: '登录',
      新規登録: '注册',
      使い方を見る: '查看使用方法',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー': '法律声明、使用条款和隐私政策',
      '管理者はお部屋を作成、メンバーは招待URLから参加します。': '管理员创建房间，成员通过邀请 URL 加入。',
      新規作成: '新建',
      お部屋名: '房间名称',
      お部屋を作る: '创建房间',
      入室可能なお部屋: '可进入的房间',
      一覧更新: '刷新列表',
      '読み込み中...': '正在加载...',
      '※ 「この部屋へ」で入室中のお部屋を切り替えられます。': '使用“进入此房间”切换当前房间。',
      '利用者:': '用户：',
      'お部屋:': '房间：',
      現在のお部屋: '当前房间',
      お部屋を選択してください: '请选择房间',
      現在のフォルダ: '当前文件夹',
      フォルダを選択してください: '请选择文件夹',
      ストレージ使用量: '存储使用量',
      '使用量 0MB': '已用 0 MB',
      '残り 0MB': '剩余 0 MB',
      '追加残り 0.00 GB・月 相当': '额外剩余 0.00 GB·月',
      'お部屋管理（管理者）': '房间管理（管理员）',
      '招待URLを発行（7日）': '生成邀请 URL（7 天）',
      招待URLを失効: '使邀请 URL 失效',
      招待URL: '邀请 URL',
      コピー: '复制',
      'お部屋を削除（全データ）': '删除房间（全部数据）',
      '※ 削除は、アップロード画像に加え、サムネイル等の自動生成データも含みます。': '删除会包含上传图片以及缩略图等自动生成数据。',
      容量: '容量',
      フリープランに戻る: '返回免费计划',
      '1GBプラン (¥980/月)': '1 GB 计划（¥980/月）',
      '5GBプラン (¥1,980/月)': '5 GB 计划（¥1,980/月）',
      '10GBプラン (¥2,980/月)': '10 GB 计划（¥2,980/月）',
      '※ 本サービスの容量表示は2進単位です（1GB=1,024MB、5GB=5,120MB、10GB=10,240MB）。':
        '本服务使用二进制单位显示容量（1 GB=1,024 MB、5 GB=5,120 MB、10 GB=10,240 MB）。',
      部屋に戻る: '返回房间',
      '1つ目の写真名を連番で反映': '将第一张照片名作为序号应用',
      '1つ目のコメントを全件に反映': '将第一条评论应用到全部',
      キャンセル: '取消',
      アップロード: '上传',
      'アップロード中...': '上传中...',
      お部屋作成: '创建房间',
      閉じる: '关闭',
      '※ 1人1部屋です。作成済みの場合は作成できません。': '每位用户只能创建一个房间。已创建时无法再次创建。',
      作成して入室: '创建并进入',
      フォルダ作成: '创建文件夹',
      '〇〇工場_yyyymmdd': '工厂_yyyymmdd',
      'フォルダパスワード（任意）': '文件夹密码（可选）',
      季節: '季节',
      春: '春',
      夏: '夏',
      秋: '秋',
      冬: '冬',
      ダークモード: '深色模式',
      フォルダパスワード: '文件夹密码',
      対象フォルダ: '目标文件夹',
      '現在のフォルダに設定します。空で保存すると解除されます。': '应用到当前文件夹。留空保存会解除。',
      'フォルダパスワード（空で解除）': '文件夹密码（留空解除）',
      '鍵を設定/解除': '设置/解除锁定',
      使い方: '使用方法',
      '新規登録後、ログイン（初回は表示名を設定）': '注册后登录。首次登录时设置显示名称。',
      'ログイン後、お部屋を作成': '登录后创建房间。',
      'フォルダ作成 → 写真アップロード → コメント追加 → 出力': '创建文件夹 → 上传照片 → 添加评论 → 导出',
      'マニュアル：': '手册：',
      こちら: '打开',
      'Photo Hub for 監査 使い方マニュアル': '审计 Photo Hub 使用手册',
      '使い方マニュアル': '使用手册',
      '作成日：': '创建日期：',
      '2026年4月19日': '2026年4月19日',
      '改訂日：': '修订日期：',
      '2026年4月30日': '2026年4月30日',
      'はじめに': '简介',
      '多くの企業の現場では監査や検品業務において、多くの手間と時間がかかっています。本アプリはこれらを効率化します。':
        '许多企业现场在审计和检查业务中需要花费大量时间和精力。本应用可提升这些工作的效率。',
      'ユーザー登録が必要': '需要用户注册',
      '管理者・お部屋メンバー・フォルダメンバーに分類': '分为管理员、房间成员、文件夹成员',
      '3階層構造（お部屋・フォルダ・写真）': '三层结构（房间、文件夹、照片）',
      'PowerPoint出力可能': '支持 PowerPoint 导出',
      '権限管理あり': '支持权限管理',
      'フリー／有料プラン': '免费/付费计划',
      '1. ユーザー登録': '1. 用户注册',
      '1-1 新規登録': '1-1 新用户注册',
      '新規ユーザーは登録を行います。': '新用户需要进行注册。',
      '1-2 ログイン': '1-2 登录',
      '認証後利用可能。': '认证后即可使用。',
      '1-3 初回設定': '1-3 初始设置',
      '表示名を設定。': '设置显示名称。',
      '2. ユーザー分類': '2. 用户分类',
      'ユーザーは管理者とメンバーに分類されます。': '用户分为管理员和成员。',
      '3. お部屋': '3. 房间',
      '1ユーザー1部屋': '每位用户 1 个房间',
      'URLで参加': '通过 URL 加入',
      '7日間有効': '有效期 7 天',
      '4. フォルダ': '4. 文件夹',
      'フリー：2つ': '免费：2 个',
      '有料：無制限': '付费：无限制',
      '5. 写真': '5. 照片',
      'カメラ / ライブラリ / ファイル': '相机 / 相册 / 文件',
      '単体 / 一括': '单个 / 批量',
      '6. コメント': '6. 评论',
      '全員閲覧可能': '所有人可查看',
      '管理者は全編集可能': '管理员可编辑全部内容',
      '7. 出力': '7. 导出',
      'PowerPoint出力': 'PowerPoint 导出',
      'フリー：透かしあり': '免费：带水印',
      '有料：透かしなし': '付费：无水印',
      '8. 権限管理': '8. 权限管理',
      '全閲覧 / 自分のみ': '所有人可查看 / 仅自己',
      '9. 料金プラン': '9. 价格计划',
      'フリー：512MB / 30日': '免费：512MB / 30天',
      '1GB：¥980': '1GB：¥980',
      '5GB：¥1,980': '5GB：¥1,980',
      '10GB：¥2,980': '10GB：¥2,980',
      '権限表': '权限表',
      '機能': '功能',
      '可': '可',
      '不可': '不可',
      料金: '价格',
      'ご利用料金は、当サービスにお預けいただくデータ量に応じて異なります。': '费用会根据存储在本服务中的数据量而变化。',
      '無料枠を超えて利用を続ける場合、管理者がサブスクプランを選択します。': '如果超过免费额度继续使用，管理员需要选择订阅计划。',
      'サブスクプラン（1か月）:': '订阅计划（月）：',
      '※ 料金操作は管理者メニュー（お部屋管理）から実行します。': '计费操作可在管理员菜单中执行。',
      開発者ダッシュボード: '开发者仪表板',
      容量不足のご案内: '容量不足提示',
      '容量を追加しますか？': '是否增加容量？',
      サブスクプランへ変更: '更改为订阅计划',
      出力形式の選択: '选择导出格式',
      出力形式を選択: '选择导出格式',
      'PDF を最優先でおすすめします。': '优先推荐 PDF。',
      最も安定して閲覧できます: '最稳定的查看方式',
      軽量PPT: '轻量 PPT',
      'できるだけ軽量化したPPTです。携帯では見れない場合があります': '尽量减小体积的 PPT。某些手机可能无法查看。',
      高画質PPT: '高画质 PPT',
      '高品質なPPTです。携帯では見れない場合があります': '高质量 PPT。某些手机可能无法查看。',
      PDFダウンロード中: '正在下载 PDF',
      出力中: '正在导出',
      'ダウンロードを開始しています...': '正在开始下载...',
      ダウンロードする: '下载',
      別タブで開く: '在新标签页打开',
      リンクをコピー: '复制链接',
      写真全体表示: '查看整张照片',
      写真プレビュー: '照片预览',
      生成完了: '生成完成',
      'リンクをコピーしました。': '链接已复制。',
      '写真名': '照片名称',
      '初回コメント（任意）': '初始评论（可选）',
      コメント: '评论',
      'まだフォルダがなかです': '还没有文件夹',
      'Cognito設定が不足しています。config.jsを確認してください。': 'Cognito 设置不足。请检查 config.js。',
      'Cognito設定が不足しています。config.jsにdomain/clientId/regionを設定してください。':
        'Cognito 设置不足。请在 config.js 中设置 domain/clientId/region。',
      'Cognitoトークン取得失敗: {message}': '获取 Cognito 令牌失败：{message}',
      'Cognitoトークンが取得できませんでした。': '无法获取 Cognito 令牌。',
      'PDFをダウンロード中... {percent}%': '正在下载 PDF... {percent}%',
      'PDFをダウンロード中... {kb}KB': '正在下载 PDF... {kb} KB',
      'PDFのダウンロードを開始しています...': '正在开始下载 PDF...',
      'PDFダウンロード失敗({status})': 'PDF 下载失败（{status}）',
      '{formatLabel} の生成が完了しました。操作を選んでください。': '{formatLabel} 已生成。请选择操作。',
      '{formatLabel} のリンクをコピーしました。': '已复制 {formatLabel} 链接。',
      '{formatLabel} を生成しています...': '正在生成 {formatLabel}...',
      '{formatLabel}で出力します。よろしいですか？': '要导出为 {formatLabel} 吗？',
      '{label}失敗: {message}': '{label} 失败：{message}',
      '{label}（現在のプラン）': '{label}（当前计划）',
      '{name} を全体表示': '查看完整图片：{name}',
      '{product}プラン': '{product} 计划',
      '{count}件': '{count} 项',
      '{count}件の写真をアップロード対象に追加しています。': '已将 {count} 张照片加入上传对象。',
      '{uploaded}/{total}件アップロード完了。': '已上传 {uploaded}/{total} 张。',
      '{uploaded}/{total}件アップロード完了。{duplicate}件は重複のためスキップしました。':
        '已上传 {uploaded}/{total} 张。因重复跳过 {duplicate} 张。',
      '{duplicate}件は重複のためスキップしました。': '因重复跳过 {duplicate} 张。',
      '{row}行目: 写真名は必須です。': '第 {row} 行：照片名称为必填。',
      '{row}行目: 写真名は20文字以内にしてください。': '第 {row} 行：照片名称请控制在 20 个字符以内。',
      '{row}行目: 初回コメントは50文字以内にしてください。': '第 {row} 行：初始评论请控制在 50 个字符以内。',
      '先にフォルダを選択してください。': '请先选择文件夹。',
      未選択: '未选择',
      '{roomName}（停止中）': '{roomName}（已停用）',
      'フォルダ {count} / 無制限': '文件夹 {count} / 无限制',
      'フォルダ {count} / {limit}': '文件夹 {count} / {limit}',
      '1GB〜10GBプラン: フォルダ無制限 / 3年保存 / PPT透かしなし':
        '1GB-10GB 计划：文件夹无限制 / 保存 3 年 / PPT 无水印',
      'フリープラン: フォルダ2個 / 30日保存 / PPT透かしあり':
        '免费计划：2 个文件夹 / 保存 30 天 / PPT 有水印',
      'フリープランへの切り替えは、以下を満たす必要があります。': '切换到免费计划需要满足以下条件。',
      '・容量が512MB未満': '- 容量小于 512 MB',
      '・フォルダの数が2つ以下': '- 文件夹数量不超过 2 个',
      '・現在の容量: {size}': '- 当前容量：{size}',
      '・現在のフォルダ数: {count}': '- 当前文件夹数：{count}',
      '{count}件の写真は{days}日保存後にアーカイブされ、現在は非表示です。アーカイブ済みデータも容量に含まれます。有料プランにすると再表示されます。':
        '{count} 张照片在保存 {days} 天后已归档，当前不显示。归档数据也会计入容量。升级到付费计划后会重新显示。',
      '使用量 {size}': '已用 {size}',
      '残り {size}': '剩余 {size}',
      'プラン:{plan}': '计划：{plan}',
      参加者: '参与者',
      'アップロード停止中（残量不足）': '上传已暂停（容量不足）',
      無料枠で利用中: '正在使用免费额度',
      'フリープランに戻る（現在のプラン）': '返回免费计划（当前计划）',
      '容量を追加しますか？（現在の残り: {remain} / 現在プラン: {plan}）':
        '是否增加容量？（当前剩余：{remain} / 当前计划：{plan}）',
      '表示名を入力してください。メニューからいつでも変更可能です。': '请输入显示名称。之后可从菜单随时修改。',
      '表示名は必須です。': '显示名称为必填。',
      '表示名を設定しました。': '已设置显示名称。',
      初回コメント: '初始评论',
      'この写真を除外': '排除此照片',
      '1つ目のコメントを先に入力してください。': '请先输入第一条评论。',
      '1つ目のコメントを全件に反映してよかですか？既存入力は上書きされます。':
        '要将第一条评论应用到全部吗？已有输入会被覆盖。',
      '1行目の写真名を先に入力してください。': '请先输入第一行照片名称。',
      '1つ目の写真名を連番で反映してよかですか？既存入力は上書きされます。':
        '要将第一张照片名按序号应用吗？已有输入会被覆盖。',
      '選択した写真と入力内容を破棄してよかですか？': '要丢弃所选照片和输入内容吗？',
      処理: '操作',
      無料プラン: '免费计划',
      不明: '未知',
      'プランを{label}へ更新しました。': '计划已更新为 {label}。',
      '決済反映に少し時間がかかっとるばい。しばらくしてプラン表示ば確認してね。':
        '付款反映可能需要一些时间。请稍后确认计划显示。',
      'お部屋に参加しました。': '已加入房间。',
      '招待URLの処理に失敗しました: {message}': '处理邀请 URL 失败：{message}',
      入室可能なお部屋がありません: '没有可进入的房间',
      '（参加中）': '（已加入）',
      '（停止中）': '（已停用）',
      '作成者: 自分': '创建者：自己',
      '作成者: 別ユーザ': '创建者：其他用户',
      入室中: '已在房间',
      停止中: '已停用',
      この部屋へ: '进入此房间',
      お部屋がありません: '没有房间',
      'ネットワークエラー: {message}': '网络错误：{message}',
      メンバーがおらんばい: '没有成员',
      閲覧: '查看',
      自分のフォルダのみ: '仅自己的文件夹',
      全フォルダ表示: '显示全部文件夹',
      '閲覧権限を更新しました。': '已更新查看权限。',
      'メンバーを削除しました。': '已删除成员。',
      'メンバー取得失敗: {message}': '获取成员失败：{message}',
      フォルダがなかです: '没有文件夹',
      'メンバー読み込み中...': '正在加载成员...',
      '設定/解除': '设置/解除',
      'フォルダを削除しました。': '已删除文件夹。',
      全フォルダ: '全部文件夹',
      権限: '权限',
      このフォルダから外す: '从此文件夹移除',
      'フォルダメンバーを外しました。': '已移除文件夹成员。',
      'フォルダ取得失敗: {message}': '获取文件夹失败：{message}',
      'プラン容量 {size}': '计划容量 {size}',
      '無料 {size}': '免费 {size}',
      '使用量 {used} / {capacity}（残り {remain}） / {folderSummary} / プラン {plan}':
        '已用 {used} / {capacity}（剩余 {remain}） / {folderSummary} / 计划 {plan}',
      'コピーする招待URLがなかです（先に発行してください）': '没有可复制的邀请 URL。请先生成。',
      '招待URLをコピーしました。': '已复制邀请 URL。',
      '招待URL（コピーしてください）': '邀请 URL（请复制）',
      '招待トークンが取得できませんでした。': '无法获取邀请令牌。',
      'この招待URLを失効してよかですか？': '要使此邀请 URL 失效吗？',
      '招待URLを失効しました。': '邀请 URL 已失效。',
      鍵: '锁',
      '●新着': '新',
      'このフォルダは鍵付きです。パスワードを入力してください。': '此文件夹已加锁。请输入密码。',
      'フォルダパスワードが必要です。': '需要文件夹密码。',
      'フォルダ: {folder}': '文件夹：{folder}',
      'フォルダパスワードが違います。': '文件夹密码不正确。',
      '画像アップロード通信エラー: {message}': '图片上传通信错误：{message}',
      '画像アップロード失敗({status})': '图片上传失败（{status}）',
      'リサイズ画像アップロード通信エラー: {message}': '缩放图片上传通信错误：{message}',
      'リサイズ画像アップロード失敗({status})': '缩放图片上传失败（{status}）',
      '同じ写真は同じフォルダにアップロードできません（重複を検知しました）。': '同一照片不能上传到同一文件夹（检测到重复）。',
      'すべて重複なのでアップロードができません。': '全部都是重复照片，无法上传。',
      'アップロード停止中です（残量不足）。管理者が容量チケットを追加するか、写真を削除してください。':
        '因容量不足，上传已暂停。请让管理员增加容量或删除照片。',
      '表示中の写真はなかです。30日を過ぎた写真はアーカイブされとるばい。':
        '当前没有显示的照片。超过 30 天的照片已归档。',
      '写真はまだなかです。': '还没有照片。',
      '投稿: {name}': '发布者：{name}',
      写真名修正: '编辑照片名称',
      写真削除: '删除照片',
      未読: '未读',
      開いたら読み込みます: '打开后加载',
      修正: '修改',
      投稿: '发布',
      コメント修正: '编辑评论',
      コメント削除: '删除评论',
      保存: '保存',
      取消: '取消',
      'このコメントを削除してよかですか？': '要删除此评论吗？',
      追加: '添加',
      'コメント ({count})': '评论（{count}）',
      入力を消去: '清除输入',
      'この写真を削除してよかですか？': '要删除此照片吗？',
      未読コメントがあります: '有未读评论',
      未読コメントなし: '没有未读评论',
      '新しい表示名を入力してください。': '请输入新的显示名称。',
      '表示名を更新しました。': '已更新显示名称。',
      'お部屋名を入力してください。': '请输入房间名称。',
      'お部屋：{roomName} が作成されました。': '房间“{roomName}”已创建。',
      '同じ部屋名は作成できません。別の部屋名にしてください。': '无法创建相同房间名。请使用其他名称。',
      'お部屋作成失敗: {message}': '创建房间失败：{message}',
      'フォルダ：{title} を作成しました。': '文件夹“{title}”已创建。',
      'Stripe決済URLが取得できませんでした。': '无法获取 Stripe 支付 URL。',
      'フリープランへ戻してよかですか？': '要返回免费计划吗？',
      '本当によかですか？（取り消せません）': '确定吗？此操作无法撤销。',
      'お部屋を削除しました。': '已删除房间。',
      'アカウントを削除しました。': '已删除账户。',
      'フォルダの鍵を更新しました。': '已更新文件夹锁。',
      '予期しないエラー: {message}': '意外错误：{message}',
      '実行エラー: {message}': '执行错误：{message}',
      '現在のお部屋を切り替えます。よろしいですか？': '要切换当前房间吗？',
      '初期化失敗: {message}': '初始化失败：{message}',
      '更新: {datetime}': '更新：{datetime}',
      全ユーザー: '全部用户',
      お部屋メンバー: '房间成员',
      フォルダメンバー: '文件夹成员',
      総容量: '总容量',
      有料プラン内訳: '付费计划明细',
      '有料プランのお部屋はまだありません。': '还没有付费计划房间。',
      お部屋と容量: '房间和容量',
      メンバー: '成员',
      'メンバー（合計）': '成员（合计）',
      'デモではログイン不要です。このまま画面を触ってみてください。': '演示中无需登录。可以直接操作页面。',
      'デモでは新規登録不要です。気になる動きだけそのまま試せます。': '演示中无需注册。可以直接试用想看的流程。',
      'デモではログイン不要です。': '演示中无需登录。',
      'デモでは新規登録不要です。': '演示中无需注册。',
      'デモではアカウント削除は行いません。': '演示中不会执行账户删除。',
      'デモでは {plan} に切り替えた状態を表示します。': '演示将显示已切换到 {plan} 的状态。',
      'フォルダが見つかりません。': '找不到文件夹。',
      LPに戻る: '返回落地页',
      デモ中: '演示中',
      登録不要: '无需注册',
      デモ画像: '演示图片',
      監査レポート: '审计报告',
      コメントなし: '无评论',
      日時不明: '日期时间不明',
      デモ利用者: '演示用户',
      新規写真: '新照片',
      新規フォルダ: '新文件夹',
      管理者: '管理员',
      作成者: '创建者',
      'お部屋がありません。': '没有房间。',
      '取得失敗: {message}': '获取失败：{message}',
      '{count}件 / 有料内 {paidPercent}% / 全体 {totalPercent}%':
        '{count} 个 / 付费中 {paidPercent}% / 全体 {totalPercent}%',
      '作成者は先に「このお部屋を削除（全データ）」を実行してください。':
        '创建者请先执行“删除此房间（全部数据）”。',
      '作成者は先に「お部屋を削除（全データ）」を実行してください。\n「{roomName}」へ移動しますか？':
        '创建者请先执行“删除房间（全部数据）”。\n要移动到“{roomName}”吗？',
      自分の部屋: '自己的房间',
      '「{roomName}」へ移動しました。': '已移动到“{roomName}”。',
      'チーム情報取得失敗: {message}（バックエンド/フロントのデプロイ差分やキャッシュの可能性）':
        '获取团队信息失败：{message}（可能是后端/前端部署差异或缓存）',
      'メンバー「{name}」の閲覧権限を変更してよかですか？': '要更改成员“{name}”的查看权限吗？',
      'メンバー「{name}」をお部屋から削除してよかですか？（本人は入れんごとなります）':
        '要从房间中删除成员“{name}”吗？本人将无法进入。',
      'フォルダ「{folder}」の招待URLを失効してよかですか？': '要使文件夹“{folder}”的邀请码 URL 失效吗？',
      'フォルダ「{folder}」のパスワードを設定してよかですか？': '要设置文件夹“{folder}”的密码吗？',
      'フォルダ「{folder}」のパスワードを解除してよかですか？': '要解除文件夹“{folder}”的密码吗？',
      'フォルダ「{folder}」を削除してよかですか？（写真とコメントも消えます）':
        '要删除文件夹“{folder}”吗？照片和评论也会被删除。',
      'メンバー「{name}」をこのフォルダから外してよかですか？': '要将成员“{name}”从此文件夹移除吗？',
      'ブラウザがコピー操作を許可しませんでした。URL欄からコピーしてください。':
        '浏览器不允许复制操作。请从 URL 栏复制。',
      'フォルダ取得失敗: ネットワーク/CORSエラーの可能性があります': '获取文件夹失败：可能是网络/CORS 错误',
      保存: '保存',
      取消: '取消',
      '管理者は脱退できません。お部屋管理から「お部屋を削除（全データ）」を実行してください。':
        '管理员不能退出。请从房间管理执行“删除房间（全部数据）”。',
      'メンバーをやめると、このお部屋には招待URLなしでは再参加できません。':
        '退出成员后，没有邀请 URL 将无法重新加入此房间。',
      '本当にメンバーをやめますか？': '确定要退出成员吗？',
      'すでに自分のお部屋を作成済みです（自分の部屋は1人1部屋）。':
        '你已经创建了自己的房间（每人只能创建一个自己的房间）。',
      'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
        '免费计划最多 2 个文件夹。付费计划可无限制。',
      'このお部屋を削除すると、フォルダ/写真/コメント/課金情報が全て削除され、Stripeの定期課金も即時停止されます。よかですか？':
        '删除此房间会删除所有文件夹/照片/评论/计费信息，并立即停止 Stripe 定期付款。继续吗？',
      'アカウントを削除すると、このユーザーでは今後ログインできません。よかですか？':
        '删除账户后，此用户今后将无法登录。继续吗？',
      '本当によかですか？（アカウント削除後は取り消せません）': '确定吗？删除账户后无法撤销。',
      '作成者は先に「お部屋を削除（全データ）」を実行してください。':
        '创建者请先执行“删除房间（全部数据）”。',
      'このフォルダを削除すると、写真とコメントも消えます。よかですか？':
        '删除此文件夹后，照片和评论也会被删除。继续吗？',
      '※ 30日保存後はアーカイブへ移動し、アーカイブは容量に含まれます。\n※ フリープランへ戻す際の容量判定にはアーカイブ済みデータも含みます。':
        '保存 30 天后会移至归档，归档数据也会计入容量。\n切换回免费计划时，容量判定也包含已归档数据。',
      'フリープランに戻りました。\n\n現在の上限は、容量512MB未満・フォルダ2個までです。':
        '已返回免费计划。\n\n当前限制为容量小于 512 MB、文件夹最多 2 个。',
      '{folder}（作成:{creator} / 容量:{size}）': '{folder}（创建者：{creator} / 容量：{size}）',
      フォルダ招待: '文件夹邀请',
      'フォルダ招待URL': '文件夹邀请 URL',
      '招待URL発行（7日）': '生成邀请 URL（7 天）',
      招待URL失効: '使邀请 URL 失效',
      '失効する招待URLがなかです（先に発行してください）': '没有要失效的邀请 URL。请先生成。',
      'フォルダ招待URLを失効しました。': '文件夹邀请 URL 已失效。',
      'フォルダのパスワードを設定しました。': '已设置文件夹密码。',
      'フォルダのパスワードを解除しました。': '已解除文件夹密码。',
    },
    vi: {
      'Photo Hub for 監査': 'Photo Hub cho kiểm toán',
      'Photo Hub for 監査 | デモ': 'Photo Hub cho kiểm toán | Demo',
      'Photo Hub for 監査 | プロダクトランディングページ': 'Photo Hub cho kiểm toán | Trang sản phẩm',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー | Photo Hub for 監査':
        'Thông báo pháp lý, Điều khoản sử dụng và Chính sách quyền riêng tư | Photo Hub cho kiểm toán',
      監査写真コメントアプリ: 'Ứng dụng ghi chú ảnh kiểm toán',
      '監査のあと、<br />会社に戻って報告書を作っていませんか？':
        'Sau kiểm toán,<br />bạn vẫn quay lại công ty để làm báo cáo?',
      '現場で終わるはずの仕事を、<br />その場で完結させる。':
        'Hoàn tất ngay tại hiện trường<br />những việc đáng lẽ phải xong tại đó.',
      無料で試す: 'Dùng thử miễn phí',
      少し触ってみる: 'Thử demo',
      '説明より先に、「今のやり方がしんどい」と感じた方のためのページです。':
        'Trang này dành cho người đã thấy cách làm hiện tại quá vất vả.',
      現場起点: 'Bắt đầu từ hiện trường',
      '写真もコメントも、その場で記録': 'Ghi ảnh và bình luận ngay tại chỗ',
      報告まで一気通貫: 'Liền mạch đến báo cáo',
      あとでPCに戻って整理し直さない: 'Không cần quay lại PC để sắp xếp lại',
      導入が軽い: 'Dễ triển khai',
      '高機能すぎず、現場で使われる作り': 'Vừa đủ chức năng để được dùng tại hiện trường',
      'こんな運用、続いていませんか？': 'Quy trình như thế này vẫn đang tiếp diễn?',
      現場ではこう動いている: 'Cách công việc đang diễn ra tại hiện trường',
      写真はスマホで撮る: 'Chụp ảnh bằng điện thoại',
      '共有はLINEやGoogle Drive': 'Chia sẻ qua LINE hoặc Google Drive',
      報告はExcelやPowerPoint: 'Báo cáo bằng Excel hoặc PowerPoint',
      その結果: 'Kết quả',
      '帰社後に1時間〜2時間の作業': 'Mất thêm 1-2 giờ sau khi quay lại công ty',
      同じ人が二度手間: 'Cùng một người phải làm lại lần nữa',
      毎回なんとなく非効率: 'Lần nào cũng thấy không hiệu quả',
      '原因は「ツールの分断」です。': 'Nguyên nhân là công cụ bị phân tách.',
      '記録と共有と報告が別々やけん、移動・再整理・二重作業が当たり前になっとる状態です。':
        'Vì ghi nhận, chia sẻ và báo cáo tách rời nhau, việc di chuyển dữ liệu, sắp xếp lại và làm trùng lặp trở thành bình thường.',
      記録: 'Ghi nhận',
      スマホ: 'Điện thoại',
      共有: 'Chia sẻ',
      クラウド: 'Đám mây',
      報告: 'Báo cáo',
      PC: 'PC',
      'この分断によって、<span class="accent">移動・再整理・二重作業</span>が発生しています。':
        'Sự phân tách này tạo ra <span class="accent">di chuyển, sắp xếp lại và làm trùng lặp</span>.',
      'すべて一体化したツールを使えばいい？': 'Chỉ cần dùng một công cụ tất cả trong một?',
      'でも現実は、そこがいちばん難しかところです。': 'Nhưng thực tế, đó là phần khó nhất.',
      高い: 'Chi phí cao',
      '1人数千円かかると、現場全員に広げにくい。':
        'Nếu tốn vài nghìn yên mỗi người, rất khó triển khai cho toàn bộ đội hiện trường.',
      設定が難しい: 'Khó thiết lập',
      '最初の設計や運用ルールづくりで止まりやすい。':
        'Dễ bị chững lại ở bước thiết kế ban đầu và tạo quy tắc vận hành.',
      使われない: 'Không được dùng',
      '覚えることが多いと、結局いつものExcelに戻る。':
        'Nếu có quá nhiều thứ phải nhớ, cuối cùng đội lại quay về Excel quen thuộc.',
      '本サービスは、この「分断」と「導入負荷」の間を埋めます。':
        'Dịch vụ này lấp khoảng trống giữa công cụ phân tách và gánh nặng triển khai.',
      '写真・コメント・報告書を<br /><strong>一つの流れで完結。</strong>':
        'Ảnh, bình luận và báo cáo<br /><strong>hoàn tất trong một luồng.</strong>',
      '現場で撮って、<br />そのまま報告まで。': 'Chụp tại hiện trường,<br />rồi đi thẳng đến báo cáo.',
      撮る: 'Chụp',
      現場で写真を残す: 'Lưu ảnh tại hiện trường',
      書く: 'Viết',
      その場でコメントを添える: 'Thêm bình luận ngay tại chỗ',
      出す: 'Xuất',
      報告の形までつなげる: 'Chuyển thành dạng báo cáo',
      'だから現場で使われる。': 'Vì vậy hiện trường sẽ dùng được.',
      '監査業務に特化しとるけん、必要以上に重たくなっていません。':
        'Vì tập trung vào công việc kiểm toán, công cụ không trở nên nặng hơn mức cần thiết.',
      機能を絞っている: 'Chức năng được tinh gọn',
      'やることが見えやすく、迷わず使える。': 'Việc cần làm rõ ràng nên có thể dùng mà không bối rối.',
      スマホで直感操作: 'Thao tác trực quan trên điện thoại',
      '現場の流れを止めずに記録できる。': 'Có thể ghi nhận mà không làm gián đoạn luồng công việc tại hiện trường.',
      設定不要: 'Không cần thiết lập',
      '導入時の説明や初期調整に時間を取られにくい。':
        'Ít mất thời gian cho giải thích khi triển khai và điều chỉnh ban đầu.',
      '「帰ってからやる」が、「現場で終わる」に変わります。':
        'Từ "làm sau khi quay về" thành "kết thúc tại hiện trường".',
      '現場 → 帰社 → PC作業 → 報告': 'Hiện trường -> công ty -> làm trên PC -> báo cáo',
      '仕事が終わったあとに、もう一度まとめ直す流れ。':
        'Luồng phải tổng hợp lại một lần nữa sau khi công việc đã xong.',
      現場で完結: 'Hoàn tất tại hiện trường',
      '撮る・書く・報告するが、一つの作業としてつながる流れ。':
        'Chụp, viết và báo cáo được nối thành một công việc.',
      '料金プラン（税込・月額）': 'Gói giá (đã gồm thuế, hàng tháng)',
      'まずは無料で試して、運用に合えばそのまま広げられます。':
        'Bắt đầu miễn phí, rồi mở rộng nếu phù hợp với vận hành.',
      '1GBプラン': 'Gói 1GB',
      '5GBプラン': 'Gói 5GB',
      '10GBプラン': 'Gói 10GB',
      ' / 月': ' / tháng',
      'まず試したい方向け。無料枠（512MB）でお試し利用できます。':
        'Dành cho người muốn thử trước. Có thể dùng thử với hạn mức miễn phí 512MB.',
      '小規模チーム向け。まず運用を始めるための基本プラン。':
        'Gói cơ bản cho đội nhỏ bắt đầu vận hành.',
      '運用が安定して写真点数が増えてきたチーム向け。':
        'Dành cho đội đã vận hành ổn định và số lượng ảnh tăng lên.',
      '複数案件・複数拠点で継続運用するチーム向け。':
        'Dành cho đội vận hành liên tục trên nhiều dự án hoặc nhiều địa điểm.',
      '料金プラン比較表': 'Bảng so sánh gói giá',
      項目: 'Mục',
      フリープラン: 'Gói miễn phí',
      '1GB〜10GBプラン': 'Gói 1GB-10GB',
      フォルダ数: 'Số thư mục',
      '2個まで': 'Tối đa 2',
      無制限: 'Không giới hạn',
      保存期間: 'Thời gian lưu',
      '30日保存<sup>※2</sup>': 'Lưu 30 ngày<sup>※2</sup>',
      '3年保存': 'Lưu 3 năm',
      PPT出力: 'Xuất PPT',
      透かしあり: 'Có watermark',
      透かしなし: 'Không watermark',
      '※1 容量にアーカイブが含まれます。<br />※2 保存期間後はアーカイブ(非表示)となります。':
        '※1 Dung lượng bao gồm dữ liệu lưu trữ.<br />※2 Sau thời gian lưu, dữ liệu sẽ được lưu trữ và ẩn.',
      申込方法: 'Cách đăng ký',
      '本ウェブサイトを通じてお申し込みいただきます。': 'Vui lòng đăng ký qua website này.',
      '無料枠を超えて利用を続ける場合、管理者がサブスクプラン（1GB/5GB/10GB）を選択します。':
        'Nếu tiếp tục sử dụng vượt hạn mức miễn phí, quản trị viên chọn gói đăng ký (1GB/5GB/10GB).',
      'クレジットカード（Stripeによる決済代行）で決済します。':
        'Thanh toán bằng thẻ tín dụng thông qua Stripe.',
      '初回は有料プラン申込時に決済、以後は有効期間中に毎月自動決済されます。':
        'Thanh toán lần đầu khi đăng ký gói trả phí, sau đó tự động thanh toán hàng tháng trong thời hạn hiệu lực.',
      申込ページへ進む: 'Đi tới trang đăng ký',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシーを見る':
        'Xem thông báo pháp lý, Điều khoản sử dụng và Chính sách quyền riêng tư',
      '帰ってから整理する監査を、ここで終わらせる。':
        'Kết thúc kiểu kiểm toán phải sắp xếp lại sau khi quay về.',
      'まず触ってみるか、先に運用イメージだけ確認するか。どちらからでも始められます。':
        'Bạn có thể thử trước hoặc xem hình dung vận hành trước. Cách nào cũng bắt đầu được.',
      '販売事業者:': 'Đơn vị bán hàng:',
      '商品名:': 'Tên sản phẩm:',
      '販売方法:': 'Phương thức bán hàng:',
      '本ウェブサイトを通じたご案内・お申し込み': 'Giới thiệu và đăng ký qua website này',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー':
        'Thông báo pháp lý, Điều khoản sử dụng và Chính sách quyền riêng tư',
      商品画面に戻る: 'Quay lại trang sản phẩm',
      特定商取引法に基づく表記: 'Thông báo theo Luật Giao dịch thương mại đặc định của Nhật Bản',
      '最終更新日: 2026年2月20日': 'Cập nhật lần cuối: 20/02/2026',
      法人名: 'Tên doanh nghiệp',
      住所: 'Địa chỉ',
      '請求があった場合は遅滞なく開示します。': 'Sẽ công bố không chậm trễ khi có yêu cầu.',
      電話番号: 'Số điện thoại',
      '受付時間: 土日 10:00-18:00 / まずはメールでお問い合わせください。':
        'Giờ tiếp nhận: Thứ bảy, Chủ nhật 10:00-18:00 / Vui lòng liên hệ qua email trước.',
      メールアドレス: 'Địa chỉ email',
      運営責任者: 'Người phụ trách vận hành',
      '事業内容・販売方法': 'Nội dung kinh doanh và phương thức bán hàng',
      '事業内容: 業務効率化に関する助言・支援サービス':
        'Nội dung kinh doanh: tư vấn và hỗ trợ nâng cao hiệu quả công việc',
      '販売方法: 本ウェブサイトを通じたご案内・お申し込み':
        'Phương thức bán hàng: giới thiệu và đăng ký qua website này',
      追加手数料: 'Phí bổ sung',
      '本サービスの利用にかかる通信費などについては、お客様のご負担となります。':
        'Khách hàng chịu các chi phí kết nối và chi phí tương tự khi sử dụng dịch vụ.',
      交換および返品に関するポリシー: 'Chính sách đổi trả',
      '＜お客様からの返品・交換＞ デジタルサービスの性質上、提供開始後の返品・返金はお受けできません。':
        '<Khách hàng đổi trả> Do tính chất của dịch vụ số, chúng tôi không chấp nhận đổi trả hoặc hoàn tiền sau khi bắt đầu cung cấp dịch vụ.',
      '＜不良品・サービスの返品・交換＞ 当方起因の不具合、重複請求、サービス提供不能が確認できた場合は、内容確認後に返金または是正対応を行います。':
        '<Đổi trả dịch vụ lỗi> Nếu xác nhận lỗi do chúng tôi, tính phí trùng lặp hoặc không thể cung cấp dịch vụ, chúng tôi sẽ kiểm tra nội dung rồi hoàn tiền hoặc khắc phục.',
      '有料プランの解約は管理画面からいつでも手続きできます。':
        'Có thể hủy gói trả phí bất cứ lúc nào từ màn hình quản lý.',
      '解約手続き後は有料プランの提供を停止し、以後の定期請求は行いません。':
        'Sau khi hủy, gói trả phí sẽ dừng cung cấp và không phát sinh thanh toán định kỳ sau đó.',
      '不審請求（チャージバック）対応方針': 'Chính sách xử lý khoản thu đáng ngờ (chargeback)',
      '不審請求が発生した場合は、サービスの発注・提供記録・メール履歴に加え、本人確認記録およびアクセスログ等の証跡を提出し、適切に対応します。':
        'Khi phát sinh khoản thu đáng ngờ, chúng tôi sẽ phản hồi phù hợp bằng cách nộp bằng chứng như hồ sơ đặt và cung cấp dịch vụ, lịch sử email, hồ sơ xác minh danh tính và log truy cập.',
      サービス提供時期: 'Thời điểm cung cấp dịch vụ',
      '決済完了後、通常は即時に反映します。システム都合で遅延する場合があります。':
        'Sau khi thanh toán hoàn tất, thông thường sẽ phản ánh ngay. Có thể chậm trễ do hệ thống.',
      利用可能な決済手段: 'Phương thức thanh toán có thể sử dụng',
      'クレジットカードのみ（Stripeによる決済代行）': 'Chỉ thẻ tín dụng (Stripe xử lý thanh toán)',
      決済期間: 'Kỳ thanh toán',
      '初回の有料プラン申込時に決済が直ちに行われます。':
        'Thanh toán được thực hiện ngay khi đăng ký gói trả phí lần đầu.',
      'その後は有料プランが継続される期間中、Stripeの定期課金により毎月自動で決済されます。':
        'Sau đó, trong thời gian gói trả phí tiếp tục, Stripe sẽ tự động thanh toán hàng tháng.',
      価格: 'Giá',
      '表示価格はすべて税込です。': 'Tất cả giá hiển thị đã bao gồm thuế.',
      '無料枠（512MB）を超えて利用を続ける場合、管理者がサブスクプランを選択します。':
        'Nếu tiếp tục sử dụng vượt hạn mức miễn phí (512MB), quản trị viên chọn gói đăng ký.',
      動作環境: 'Môi trường hoạt động',
      '本サービスは、インターネット接続環境下でブラウザから利用するクラウドサービスです。ご利用にあたっては、以下の環境を推奨します。':
        'Dịch vụ này là dịch vụ đám mây sử dụng qua trình duyệt trong môi trường có kết nối internet. Chúng tôi khuyến nghị môi trường sau.',
      '<strong>対応OS（最新版推奨）</strong><br>Windows / macOS / iOS / Android':
        '<strong>OS hỗ trợ (khuyến nghị bản mới nhất)</strong><br>Windows / macOS / iOS / Android',
      '<strong>対応ブラウザ（各最新版）</strong><br>Google Chrome / Microsoft Edge / Safari':
        '<strong>Trình duyệt hỗ trợ (bản mới nhất)</strong><br>Google Chrome / Microsoft Edge / Safari',
      '<strong>インターネット接続</strong><br>常時接続の通信環境が必要です。回線状況により、表示速度やアップロード速度に影響が出る場合があります。':
        '<strong>Kết nối internet</strong><br>Cần môi trường kết nối liên tục. Tốc độ hiển thị và tải lên có thể bị ảnh hưởng bởi tình trạng đường truyền.',
      '<strong>JavaScript・Cookie</strong><br>本サービスでは JavaScript および Cookie を使用します。ブラウザ設定で無効化されている場合、一部機能が正常に動作しないことがあります。':
        '<strong>JavaScript và Cookie</strong><br>Dịch vụ này sử dụng JavaScript và Cookie. Nếu bị vô hiệu hóa trong trình duyệt, một số chức năng có thể không hoạt động bình thường.',
      '<strong>その他</strong><br>画像アップロード・閲覧に必要な端末ストレージ空き容量を確保してください。推奨環境外では、表示崩れや一部機能が利用できない場合があります。':
        '<strong>Khác</strong><br>Vui lòng đảm bảo dung lượng trống trên thiết bị để tải lên và xem hình ảnh. Ngoài môi trường khuyến nghị, bố cục có thể bị lỗi hoặc một số chức năng không dùng được.',
      '利用規約': 'Điều khoản sử dụng',
      '制定日: 2025年2月24日 / 最終改定日: 2026年2月17日': 'Ngày ban hành: 24/02/2025 / Sửa đổi lần cuối: 17/02/2026',
      '本利用規約（以下「本規約」）は、あおき業務企画（以下「当方」）が提供する各種サービス（以下「本サービス」）の利用条件を定めるものです。利用者は、本規約に同意のうえ本サービスを利用するものとします。':
        'Điều khoản sử dụng này quy định điều kiện sử dụng các dịch vụ do あおき業務企画 cung cấp. Người dùng sử dụng dịch vụ sau khi đồng ý với các điều khoản này.',
      '1. 適用範囲': '1. Phạm vi áp dụng',
      '本規約は、本サービスの利用に関する当方と利用者との一切の関係に適用されます。':
        'Các điều khoản này áp dụng cho mọi quan hệ giữa chúng tôi và người dùng liên quan đến việc sử dụng dịch vụ.',
      '2. 同意': '2. Đồng ý',
      '利用者は、本サービスを利用した時点で本規約および当方のプライバシーポリシーに同意したものとみなされます。':
        'Khi sử dụng dịch vụ, người dùng được xem là đã đồng ý với các điều khoản này và Chính sách quyền riêng tư của chúng tôi.',
      '3. アカウント管理': '3. Quản lý tài khoản',
      '利用者は、自己の責任でアカウント情報を管理し、第三者への貸与・譲渡・共有を行わないものとします。':
        'Người dùng tự chịu trách nhiệm quản lý thông tin tài khoản và không cho bên thứ ba mượn, chuyển nhượng hoặc chia sẻ.',
      'アカウントの不正使用により生じた損害について、当方に故意または重過失がある場合を除き、当方は責任を負いません。':
        'Chúng tôi không chịu trách nhiệm về thiệt hại phát sinh do sử dụng trái phép tài khoản, trừ trường hợp chúng tôi cố ý hoặc có lỗi nghiêm trọng.',
      '本規約における「非アクティブ」とは、無料プランのアカウントについて、最終ログイン日から365日間ログインが確認できない状態をいいます。':
        '"Không hoạt động" trong các điều khoản này là trạng thái tài khoản gói miễn phí không ghi nhận đăng nhập trong 365 ngày kể từ ngày đăng nhập cuối cùng.',
      '前項の非アクティブ状態が継続した場合、当方は、事前の通知なく、当該アカウントおよび関連データを自動的に削除するものとします。':
        'Nếu trạng thái không hoạt động nêu trên tiếp tục, chúng tôi có thể tự động xóa tài khoản và dữ liệu liên quan mà không thông báo trước.',
      '削除の実施後、当該アカウントおよび関連データは復元できません。':
        'Sau khi xóa, tài khoản và dữ liệu liên quan không thể khôi phục.',
      'ただし、法令遵守、不正利用防止、請求・監査対応等のため保存が必要な情報（請求履歴、決済関連記録、監査ログ等）については、法令上より長い保存義務がある場合を除き、削除実施日から3年間保持し、期間経過後に削除または匿名化します。':
        'Tuy nhiên, thông tin cần lưu giữ để tuân thủ pháp luật, phòng chống sử dụng trái phép, xử lý thanh toán và kiểm toán, như lịch sử hóa đơn, hồ sơ thanh toán và log kiểm toán, sẽ được giữ trong 3 năm kể từ ngày xóa, trừ khi pháp luật yêu cầu thời hạn dài hơn, rồi sẽ bị xóa hoặc ẩn danh hóa.',
      '前項にもとづく削除が実施された場合、当方に故意または重過失がある場合を除き、当該削除により利用者に生じた損害について当方は責任を負いません。':
        'Nếu việc xóa được thực hiện theo khoản trên, chúng tôi không chịu trách nhiệm về thiệt hại phát sinh cho người dùng do việc xóa đó, trừ trường hợp chúng tôi cố ý hoặc có lỗi nghiêm trọng.',
      '4. 禁止事項': '4. Hành vi bị cấm',
      '利用者は、以下の行為をしてはなりません。': 'Người dùng không được thực hiện các hành vi sau.',
      '・法令または公序良俗に違反する行為': '- Hành vi vi phạm pháp luật hoặc trật tự công cộng và đạo đức xã hội',
      '・犯罪行為に関連する行為': '- Hành vi liên quan đến tội phạm',
      '・当方または第三者の知的財産権、名誉、プライバシーその他の権利利益を侵害する行為':
        '- Hành vi xâm phạm quyền sở hữu trí tuệ, danh dự, quyền riêng tư hoặc quyền lợi khác của chúng tôi hoặc bên thứ ba',
      '・不正アクセス、過度な負荷、脆弱性探索その他本サービスの運営を妨害する行為':
        '- Truy cập trái phép, gây tải quá mức, dò tìm lỗ hổng hoặc hành vi khác cản trở vận hành dịch vụ',
      '・本サービスを通じた無断の営業、宣伝、勧誘、スパム行為':
        '- Kinh doanh, quảng cáo, chào mời hoặc gửi spam trái phép thông qua dịch vụ',
      '・虚偽情報の登録または本人になりすます行為': '- Đăng ký thông tin sai sự thật hoặc mạo danh người khác',
      '・第三者のデータを権限なくアップロード、共有、公開する行為':
        '- Tải lên, chia sẻ hoặc công khai dữ liệu của bên thứ ba khi không có quyền',
      '・リバースエンジニアリング、解析、複製、改変、再配布その他当方が不適切と判断する行為':
        '- Đảo ngược kỹ thuật, phân tích, sao chép, sửa đổi, phân phối lại hoặc hành vi khác mà chúng tôi cho là không phù hợp',
      '5. 利用停止等': '5. Tạm dừng sử dụng',
      '当方は、利用者が本規約に違反した場合、または本サービス運営上必要と判断した場合、事前通知なく利用停止、データ削除、アカウント停止等の措置を行うことがあります。':
        'Nếu người dùng vi phạm các điều khoản này hoặc chúng tôi thấy cần thiết cho việc vận hành dịch vụ, chúng tôi có thể tạm dừng sử dụng, xóa dữ liệu, dừng tài khoản hoặc thực hiện biện pháp tương tự mà không thông báo trước.',
      '6. 知的財産権': '6. Quyền sở hữu trí tuệ',
      '本サービスに関する著作権、商標権その他の知的財産権は、当方または正当な権利者に帰属します。利用者が本サービスにアップロードしたデータの権利は利用者または正当な権利者に留保されます。':
        'Bản quyền, nhãn hiệu và các quyền sở hữu trí tuệ khác liên quan đến dịch vụ thuộc về chúng tôi hoặc chủ sở hữu hợp pháp. Quyền đối với dữ liệu người dùng tải lên dịch vụ được giữ bởi người dùng hoặc chủ sở hữu hợp pháp.',
      '7. 免責および責任制限': '7. Miễn trừ và giới hạn trách nhiệm',
      '当方は、本サービスの完全性、正確性、継続性、有用性、特定目的適合性を保証しません。通信障害、システム障害、外部サービス障害、不可抗力等により発生した損害について、当方は責任を負いません。':
        'Chúng tôi không bảo đảm tính đầy đủ, chính xác, liên tục, hữu ích hoặc phù hợp với mục đích cụ thể của dịch vụ. Chúng tôi không chịu trách nhiệm về thiệt hại phát sinh do sự cố truyền thông, sự cố hệ thống, sự cố dịch vụ bên ngoài, bất khả kháng hoặc sự kiện tương tự.',
      '当方の責任が認められる場合でも、当方に故意または重過失がある場合を除き、利用者が当方に直近3か月間に実際に支払った金額を上限として賠償責任を負うものとします。':
        'Ngay cả khi trách nhiệm của chúng tôi được công nhận, trừ trường hợp chúng tôi cố ý hoặc có lỗi nghiêm trọng, trách nhiệm bồi thường được giới hạn ở số tiền người dùng thực tế đã trả cho chúng tôi trong 3 tháng gần nhất.',
      '8. 規約の変更': '8. Thay đổi điều khoản',
      '当方は、法令改正や運用上の必要に応じて本規約を変更することがあります。重要な変更は本ウェブサイト上で公表します。':
        'Chúng tôi có thể thay đổi các điều khoản này do sửa đổi pháp luật hoặc nhu cầu vận hành. Các thay đổi quan trọng sẽ được công bố trên website này.',
      '9. 準拠法・管轄': '9. Luật áp dụng và thẩm quyền',
      '本規約は日本法に準拠し、本サービスに関して紛争が生じた場合は、当方所在地を管轄する裁判所を第一審の専属的合意管轄裁判所とします。':
        'Các điều khoản này tuân theo pháp luật Nhật Bản. Nếu phát sinh tranh chấp liên quan đến dịch vụ, tòa án có thẩm quyền tại nơi chúng tôi đặt trụ sở sẽ là tòa án có thẩm quyền độc quyền ở cấp sơ thẩm.',
      'プライバシーポリシー': 'Chính sách quyền riêng tư',
      'あおき業務企画（以下「当方」）は、当方が提供するサービスにおける利用者情報の取扱いについて、以下のとおりプライバシーポリシー（以下「本ポリシー」）を定めます。':
        'あおき業務企画 thiết lập Chính sách quyền riêng tư này về việc xử lý thông tin người dùng trong các dịch vụ do chúng tôi cung cấp.',
      '1. 取得する情報': '1. Thông tin thu thập',
      '当方は、サービス提供・運営のために、次の情報を取得することがあります。':
        'Chúng tôi có thể thu thập các thông tin sau để cung cấp và vận hành dịch vụ.',
      'アカウント情報（メールアドレス、認証に必要な識別子）':
        'Thông tin tài khoản (địa chỉ email, định danh cần thiết cho xác thực)',
      'プロフィール情報（表示名）': 'Thông tin hồ sơ (tên hiển thị)',
      'サービス利用情報（所属ルーム、操作履歴、アップロードデータ、コメント、課金状態）':
        'Thông tin sử dụng dịch vụ (phòng tham gia, lịch sử thao tác, dữ liệu tải lên, bình luận, trạng thái thanh toán)',
      '技術情報（アクセスログ、エラー情報、端末・ブラウザ情報、Cookieまたはこれに類する技術）':
        'Thông tin kỹ thuật (log truy cập, thông tin lỗi, thông tin thiết bị và trình duyệt, Cookie hoặc công nghệ tương tự)',
      '決済関連情報（Stripe上の顧客ID・サブスクリプション情報等。カード番号等は当方で保持しません）':
        'Thông tin liên quan đến thanh toán (ID khách hàng và thông tin đăng ký trên Stripe. Chúng tôi không lưu số thẻ.)',
      '2. 利用目的': '2. Mục đích sử dụng',
      '取得した情報は、次の目的で利用します。': 'Thông tin thu thập được sử dụng cho các mục đích sau.',
      'サービスの提供、本人確認、契約履行、アフターサポートのため':
        'Để cung cấp dịch vụ, xác minh danh tính, thực hiện hợp đồng và hỗ trợ sau dịch vụ',
      'お問い合わせへの回答、重要なご連絡のため': 'Để trả lời liên hệ và gửi thông báo quan trọng',
      '請求・決済・返金対応および不正利用防止のため':
        'Để xử lý hóa đơn, thanh toán, hoàn tiền và phòng chống sử dụng trái phép',
      'サービス品質の向上、機能改善、利用状況分析のため':
        'Để nâng cao chất lượng dịch vụ, cải thiện chức năng và phân tích tình hình sử dụng',
      '法令・規約等に基づく対応のため': 'Để xử lý theo pháp luật, quy định và điều khoản',
      '3. 第三者提供': '3. Cung cấp cho bên thứ ba',
      '当方は、法令で認められる場合を除き、本人の同意なく個人情報を第三者に提供しません。ただし、サービス運営に必要な範囲で、業務委託先（決済代行、インフラ、分析ツール等）へ取扱いを委託することがあります。この場合、必要かつ適切な監督を行います。':
        'Trừ khi pháp luật cho phép, chúng tôi không cung cấp thông tin cá nhân cho bên thứ ba khi chưa có sự đồng ý của cá nhân. Tuy nhiên, trong phạm vi cần thiết cho vận hành dịch vụ, chúng tôi có thể ủy thác xử lý cho nhà thầu như đơn vị thanh toán, hạ tầng, công cụ phân tích. Khi đó, chúng tôi sẽ giám sát cần thiết và phù hợp.',
      '4. 安全管理措置': '4. Biện pháp quản lý an toàn',
      '当方は、個人情報への不正アクセス、漏えい、滅失、毀損等を防止するため、合理的な安全管理措置を講じます。なお、インターネット通信の性質上、完全な安全性を保証するものではありません。':
        'Chúng tôi áp dụng các biện pháp quản lý an toàn hợp lý để ngăn truy cập trái phép, rò rỉ, mất mát, hư hỏng và các sự cố tương tự đối với thông tin cá nhân. Tuy nhiên, do tính chất của truyền thông internet, chúng tôi không bảo đảm an toàn tuyệt đối.',
      '5. Cookie等の利用': '5. Sử dụng Cookie',
      '当方ウェブサイトでは、利便性向上やアクセス解析のためCookie等を利用する場合があります。利用者はブラウザ設定によりCookieを無効化できますが、一部機能が利用できない場合があります。':
        'Website của chúng tôi có thể sử dụng Cookie và công nghệ tương tự để cải thiện tiện ích và phân tích truy cập. Người dùng có thể vô hiệu hóa Cookie trong trình duyệt, nhưng một số chức năng có thể không sử dụng được.',
      '6. 保有個人データの開示等の請求': '6. Yêu cầu công bố dữ liệu cá nhân đang giữ',
      'ご本人から、保有個人データの開示、訂正、追加、削除、利用停止等の請求があった場合は、ご本人確認のうえ、法令に従って適切に対応します。':
        'Khi cá nhân yêu cầu công bố, chỉnh sửa, bổ sung, xóa, ngừng sử dụng hoặc xử lý tương tự đối với dữ liệu cá nhân đang giữ, chúng tôi sẽ xác minh danh tính và xử lý phù hợp theo pháp luật.',
      'アカウント削除後のデータは原則復元できません。ただし、法令遵守、不正利用防止、請求・監査対応のために必要な情報は、法令上より長い保存義務がある場合を除き、削除実施日から3年間保持し、期間経過後に削除または匿名化します。':
        'Dữ liệu sau khi xóa tài khoản về nguyên tắc không thể khôi phục. Tuy nhiên, thông tin cần thiết để tuân thủ pháp luật, phòng chống sử dụng trái phép, xử lý thanh toán và kiểm toán sẽ được giữ trong 3 năm kể từ ngày xóa, trừ khi pháp luật yêu cầu thời hạn dài hơn, rồi sẽ bị xóa hoặc ẩn danh hóa.',
      '7. 返金・不審請求対応における情報利用': '7. Sử dụng thông tin khi xử lý hoàn tiền và khoản thu đáng ngờ',
      '返金・不審請求（チャージバック）対応のため、当方は、取引記録、請求・決済履歴、サブスクリプション変更履歴、監査ログ、認証・アクセスログ等を確認し、必要に応じて決済事業者または関係機関へ提出する場合があります。':
        'Để xử lý hoàn tiền và khoản thu đáng ngờ (chargeback), chúng tôi có thể kiểm tra hồ sơ giao dịch, lịch sử hóa đơn và thanh toán, lịch sử thay đổi đăng ký, log kiểm toán, log xác thực và truy cập, và có thể nộp cho đơn vị thanh toán hoặc cơ quan liên quan khi cần.',
      '8. ポリシーの改定': '8. Sửa đổi chính sách',
      '本ポリシーは、法令改正や運用上の必要に応じて改定することがあります。重要な変更がある場合は、当ウェブサイト上で公表します。':
        'Chính sách này có thể được sửa đổi do thay đổi pháp luật hoặc nhu cầu vận hành. Nếu có thay đổi quan trọng, chúng tôi sẽ công bố trên website này.',
      '9. お問い合わせ窓口': '9. Liên hệ',
      '本ポリシーに関するお問い合わせは、上記「特定商取引法に基づく表記」のお問い合わせ先をご参照ください。':
        'Đối với liên hệ về chính sách này, vui lòng tham khảo thông tin liên hệ trong phần Thông báo pháp lý ở trên.',
      '以上': 'Hết',
      menu: 'menu',
      お部屋: 'Phòng',
      管理: 'Quản lý',
      作成: 'Tạo',
      脱退: 'Rời khỏi',
      フォルダ: 'Thư mục',
      パスワード: 'Mật khẩu',
      出力: 'Xuất',
      アカウント: 'Tài khoản',
      テーマ: 'Giao diện',
      開発者: 'Nhà phát triển',
      名前変更: 'Đổi tên',
      削除: 'Xóa',
      ログアウト: 'Đăng xuất',
      '使い方・料金': 'Cách dùng và giá',
      ログイン: 'Đăng nhập',
      新規登録: 'Đăng ký',
      使い方を見る: 'Xem hướng dẫn',
      '特定商取引法に基づく表記・利用規約・プライバシーポリシー': 'Thông báo pháp lý, Điều khoản và Chính sách quyền riêng tư',
      '管理者はお部屋を作成、メンバーは招待URLから参加します。': 'Quản trị viên tạo phòng, thành viên tham gia bằng URL mời.',
      新規作成: 'Tạo mới',
      お部屋名: 'Tên phòng',
      お部屋を作る: 'Tạo phòng',
      入室可能なお部屋: 'Phòng có thể vào',
      一覧更新: 'Làm mới danh sách',
      '読み込み中...': 'Đang tải...',
      '※ 「この部屋へ」で入室中のお部屋を切り替えられます。': 'Dùng "Vào phòng này" để chuyển phòng đang sử dụng.',
      '利用者:': 'Người dùng:',
      'お部屋:': 'Phòng:',
      現在のお部屋: 'Phòng hiện tại',
      お部屋を選択してください: 'Chọn phòng',
      現在のフォルダ: 'Thư mục hiện tại',
      フォルダを選択してください: 'Chọn thư mục',
      ストレージ使用量: 'Dung lượng đã dùng',
      '使用量 0MB': 'Đã dùng 0 MB',
      '残り 0MB': 'Còn lại 0 MB',
      '追加残り 0.00 GB・月 相当': 'Phần bổ sung còn lại 0.00 GB-tháng',
      'お部屋管理（管理者）': 'Quản lý phòng (quản trị viên)',
      '招待URLを発行（7日）': 'Tạo URL mời (7 ngày)',
      招待URLを失効: 'Thu hồi URL mời',
      招待URL: 'URL mời',
      コピー: 'Sao chép',
      'お部屋を削除（全データ）': 'Xóa phòng (toàn bộ dữ liệu)',
      '※ 削除は、アップロード画像に加え、サムネイル等の自動生成データも含みます。': 'Việc xóa bao gồm ảnh đã tải lên và dữ liệu tự động tạo như ảnh thu nhỏ.',
      容量: 'Dung lượng',
      フリープランに戻る: 'Quay lại gói miễn phí',
      '1GBプラン (¥980/月)': 'Gói 1 GB (¥980/tháng)',
      '5GBプラン (¥1,980/月)': 'Gói 5 GB (¥1,980/tháng)',
      '10GBプラン (¥2,980/月)': 'Gói 10 GB (¥2,980/tháng)',
      '※ 本サービスの容量表示は2進単位です（1GB=1,024MB、5GB=5,120MB、10GB=10,240MB）。':
        'Dung lượng được hiển thị theo đơn vị nhị phân (1 GB=1.024 MB, 5 GB=5.120 MB, 10 GB=10.240 MB).',
      部屋に戻る: 'Quay lại phòng',
      '1つ目の写真名を連番で反映': 'Áp dụng tên ảnh đầu tiên theo số thứ tự',
      '1つ目のコメントを全件に反映': 'Áp dụng bình luận đầu tiên cho tất cả',
      キャンセル: 'Hủy',
      アップロード: 'Tải lên',
      'アップロード中...': 'Đang tải lên...',
      お部屋作成: 'Tạo phòng',
      閉じる: 'Đóng',
      '※ 1人1部屋です。作成済みの場合は作成できません。': 'Mỗi người chỉ được tạo một phòng. Nếu đã tạo thì không thể tạo thêm.',
      作成して入室: 'Tạo và vào phòng',
      フォルダ作成: 'Tạo thư mục',
      '〇〇工場_yyyymmdd': 'Nha_may_yyyymmdd',
      'フォルダパスワード（任意）': 'Mật khẩu thư mục (tùy chọn)',
      季節: 'Mùa',
      春: 'Xuân',
      夏: 'Hè',
      秋: 'Thu',
      冬: 'Đông',
      ダークモード: 'Chế độ tối',
      フォルダパスワード: 'Mật khẩu thư mục',
      対象フォルダ: 'Thư mục mục tiêu',
      '現在のフォルダに設定します。空で保存すると解除されます。': 'Áp dụng cho thư mục hiện tại. Để trống khi lưu để gỡ bỏ.',
      'フォルダパスワード（空で解除）': 'Mật khẩu thư mục (để trống để gỡ)',
      '鍵を設定/解除': 'Đặt/gỡ khóa',
      使い方: 'Cách dùng',
      '新規登録後、ログイン（初回は表示名を設定）': 'Đăng ký rồi đăng nhập. Lần đầu hãy đặt tên hiển thị.',
      'ログイン後、お部屋を作成': 'Sau khi đăng nhập, tạo phòng.',
      'フォルダ作成 → 写真アップロード → コメント追加 → 出力': 'Tạo thư mục -> tải ảnh lên -> thêm bình luận -> xuất',
      'マニュアル：': 'Tài liệu:',
      こちら: 'Mở',
      'Photo Hub for 監査 使い方マニュアル': 'Hướng dẫn sử dụng Photo Hub cho kiểm toán',
      '使い方マニュアル': 'Hướng dẫn sử dụng',
      '作成日：': 'Ngày tạo:',
      '2026年4月19日': '19 tháng 4, 2026',
      '改訂日：': 'Ngày sửa đổi:',
      '2026年4月30日': '30 tháng 4, 2026',
      'はじめに': 'Giới thiệu',
      '多くの企業の現場では監査や検品業務において、多くの手間と時間がかかっています。本アプリはこれらを効率化します。':
        'Nhiều hiện trường doanh nghiệp mất nhiều thời gian và công sức cho công việc kiểm toán và kiểm tra. Ứng dụng này giúp tối ưu các công việc đó.',
      'ユーザー登録が必要': 'Cần đăng ký người dùng',
      '管理者・お部屋メンバー・フォルダメンバーに分類': 'Phân loại thành quản trị viên, thành viên phòng và thành viên thư mục',
      '3階層構造（お部屋・フォルダ・写真）': 'Cấu trúc 3 tầng: phòng, thư mục và ảnh',
      'PowerPoint出力可能': 'Có thể xuất PowerPoint',
      '権限管理あり': 'Có quản lý quyền',
      'フリー／有料プラン': 'Gói miễn phí / trả phí',
      '1. ユーザー登録': '1. Đăng ký người dùng',
      '1-1 新規登録': '1-1 Đăng ký mới',
      '新規ユーザーは登録を行います。': 'Người dùng mới cần đăng ký.',
      '1-2 ログイン': '1-2 Đăng nhập',
      '認証後利用可能。': 'Có thể sử dụng sau khi xác thực.',
      '1-3 初回設定': '1-3 Thiết lập ban đầu',
      '表示名を設定。': 'Đặt tên hiển thị.',
      '2. ユーザー分類': '2. Phân loại người dùng',
      'ユーザーは管理者とメンバーに分類されます。': 'Người dùng được phân loại thành quản trị viên và thành viên.',
      '3. お部屋': '3. Phòng',
      '1ユーザー1部屋': 'Mỗi người dùng có 1 phòng',
      'URLで参加': 'Tham gia bằng URL',
      '7日間有効': 'Có hiệu lực trong 7 ngày',
      '4. フォルダ': '4. Thư mục',
      'フリー：2つ': 'Miễn phí: 2 thư mục',
      '有料：無制限': 'Trả phí: không giới hạn',
      '5. 写真': '5. Ảnh',
      'カメラ / ライブラリ / ファイル': 'Máy ảnh / thư viện / tệp',
      '単体 / 一括': 'Đơn lẻ / hàng loạt',
      '6. コメント': '6. Bình luận',
      '全員閲覧可能': 'Mọi người đều có thể xem',
      '管理者は全編集可能': 'Quản trị viên có thể chỉnh sửa tất cả',
      '7. 出力': '7. Xuất',
      'PowerPoint出力': 'Xuất PowerPoint',
      'フリー：透かしあり': 'Miễn phí: có watermark',
      '有料：透かしなし': 'Trả phí: không có watermark',
      '8. 権限管理': '8. Quản lý quyền',
      '全閲覧 / 自分のみ': 'Mọi người / chỉ mình tôi',
      '9. 料金プラン': '9. Gói giá',
      'フリー：512MB / 30日': 'Miễn phí: 512 MB / 30 ngày',
      '1GB：¥980': '1 GB: ¥980',
      '5GB：¥1,980': '5 GB: ¥1,980',
      '10GB：¥2,980': '10 GB: ¥2,980',
      '権限表': 'Bảng quyền',
      '機能': 'Chức năng',
      '可': 'Được phép',
      '不可': 'Không được phép',
      料金: 'Giá',
      'ご利用料金は、当サービスにお預けいただくデータ量に応じて異なります。': 'Phí sử dụng phụ thuộc vào lượng dữ liệu lưu trong dịch vụ.',
      '無料枠を超えて利用を続ける場合、管理者がサブスクプランを選択します。': 'Nếu tiếp tục sử dụng vượt mức miễn phí, quản trị viên chọn gói đăng ký.',
      'サブスクプラン（1か月）:': 'Gói đăng ký (hàng tháng):',
      '※ 料金操作は管理者メニュー（お部屋管理）から実行します。': 'Thao tác thanh toán nằm trong menu quản trị.',
      開発者ダッシュボード: 'Bảng điều khiển nhà phát triển',
      容量不足のご案内: 'Thông báo thiếu dung lượng',
      '容量を追加しますか？': 'Thêm dung lượng?',
      サブスクプランへ変更: 'Chuyển sang gói đăng ký',
      出力形式の選択: 'Chọn định dạng xuất',
      出力形式を選択: 'Chọn định dạng xuất',
      'PDF を最優先でおすすめします。': 'Ưu tiên khuyến nghị PDF.',
      最も安定して閲覧できます: 'Xem ổn định nhất',
      軽量PPT: 'PPT nhẹ',
      'できるだけ軽量化したPPTです。携帯では見れない場合があります': 'PPT được giảm dung lượng tối đa. Một số điện thoại có thể không xem được.',
      高画質PPT: 'PPT chất lượng cao',
      '高品質なPPTです。携帯では見れない場合があります': 'PPT chất lượng cao. Một số điện thoại có thể không xem được.',
      PDFダウンロード中: 'Đang tải PDF',
      出力中: 'Đang xuất',
      'ダウンロードを開始しています...': 'Đang bắt đầu tải xuống...',
      ダウンロードする: 'Tải xuống',
      別タブで開く: 'Mở trong tab mới',
      リンクをコピー: 'Sao chép liên kết',
      写真全体表示: 'Xem toàn bộ ảnh',
      写真プレビュー: 'Xem trước ảnh',
      生成完了: 'Đã tạo xong',
      'リンクをコピーしました。': 'Đã sao chép liên kết.',
      '写真名': 'Tên ảnh',
      '初回コメント（任意）': 'Bình luận đầu tiên (tùy chọn)',
      コメント: 'Bình luận',
      'まだフォルダがなかです': 'Chưa có thư mục',
      'Cognito設定が不足しています。config.jsを確認してください。': 'Thiếu cấu hình Cognito. Hãy kiểm tra config.js.',
      'Cognito設定が不足しています。config.jsにdomain/clientId/regionを設定してください。':
        'Thiếu cấu hình Cognito. Hãy đặt domain/clientId/region trong config.js.',
      'Cognitoトークン取得失敗: {message}': 'Không lấy được token Cognito: {message}',
      'Cognitoトークンが取得できませんでした。': 'Không lấy được token Cognito.',
      'PDFをダウンロード中... {percent}%': 'Đang tải PDF... {percent}%',
      'PDFをダウンロード中... {kb}KB': 'Đang tải PDF... {kb} KB',
      'PDFのダウンロードを開始しています...': 'Đang bắt đầu tải PDF...',
      'PDFダウンロード失敗({status})': 'Tải PDF thất bại ({status})',
      '{formatLabel} の生成が完了しました。操作を選んでください。': '{formatLabel} đã sẵn sàng. Hãy chọn thao tác.',
      '{formatLabel} のリンクをコピーしました。': 'Đã sao chép liên kết {formatLabel}.',
      '{formatLabel} を生成しています...': 'Đang tạo {formatLabel}...',
      '{formatLabel}で出力します。よろしいですか？': 'Xuất dưới dạng {formatLabel}?',
      '{label}失敗: {message}': '{label} thất bại: {message}',
      '{label}（現在のプラン）': '{label} (gói hiện tại)',
      '{name} を全体表示': 'Xem toàn bộ ảnh: {name}',
      '{product}プラン': 'Gói {product}',
      '{count}件': '{count} mục',
      '{count}件の写真をアップロード対象に追加しています。': 'Đã thêm {count} ảnh vào danh sách tải lên.',
      '{uploaded}/{total}件アップロード完了。': 'Đã tải lên {uploaded}/{total}.',
      '{uploaded}/{total}件アップロード完了。{duplicate}件は重複のためスキップしました。':
        'Đã tải lên {uploaded}/{total}. Bỏ qua {duplicate} ảnh trùng.',
      '{duplicate}件は重複のためスキップしました。': 'Đã bỏ qua {duplicate} ảnh trùng.',
      '{row}行目: 写真名は必須です。': 'Dòng {row}: bắt buộc nhập tên ảnh.',
      '{row}行目: 写真名は20文字以内にしてください。': 'Dòng {row}: tên ảnh tối đa 20 ký tự.',
      '{row}行目: 初回コメントは50文字以内にしてください。': 'Dòng {row}: bình luận đầu tiên tối đa 50 ký tự.',
      '先にフォルダを選択してください。': 'Hãy chọn thư mục trước.',
      未選択: 'Chưa chọn',
      '{roomName}（停止中）': '{roomName} (đã dừng)',
      'フォルダ {count} / 無制限': 'Thư mục {count} / không giới hạn',
      'フォルダ {count} / {limit}': 'Thư mục {count} / {limit}',
      '1GB〜10GBプラン: フォルダ無制限 / 3年保存 / PPT透かしなし':
        'Gói 1GB-10GB: thư mục không giới hạn / lưu 3 năm / không watermark PPT',
      'フリープラン: フォルダ2個 / 30日保存 / PPT透かしあり':
        'Gói miễn phí: 2 thư mục / lưu 30 ngày / có watermark PPT',
      'フリープランへの切り替えは、以下を満たす必要があります。':
        'Để chuyển về gói miễn phí, cần đáp ứng các điều kiện sau.',
      '・容量が512MB未満': '- Dung lượng dưới 512 MB',
      '・フォルダの数が2つ以下': '- Số thư mục không quá 2',
      '・現在の容量: {size}': '- Dung lượng hiện tại: {size}',
      '・現在のフォルダ数: {count}': '- Số thư mục hiện tại: {count}',
      '{count}件の写真は{days}日保存後にアーカイブされ、現在は非表示です。アーカイブ済みデータも容量に含まれます。有料プランにすると再表示されます。':
        '{count} ảnh đã được lưu trữ sau {days} ngày và hiện đang bị ẩn. Dữ liệu đã lưu trữ vẫn tính vào dung lượng. Nâng cấp gói trả phí để hiển thị lại.',
      '使用量 {size}': 'Đã dùng {size}',
      '残り {size}': 'Còn lại {size}',
      'プラン:{plan}': 'Gói: {plan}',
      参加者: 'Thành viên',
      'アップロード停止中（残量不足）': 'Đang tạm dừng tải lên (thiếu dung lượng)',
      無料枠で利用中: 'Đang dùng hạn mức miễn phí',
      'フリープランに戻る（現在のプラン）': 'Quay lại gói miễn phí (gói hiện tại)',
      '容量を追加しますか？（現在の残り: {remain} / 現在プラン: {plan}）':
        'Thêm dung lượng? (Còn lại: {remain} / Gói hiện tại: {plan})',
      '表示名を入力してください。メニューからいつでも変更可能です。':
        'Nhập tên hiển thị. Bạn có thể đổi bất cứ lúc nào trong menu.',
      '表示名は必須です。': 'Bắt buộc nhập tên hiển thị.',
      '表示名を設定しました。': 'Đã đặt tên hiển thị.',
      初回コメント: 'Bình luận đầu tiên',
      'この写真を除外': 'Loại ảnh này',
      '1つ目のコメントを先に入力してください。': 'Hãy nhập bình luận đầu tiên trước.',
      '1つ目のコメントを全件に反映してよかですか？既存入力は上書きされます。':
        'Áp dụng bình luận đầu tiên cho tất cả? Nội dung đã nhập sẽ bị ghi đè.',
      '1行目の写真名を先に入力してください。': 'Hãy nhập tên ảnh ở dòng đầu tiên trước.',
      '1つ目の写真名を連番で反映してよかですか？既存入力は上書きされます。':
        'Áp dụng tên ảnh đầu tiên theo số thứ tự? Nội dung đã nhập sẽ bị ghi đè.',
      '選択した写真と入力内容を破棄してよかですか？': 'Hủy ảnh đã chọn và nội dung đã nhập?',
      処理: 'Thao tác',
      無料プラン: 'Gói miễn phí',
      不明: 'Không rõ',
      'プランを{label}へ更新しました。': 'Đã cập nhật gói sang {label}.',
      '決済反映に少し時間がかかっとるばい。しばらくしてプラン表示ば確認してね。':
        'Thanh toán có thể mất một lúc để phản ánh. Hãy kiểm tra lại gói sau.',
      'お部屋に参加しました。': 'Đã tham gia phòng.',
      '招待URLの処理に失敗しました: {message}': 'Xử lý URL mời thất bại: {message}',
      入室可能なお部屋がありません: 'Không có phòng có thể vào',
      '（参加中）': '(đang tham gia)',
      '（停止中）': '(đã dừng)',
      '作成者: 自分': 'Người tạo: bạn',
      '作成者: 別ユーザ': 'Người tạo: người khác',
      入室中: 'Đang trong phòng',
      停止中: 'Đã dừng',
      この部屋へ: 'Vào phòng này',
      お部屋がありません: 'Không có phòng',
      'ネットワークエラー: {message}': 'Lỗi mạng: {message}',
      メンバーがおらんばい: 'Không có thành viên',
      閲覧: 'Xem',
      自分のフォルダのみ: 'Chỉ thư mục của mình',
      全フォルダ表示: 'Hiển thị mọi thư mục',
      '閲覧権限を更新しました。': 'Đã cập nhật quyền xem.',
      'メンバーを削除しました。': 'Đã xóa thành viên.',
      'メンバー取得失敗: {message}': 'Không lấy được thành viên: {message}',
      フォルダがなかです: 'Không có thư mục',
      'メンバー読み込み中...': 'Đang tải thành viên...',
      '設定/解除': 'Đặt/gỡ',
      'フォルダを削除しました。': 'Đã xóa thư mục.',
      全フォルダ: 'Mọi thư mục',
      権限: 'Quyền',
      このフォルダから外す: 'Gỡ khỏi thư mục này',
      'フォルダメンバーを外しました。': 'Đã gỡ thành viên thư mục.',
      'フォルダ取得失敗: {message}': 'Không lấy được thư mục: {message}',
      'プラン容量 {size}': 'Dung lượng gói {size}',
      '無料 {size}': 'Miễn phí {size}',
      '使用量 {used} / {capacity}（残り {remain}） / {folderSummary} / プラン {plan}':
        'Đã dùng {used} / {capacity} (còn {remain}) / {folderSummary} / Gói {plan}',
      'コピーする招待URLがなかです（先に発行してください）': 'Không có URL mời để sao chép. Hãy phát hành trước.',
      '招待URLをコピーしました。': 'Đã sao chép URL mời.',
      '招待URL（コピーしてください）': 'URL mời (hãy sao chép)',
      '招待トークンが取得できませんでした。': 'Không lấy được token mời.',
      'この招待URLを失効してよかですか？': 'Thu hồi URL mời này?',
      '招待URLを失効しました。': 'Đã thu hồi URL mời.',
      鍵: 'Khóa',
      '●新着': 'Mới',
      'このフォルダは鍵付きです。パスワードを入力してください。': 'Thư mục này bị khóa. Hãy nhập mật khẩu.',
      'フォルダパスワードが必要です。': 'Cần mật khẩu thư mục.',
      'フォルダ: {folder}': 'Thư mục: {folder}',
      'フォルダパスワードが違います。': 'Mật khẩu thư mục không đúng.',
      '画像アップロード通信エラー: {message}': 'Lỗi kết nối khi tải ảnh lên: {message}',
      '画像アップロード失敗({status})': 'Tải ảnh lên thất bại ({status})',
      'リサイズ画像アップロード通信エラー: {message}': 'Lỗi kết nối khi tải ảnh thu nhỏ: {message}',
      'リサイズ画像アップロード失敗({status})': 'Tải ảnh thu nhỏ thất bại ({status})',
      '同じ写真は同じフォルダにアップロードできません（重複を検知しました）。':
        'Không thể tải cùng một ảnh vào cùng thư mục (đã phát hiện trùng).',
      'すべて重複なのでアップロードができません。': 'Tất cả đều trùng nên không thể tải lên.',
      'アップロード停止中です（残量不足）。管理者が容量チケットを追加するか、写真を削除してください。':
        'Đang tạm dừng tải lên do thiếu dung lượng. Quản trị viên cần thêm dung lượng hoặc xóa ảnh.',
      '表示中の写真はなかです。30日を過ぎた写真はアーカイブされとるばい。':
        'Không có ảnh đang hiển thị. Ảnh quá 30 ngày đã được lưu trữ.',
      '写真はまだなかです。': 'Chưa có ảnh.',
      '投稿: {name}': 'Đăng bởi: {name}',
      写真名修正: 'Sửa tên ảnh',
      写真削除: 'Xóa ảnh',
      未読: 'Chưa đọc',
      開いたら読み込みます: 'Mở để tải',
      修正: 'Đã sửa',
      投稿: 'Đăng',
      コメント修正: 'Sửa bình luận',
      コメント削除: 'Xóa bình luận',
      保存: 'Lưu',
      取消: 'Hủy',
      'このコメントを削除してよかですか？': 'Xóa bình luận này?',
      追加: 'Thêm',
      'コメント ({count})': 'Bình luận ({count})',
      入力を消去: 'Xóa nhập liệu',
      'この写真を削除してよかですか？': 'Xóa ảnh này?',
      未読コメントがあります: 'Có bình luận chưa đọc',
      未読コメントなし: 'Không có bình luận chưa đọc',
      '新しい表示名を入力してください。': 'Nhập tên hiển thị mới.',
      '表示名を更新しました。': 'Đã cập nhật tên hiển thị.',
      'お部屋名を入力してください。': 'Nhập tên phòng.',
      'お部屋：{roomName} が作成されました。': 'Đã tạo phòng "{roomName}".',
      '同じ部屋名は作成できません。別の部屋名にしてください。': 'Không thể tạo tên phòng trùng. Hãy chọn tên khác.',
      'お部屋作成失敗: {message}': 'Tạo phòng thất bại: {message}',
      'フォルダ：{title} を作成しました。': 'Đã tạo thư mục "{title}".',
      'Stripe決済URLが取得できませんでした。': 'Không lấy được URL thanh toán Stripe.',
      'フリープランへ戻してよかですか？': 'Quay lại gói miễn phí?',
      '本当によかですか？（取り消せません）': 'Bạn chắc chắn chứ? Không thể hoàn tác.',
      'お部屋を削除しました。': 'Đã xóa phòng.',
      'アカウントを削除しました。': 'Đã xóa tài khoản.',
      'フォルダの鍵を更新しました。': 'Đã cập nhật khóa thư mục.',
      '予期しないエラー: {message}': 'Lỗi không mong muốn: {message}',
      '実行エラー: {message}': 'Lỗi thực thi: {message}',
      '現在のお部屋を切り替えます。よろしいですか？': 'Chuyển phòng hiện tại?',
      '初期化失敗: {message}': 'Khởi tạo thất bại: {message}',
      '更新: {datetime}': 'Cập nhật: {datetime}',
      全ユーザー: 'Tất cả người dùng',
      お部屋メンバー: 'Thành viên phòng',
      フォルダメンバー: 'Thành viên thư mục',
      総容量: 'Tổng dung lượng',
      有料プラン内訳: 'Chi tiết gói trả phí',
      '有料プランのお部屋はまだありません。': 'Chưa có phòng dùng gói trả phí.',
      お部屋と容量: 'Phòng và dung lượng',
      メンバー: 'Thành viên',
      'メンバー（合計）': 'Thành viên (tổng)',
      'デモではログイン不要です。このまま画面を触ってみてください。':
        'Demo không cần đăng nhập. Bạn có thể thao tác ngay trên màn hình.',
      'デモでは新規登録不要です。気になる動きだけそのまま試せます。':
        'Demo không cần đăng ký. Hãy thử các thao tác bạn muốn xem.',
      'デモではログイン不要です。': 'Demo không cần đăng nhập.',
      'デモでは新規登録不要です。': 'Demo không cần đăng ký.',
      'デモではアカウント削除は行いません。': 'Demo không thực hiện xóa tài khoản.',
      'デモでは {plan} に切り替えた状態を表示します。': 'Demo sẽ hiển thị trạng thái đã chuyển sang {plan}.',
      'フォルダが見つかりません。': 'Không tìm thấy thư mục.',
      LPに戻る: 'Quay lại trang giới thiệu',
      デモ中: 'Đang demo',
      登録不要: 'Không cần đăng ký',
      デモ画像: 'Ảnh demo',
      監査レポート: 'Báo cáo kiểm toán',
      コメントなし: 'Không có bình luận',
      日時不明: 'Không rõ ngày giờ',
      デモ利用者: 'Người dùng demo',
      新規写真: 'Ảnh mới',
      新規フォルダ: 'Thư mục mới',
      管理者: 'Quản trị viên',
      作成者: 'Người tạo',
      'お部屋がありません。': 'Không có phòng.',
      '取得失敗: {message}': 'Không lấy được: {message}',
      '{count}件 / 有料内 {paidPercent}% / 全体 {totalPercent}%':
        '{count} mục / {paidPercent}% trong gói trả phí / {totalPercent}% tổng',
      '作成者は先に「このお部屋を削除（全データ）」を実行してください。':
        'Người tạo cần chạy “Xóa phòng này (toàn bộ dữ liệu)” trước.',
      '作成者は先に「お部屋を削除（全データ）」を実行してください。\n「{roomName}」へ移動しますか？':
        'Người tạo cần chạy “Xóa phòng (toàn bộ dữ liệu)” trước.\nChuyển đến “{roomName}”?',
      自分の部屋: 'Phòng của tôi',
      '「{roomName}」へ移動しました。': 'Đã chuyển đến “{roomName}”.',
      'チーム情報取得失敗: {message}（バックエンド/フロントのデプロイ差分やキャッシュの可能性）':
        'Không lấy được thông tin nhóm: {message} (có thể do khác biệt triển khai backend/frontend hoặc cache)',
      'メンバー「{name}」の閲覧権限を変更してよかですか？': 'Đổi quyền xem của thành viên “{name}”?',
      'メンバー「{name}」をお部屋から削除してよかですか？（本人は入れんごとなります）':
        'Xóa thành viên “{name}” khỏi phòng? Người này sẽ không thể vào.',
      'フォルダ「{folder}」の招待URLを失効してよかですか？': 'Thu hồi URL mời của thư mục “{folder}”?',
      'フォルダ「{folder}」のパスワードを設定してよかですか？': 'Đặt mật khẩu cho thư mục “{folder}”?',
      'フォルダ「{folder}」のパスワードを解除してよかですか？': 'Gỡ mật khẩu của thư mục “{folder}”?',
      'フォルダ「{folder}」を削除してよかですか？（写真とコメントも消えます）':
        'Xóa thư mục “{folder}”? Ảnh và bình luận cũng sẽ bị xóa.',
      'メンバー「{name}」をこのフォルダから外してよかですか？': 'Gỡ thành viên “{name}” khỏi thư mục này?',
      'ブラウザがコピー操作を許可しませんでした。URL欄からコピーしてください。':
        'Trình duyệt không cho phép sao chép. Hãy sao chép từ ô URL.',
      'フォルダ取得失敗: ネットワーク/CORSエラーの可能性があります': 'Không lấy được thư mục: có thể lỗi mạng/CORS',
      '管理者は脱退できません。お部屋管理から「お部屋を削除（全データ）」を実行してください。':
        'Quản trị viên không thể rời phòng. Hãy xóa phòng trong quản lý phòng trước.',
      'メンバーをやめると、このお部屋には招待URLなしでは再参加できません。':
        'Nếu rời phòng, bạn không thể tham gia lại phòng này nếu không có URL mời.',
      '本当にメンバーをやめますか？': 'Bạn thật sự muốn rời với tư cách thành viên?',
      'すでに自分のお部屋を作成済みです（自分の部屋は1人1部屋）。':
        'Bạn đã tạo phòng của mình rồi (mỗi người chỉ có một phòng).',
      'フリープランではフォルダは2つまでです。有料プランで無制限になります。':
        'Gói miễn phí chỉ có tối đa 2 thư mục. Gói trả phí không giới hạn.',
      'このお部屋を削除すると、フォルダ/写真/コメント/課金情報が全て削除され、Stripeの定期課金も即時停止されます。よかですか？':
        'Xóa phòng này sẽ xóa toàn bộ thư mục/ảnh/bình luận/thông tin thanh toán và dừng đăng ký Stripe ngay. Tiếp tục?',
      'アカウントを削除すると、このユーザーでは今後ログインできません。よかですか？':
        'Xóa tài khoản sẽ khiến người dùng này không thể đăng nhập về sau. Tiếp tục?',
      '本当によかですか？（アカウント削除後は取り消せません）': 'Bạn chắc chắn chứ? Xóa tài khoản không thể hoàn tác.',
      '作成者は先に「お部屋を削除（全データ）」を実行してください。':
        'Người tạo cần chạy “Xóa phòng (toàn bộ dữ liệu)” trước.',
      'このフォルダを削除すると、写真とコメントも消えます。よかですか？':
        'Xóa thư mục này cũng sẽ xóa ảnh và bình luận. Tiếp tục?',
      '※ 30日保存後はアーカイブへ移動し、アーカイブは容量に含まれます。\n※ フリープランへ戻す際の容量判定にはアーカイブ済みデータも含みます。':
        'Sau 30 ngày lưu, dữ liệu sẽ chuyển vào lưu trữ và vẫn được tính vào dung lượng.\nKhi chuyển về gói miễn phí, dữ liệu đã lưu trữ cũng được tính.',
      'フリープランに戻りました。\n\n現在の上限は、容量512MB未満・フォルダ2個までです。':
        'Đã quay lại gói miễn phí.\n\nGiới hạn hiện tại là dưới 512 MB dung lượng và tối đa 2 thư mục.',
      '{folder}（作成:{creator} / 容量:{size}）': '{folder} (người tạo: {creator} / dung lượng: {size})',
      フォルダ招待: 'Lời mời thư mục',
      'フォルダ招待URL': 'URL mời thư mục',
      '招待URL発行（7日）': 'Phát hành URL mời (7 ngày)',
      招待URL失効: 'Thu hồi URL mời',
      '失効する招待URLがなかです（先に発行してください）': 'Không có URL mời để thu hồi. Hãy phát hành trước.',
      'フォルダ招待URLを失効しました。': 'Đã thu hồi URL mời thư mục.',
      'フォルダのパスワードを設定しました。': 'Đã đặt mật khẩu thư mục.',
      'フォルダのパスワードを解除しました。': 'Đã gỡ mật khẩu thư mục.',
    },
  };

  function normalizeLanguage(raw) {
    const value = String(raw || '').trim().toLowerCase();
    if (!value) return '';
    if (LANGUAGE_ALIASES[value]) return LANGUAGE_ALIASES[value];
    const base = value.split('-')[0];
    return LANGUAGE_ALIASES[base] || '';
  }

  function detectLanguage() {
    const configured = normalizeLanguage(window.KANSA_CONFIG?.language);
    if (configured) return configured;
    const stored = normalizeLanguage(window.localStorage.getItem('kansa_language'));
    if (stored) return stored;
    const candidates = Array.isArray(navigator.languages) && navigator.languages.length ? navigator.languages : [navigator.language];
    for (const candidate of candidates) {
      const normalized = normalizeLanguage(candidate);
      if (normalized) return normalized;
    }
    return 'ja';
  }

  const currentLanguage = detectLanguage();
  const dictionary = TRANSLATIONS[currentLanguage] || {};

  function translateText(text) {
    const value = String(text || '');
    const compact = value.trim();
    if (!compact) return value;
    const translated = dictionary[compact];
    if (!translated) return value;
    return value.replace(compact, translated);
  }

  function formatText(key, values = {}) {
    const template = translateText(key);
    return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) =>
      Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : match
    );
  }

  function translateNodeText(node) {
    if (!node || node.nodeType !== Node.TEXT_NODE) return;
    const next = translateText(node.nodeValue);
    if (next !== node.nodeValue) node.nodeValue = next;
  }

  function translateElementAttributes(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) return;
    const attrSpec = element.getAttribute('data-i18n-attr');
    if (attrSpec) {
      attrSpec.split(';').forEach((entry) => {
        const [attr, key] = entry.split(':').map((part) => String(part || '').trim());
        if (!attr || !key) return;
        element.setAttribute(attr, translateText(key));
      });
    }
    ['placeholder', 'aria-label', 'title', 'alt'].forEach((attr) => {
      if (!element.hasAttribute(attr)) return;
      const current = element.getAttribute(attr);
      const next = translateText(current);
      if (next !== current) element.setAttribute(attr, next);
    });
  }

  function translateElementContent(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) return;
    const htmlKey = element.getAttribute('data-i18n-html');
    if (htmlKey) {
      const next = translateText(htmlKey);
      if (next !== htmlKey && element.innerHTML !== next) element.innerHTML = next;
      return;
    }
    const textKey = element.getAttribute('data-i18n');
    if (textKey) {
      const next = translateText(textKey);
      if (element.textContent !== next) element.textContent = next;
    }
  }

  function translateRoot(root) {
    const target = root || document.body;
    if (!target) return;
    if (target.nodeType === Node.ELEMENT_NODE) {
      translateElementContent(target);
      translateElementAttributes(target);
    }
    const walker = document.createTreeWalker(target, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    let node = walker.nextNode();
    while (node) {
      if (node.nodeType === Node.TEXT_NODE) translateNodeText(node);
      if (node.nodeType === Node.ELEMENT_NODE) {
        translateElementContent(node);
        translateElementAttributes(node);
      }
      node = walker.nextNode();
    }
  }

  function applyLanguage() {
    document.documentElement.lang = currentLanguage;
    document.documentElement.dataset.lang = currentLanguage;
    document.title = translateText(document.title);
    translateRoot(document.body);
  }

  window.KANSA_I18N = {
    language: currentLanguage,
    supportedLanguages: SUPPORTED_LANGUAGES.slice(),
    t: translateText,
    format: formatText,
    apply: applyLanguage,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyLanguage, { once: true });
  } else {
    applyLanguage();
  }

  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === Node.TEXT_NODE) translateNodeText(node);
        if (node.nodeType === Node.ELEMENT_NODE) translateRoot(node);
      });
      if (mutation.type === 'attributes') {
        translateElementContent(mutation.target);
        translateElementAttributes(mutation.target);
      }
    });
  });

  document.addEventListener(
    'DOMContentLoaded',
    () => {
      if (!document.body) return;
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['placeholder', 'aria-label', 'title', 'alt', 'data-i18n', 'data-i18n-html', 'data-i18n-attr'],
      });
    },
    { once: true }
  );
})();
