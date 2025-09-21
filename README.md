# BreachPilot v2.0

自動ペネトレーションテストシステム

## 🎯 概要

BreachPilotは、OSINTからエクスプロイトまでの完全な侵入テストワークフローを自動化するシステムです。CrewAIエージェントを使用して脆弱性分析とPoC選択を行い、すべての結果をJSON形式で保存・可視化します。

## ✨ 主な機能

### ワークフロー

1. **ターゲットIP指定** - ユーザーが攻撃対象のIPアドレスを入力
2. **OSINT収集** - ホスト名、ドメイン、サブドメイン、WHOIS情報、公開サービスの収集
3. **Nmapスキャン** - ポート、サービス、OS検出、脆弱性スキャン
4. **CVE分析（Analyst Agent）** - CrewAIエージェントによるCVE特定とXAIによる根拠説明
5. **PoC検索** - Exploit-DB、GitHub、Metasploitからエクスプロイトコードを検索
6. **ユーザー承認** - 実行するエクスプロイトの選択
7. **エクスプロイト実行** - サンドボックス環境での安全な実行
8. **成功確認** - エクスプロイトの成功/失敗を検証
9. **レポート生成** - MarkdownとPDF形式での詳細レポート作成

### OSINT収集情報

- ホスト名
- ドメイン
- サブドメイン一覧
- WHOIS情報（登録者、有効期限など）
- 公開サービス一覧（バナー情報含む）
- Shodanデータ（オプション）

## 🚀 セットアップ

### 必要要件

- Python 3.9+
- Nmap
- Git
- (オプション) Metasploit Framework

### インストール

```bash
# リポジトリのクローン
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout feature/dev_v2

# 依存関係のインストール
pip install -r requirements.txt

# 環境変数の設定
cp .env.example .env
# .envファイルを編集してAPIキーを設定

# Nmapのインストール（Ubuntu/Debian）
sudo apt-get update
sudo apt-get install nmap

# （オプション）Metasploitのインストール
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

### 設定

`.env`ファイルに以下の情報を設定：

```env
OPENAI_API_KEY=your_openai_api_key_here  # 必須
SHODAN_API_KEY=your_shodan_api_key_here  # オプション
```

## 📖 使用方法

### Webインターフェース

```bash
# サーバー起動
python run.py

# ブラウザで以下にアクセス
http://localhost:8000/ui
```

### APIエンドポイント

```bash
# スキャン開始
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "192.168.1.100"}'

# OSINT実行
curl -X POST http://localhost:8000/api/scan/{session_id}/osint

# Nmap実行
curl -X POST http://localhost:8000/api/scan/{session_id}/nmap

# 脆弱性分析
curl -X POST http://localhost:8000/api/scan/{session_id}/analyze

# PoC検索
curl -X POST http://localhost:8000/api/scan/{session_id}/poc

# エクスプロイト承認
curl -X POST http://localhost:8000/api/scan/{session_id}/approve \
  -H "Content-Type: application/json" \
  -d '["CVE-2020-1472", "CVE-2021-44228"]'

# エクスプロイト実行
curl -X POST http://localhost:8000/api/scan/{session_id}/exploit

# レポート生成
curl -X POST http://localhost:8000/api/scan/{session_id}/report

# レポートダウンロード
curl http://localhost:8000/api/scan/{session_id}/download/report?format=pdf -o report.pdf
```

### Python API

```python
from backend.orchestrator import ScanOrchestrator
from backend.models import ScanRequest

# オーケストレーター初期化
orchestrator = ScanOrchestrator()

# スキャン開始
request = ScanRequest(target_ip="192.168.1.100")
session = orchestrator.start_scan(request)

# 各ステップ実行
osint_result = orchestrator.run_osint(session.session_id)
nmap_result = orchestrator.run_nmap(session.session_id)
analyst_result = orchestrator.run_analysis(session.session_id)
poc_results = orchestrator.search_pocs(session.session_id)

# エクスプロイト承認
approved_cves = ["CVE-2020-1472"]
orchestrator.await_user_approval(session.session_id, approved_cves)

# エクスプロイト実行
exploit_results = orchestrator.run_exploits(session.session_id)

# レポート生成
report = orchestrator.generate_report(session.session_id)
```

## 🧪 Zerologon脆弱性のテスト

VMware内のWindowsサーバー（CVE-2020-1472: Zerologon脆弱性）に対するテスト例：

```bash
# Webインターフェースでターゲット入力
# 例: 192.168.1.10 (VMware内のドメインコントローラー)

# 各ステップを順次実行
# 1. OSINT → ホスト名やドメイン情報を収集
# 2. Nmap → ポート445、135などを検出
# 3. Analysis → CVE-2020-1472を特定
# 4. PoC Search → Zerologonエクスプロイトを検索
# 5. 承認 → CVE-2020-1472を選択
# 6. 実行 → Metasploitモジュールを使用して攻撃
# 7. レポート → 結果をPDF/Markdownで出力
```

## 📁 プロジェクト構造

```
BreachPilot/
├── backend/
│   ├── __init__.py
│   ├── config.py              # 設定管理
│   ├── models.py              # データモデル
│   ├── main.py                # FastAPI アプリケーション
│   ├── orchestrator.py        # メインワークフロー
│   ├── scanners/
│   │   ├── osint_scanner.py   # OSINT収集
│   │   └── nmap_scanner.py    # Nmapスキャン
│   ├── agents/
│   │   ├── analyst_crew.py    # CVE分析エージェント
│   │   └── poc_crew.py        # PoC検索エージェント
│   ├── exploiter/
│   │   └── exploit_executor.py # エクスプロイト実行
│   └── report/
│       └── report_generator.py # レポート生成
├── frontend/
│   ├── index.html             # Webインターフェース
│   └── static/
│       └── app.js             # Vue.js アプリケーション
├── data/                      # JSON結果ファイル
├── reports/                   # 生成されたレポート
├── requirements.txt
├── .env.example
├── run.py                     # メインエントリーポイント
└── README.md
```

## 🔒 セキュリティ注意事項

⚠️ **警告**: このツールは教育目的および承認された侵入テストにのみ使用してください。

- 必ず自身が所有するシステムまたは明示的な許可を得たシステムに対してのみ使用すること
- エクスプロイトは隔離された環境で実行することを推奨
- 本番環境での使用は避けること
- すべての活動はログに記録され、法的証拠として使用される可能性があります

## 📊 データフロー

各ステップの結果はJSON形式で保存されます：

- `{target_ip}_osint.json` - OSINT結果
- `{target_ip}_nmap.json` - Nmapスキャン結果
- `{target_ip}_analyst.json` - CVE分析結果
- `{cve_id}_poc.json` - PoC検索結果
- `{target_ip}_{cve_id}_exploit.json` - エクスプロイト結果
- `{target_ip}_report.json` - 最終レポート
- `session_{session_id}.json` - セッション状態

## 🛠️ トラブルシューティング

### Nmapがインストールされていない

```bash
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS
```

### OpenAI APIキーエラー

`.env`ファイルに正しいAPIキーが設定されているか確認してください。

### Metasploitモジュールが見つからない

Metasploit Frameworkをインストールし、パスが正しく設定されているか確認してください。

### ポート権限エラー

NmapのSYNスキャンにはroot権限が必要です：

```bash
sudo python run.py
```

## 🤝 貢献

プルリクエストを歓迎します。大きな変更の場合は、まずissueを開いて変更内容を議論してください。

## 📝 ライセンス

MIT License

## 🙏 謝辞

- [CrewAI](https://www.crewai.com/) - マルチエージェントフレームワーク
- [Nmap](https://nmap.org/) - ネットワークスキャナー
- [Metasploit](https://www.metasploit.com/) - エクスプロイトフレームワーク
- [FastAPI](https://fastapi.tiangolo.com/) - Webフレームワーク

## 📧 サポート

問題が発生した場合は、GitHubのIssuesセクションで報告してください。
