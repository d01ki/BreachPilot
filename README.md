# BreachPilot v2.0

自動ペネトレーションテストシステム

## 🚀 クイックスタート

```bash
# 1. リポジトリをクローン
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
git checkout feature/dev_v2

# 2. セットアップスクリプト実行
chmod +x setup.sh
./setup.sh

# 3. 環境変数設定
cp .env.example .env
# .envを編集してOPENAI_API_KEYを追加

# 4. アプリケーション起動
source venv/bin/activate
python3 app.py

# 5. ブラウザでアクセス
# http://localhost:8000/ui
```

## 🎯 概要

BreachPilotは、OSINTからエクスプロイトまでの完全な侵入テストワークフローを自動化するシステムです。

### 主な機能

1. **OSINT収集** - ホスト名、ドメイン、公開サービス情報を収集
2. **Nmapスキャン** - ポート、サービス、OS検出、脆弱性スキャン
3. **CVE分析** - CrewAIエージェントによる脆弱性特定
4. **PoC検索** - GitHub、Metasploitからエクスプロイト検索
5. **エクスプロイト実行** - ユーザー承認後に実行
6. **レポート生成** - Markdown/PDF形式で出力

## 📦 必要要件

- Python 3.9+
- Nmap
- Git

## 💻 インストール

### 方法1: セットアップスクリプト（推奨）

```bash
chmod +x setup.sh
./setup.sh
```

### 方法2: 手動インストール

```bash
# 仮想環境作成
python3 -m venv venv
source venv/bin/activate

# 依存関係インストール
pip install -r requirements.txt
```

### 方法3: Docker

```bash
docker-compose up -d
```

## ⚙️ 設定

`.env`ファイルを作成：

```bash
cp .env.example .env
```

`.env`を編集：

```env
# 必須
OPENAI_API_KEY=sk-your-key-here

# オプション
SHODAN_API_KEY=your-shodan-key
```

## 🖥️ 使い方

### Webインターフェース

```bash
python3 app.py
```

ブラウザで `http://localhost:8000/ui` を開く

### API

```bash
# スキャン開始
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "192.168.1.100"}'
```

## 📁 プロジェクト構造

```
BreachPilot/
├── backend/           # バックエンドロジック
│   ├── agents/       # CrewAIエージェント
│   ├── scanners/     # OSINT/Nmapスキャナー
│   ├── exploiter/    # エクスプロイト実行
│   └── report/       # レポート生成
├── frontend/         # Webインターフェース
├── data/            # スキャン結果（JSON）
├── reports/         # 生成レポート
└── app.py          # メインエントリーポイント
```

## 🔧 トラブルシューティング

### 依存関係エラー

```bash
# 仮想環境を再作成
rm -rf venv
chmod +x setup.sh
./setup.sh
```

### Nmapがない

```bash
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS
```

### ポート権限エラー

```bash
sudo python3 app.py
```

詳細は `TROUBLESHOOTING.md` を参照

## ⚠️ 注意事項

このツールは教育目的および**承認された**ペネトレーションテストにのみ使用してください。

- 自分が所有するシステムにのみ使用
- 不正アクセスは違法です
- すべての活動はログに記録されます

## 📝 ライセンス

MIT License

## 🤝 貢献

プルリクエスト歓迎！

## 📧 サポート

問題があれば [Issues](https://github.com/d01ki/BreachPilot/issues) で報告してください。
