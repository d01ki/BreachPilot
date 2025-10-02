# BreachPilot Installation Guide

## システム要件

### 最小要件
- Python 3.10以降
- 2GB RAM
- 1GB ディスク空間
- nmap

### 推奨要件
- Python 3.11+
- 4GB RAM
- 5GB ディスク空間
- 安定したインターネット接続

## ステップバイステップインストール

### 1. システムの準備

#### Ubuntu/Debian
```bash
# システムアップデート
sudo apt-get update
sudo apt-get upgrade -y

# 必要なパッケージのインストール
sudo apt-get install -y python3.11 python3-pip nmap git
```

#### macOS
```bash
# Homebrewのインストール（未インストールの場合）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 必要なパッケージのインストール
brew install python@3.11 nmap git
```

#### Windows
```powershell
# Python 3.11のインストール
# https://www.python.org/downloads/ からダウンロード

# nmapのインストール
# https://nmap.org/download.html からダウンロード

# Gitのインストール
# https://git-scm.com/download/win からダウンロード
```

### 2. リポジトリのクローン

```bash
# リポジトリをクローン
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot

# 正しいブランチに切り替え
git checkout crewai-redesign-professional
```

### 3. Python仮想環境の作成

```bash
# 仮想環境の作成
python3 -m venv venv

# 仮想環境の有効化
# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 4. 依存関係のインストール

```bash
# 依存関係のインストール
pip install --upgrade pip
pip install -r requirements.txt
```

### 5. 環境設定

```bash
# .envファイルの作成
cp .env.example .env

# .envファイルを編集
nano .env  # または好みのエディタを使用
```

`.env`ファイルに以下を設定：

```env
# 必須: OpenAI API Key
OPENAI_API_KEY=sk-your-api-key-here

# 推奨設定
LLM_MODEL=gpt-4o-mini
DEBUG=false
LOG_LEVEL=INFO

# オプション: Webサーチ用
SERPER_API_KEY=your-serper-key-here
```

### 6. データディレクトリの作成

```bash
# データディレクトリを作成
mkdir -p data
chmod 755 data
```

### 7. nmapの権限設定（Linux/macOS）

```bash
# nmapに必要な権限を付与（オプション）
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

### 8. インストールの確認

```bash
# Pythonバージョンの確認
python --version
# 出力例: Python 3.11.x

# nmapの確認
nmap --version
# 出力例: Nmap version 7.x

# 依存関係の確認
pip list | grep -E "fastapi|crewai|openai"
```

### 9. 初回起動

```bash
# アプリケーションの起動
python app.py
```

以下のような出力が表示されれば成功です：

```
======================================================================
🛡️  BREACHPILOT PROFESSIONAL SECURITY ASSESSMENT FRAMEWORK
🤖  CrewAI Architecture - Enterprise Edition v2.0
======================================================================
🌐 Web Interface: http://localhost:8000
📚 API Documentation: http://localhost:8000/docs
📊 System Status: http://localhost:8000/status
🤖 CrewAI Status: http://localhost:8000/crewai/status
======================================================================
⚙️  Configuration Status:
   LLM Model: gpt-4o-mini
   OpenAI API: ✅ Configured
   Serper API: ⚠️  Optional
   Debug Mode: ❌ Disabled
   Log Level: INFO

🚀 Starting CrewAI Security Assessment Framework...
======================================================================
```

### 10. ブラウザでアクセス

ブラウザで以下のURLにアクセス：

```
http://localhost:8000
```

## トラブルシューティング

### エラー: "ModuleNotFoundError"

```bash
# 依存関係を再インストール
pip install --force-reinstall -r requirements.txt
```

### エラー: "OpenAI API key not configured"

```bash
# .envファイルを確認
cat .env | grep OPENAI_API_KEY

# APIキーが正しく設定されているか確認
```

### エラー: "nmap: command not found"

```bash
# nmapをインストール
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap
```

### ポート8000が使用中

```bash
# 別のポートを使用
export PORT=8080
python app.py
```

### 権限エラー（Linux）

```bash
# sudoで実行（推奨されない）
sudo python app.py

# または、nmapに権限を付与
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## Docker を使用したインストール

```bash
# Dockerイメージのビルド
docker build -t breachpilot .

# コンテナの起動
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=your-key-here \
  -v $(pwd)/data:/app/data \
  breachpilot
```

## アップデート

```bash
# 最新のコードを取得
git pull origin crewai-redesign-professional

# 依存関係を更新
pip install --upgrade -r requirements.txt

# アプリケーションを再起動
python app.py
```

## アンインストール

```bash
# 仮想環境を無効化
deactivate

# プロジェクトディレクトリを削除
cd ..
rm -rf BreachPilot
```

## 次のステップ

1. [クイックスタートガイド](QUICKSTART.md)を読む
2. 基本的なスキャンを実行してみる
3. [API ドキュメント](http://localhost:8000/docs)を確認
4. より高度な機能を探索

## サポート

問題が解決しない場合：

1. [既存のIssue](https://github.com/d01ki/BreachPilot/issues)を確認
2. 新しいIssueを作成
3. ログファイルを添付（`data/`ディレクトリ内）
