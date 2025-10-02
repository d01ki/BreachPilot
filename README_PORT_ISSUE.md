# Port Already in Use - トラブルシューティング

## ⚠️ エラー: `[Errno 98] address already in use`

このエラーは、ポート8000が既に別のプロセスで使用されていることを示します。

---

## 🔧 解決方法

### 方法1: 既存プロセスの停止（推奨）

#### ステップ1: 使用中のプロセスを確認
```bash
# ポート8000を使用しているプロセスを表示
lsof -i :8000

# または
netstat -tulpn | grep :8000
```

**出力例:**
```
COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python  12345 iniad   3u  IPv4  xxxxx      0t0  TCP *:8000 (LISTEN)
```

#### ステップ2: プロセスを停止
```bash
# PIDを使用して停止（上記の例ではPID=12345）
kill -9 12345

# または、ポート番号で直接停止
fuser -k 8000/tcp

# または、すべてのBreachPilotプロセスを停止
pkill -f "uvicorn.*8000"
```

#### ステップ3: BreachPilotを再起動
```bash
python app.py
```

---

### 方法2: 別のポートを使用

#### オプション1: コマンドライン引数
```bash
# ポート8001で起動
python app.py --port 8001

# ポート9000で起動
python app.py --port 9000
```

#### オプション2: 環境変数
```bash
# 環境変数で指定
PORT=8001 python app.py

# または
export PORT=8001
python app.py
```

#### オプション3: 自動ポート検索スクリプト
```bash
# 実行権限を付与
chmod +x start.sh

# 自動的に利用可能なポートを見つけて起動
./start.sh

# または特定のポートから探索
./start.sh 8001
```

---

### 方法3: すべて停止して再起動

```bash
# すべてのPythonプロセスを表示
ps aux | grep python

# BreachPilot関連のプロセスをすべて停止
pkill -f "BreachPilot"
pkill -f "uvicorn"

# ポートが解放されたことを確認
lsof -i :8000

# 再起動
python app.py
```

---

## 🔍 デバッグ手順

### 1. ポート使用状況の詳細確認

```bash
# 詳細情報を表示
lsof -i :8000 -P -n

# プロセスの完全な情報
ps -fp <PID>
```

### 2. 複数のポートをチェック

```bash
# 8000-8010の範囲でチェック
for port in {8000..8010}; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null; then
        echo "Port $port: IN USE"
    else
        echo "Port $port: AVAILABLE"
    fi
done
```

### 3. BreachPilotプロセスの確認

```bash
# BreachPilot関連のすべてのプロセス
ps aux | grep -i breachpilot

# Pythonで実行中のすべてのプロセス
ps aux | grep "python.*app.py"
```

---

## 📊 よくある原因

### 1. 前回の実行が正常終了しなかった

**症状:** Ctrl+Cで停止したが、プロセスが残っている

**解決:**
```bash
pkill -f "uvicorn.*8000"
python app.py
```

### 2. 複数のインスタンスを起動してしまった

**症状:** 複数のターミナルで起動を試みた

**解決:**
```bash
# すべてのインスタンスを停止
pkill -f "app.py"

# 1つだけ起動
python app.py
```

### 3. 他のアプリケーションがポートを使用

**症状:** 別のWebサーバーやアプリケーションがポート8000を使用

**解決:**
```bash
# 別のポートを使用
python app.py --port 8001
```

### 4. システム再起動後も解決しない

**症状:** 再起動しても問題が続く

**解決:**
```bash
# システムのポート割り当てをチェック
sudo netstat -tulpn | grep :8000

# 権限の問題の可能性
sudo lsof -i :8000
```

---

## ⚙️ 設定ファイルでデフォルトポートを変更

### .env ファイルを作成

```bash
# プロジェクトルートに .env ファイルを作成
cat > .env << 'EOF'
# BreachPilot Configuration
PORT=8001
HOST=0.0.0.0
EOF
```

### 使用方法

```bash
# .env ファイルから設定を読み込み
python app.py
```

---

## 🚀 推奨される起動方法

### 開発環境

```bash
# 自動ポート検索を使用
./start.sh

# または手動で指定
python app.py --port 8001
```

### 本番環境

```bash
# systemdサービスとして実行（推奨）
sudo systemctl start breachpilot

# または明示的にポート指定
PORT=8000 python app.py
```

---

## 📝 クイックリファレンス

| コマンド | 説明 |
|---------|------|
| `lsof -i :8000` | ポート8000の使用状況を確認 |
| `kill -9 <PID>` | プロセスを強制停止 |
| `fuser -k 8000/tcp` | ポート8000を使用中のプロセスを停止 |
| `python app.py --port 8001` | ポート8001で起動 |
| `./start.sh` | 自動的に利用可能なポートで起動 |
| `pkill -f "uvicorn"` | すべてのuvicornプロセスを停止 |

---

## ❓ さらにヘルプが必要な場合

### ヘルプコマンド

```bash
# app.pyのヘルプを表示
python app.py --help
```

**出力:**
```
usage: app.py [-h] [--port PORT] [--host HOST] [--reload]

BreachPilot - Automated Penetration Testing System

optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -p PORT  Port to run the server on (default: 8000)
  --host HOST           Host to bind to (default: 0.0.0.0)
  --reload              Enable auto-reload for development
```

### GitHub Issues

問題が解決しない場合は、以下の情報を含めてIssueを作成してください:

1. エラーメッセージの完全な出力
2. `lsof -i :8000` の出力
3. OS情報: `uname -a`
4. Python バージョン: `python --version`

---

**最終更新:** 2025-01-02  
**作成者:** BreachPilot Team
