# BreachPilot

BreachPilotは、自動ペネトレーションテストシステムです。指定されたターゲットに対してNmapスキャン、CVE分析、PoC検索、および脆弱性検証を実行します。

## 機能

- **Nmapスキャン**: ターゲットのポートスキャンとサービス検出
- **CVE分析**: 発見されたサービスの脆弱性分析
- **PoC検索**: 特定されたCVEに対するProof-of-Conceptの検索
- **脆弱性検証**: PoC実行による脆弱性の実際の検証

## セットアップ

### 要件

- Python 3.8+
- Nmap
- Git

### インストール

1. リポジトリをクローン:
```bash
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot
```

2. セットアップスクリプトを実行:
```bash
chmod +x setup.sh
./setup.sh
```

3. または手動でセットアップ:
```bash
pip install -r requirements.txt
```

### 必要なツールのインストール

```bash
chmod +x install_tools.sh
./install_tools.sh
```

## 使用方法

### Webインターフェース

1. サーバーを起動:
```bash
python app.py
```

2. ブラウザで `http://localhost:8000/ui` にアクセス

3. ターゲットIPを入力して「Start Scan」をクリック

4. 各ステップを順番に実行:
   - **Nmapスキャン**: ポートスキャンとサービス検出
   - **CVE分析**: 脆弱性の特定と分析
   - **PoC検索**: 選択したCVEのPoC検索
   - **脆弱性検証**: PoCの実行と検証

### API

詳細なAPIドキュメントは `http://localhost:8000/docs` で確認できます。

#### 基本的なAPI使用例:

1. スキャンセッション開始:
```bash
curl -X POST "http://localhost:8000/api/scan/start" \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "192.168.1.100"}'
```

2. Nmapスキャン実行:
```bash
curl -X POST "http://localhost:8000/api/scan/{session_id}/nmap"
```

3. CVE分析実行:
```bash
curl -X POST "http://localhost:8000/api/scan/{session_id}/analyze"
```

## 設定

### 環境変数

`.env`ファイルを作成して設定をカスタマイズできます:

```bash
# データディレクトリ
DATA_DIR=./data

# レポート出力ディレクトリ  
REPORTS_DIR=./reports

# ログレベル
LOG_LEVEL=INFO
```

## ディレクトリ構造

```
BreachPilot/
├── app.py                 # メインアプリケーション
├── backend/               # バックエンドコード
│   ├── main.py           # FastAPI アプリケーション
│   ├── models.py         # データモデル
│   ├── orchestrator.py   # スキャンオーケストレーター
│   ├── agents/           # AI エージェント
│   ├── scanners/         # スキャナー (Nmap)
│   └── exploiter/        # エクスプロイト実行器
├── frontend/             # フロントエンドファイル
│   ├── index.html        # メインUI
│   └── static/           # 静的ファイル
└── data/                 # スキャンデータ保存
```

## 特徴

### 高度なNmapスキャン
- ポートスキャン
- サービス検出
- OS検出
- ドメインコントローラー識別

### インテリジェントCVE分析
- サービス情報に基づく脆弱性特定
- CVSS スコア評価
- 詳細な脆弱性説明

### 自動PoC検索
- GitHub からの PoC 検索
- 組み込みエクスプロイト (Zerologon等)
- コード品質評価

### 脆弱性検証
- PoC の自動実行
- 結果の詳細分析
- 成功/失敗の判定

## セキュリティ注意事項

⚠️ **重要**: このツールは教育目的および承認されたペネトレーションテストでのみ使用してください。

- 適切な許可なしに他人のシステムをスキャンすることは違法です
- テスト環境または自分が所有するシステムでのみ使用してください
- 発見された脆弱性は責任を持って開示してください

## トラブルシューティング

### よくある問題

1. **Nmapが見つからない**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap
   
   # CentOS/RHEL
   sudo yum install nmap
   
   # macOS
   brew install nmap
   ```

2. **権限エラー**:
   ```bash
   # Nmapをrootで実行する場合
   sudo python app.py
   ```

3. **ポートが使用中**:
   ```bash
   # 別のポートを使用
   uvicorn backend.main:app --host 0.0.0.0 --port 8001
   ```

## 開発

### 開発環境のセットアップ

```bash
# 開発用依存関係のインストール
pip install -r requirements.txt

# テストの実行
python -m pytest

# コードフォーマット
black backend/ frontend/
```

### 貢献

1. このリポジトリをフォーク
2. 機能ブランチを作成 (`git checkout -b feature/amazing-feature`)
3. 変更をコミット (`git commit -m 'Add amazing feature'`)
4. ブランチにプッシュ (`git push origin feature/amazing-feature`)
5. プルリクエストを作成

## 変更履歴

### v2.0 (現在)
- OSINT機能の削除
- ステップ別実行の改善
- リアルタイム結果表示
- UI/UXの向上

### v1.x
- 初期リリース
- 基本的なスキャン機能

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。詳細は[LICENSE](LICENSE)ファイルを参照してください。

## サポート

- **Issues**: [GitHub Issues](https://github.com/d01ki/BreachPilot/issues)
- **Discussions**: [GitHub Discussions](https://github.com/d01ki/BreachPilot/discussions)

---

**免責事項**: このツールは教育目的でのみ提供されています。使用者は適用される法律と規制を遵守する責任があります。