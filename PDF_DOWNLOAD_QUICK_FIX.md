# 🚀 PDF Download Quick Fix Guide

## 即座にテストするための手順

### 1. 🔧 クイックセットアップ

```bash
# 1. リポジトリをクローン/プル
git pull origin professional-cve-analysis

# 2. 依存関係をインストール  
pip install -r requirements.txt

# 3. ディレクトリを作成
mkdir -p data/reports

# 4. 権限設定
chmod 755 data/reports

# 5. WeasyPrintをインストール (PDF生成用)
pip install weasyprint

# 6. テストデータを生成
bash test_pdf_download.sh
```

### 2. 🚀 サーバー起動

```bash
python3 app.py
```

### 3. 🧪 テスト方法

#### Method A: ブラウザでテスト

1. **http://localhost:8000** を開く
2. **Target IP:** `192.168.1.100` を入力
3. **Initialize Assessment** をクリック
4. **Execute Scan** をクリック  
5. **Execute Analysis** をクリック
6. **Generate Report** をクリック
7. **Download PDF** をクリック ← ここでダウンロードが開始されるはず

#### Method B: 直接APIでテスト

```bash
# テストレポートを生成
curl -X GET "http://localhost:8000/api/reports/test/192.168.1.100"

# 利用可能なレポートを確認
curl -X GET "http://localhost:8000/api/reports/list/192.168.1.100"

# PDFダウンロードをテスト
curl -O "http://localhost:8000/api/reports/download/pdf/192.168.1.100"

# HTMLダウンロードをテスト  
curl -O "http://localhost:8000/api/reports/download/html/192.168.1.100"
```

### 4. 📋 修正された主要ポイント

#### ✅ バックエンドAPI修正
- **StreamingResponse** を使用したPDF配信
- **enhanced CORS** 設定でContent-Disposition対応
- **複数のファイル検索パターン** で確実にファイルを発見
- **詳細なログ出力** でデバッグを簡素化
- **テストエンドポイント** `/api/reports/test/{target_ip}` を追加

#### ✅ フロントエンド修正
- **downloadReportWithFetch()** メソッドで堅牢なダウンロード処理
- **エラーハンドリング** の強化 (404時に利用可能レポートを自動検索)
- **ファイル存在確認** 後のダウンロード実行
- **Blob処理** でブラウザ互換性を向上

#### ✅ ファイル検索の改良
```python
# 複数パターンでファイル検索
search_patterns = [
    f"{reports_dir}/*{target_ip}*.{report_type}",
    f"{reports_dir}/enterprise_assessment_{target_ip}_*.{report_type}",
    f"{reports_dir}/professional_assessment_{target_ip}*.{report_type}",
    f"{reports_dir}/{target_ip}_report.{report_type}",
]
```

### 5. 🐛 トラブルシューティング

#### 問題: "Report not found"
```bash
# 解決: テストレポートを生成
curl -X GET "http://localhost:8000/api/reports/test/192.168.1.100"

# または手動でディレクトリを確認
ls -la data/reports/
```

#### 問題: PDFが空/壊れている
```bash
# 解決: WeasyPrintの状態を確認
python3 -c "import weasyprint; print('WeasyPrint OK')"

# 失敗する場合はシステム依存関係をインストール
# Ubuntu/Debian:
sudo apt-get install python3-dev python3-pip python3-cffi python3-brotli libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0

# macOS:
brew install pango

# Windows:
# WeasyPrintは自動的にフォールバックモードを使用
```

#### 問題: ブラウザでダウンロードが開始されない
```javascript
// 解決: ブラウザのコンソールで直接テスト
fetch('/api/reports/download/pdf/192.168.1.100')
  .then(response => response.blob())
  .then(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'test_report.pdf';
    a.click();
    window.URL.revokeObjectURL(url);
  });
```

#### 問題: CORS エラー
```bash
# 確認: サーバーログでCORS設定を確認
# main.pyで以下が設定されているはず:
# expose_headers=["Content-Disposition", "Content-Type"]
```

### 6. 🎯 確実に動作させる手順

#### Step 1: 基本セットアップ確認
```bash
# プロジェクトディレクトリで実行
pwd  # /path/to/BreachPilot になっているはず

# 必要ディレクトリの確認
ls -la data/
ls -la data/reports/
```

#### Step 2: 依存関係の完全インストール
```bash
# 仮想環境を作成（推奨）
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 要件を最新にインストール
pip install --upgrade pip
pip install -r requirements.txt
pip install weasyprint  # PDF生成に必須
```

#### Step 3: テストデータの生成
```bash
# テストスクリプトを実行可能にする
chmod +x test_pdf_download.sh

# テストデータを生成
./test_pdf_download.sh
```

#### Step 4: サーバー起動とテスト
```bash
# サーバー起動
python3 app.py

# 別ターミナルでテスト
curl -X GET "http://localhost:8000/api/reports/test/192.168.1.100"
curl -X GET "http://localhost:8000/api/reports/list/192.168.1.100"
curl -I "http://localhost:8000/api/reports/download/pdf/192.168.1.100"
```

### 7. 💡 デバッグ情報の確認

#### サーバーログで確認すべきポイント
```bash
# サーバー起動時に以下が表示されるはず:
# INFO: Reports directory: /path/to/data/reports
# INFO: Static reports directory mounted at /reports

# ダウンロード時のログ:
# INFO: Download request: pdf report for 192.168.1.100
# INFO: Serving PDF report: /path/to/file.pdf (12345 bytes)
```

#### ブラウザ開発者ツールで確認
```javascript
// Network タブで以下を確認:
// 1. /api/reports/download/pdf/192.168.1.100 のリクエスト
// 2. Status: 200 OK
// 3. Response Headers:
//    - Content-Type: application/pdf
//    - Content-Disposition: attachment; filename=security_assessment_192.168.1.100.pdf
//    - Content-Length: [ファイルサイズ]
```

### 8. 🎉 成功の確認

#### 正常に動作している場合:
1. ✅ サーバーがエラーなく起動
2. ✅ `/api/reports/list/192.168.1.100` でファイルリストが表示
3. ✅ ブラウザの「Download PDF」ボタンでファイルダウンロード開始
4. ✅ ダウンロードフォルダにPDFファイルが保存
5. ✅ PDFファイルが正常に開ける

### 9. 🔄 もし全て失敗する場合

#### 完全リセット手順:
```bash
# 1. 全てクリーンアップ
rm -rf data/
rm -rf venv/
rm -rf __pycache__/
rm -rf backend/__pycache__/

# 2. 最初からセットアップ
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
mkdir -p data/reports
chmod 755 data/reports

# 3. 手動でテストファイル作成
echo "Test PDF Content" > data/reports/test_report_192.168.1.100_$(date +%Y%m%d_%H%M%S).pdf

# 4. サーバー起動してテスト
python3 app.py
```

### 10. 📞 サポート

もし上記の手順で解決しない場合、以下の情報を確認してください:

```bash
# 環境情報
python3 --version
pip list | grep -E "(weasyprint|fastapi|requests)"
ls -la data/reports/
curl -I http://localhost:8000/

# ログ出力
python3 app.py 2>&1 | tee server.log
```

この修正により、PDFダウンロード機能は確実に動作するはずです！ 🎯
