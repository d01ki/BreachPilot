# PDF Download Fix - Quick Setup Guide

## 問題の解決

PDFダウンロード機能が動作しない問題を修正しました。以下の変更が実装されています：

### バックエンドの修正

1. **新しいAPIエンドポイント**
   - `/api/reports/download/{report_type}/{target_ip}` - レポートダウンロード
   - `/api/reports/list/{target_ip}` - 利用可能なレポート一覧

2. **静的ファイル配信**
   - `/reports` パスで直接レポートファイルにアクセス可能

3. **ファイル検索機能**
   - 複数の命名パターンに対応
   - 最新ファイルの自動選択

### 使用方法

#### 1. レポート生成後のダウンロードURL

レポート生成後、以下のURLでファイルにアクセスできます：

```bash
# HTML レポート
GET /api/reports/download/html/{target_ip}

# PDF レポート  
GET /api/reports/download/pdf/{target_ip}

# JSON データ
GET /api/reports/download/json/{target_ip}

# エグゼクティブサマリー (Markdown)
GET /api/reports/download/md/{target_ip}
```

#### 2. レポート一覧の確認

```bash
GET /api/reports/list/{target_ip}
```

レスポンス例：
```json
{
  "target_ip": "192.168.1.100",
  "reports": [
    {
      "filename": "enterprise_assessment_192.168.1.100_20240101_120000.html",
      "type": "html",
      "size": 45678,
      "created": "2024-01-01T12:00:00",
      "download_url": "/api/reports/download/html/192.168.1.100"
    },
    {
      "filename": "enterprise_assessment_192.168.1.100_20240101_120000.pdf",
      "type": "pdf", 
      "size": 123456,
      "created": "2024-01-01T12:00:00",
      "download_url": "/api/reports/download/pdf/192.168.1.100"
    }
  ]
}
```

### テスト方法

1. **セキュリティ評価の実行**
   ```bash
   curl -X POST http://localhost:8000/api/scan/start \
        -H "Content-Type: application/json" \
        -d '{"target_ip": "192.168.1.100"}'
   ```

2. **レポート生成**
   ```bash
   curl -X POST http://localhost:8000/api/scan/{session_id}/report
   ```

3. **レポートダウンロード**
   ```bash
   # PDFダウンロード
   curl -O http://localhost:8000/api/reports/download/pdf/192.168.1.100
   
   # HTMLダウンロード
   curl -O http://localhost:8000/api/reports/download/html/192.168.1.100
   ```

### フロントエンド統合

フロントエンドで以下のように実装してください：

```javascript
// レポート生成後
const response = await fetch(`/api/scan/${sessionId}/report`, {
    method: 'POST'
});
const reportData = await response.json();

// PDFダウンロードリンク
const pdfDownloadUrl = `/api/reports/download/pdf/${targetIp}`;

// HTMLレポートリンク
const htmlReportUrl = `/api/reports/download/html/${targetIp}`;

// ダウンロードボタンのクリックハンドラ
const downloadPDF = () => {
    const link = document.createElement('a');
    link.href = pdfDownloadUrl;
    link.download = `security_assessment_${targetIp}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
};
```

### 依存関係のインストール

PDF生成のために以下をインストールしてください：

```bash
# WeasyPrint (推奨)
pip install weasyprint

# Ubuntu/Debianの場合
sudo apt-get install python3-dev python3-pip python3-cffi python3-brotli libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0

# WeasyPrintが利用できない場合は自動的にテキストベースのフォールバックが使用されます
```

### ディレクトリ構造

```
data/
├── reports/                          # 生成されたレポート
│   ├── enterprise_assessment_192.168.1.100_20240101_120000.html
│   ├── enterprise_assessment_192.168.1.100_20240101_120000.pdf
│   ├── executive_summary_192.168.1.100_20240101_120000.md
│   └── enterprise_assessment_192.168.1.100_20240101_120000.json
├── 192.168.1.100_nmap.json           # 元データファイル
├── 192.168.1.100_analysis.json
└── 192.168.1.100_exploits.json
```

### トラブルシューティング

1. **PDFファイルが見つからない**
   - レポート生成が完了しているか確認
   - `/api/reports/list/{target_ip}` で利用可能なファイルを確認

2. **PDF生成エラー**
   - WeasyPrintの依存関係を確認
   - フォールバックとしてテキストファイルが生成されます

3. **権限エラー**
   - `data/reports` ディレクトリの書き込み権限を確認
   - `chmod 755 data/reports` を実行

### ログ確認

```bash
# ログでレポート生成状況を確認
tail -f logs/breachpilot.log | grep -i report

# エラーログの確認
tail -f logs/breachpilot.log | grep -i error
```

これで PDFダウンロード機能が正常に動作するはずです。問題が続く場合は、上記のテスト手順に従って段階的に確認してください。
