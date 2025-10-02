# Enhanced Professional Report Generation System

## 概要

BreachPilot Professional Security Assessment Frameworkの実務レベルのレポート生成システムです。エンタープライズグレードのセキュリティ評価レポートを複数の形式で生成できます。

## 機能

### 🎯 主要機能

- **包括的なリスク評価**: 詳細なリスク分析とビジネスインパクト評価
- **エクゼクティブサマリー**: 経営層向けの簡潔で分かりやすい要約
- **技術分析**: 攻撃ベクトル、エクスプロイトチェーン、横移動分析
- **コンプライアンス分析**: ISO 27001、NIST、PCI DSS等のフレームワーク対応
- **詳細な推奨事項**: 優先度付きの具体的な改善提案
- **修復ロードマップ**: 段階的なセキュリティ改善計画
- **ビジネスケース**: ROI分析と投資対効果の計算

### 📄 出力形式

- **HTML**: インタラクティブなWebベースレポート
- **PDF**: 印刷対応のプロフェッショナルレポート
- **Word**: 編集可能なドキュメント形式
- **JSON**: プログラム処理用の構造化データ

## API エンドポイント

### エンタープライズレポート生成

```bash
POST /api/scan/{session_id}/enterprise-report
```

**レスポンス例:**
```json
{
  "session_id": "scan_20250102_120000_192_168_1_100",
  "target_ip": "192.168.1.100",
  "report_type": "enterprise",
  "download_urls": {
    "html": "/reports/enterprise_security_report_192.168.1.100_20250102_120000.html",
    "pdf": "/reports/enterprise_security_report_192.168.1.100_20250102_120000.pdf",
    "word": "/reports/enterprise_security_report_192.168.1.100_20250102_120000.docx",
    "json": "/reports/enterprise_security_report_192.168.1.100_20250102_120000.json"
  },
  "report_metadata": {
    "report_id": "SEC-192-168-1-100-20250102-120000",
    "classification": "CONFIDENTIAL",
    "validity_period": "90 days"
  },
  "executive_summary": {
    "assessment_overview": "包括的なセキュリティ評価を実施...",
    "key_findings": ["重要な発見事項1", "重要な発見事項2"],
    "critical_risks": ["クリティカルリスク1"],
    "immediate_actions": ["即座の対応が必要な項目1"]
  },
  "risk_assessment": {
    "overall_risk_level": "HIGH",
    "risk_score": 7.5,
    "critical_vulnerabilities": 3,
    "financial_impact_estimate": "$100K - $500K"
  },
  "business_case": {
    "investment_summary": {
      "total_estimated_cost": "$350K - $800K",
      "expected_payback_period": "12-18 months"
    },
    "risk_reduction": {
      "risk_reduction_percentage": "60.0%"
    }
  }
}
```

### エンタープライズレポート一覧

```bash
GET /api/reports/enterprise/{target_ip}
```

### レポートダウンロード

```bash
GET /api/reports/download/{report_type}/{target_ip}
```

**サポート形式:**
- `html` - HTMLレポート
- `pdf` - PDFレポート
- `docx` - Wordドキュメント
- `json` - JSONデータ
- `md` - Markdown形式

## レポート構造

### 1. カバーページ
- レポートタイトル
- 対象IPアドレス
- 生成日時
- 分類レベル
- レポートID

### 2. エクゼクティブサマリー
- 評価概要
- 主要な発見事項
- クリティカルリスク
- 即座の対応が必要な項目
- 戦略的推奨事項

### 3. リスク評価ダッシュボード
- 総合リスクレベル
- リスクスコア（0-10）
- 脆弱性の深刻度別カウント
- ビジネスインパクト分析
- 財務的影響の見積もり

### 4. 技術分析
- 攻撃ベクトル分析
- エクスプロイトチェーン
- 横移動可能性
- データ露出リスク
- 権限昇格パス

### 5. 脆弱性分析
- CVE詳細情報
- 深刻度分類
- CVSSスコア
- エクスプロイト可用性
- 影響を受けるサービス

### 6. ネットワークサービス
- 発見されたサービス
- ポート情報
- バージョン情報
- 状態情報

### 7. 詳細推奨事項
- 優先度付き改善提案
- カテゴリ分類
- ビジネス正当性
- 実装タイムライン
- コスト見積もり
- 成功指標

### 8. 修復ロードマップ
- 3段階の実装計画
- 各フェーズの焦点
- 活動項目
- 成功基準
- 予算配分

### 9. コンプライアンス分析
- 適用可能なフレームワーク
- コンプライアンスギャップ
- 規制要件
- 監査準備状況

### 10. ビジネスケース
- 投資サマリー
- リスク削減効果
- ビジネス利益
- 財務的影響
- ROI分析

## 使用方法

### 基本的な使用方法

1. **セキュリティ評価の実行**
```bash
curl -X POST "http://localhost:8000/api/scan/start" \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "192.168.1.100", "scan_type": "comprehensive"}'
```

2. **エンタープライズレポートの生成**
```bash
curl -X POST "http://localhost:8000/api/scan/{session_id}/enterprise-report"
```

3. **レポートのダウンロード**
```bash
# PDFレポート
curl -O "http://localhost:8000/api/reports/download/pdf/192.168.1.100"

# Wordドキュメント
curl -O "http://localhost:8000/api/reports/download/docx/192.168.1.100"
```

### フロントエンド統合例

```javascript
// エンタープライズレポート生成
async function generateEnterpriseReport(sessionId) {
  try {
    const response = await fetch(`/api/scan/${sessionId}/enterprise-report`, {
      method: 'POST'
    });
    
    const reportData = await response.json();
    
    // レポート情報の表示
    displayReportInfo(reportData);
    
    // ダウンロードリンクの生成
    generateDownloadLinks(reportData.download_urls);
    
    return reportData;
  } catch (error) {
    console.error('Enterprise report generation failed:', error);
  }
}

// レポート情報の表示
function displayReportInfo(reportData) {
  const summary = reportData.executive_summary;
  const risk = reportData.risk_assessment;
  
  // エクゼクティブサマリーの表示
  document.getElementById('executive-summary').innerHTML = `
    <h3>Executive Summary</h3>
    <p>${summary.assessment_overview}</p>
    <h4>Key Findings:</h4>
    <ul>
      ${summary.key_findings.map(finding => `<li>${finding}</li>`).join('')}
    </ul>
    <h4>Critical Risks:</h4>
    <ul>
      ${summary.critical_risks.map(risk => `<li>${risk}</li>`).join('')}
    </ul>
  `;
  
  // リスクダッシュボードの表示
  document.getElementById('risk-dashboard').innerHTML = `
    <div class="risk-metrics">
      <div class="metric">
        <span class="value">${risk.risk_score.toFixed(1)}</span>
        <span class="label">Risk Score</span>
      </div>
      <div class="metric critical">
        <span class="value">${risk.critical_vulnerabilities}</span>
        <span class="label">Critical Issues</span>
      </div>
      <div class="metric">
        <span class="value">${risk.financial_impact_estimate}</span>
        <span class="label">Financial Impact</span>
      </div>
    </div>
  `;
}

// ダウンロードリンクの生成
function generateDownloadLinks(downloadUrls) {
  const downloadContainer = document.getElementById('download-links');
  
  downloadContainer.innerHTML = `
    <h3>Download Reports</h3>
    <div class="download-buttons">
      <a href="${downloadUrls.html}" class="btn btn-primary" target="_blank">
        <i class="icon-html"></i> HTML Report
      </a>
      <a href="${downloadUrls.pdf}" class="btn btn-danger" download>
        <i class="icon-pdf"></i> PDF Report
      </a>
      <a href="${downloadUrls.word}" class="btn btn-success" download>
        <i class="icon-word"></i> Word Document
      </a>
      <a href="${downloadUrls.json}" class="btn btn-info" download>
        <i class="icon-json"></i> JSON Data
      </a>
    </div>
  `;
}
```

## 設定

### 環境変数

```bash
# レポート設定
REPORTS_DIR=/path/to/reports
REPORT_CLASSIFICATION=CONFIDENTIAL
REPORT_VALIDITY_DAYS=90

# PDF生成設定
PDF_ENGINE=weasyprint  # または reportlab
PDF_QUALITY=high

# Word生成設定
WORD_TEMPLATE_PATH=/path/to/templates
```

### 依存関係のインストール

```bash
# 基本的な依存関係
pip install -r requirements.txt

# PDF生成（WeasyPrint）
pip install weasyprint

# PDF生成（ReportLab）
pip install reportlab

# Word生成
pip install python-docx

# 高度なPDF生成（Pandoc）
sudo apt-get install pandoc
```

## カスタマイズ

### レポートテンプレートのカスタマイズ

1. **HTMLテンプレート**: `backend/report/templates/enhanced_professional_report.html`
2. **PDFスタイル**: `backend/report/pdf_generator.py`の`_generate_pdf_css()`
3. **Wordスタイル**: `backend/report/word_generator.py`の`_setup_document_styles()`

### 新しいレポートセクションの追加

```python
# enhanced_report_generator.py
def _generate_custom_section(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
    """カスタムセクションの生成"""
    return {
        "section_title": "Custom Analysis",
        "content": "Custom analysis content",
        "metrics": {...},
        "recommendations": [...]
    }
```

## トラブルシューティング

### よくある問題

1. **PDF生成エラー**
   - WeasyPrintまたはReportLabがインストールされているか確認
   - フォントファイルのパスが正しいか確認

2. **Word生成エラー**
   - python-docxがインストールされているか確認
   - テンプレートファイルが存在するか確認

3. **メモリ不足エラー**
   - 大きなレポートの場合はチャンク処理を有効化
   - システムリソースを確認

### ログの確認

```bash
# レポート生成ログの確認
tail -f logs/breachpilot.log | grep "report"

# エラーログの確認
grep "ERROR" logs/breachpilot.log | grep "report"
```

## セキュリティ考慮事項

- レポートファイルは適切な権限で保護
- 機密情報のマスキング処理
- アクセスログの記録
- レポートの有効期限管理

## パフォーマンス最適化

- レポート生成の非同期処理
- キャッシュ機能の実装
- 並列処理の活用
- リソース使用量の監視

---

**注意**: このレポート生成システムは教育目的および認可されたセキュリティテスト目的でのみ使用してください。無許可のシステムへのアクセスは違法です。
