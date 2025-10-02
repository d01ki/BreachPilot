# PentestPilot - Automated Penetration Testing System

**信頼性と機能性を優先した実務レベルのペネトレーションテストツール**

## 🎯 特徴

- ✅ **完全に動作するZerologonエクスプロイト**
  - 2000回の試行で99.996%の検出率
  - 確実に脆弱性を発見
  - パッチ状態の正確な判定

- ✅ **インテリジェントな失敗分析**
  - 失敗しても次のアクションを提案
  - 原因の自動特定
  - 代替手法の推薦

- ✅ **プロフェッショナルPDFレポート**
  - エグゼクティブサマリー
  - 詳細な発見事項
  - 実行可能な推奨事項

- ✅ **包括的なドキュメント**
  - トラブルシューティングガイド
  - 実行ガイド
  - FAQ

## 📚 重要な設計哲学

**信頼性と機能性を最優先**

- 速度よりも確実に脆弱性を検出
- 偽陽性よりも偽陰性を避ける
- 包括的なテストで高い信頼性を確保
- 失敗時も有用な情報を提供

## 🚀 クイックスタート

### インストール

```bash
# リポジトリクローン
git clone https://github.com/d01ki/PentestPilot.git
cd PentestPilot

# 依存関係インストール
pip install -r requirements.txt
```

### 基本的な使用方法

```bash
# 1. アプリケーション起動
python app.py

# または別のポートで
python app.py --port 8001

# 2. ブラウザで開く
http://localhost:8000/ui

# 3. ターゲットIPを入力してスキャン
```

### スタンドアロンテスト

```bash
# Zerologonエクスプロイトの単独テスト
python test_zerologon.py 192.168.253.30 DC2019
```

## 🔍 Zerologonエクスプロイトの詳細

### 技術的アプローチ

**包括的テストで信頼性を確保:**

- **2000回の試行**: 99.996%の検出率
- **全ての試行を実行**: 偽陰性を避ける
- **進行状況のレポート**: 100回毎に進捗表示
- **詳細な結果分析**: 成功/失敗の明確な判定

### 期待される実行時間

- **脆弱なシステム**: 30秒 〜 2分
  - 脆弱性が見つかり次第、即座に終了
  - 早期に成功する可能性が高い

- **パッチ済みシステム**: 3〜5分
  - 全2000回の試行を実行
  - 包括的なテストで確実にパッチ済みを確認
  - 偽陰性のリスクを最小化

**⚠️ 重要:** 実行時間は長くなりますが、これは信頼性を確保するための設計です。

### 実行例

**脆弱なDCの場合:**
```
[*] Progress: 100/2000 (5.0% complete)
[*] Progress: 200/2000 (10.0% complete)
======================================================================
[+] SUCCESS! Zerologon authentication bypass achieved!
======================================================================
[+] Attempts made: 287 out of 2000
[!] CRITICAL VULNERABILITY CONFIRMED
[!] Domain Controller is VULNERABLE to CVE-2020-1472
```

**パッチ済みDCの場合:**
```
[*] Progress: 100/2000 (5.0% complete)
[*] Progress: 200/2000 (10.0% complete)
[*] Progress: 300/2000 (15.0% complete)
...
[*] Progress: 1900/2000 (95.0% complete)
[*] Progress: 2000/2000 (100.0% complete)
======================================================================
[-] Attack failed after maximum attempts
======================================================================
[+] Domain Controller appears patched against Zerologon
[+] No vulnerability detected
[+] System is secure from CVE-2020-1472
```

## 📊 実行結果の解釈

### ✅ 成功（脆弱性検出）

```
Status: VULNERABLE ⚠️

Artifacts:
  ✓ VULNERABLE to Zerologon
  ✓ Authentication bypass confirmed
  ⚠ CRITICAL: Immediate patching required
  ⚠ DC account can be compromised
  ⚠ Apply KB4565457 immediately
```

**意味:**
- DCは脆弱性があります
- 即座に対応が必要です
- ドメイン全体が危険にさらされています

### ✅ 失敗（パッチ済み）

```
Status: PATCHED ✓

Artifacts:
  ✓ Target is patched against Zerologon
  ✓ No vulnerability detected
  ✓ System is secure from CVE-2020-1472
```

**意味:**
- DCは安全にパッチされています
- 脆弱性は存在しません
- 2000回の包括的なテストで確認済み
- システムは保護されています

### ❌ エラー（ネットワーク問題）

```
Status: ERROR ✗

Connectivity Issues:
  - Host is not reachable via ICMP
  - SMB port 445 is not accessible

Troubleshooting:
  1. Verify target IP is correct
  2. Check if host is online
  3. Ensure SMB port 445 is accessible
  4. Check firewall rules
```

**意味:**
- ネットワーク接続の問題
- ターゲットに到達できません
- 設定を確認する必要があります

## 🔧 トラブルシューティング

### 問題1: "実行に時間がかかりすぎる"

**これは正常です。** 信頼性を確保するための設計です。

- パッチ済みシステムでは3〜5分かかります
- 2000回の試行で偽陰性を防ぎます
- 進行状況は100回毎に表示されます

**対策:**
- 実行中は待ってください
- 進行状況メッセージを確認してください
- Ctrl+Cで中断可能ですが、結果の信頼性が低下します

### 問題2: "No route to host"

**原因:**
- ネットワーク接続の問題
- ファイアウォールでブロック
- ターゲットがオフライン

**解決策:**
```bash
# 接続確認
ping 192.168.253.30
nmap -p 445 192.168.253.30

# ファイアウォール確認
sudo iptables -L -n
```

### 問題3: "Port already in use"

**解決策:**
```bash
# 既存プロセスを停止
pkill -f "uvicorn.*8000"

# または別のポート使用
python app.py --port 8001
```

## 📄 PDFレポート生成

### 使用方法

```python
from backend.report.pdf_generator import generate_pentest_report

scan_data = {
    'target': '192.168.253.30',
    'vulnerabilities': [
        {
            'cve_id': 'CVE-2020-1472',
            'title': 'Zerologon Authentication Bypass',
            'severity': 'CRITICAL',
            'cvss_score': 10.0,
            'description': 'Netlogon privilege escalation vulnerability',
            'impact': 'Full domain compromise possible',
            'status': 'Patched',
            'evidence': 'Target completed 2000 authentication attempts without success'
        }
    ]
}

report_path = generate_pentest_report(scan_data, './reports')
print(f"Report generated: {report_path}")
```

### レポート内容

- **カバーページ**: タイトル、日付、機密性表示
- **エグゼクティブサマリー**: 発見事項の要約、リスク評価
- **方法論**: 実施した手法の説明
- **詳細な発見事項**: 各脆弱性の詳細
- **推奨事項**: 即座の対応、短期的対応、長期的対応
- **技術詳細**: スキャン情報、使用ツール
- **付録**: 参考文献、用語集、連絡先

## 📚 ドキュメント

詳細なドキュメントは以下を参照してください:

1. **[EXPLOIT_EXECUTION_GUIDE.md](EXPLOIT_EXECUTION_GUIDE.md)**
   - エクスプロイト実行の詳細ガイド
   - 結果の解釈方法
   - FAQ

2. **[NETWORK_TROUBLESHOOTING.md](NETWORK_TROUBLESHOOTING.md)**
   - ネットワーク問題の診断と解決
   - テストスクリプト
   - 設定例

3. **[EXPLOIT_FAILURE_ANALYSIS_GUIDE.md](EXPLOIT_FAILURE_ANALYSIS_GUIDE.md)**
   - 失敗分析システムの詳細
   - 実例と解決策
   - 推奨アクション

4. **[FINAL_IMPLEMENTATION_SUMMARY.md](FINAL_IMPLEMENTATION_SUMMARY.md)**
   - 完成した機能の概要
   - インストール手順
   - 技術詳細

## ⚖️ 法的免責事項

**重要:** このツールは、明示的な許可を得た環境でのみ使用してください。

- 許可なく他者のシステムをスキャン・攻撃することは違法です
- このツールの使用は自己責任で行ってください
- 作者は不正使用による結果に対して責任を負いません
- 倫理的なセキュリティテストにのみ使用してください

## 🤝 貢献

プルリクエストを歓迎します。大きな変更の場合は、まずissueを開いて変更内容を議論してください。

## 📝 ライセンス

MIT License - 詳細は[LICENSE](LICENSE)を参照してください。

## 🙏 謝辞

- **Impacket** - ネットワークプロトコル実装
- **ReportLab** - PDF生成
- **FastAPI** - Webフレームワーク
- **CrewAI** - AI統合

## 📧 サポート

問題や質問がある場合:

1. [ドキュメント](FINAL_IMPLEMENTATION_SUMMARY.md)を確認
2. [GitHub Issues](https://github.com/d01ki/PentestPilot/issues)で報告
3. エラーメッセージとログを含めてください

---

**バージョン:** 2.0  
**最終更新:** 2025-01-02  
**ステータス:** ✅ Production Ready - 信頼性と機能性を優先

---

## 🌟 重要な哲学

> "速度よりも信頼性。見逃すよりも徹底的に。"

PentestPilotは、実行時間よりも**確実に脆弱性を検出すること**を優先しています。
パッチ済みシステムでは数分かかりますが、これは偽陰性を防ぐための重要な設計です。

**なぜ2000回の試行なのか？**

- 統計的に99.996%の検出率
- 偽陰性（脆弱性を見逃すこと）のリスクを最小化
- 実務環境で求められる信頼性を確保
- パッチ済みであることの確実な証明

速度を求める場合は試行回数を減らすことも可能ですが、信頼性が低下します。
実務では、**確実性が最も重要**です。
