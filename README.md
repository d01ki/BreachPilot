# 🚀 BreachPilot - 簡潔版セットアップ

## クイックスタート

```bash
# 1. 依存関係インストール
pip install flask python-dotenv

# 2. 実行
python app.py

# 3. アクセス
http://localhost:5000/pentest
```

## 動作フロー

1. **Port Scan (Mock)** - 2秒
   - Zerologon脆弱性のあるDC環境をシミュレート
   - 10ポート検出

2. **CVE Analysis** - 即座
   - パターンマッチングでCVE特定
   - Zerologon (CVE-2020-1472)
   - SMBGhost (CVE-2020-0796)
   - BlueKeep (CVE-2019-0708)

3. **結果表示**
   - Port Scan結果
   - CVE + PoC情報

## トラブルシューティング

### 結果が表示されない場合

```bash
# ブラウザでF12 → Console
# Status data を確認

# reports/ フォルダを確認
ls -la reports/
cat reports/{chain_id}/scan.json
cat reports/{chain_id}/vulnerabilities.json
```

### OpenAI使用する場合

```bash
export OPENAI_API_KEY="sk-..."
pip install crewai langchain-openai
```

現在はフォールバックモードで確実に動作します。
