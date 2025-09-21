# 🚀 Quick Setup Guide

## ✅ 即座にテスト可能（ツール不要）

```bash
git pull
python app.py
```

**http://localhost:5000/pentest** にアクセス

任意のターゲット名を入力（例: `test.example.com`）→ 結果が返ります！

---

## 📊 実装済み機能

### ✅ シミュレーションモード（デフォルト）
- ツールのインストール不要
- リアルなデータを生成
- 12秒で完了

### ✅ CrewAI分析（オプション）
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

3つのAIエージェントが協力：
1. **Vulnerability Analyst** - CVE特定
2. **CVE Researcher** - 詳細調査
3. **XAI Explainer** - 根拠説明

### ✅ XAI（説明可能AI）
各CVEに対して：
- **WHY** - なぜ特定されたか
- **EVIDENCE** - 証拠
- **ATTACK VECTOR** - 攻撃方法
- **IMPACT** - 影響度

---

## 📁 プロジェクト構成

```
BreachPilot/
├── app.py                          # Flask app
├── templates/pentest.html          # UI with XAI display
├── src/
│   ├── tools/
│   │   └── simulation_tools.py    # シミュレーション
│   └── agents/
│       ├── realtime_orchestrator.py   # タスク実行
│       └── ai_vulnerability_analyst.py # CrewAI分析
└── reports/{chain_id}/             # 結果
    ├── osint.json
    ├── nmap.json
    └── ai_vulnerabilities.json
```

---

## 🎯 使い方

### 1. シミュレーションテスト（推奨）
```bash
python app.py
# http://localhost:5000/pentest
# Target: demo.target.com
# ✅ 12秒で結果表示
```

### 2. AI分析付き
```bash
export ANTHROPIC_API_KEY="your-key"
pip install crewai langchain-anthropic
python app.py
```

### 3. 実ツール使用
```bash
export SIMULATION_MODE="false"
pip install dnspython python-whois pyOpenSSL
sudo apt-get install nmap
python app.py
```

---

## 🔍 結果の確認

### UI表示
1. **進捗バー** - 0% → 50% → 100%
2. **ライブログ** - リアルタイム実行
3. **結果カード**:
   - OSINT: DNS, Subdomains, SSL
   - Nmap: Open ports, Services
   - CVE: Vulnerabilities with severity
   - XAI: AI reasoning for each CVE

### JSONファイル
```bash
cat reports/{chain_id}/ai_vulnerabilities.json
```

---

## 🐛 トラブルシューティング

### 結果が表示されない
```javascript
// F12 → Console
// エラーを確認
```

### 進捗バーが動かない
```bash
# APIレスポンス確認
curl http://localhost:5000/api/attack-chain/{id}/status
```

### シミュレーションを無効化
```bash
export SIMULATION_MODE="false"
```

---

## 📊 シミュレーション結果例

```json
{
  "osint": {
    "subdomains": ["www.target.com", "mail.target.com", ...],
    "dns_records": {"A": ["192.168.1.100"], ...}
  },
  "nmap": {
    "ports": [
      {"port": "22", "service": "ssh", "version": "OpenSSH 7.4"},
      {"port": "80", "service": "http", "version": "Apache 2.4.6"}
    ]
  },
  "vulnerabilities": {
    "vulnerabilities": [
      {
        "cve": "CVE-2021-44228",
        "severity": "CRITICAL",
        "cvss_score": 10.0
      }
    ],
    "xai_explanations": {
      "CVE-2021-44228": {
        "why_identified": "Apache version matches vulnerable range",
        "evidence": "Service: Apache 2.4.6 on port 8080",
        "attack_vector": "Remote code execution via Log4j",
        "impact": "Full system compromise possible"
      }
    }
  }
}
```

---

## 🎉 まとめ

**必要な手順：**
```bash
git pull
python app.py
```

**それだけ！** すぐに動作確認できます。

API keyがあれば、より高度なAI分析も利用可能です。
