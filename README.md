# BreachPilot 🚀

<div align="center">

![Python Version](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![AI Powered](https://img.shields.io/badge/AI-Claude%20Powered-purple.svg)
![Framework](https://img.shields.io/badge/Framework-CrewAI-orange.svg)
![Status](https://img.shields.io/badge/Status-Alpha-yellow.svg)

**AI-powered penetration testing tool using CrewAI with Human-in-the-loop design**

[🚀 Quick Start](#-quick-start) • [📚 Documentation](docs/) • [🤝 Contributing](CONTRIBUTING.md) • [🛡️ Security](docs/SECURITY.md)

</div>

---

## 🎯 概要

BreachPilotは、LLM（Claude）とCrewAIを活用してペネトレーションテストの初期診断から脆弱性分析、レポート生成までを自動化するCLIツールです。

### ✨ 主な特徴

- **🤖 AI エージェント構成**: 3つの専門エージェント（ReconAgent, PoCAgent, ReportAgent）
- **🛡️ Human-in-the-Loop**: 重要な決定には必ずユーザーの承認が必要
- **📊 プロフェッショナルレポート**: Markdown形式での包括的なセキュリティレポート
- **🎓 教育重視**: 学習と理解を促進する詳細な説明と安全な設計
- **🔒 セキュリティファースト**: 安全なデフォルト設定と包括的なロギング

### 🎯 対象ユーザー

- サイバーセキュリティ研究者・教育者
- ペネトレーションテスト学習者
- 発表・教育デモを行う技術者
- 認可されたセキュリティテスト実施者

## 🚀 Quick Start

### インストール

```bash
# リポジトリのクローン
git clone https://github.com/d01ki/BreachPilot.git
cd BreachPilot

# 自動インストール（推奨）
chmod +x scripts/install.sh
./scripts/install.sh

# Claude API キーの設定
export ANTHROPIC_API_KEY="your-claude-api-key-here"
```

### 基本的な使用方法

```bash
# 基本スキャン
breachpilot --target 192.168.1.10

# カスタムレポート出力
breachpilot --target scanme.nmap.org --output my_report.md --verbose

# デモ実行（安全なテストターゲット使用）
./scripts/demo.sh
```

## 🏗️ システム構成

### エージェント アーキテクチャ

```
┌─────────────────────────────────────────────────────────────────┐
│                     BreachPilot Crew                           │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   ReconAgent    │   PoCAgent      │      ReportAgent            │
│                 │                 │                             │
│ • Nmap スキャン  │ • CVE 分析      │ • Markdown レポート生成      │
│ • サービス検出   │ • ユーザー承認   │ • 推奨事項作成              │
│ • 結果構造化     │ • リスク評価     │ • 方法論文書化              │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

### ワークフロー

1. **🔍 偵察フェーズ（自動）**
   - Nmapによるポート・サービススキャン
   - サービスバージョンの識別
   - JSON形式での結果保存

2. **🎯 脆弱性分析フェーズ（ユーザー承認必須）**
   - CVE候補の推定と提示
   - ユーザーによる承認・却下の判断
   - 承認されたCVEのみ次工程へ

3. **📋 レポート生成フェーズ（自動）**
   - 包括的なMarkdownレポート作成
   - エグゼクティブサマリーと技術詳細
   - 実行可能な改善推奨事項

## 📖 使用例

### シナリオ1: Windows Server のテスト

```bash
breachpilot --target 192.168.1.100 --output windows_assessment.md
```

**想定されるフロー:**
1. SMB、RDP等のWindowsサービスを発見
2. EternalBlue (CVE-2017-0144) 等のCVEを提案
3. ユーザーが関連するCVEを承認
4. Windows固有の推奨事項を含むレポートを生成

### シナリオ2: Linux Webサーバーの評価

```bash
breachpilot --target webserver.example.com --verbose
```

**想定されるフロー:**
1. HTTP/HTTPS、SSHサービスを発見
2. Apache/Nginxのバージョンを特定
3. Webサーバーおよび SSH の CVE を提案
4. ユーザーが脆弱性を選択
5. Webセキュリティ推奨事項を含むレポートを作成

## 🛡️ セキュリティについて

> **⚠️ 重要な注意事項**
> 
> このツールは教育および認可されたテスト目的でのみ設計されています。許可されたネットワークでのみ使用してください。

### セキュリティ機能

- ✅ **明示的承認**: CVE選択とPoC実行には必ずユーザー承認が必要
- ✅ **自動攻撃なし**: 識別に焦点を置き、自動的な攻撃は行わない
- ✅ **包括的ログ**: すべての判断とアクションを記録
- ✅ **安全なデフォルト**: 控えめなスキャンパラメータとタイムアウト保護

### 法的コンプライアンス

- 所有するシステムまたは明示的な許可を得たシステムでのみ使用
- すべての活動を文書化し、監査証跡を維持
- 適用される法律と規制の遵守

## 📊 サンプルレポート

生成されるレポートには以下が含まれます：

```markdown
# BreachPilot Penetration Test Report

**Target**: 192.168.1.10
**Date**: 2024-09-04

## 🎯 Executive Summary
3つのオープンポートで1つの高重要度脆弱性を特定しました。

## 🔍 Findings

### Port 445/tcp - Microsoft-DS (SMB)
- **Service**: Windows Server 2008 R2
- **Status**: ⚠️ Vulnerable
- **CVE**: CVE-2017-0144 (EternalBlue)
- **Severity**: Critical
- **CVSS**: 8.1

## 📝 Recommendations
1. **即座の対応**: MS17-010セキュリティ更新プログラムの適用
2. **ネットワーク**: SMBアクセスの制限
3. **監視**: SMBログの有効化
```

## 🔧 開発とカスタマイズ

### カスタムエージェントの作成

```python
from crewai import Agent
from crewai.tools import tool

@tool
def custom_security_scan(target: str) -> str:
    """カスタムセキュリティスキャンツール"""
    # カスタム実装
    pass

class CustomSecurityAgent:
    def __init__(self):
        self.agent = Agent(
            role="カスタムセキュリティ専門家",
            goal="専用ツールを使用した専門的セキュリティ分析",
            tools=[custom_security_scan]
        )
```

### カスタムレポートテンプレート

```python
class CustomReportTemplate:
    def generate_report(self, findings):
        # カスタムレポート形式の実装
        return custom_formatted_report
```

## 📋 必要なシステム要件

### 最小要件
- **OS**: Linux (Kali推奨), macOS, Windows (WSL2)
- **Python**: 3.10以上
- **メモリ**: 最低4GB RAM
- **ネットワーク**: インターネット接続（CVE検索とAI処理用）

### 必要なツール
- **Nmap**: ネットワークスキャン用
- **Git**: リポジトリ管理用
- **Claude API**: AI分析用（ANTHROPIC_API_KEY が必要）

## 🐛 トラブルシューティング

### よくある問題

#### "Target unreachable"
- ネットワーク接続を確認
- ターゲットIP/ホスト名を検証
- ファイアウォール規則を確認

#### "No CVEs found"
- サービスが最新の可能性
- CVEデータベースにエントリがない可能性
- サービスバージョン検出を確認

#### "API key error"
- ANTHROPIC_API_KEY が設定されているか確認
- APIキーの権限を確認
- インターネット接続を確認

## 📚 詳細ドキュメント

- [📦 インストールガイド](docs/INSTALLATION.md) - 詳細なセットアップ手順
- [📖 使用方法ガイド](docs/USAGE.md) - コマンドラインオプションとワークフロー
- [🛡️ セキュリティ考慮事項](docs/SECURITY.md) - 重要な安全情報
- [🏗️ アーキテクチャ概要](docs/ARCHITECTURE.md) - 技術実装詳細
- [🤝 コントリビューションガイド](CONTRIBUTING.md) - プロジェクトへの貢献方法

## 🤝 コミュニティとサポート

- **GitHub Issues**: バグ報告と機能リクエスト
- **GitHub Discussions**: 質問と経験の共有
- **Contributing**: みんなのためのBreachPilot改善
- **Security**: セキュリティ問題の責任ある開示

## 🗓️ ロードマップ

### v0.2.0 (予定)
- [ ] マルチターゲットスキャン対応
- [ ] リアルタイムCVEデータベース統合
- [ ] PDF/JSON レポート形式
- [ ] パフォーマンスの最適化

### v0.3.0 (予定)
- [ ] Webベースダッシュボード
- [ ] MITRE ATT&CK フレームワークマッピング
- [ ] プラグインシステム
- [ ] Docker コンテナ化

### v1.0.0 (予定)
- [ ] エンタープライズ機能
- [ ] 高度なレポート機能
- [ ] クラウドデプロイメントオプション
- [ ] 商用サポート

## 📄 ライセンス

BreachPilotは[MIT License](LICENSE)の下でリリースされています。詳細についてはLICENSEファイルを参照してください。

## ⚖️ 法的通知

このツールは教育と認可されたテスト目的でのみ提供されています。ユーザーはシステムをスキャンする前に適切な認可を得ていることを確認する責任があります。開発者はこのツールの誤用について一切の責任を負いません。

## 🎉 謝辞

- **Anthropic** - Claude AIプラットフォームの提供
- **CrewAI** - 優秀なマルチエージェントオーケストレーションフレームワーク
- **Nmap Project** - 強力なネットワークスキャン機能
- **セキュリティコミュニティ** - 継続的なフィードバックとサポート

---

<div align="center">

**🚀 今すぐ始めよう!**

[📦 BreachPilotをインストール](docs/INSTALLATION.md) | [📚 ドキュメントを読む](docs/USAGE.md) | [🤝 コントリビュート](CONTRIBUTING.md)

---

<sub>Made with ❤️ for the cybersecurity education community</sub>

</div>
