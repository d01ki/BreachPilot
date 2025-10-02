# Network Troubleshooting Guide

## 🔍 "No Route to Host" Error

### Error Message
```
OSError: [Errno 113] No route to host
impacket.dcerpc.v5.rpcrt.DCERPCException: Could not connect
```

### What This Means

このエラーは、BreachPilotが対象のDomain Controllerに接続できないことを意味します。これはネットワーク接続の問題であり、脆弱性検査の問題ではありません。

## ✅ 解決手順

### 1. 基本的な接続確認

#### ステップ 1: Pingテスト
```bash
ping 192.168.253.30
```

**期待される結果:**
```
64 bytes from 192.168.253.30: icmp_seq=1 ttl=128 time=1.23 ms
```

**エラーの場合:**
```
Destination Host Unreachable
```
→ ネットワーク接続の問題

#### ステップ 2: SMBポート確認
```bash
nmap -p 445 192.168.253.30
```

**期待される結果:**
```
445/tcp open  microsoft-ds
```

**エラーの場合:**
```
445/tcp filtered microsoft-ds
```
→ ファイアウォールでブロックされている

#### ステップ 3: RPC接続テスト
```bash
rpcclient -U "" 192.168.253.30
```

**期待される結果:**
```
rpcclient $> 
```

**エラーの場合:**
```
Cannot connect to server
```
→ RPCサービスが利用できない

### 2. よくある原因と解決策

#### 原因 1: 異なるネットワークセグメント

**症状:**
- Pingが失敗
- "No route to host"

**確認:**
```bash
# 自分のIPアドレスを確認
ip addr show

# ルーティングテーブルを確認
route -n
```

**解決策:**
- 同じネットワークに接続
- VPN経由で接続
- ルーティング設定を追加

#### 原因 2: ファイアウォールでブロック

**症状:**
- Pingは成功するがSMBポートが閉じている
- "Connection refused" または "No route to host"

**確認:**
```bash
# Linuxファイアウォール確認
sudo iptables -L -n

# Windows Firewallの場合
# Windowsの"セキュリティとメンテナンス"から確認
```

**解決策:**
```bash
# Linux: 一時的にファイアウォールを無効化（テスト目的）
sudo iptables -F

# または特定のIPを許可
sudo iptables -A OUTPUT -d 192.168.253.30 -j ACCEPT
```

#### 原因 3: ターゲットDCがオフライン

**症状:**
- すべての接続テストが失敗

**確認:**
- DCの電源状態を確認
- DCのネットワークケーブルを確認
- DCの管理コンソールにアクセス

**解決策:**
- DCを起動
- ネットワーク設定を確認

#### 原因 4: VMwareやHyper-Vのネットワーク設定

**症状:**
- 仮想環境内でのみ問題が発生

**確認:**
- VMのネットワークアダプタ設定
- ブリッジモード vs NATモード

**解決策:**
```
VMware:
1. VM Settings → Network Adapter
2. "Bridged" モードに変更
3. 物理ネットワークアダプタを選択

Hyper-V:
1. VM Settings → Network Adapter
2. "External" スイッチを選択
```

### 3. ネットワーク設定例

#### 推奨されるネットワーク構成

```
[BreachPilot] 192.168.253.10/24
      |
      | (同じネットワーク)
      |
[Target DC]   192.168.253.30/24
```

#### ファイアウォールルール

**必要なポート:**
- TCP 445 (SMB/CIFS)
- TCP 135 (RPC Endpoint Mapper)
- TCP 139 (NetBIOS)
- Dynamic RPC ports (49152-65535)

**iptablesルール例:**
```bash
# SMBを許可
sudo iptables -A OUTPUT -p tcp --dport 445 -d 192.168.253.30 -j ACCEPT

# RPCを許可
sudo iptables -A OUTPUT -p tcp --dport 135 -d 192.168.253.30 -j ACCEPT

# Dynamic RPCポートを許可
sudo iptables -A OUTPUT -p tcp --dport 49152:65535 -d 192.168.253.30 -j ACCEPT
```

## 🔄 修正されたエクスプロイト実行フロー

### 新しい実行プロセス

```
1. Pre-flight Check
   ├─ Ping Test
   ├─ SMB Port Check (445)
   └─ Result: ✅ or ❌
       |
       ├─ ✅ Continue to Exploit
       └─ ❌ Show Error & Troubleshooting

2. Exploit Execution
   ├─ Connect to Netlogon
   ├─ Perform Attack
   └─ Return Result
```

### 改善されたエラーメッセージ

**修正前:**
```python
Traceback (most recent call last):
  File "/tmp/tmp.py", line 24
    binding = epm.hept_map(...)
OSError: [Errno 113] No route to host
```

**修正後:**
```
[!] Pre-flight check failed

Connectivity Issues:
  - Host 192.168.253.30 is not reachable via ICMP
  - SMB port 445 is not accessible on 192.168.253.30

[*] Troubleshooting:
  1. Verify target IP is correct: 192.168.253.30
  2. Check if host is online: ping 192.168.253.30
  3. Ensure SMB port 445 is accessible
  4. Check firewall rules
  5. Verify you're on the same network

Artifacts:
  ⚠ Network connectivity issue
  ✗ Cannot reach target - Check network/firewall
```

## 🧪 テスト手順

### 完全なネットワークテスト

```bash
#!/bin/bash
# network_test.sh

TARGET="192.168.253.30"

echo "========================================"
echo "Network Connectivity Test for $TARGET"
echo "========================================"
echo

echo "[1] Ping Test..."
ping -c 3 -W 2 $TARGET
if [ $? -eq 0 ]; then
    echo "✓ Ping successful"
else
    echo "✗ Ping failed"
fi
echo

echo "[2] SMB Port (445) Test..."
nc -zv $TARGET 445 -w 3
if [ $? -eq 0 ]; then
    echo "✓ SMB port accessible"
else
    echo "✗ SMB port not accessible"
fi
echo

echo "[3] RPC Endpoint Mapper (135) Test..."
nc -zv $TARGET 135 -w 3
if [ $? -eq 0 ]; then
    echo "✓ RPC port accessible"
else
    echo "✗ RPC port not accessible"
fi
echo

echo "[4] Traceroute..."
traceroute -m 10 $TARGET
echo

echo "Test complete!"
```

### 実行方法

```bash
chmod +x network_test.sh
./network_test.sh
```

## 📊 エラー診断チャート

```
接続失敗
    |
    ├─ Pingが失敗
    |   |
    |   ├─ ホストがオフライン
    |   └─ ネットワークルーティング問題
    |
    ├─ Pingは成功、SMBポート失敗
    |   |
    |   ├─ ファイアウォールでブロック
    |   └─ SMBサービスが停止
    |
    └─ 全て成功するが接続失敗
        |
        ├─ Impacketのバグ
        └─ DCのNetlogonサービス問題
```

## 💡 ベストプラクティス

### テスト環境の推奨構成

1. **隔離されたネットワーク**
   - 本番環境と分離
   - 専用のVLAN
   - インターネットから隔離

2. **ネットワーク構成**
   ```
   [Physical Network]
        |
        ├─ [BreachPilot VM]
        |   IP: 192.168.253.10
        |   Network: Bridged
        |
        └─ [Test DC VM]
            IP: 192.168.253.30
            Network: Bridged
   ```

3. **ファイアウォール設定**
   - テスト中は最小限のルール
   - 必要なポートのみ開放
   - テスト後は元に戻す

### トラブルシューティングチェックリスト

- [ ] ターゲットIPが正しい
- [ ] ターゲットがオンライン
- [ ] 同じネットワークセグメント
- [ ] ファイアウォールルールが適切
- [ ] SMBポート445が開いている
- [ ] RPCポート135が開いている
- [ ] Netlogonサービスが起動
- [ ] impacketが正しくインストール
- [ ] Python環境が正しい

## 🔧 高度なトラブルシューティング

### Wiresharkでパケットキャプチャ

```bash
# ネットワークトラフィックをキャプチャ
sudo tcpdump -i eth0 -w capture.pcap host 192.168.253.30

# または Wireshark で
# Filter: ip.addr == 192.168.253.30
```

### Netlogonサービス確認（DC側）

```powershell
# PowerShell on DC
Get-Service Netlogon

# サービスが停止している場合
Start-Service Netlogon

# ログ確認
Get-EventLog -LogName System -Source Netlogon -Newest 50
```

### ネットワークインターフェース確認

```bash
# 利用可能なインターフェース
ip link show

# インターフェース設定
ip addr show eth0

# ルーティングテーブル詳細
ip route show

# ARPテーブル
arp -a
```

## 📚 参考リソース

### Microsoft公式ドキュメント

- [Netlogon Service](https://docs.microsoft.com/en-us/windows-server/security/netlogon)
- [SMB Protocol](https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smb-known-issues)
- [RPC Port Requirements](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)

### トラブルシューティングツール

1. **nmap** - ポートスキャン
2. **tcpdump/Wireshark** - パケットキャプチャ
3. **nc (netcat)** - ポート接続テスト
4. **rpcclient** - RPC接続テスト
5. **smbclient** - SMB接続テスト

## ❓ FAQ

### Q: Pingは成功するのにExploitが失敗する

A: SMBポート(445)がブロックされている可能性があります。ファイアウォール設定を確認してください。

### Q: 同じネットワークにいるのに接続できない

A: VMのネットワーク設定を確認してください。NATモードではなくBridgedモードを使用する必要があります。

### Q: DCに直接アクセスできるのにBreachPilotから接続できない

A: BreachPilotを実行しているホストのファイアウォール設定を確認してください。

### Q: 他のツール（nmap等）は動作するのにZerologonが失敗する

A: impacketライブラリの問題の可能性があります。以下を試してください：
```bash
pip install --force-reinstall impacket
```

---

**ドキュメントバージョン:** 1.0  
**最終更新:** 2025-01-02  
**作成者:** BreachPilot Security Team
