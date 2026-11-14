# WiFi Signal & Stability Analyzer

> **Created with AI**: 本ツールは **Google Antigravity** 上で **Orchestrator (Argon)**（Google DeepMind Gemini モデル）を使用して作成されました。

接続中のWi-Fiアクセスポイントについて、以下の4つの観点から信号品質・回線安定性・速度・安全性を総合診断し、用途別の適性（`◎ 最適` / `○ 快適` / `△ 注意` / `× 不向き`）を判定するクロスプラットフォームGUIツールです。

外部の `pip` パッケージを必要とせず、Python標準ライブラリのみで動作します（macOS / Windows / Linux 対応）。

## 評価項目

1. **信号品質 (RF Signal)**
   - RSSI (`-n dBm`)、ノイズフロア、SNR (`dB`)、周波数帯 (`2.4GHz` / `5GHz` / `6GHz`)、リンク速度、PHY規格 (`802.11ax` 等)
   - macOS (`CoreWLAN` + `system_profiler` + `ipconfig` + `networksetup`)、Windows (`netsh wlan`)、Linux (`nmcli` / `iw` / `/proc/net/wireless`) に対応
2. **安定性 (Ping RTT & パケットロス)**
   - 異なるAS/役割を持つ4つの推奨ターゲットへ低負荷で並列Ping（軽量モード: 各4回 / 0.25秒間隔）を実施
     - `1.1.1.1` — **Cloudflare DNS (Anycast)**: 高速エッジまでのIP直接疎通・基本RTT測定
     - `8.8.8.8` — **Google Public DNS (Anycast)**: 別AS経路での安定性・特定ISP経路障害の切り分け
     - `9.9.9.9` — **Quad9 DNS (Anycast)**: 第3の独立Anycastネットワークでの到達性確認
     - `google.co.jp` — **Google JP**: DNS名前解決を含む国内Web到達性の確認
   - `--targets` オプションやGUIの入力欄から測定先をカスタマイズ可能
   - 最小 / 平均 / 最大RTT、ジッター（ゆらぎ）、パケットロス率を算出（ICMP遮断環境では `TCP-443` 計測に自動フォールバック）
3. **通信速度 (Cloudflare Speedtest / `cloudflare-speed-cli`)**
   - [kavehtehrani/cloudflare-speed-cli](https://github.com/kavehtehrani/cloudflare-speed-cli) を `--json` モードで呼び出し、ダウンロード / アップロード速度・待機時遅延 / 負荷時遅延 (Bufferbloat指標)・接続先Colo/ISPを高精度に測定
   - 未導入の場合は対応OS/CPUの公式リリースバイナリをSHA-256検証付きで `./bin/` へ自動配置（オフラインや実行不可時は内蔵Pythonクライアントへフォールバック）
   - 軽量モードでは短時間・少数並列 (`3s` / concurrency `3`) に抑えて回線負荷を軽減
4. **セキュリティリスク**
   - 認証/暗号化方式 (`WPA3`, `WPA2`, `WPA (TKIP)`, `WEP`, `OWE`, `Open`) の判定
   - 公開/フリーWi-Fi特有のSSIDパターン検知と、HTTPキャプティブポータル検出

## 適性を判定する6つの用途

- **Webブラウジング・SNS・メール**
- **高画質動画視聴 (YouTube / 4K配信)**
- **Web会議・音声通話 (Zoom / Teams)**
- **オンラインゲーム (FPS・対人対戦)**
- **大容量ファイル送受信・クラウド作業**
- **機密業務・ネットバンキング・決済**

## 評価モードとリアルタイム監視

* **単発診断モード**:
  * `light`（低負荷・推奨） / `standard`（詳細計測） / `ping-only`（速度計測なし）
* **リアルタイム連続監視モード (`realtime`)**:
  * 常に複数の宛先へ低負荷Pingを送信しつつ Wi-Fi 信号強度 (`RSSI`, `Noise`, `SNR`, リンク速度) を監視します。
  * **直近3分間（180秒）の平均値によるランク評価**: 単発のスパイクだけで判定が上下しないよう、セッション内の過去3分間（経過3分未満の場合は開始からの全データ）のRF・RTT・ジッター・ロス率を平均化してランク・用途別適性を評価します。
  * **セッションCSV自動保存**: 監視中の各測定データを日時・SSID付きで `reports/realtime_<YYYYMMDD_HHMMSS>_<SSID>.csv` へ自動記録します（カラム: `日時`, `SSID`, `RF`, `ping ms`, `jitter`, `パケットロスしたかどうか`, `パケットロス率`, `最大ping ms`, `ノイズ(dBm)`, `SNR(dB)`, `周波数帯`, `チャネル`, `リンク速度(Mbps)`, `BSSID`, `信号スコア`, `安定性スコア`, `セッション評価スコア`, `セッション評価ランク`, `単発スコア`, `単発ランク`, `検知イベント`）。
  * **異常検知**: パケットロス発生・ジッター/RTTの急変動（ブレ）・高遅延スパイク・RF信号低下を検知すると警告バナーとタイムスタンプ付きイベントログに表示します。
  * **推移グラフ**: GUI上で `Ping RTT & ジッター (ms)` と `パケットロス率 (%) & RSSI (dBm)` の時系列グラフを描画します。
  * 新しい診断や監視を開始すると、直前に表示されていた記録・グラフ・ログは即座にクリアされます。

## 使い方

### GUIの起動（デフォルト）
```bash
python3 wifi_analyzer.py
```

- GUIは起動直後は**待機状態**で開き、「診断を実行」または「リアルタイム監視」ボタンを押したタイミングで測定を開始します。
- macOS ではネイティブ Cocoa + `WKWebView` ウィンドウ (`./bin/macos_webview`) でダッシュボードGUIを表示します。
- Windows / Linux では Tcl/Tk 8.6 以上の Tkinter デスクトップGUI（または利用不可環境ではローカルWebダッシュボードGUI）を起動します。

### 起動オプション

```bash
# ローカルWebダッシュボードGUI（ブラウザ）を明示的に起動
python3 wifi_analyzer.py --gui web

# TkinterデスクトップGUIを明示的に起動 (Tcl/Tk 8.6以上)
python3 wifi_analyzer.py --gui tk

# CLIモードで要点を絞ったサマリーを出力
python3 wifi_analyzer.py --cli

# CLIモードでリアルタイム連続監視を実行 (Ctrl+Cで停止、--ticks で回数指定、--csv で保存先指定も可)
python3 wifi_analyzer.py --cli --mode realtime

# CLIモードで詳細Markdownレポートを出力
python3 wifi_analyzer.py --cli --md

# CLIモードでJSON出力（詳細モード）
python3 wifi_analyzer.py --json --mode standard

# 速度測定を行わず、信号品質・Ping・セキュリティのみ高速診断
python3 wifi_analyzer.py --cli --mode ping-only
```

## テストの実行

```bash
python3 -m unittest discover -s tests -v
```
