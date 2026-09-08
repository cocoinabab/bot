BedrockTrafficWatch v7 ULTIMATE
===============================

用途
----
這是給 Minecraft Bedrock BOT 功能研究用的最終整合抓包版。
保留「正常 Minecraft 客戶端」的多層資料，讓同一個操作可以從：

遊戲 Packet struct -> 原始 MCPE packet bytes -> RakNet frame -> 原始 UDP/IP

一路往下對照。

V7 同時記錄
-----------
1. decoded-*.log
   人類容易搜尋的摘要。

2. full-*.jsonl.gz
   所有 gophertunnel 已解密 Packet 的完整遞迴 struct dump。
   pointer / interface / struct / slice / array / map / Optional 會往內展開。
   []byte / [N]byte 保存完整 HEX。

3. raw-mcpe-*.jsonl.gz
   gophertunnel PacketFunc 提供的原始 MCPE packet header + payload。
   client-leg 與 server-leg 都抓，因此可以比較：
   C->Proxy / Proxy->Server / Server->Proxy / Proxy->Client。
   每筆保存 packet id、sub-client IDs、src/dst、payload HEX、完整 packet HEX。

   安全例外：Login packet 可能包含登入憑證，因此 payload 不落盤，
   只保留長度與 SHA-256。遊戲中的一般 Packet 不受影響。

4. events-*.jsonl.gz
   高價值 Packet 的快速索引，例如 movement / pickup / inventory /
   container / block / interaction / combat_or_use / form / command。

5. links-*.jsonl.gz
   將 full dump 的 packet seq 對應 ingress/egress raw MCPE seq，
   方便比較「客戶端原始 packet」與「proxy 重新送往另一端的 packet」。

6. wire-pre-*.pcap
   WinDivert priority -1000：在透明改寫之前看到的原始 UDP/IP。
   對客戶端送出流量，可看到原本的伺服器 IP/port。

7. wire-post-*.pcap
   WinDivert priority +1000：在透明改寫/重注入之後看到的 UDP/IP。
   可用來確認 NAT rewrite、實際送出方向與低層封包差異。

8. wire-index-*.jsonl.gz
   PCAP 的 RakNet 快速索引，包含：
   - inbound/outbound
   - src/dst
   - ACK / NAK records
   - datagram sequence
   - frame reliability
   - message index
   - sequence index
   - ordering index / channel
   - split count / id / index
   - OpenConnection MTU（可解析時）
   - frame body preview

使用
----
1. 解壓縮整個資料夾。
2. 雙擊 START_V7_ULTIMATE.cmd。
3. V7 會自動尋找舊版的 WinDivert.dll + WinDivert64.sys。
   找不到時，再把 DLL/SYS 放到 V7 資料夾同一層。
4. V7 也會嘗試沿用舊版 private\microsoft-token.json。
5. 看到 [DECRYPTED] 後才開始做要研究的遊戲動作。
6. 每種動作建議做 3~5 次，中間停 1~2 秒：
   - 走 / 跑 / 跳 / 蹲
   - 挖方塊 / 放方塊
   - 撿物 / 丟物
   - 切快捷欄
   - 使用物品 / 吃東西 / 拉弓
   - 攻擊玩家 / 生物 / 互動實體
   - 開箱 / 桶 / 熔爐 / 其他容器
   - 背包搬物 / 分堆 / 合併
   - 指令 / 表單
7. 完成後正常關閉程式，等檔案 flush 完成。
8. 檔案太大時，雙擊 PACK_LATEST.cmd，它會把最新一組抓包整理成 ZIP。
   private\microsoft-token.json 絕對不會加入 ZIP。

最重要要傳給 ChatGPT 的檔案
---------------------------
優先：
  full-*.jsonl.gz
  raw-mcpe-*.jsonl.gz
  events-*.jsonl.gz
  links-*.jsonl.gz
  decoded-*.log

如果要查 RakNet / Invalid action / timeout / 重傳 / ACK/NAK / ordering：
  wire-index-*.jsonl.gz
  wire-pre-*.pcap
  wire-post-*.pcap

注意
----
- PCAP 是 raw IP link type 101，可用 Wireshark 開啟。
- pre/post PCAP 是兩個觀察點，不是重複檔；它們用來比較透明改寫前後。
- RakNet frame parser 是診斷用 best-effort 索引；PCAP 本身仍保留完整原始 bytes，
  因此即使索引遇到未來協議差異，也可以回到 PCAP 重新分析。
- 不要把 private\microsoft-token.json 傳給任何人。
- wire-pre/wire-post 是原始網路封包，可能包含登入/工作階段識別資訊；只有需要查 RakNet/握手問題時才分享。
