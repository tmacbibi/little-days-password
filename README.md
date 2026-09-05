# 小日子密碼 v1

一個只保存「密碼提示」的本機 PWA。設計原則：真正密碼不需要、也不應輸入 App。

## v1 功能
- 首次建立 6～12 位 App PIN
- AES-GCM 本機加密
- 新增 / 編輯 / 刪除密碼提示
- 自由使用 `*` 或任何符號遮蔽任意字元
- 搜尋、分類、常用
- 顯示 / 隱藏提示
- 複製帳號、複製提示
- 離線使用（PWA Service Worker）
- 背景超過 30 秒自動鎖定；操作閒置 3 分鐘自動鎖定
- 每支手機資料各自獨立，不需要登入、不會彼此同步

## 重要安全說明
- 請只輸入「已遮蔽的提示」，不要輸入真正完整密碼。
- PIN 忘記後無法解密資料，v1 沒有雲端復原功能。
- 資料儲存在該瀏覽器 / PWA 的 Local Storage，清除 Safari 網站資料或刪除 PWA 可能造成資料遺失。
- v1 適合「提示本」，不是取代 1Password / Apple Passwords 等完整密碼管理器。

## 本機預覽
直接雙擊 `index.html` 可以看介面，但 PWA / Service Worker 需透過 HTTP(S) 才完整運作。

例如電腦有 Python：

```bash
python3 -m http.server 8080
```

然後瀏覽 `http://localhost:8080`。

## 放到 iPhone 最簡單的方式
將整個資料夾部署到任一支援 HTTPS 的靜態網站服務，例如 GitHub Pages、Cloudflare Pages、Netlify 或 Vercel。

部署完成後：
1. iPhone 用 Safari 開啟網址。
2. 點「分享」。
3. 點「加入主畫面」。
4. 開啟「作為網頁 App」。
5. 你和太太可使用同一網址安裝，但兩支手機的資料完全分開。

## 後續推薦 v1.1
- Face ID / Passkey 解鎖捷徑（保留 PIN 作為加密金鑰來源）
- 加密備份 / 匯入功能
- 自訂分類
- 快速新增模板與常用帳號
