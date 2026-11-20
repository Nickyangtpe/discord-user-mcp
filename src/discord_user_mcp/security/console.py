"""Local human approval console and dashboard.

An MCP client is not guaranteed to have a confirmation UI, so the server ships
its own: a loopback-only HTTP page with a random per-process token.

Security properties
-------------------
* Binds to 127.0.0.1 (a non-loopback host is rejected by config validation).
* Every request needs the console token, compared in constant time.
* There is no CORS header, so a web page cannot read responses.
* The token is printed to stderr and (optionally) written to
  ``<state>/approval-console.json`` with 0600 permissions. It is never exposed
  through any MCP tool.
* Failed authentication attempts are rate limited.
* Settings editable here never include the token, the API base URL or the
  console bind address, so the page cannot redirect credentials or widen its
  own exposure. Disabling read-only mode needs a typed phrase.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..api.errors import ApprovalError, DiscordUserMCPError
from ..config import (
    DASHBOARD_CONFIRMATION_PHRASE,
    DASHBOARD_LOCKED_KEYS,
    DashboardSettings,
    Settings,
    apply_dashboard_settings,
    console_token_from_env,
    dashboard_settings_from,
    save_dashboard_settings,
)
from ..utils.redact import configure_logging
from .approval import ApprovalManager, iso

logger = logging.getLogger(__name__)

MAX_BODY = 64 * 1024
MAX_FAILED_ATTEMPTS = 20
FAILED_WINDOW_SECONDS = 60.0
APPROVAL_STATUSES = {
    "pending",
    "approved",
    "executing",
    "completed",
    "failed",
    "denied",
    "expired",
    "cancelled",
}

PAGE = """<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Discord MCP Dashboard</title>
<style>
  :root { color-scheme:dark; --bg:#0d1117; --panel:#151a23; --panel2:#1b212c;
    --line:#252c3b; --line2:#343e52; --text:#f3f5fb; --muted:#8e98aa;
    --brand:#5865f2; --brand2:#5865f2; --ok:#45c98e; --no:#ed6674; --warn:#e6ac43;
    --shadow:none; }
  * { box-sizing:border-box; }
  html { min-height:100%; background:var(--bg); }
  body { margin:0; min-height:100vh; color:var(--text); overflow-x:hidden;
    font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI","Noto Sans TC",sans-serif;
    background:var(--bg); }
  header { max-width:1120px; margin:0 auto; padding:28px 24px 20px; display:flex;
    justify-content:space-between; align-items:center; gap:18px; position:relative; }
  .brand { display:flex; align-items:center; gap:12px; }
  .brand-mark { width:42px; height:42px; display:grid; place-items:center; border-radius:13px;
    color:white; font-size:13px; font-weight:750; letter-spacing:-.2px;
    background:var(--brand); border:1px solid #6975f4; box-shadow:none; }
  h1 { font-size:17px; margin:0; font-weight:720; letter-spacing:-.2px; }
  .brand-copy { color:var(--muted); font-size:12px; margin-top:1px; }
  .status-chip { display:flex; align-items:center; gap:8px; max-width:520px; padding:8px 12px;
    border:1px solid var(--line); border-radius:8px; color:#b9c1d1; background:var(--panel);
    font-size:12px; }
  .status-dot { width:7px; height:7px; border-radius:50%; flex:0 0 auto; background:var(--ok);
    box-shadow:0 0 0 3px rgba(69,201,142,.1); }
  .header-actions { display:flex; align-items:center; gap:8px; }
  .language-select { width:auto; min-height:34px; padding:7px 30px 7px 10px; border-radius:8px;
    color:#c4ccda; background-color:var(--panel); border-color:var(--line); font-size:12px; }
  .sub,.help { color:var(--muted); font-size:12px; }
  .help { margin-top:7px; } .help.warn { color:var(--warn); }
  .workspace { max-width:1120px; margin:0 auto; padding:0 24px 36px; position:relative; }
  nav { display:flex; gap:4px; width:max-content; max-width:100%; padding:5px; margin-bottom:22px;
    border:1px solid var(--line); border-radius:10px; background:var(--panel); overflow:auto; }
  nav button { border:0; border-radius:9px; background:transparent; color:var(--muted); min-width:86px;
    padding:8px 14px; font-weight:650; white-space:nowrap; box-shadow:none; }
  nav button:hover { color:var(--text); background:rgba(255,255,255,.035); }
  nav button.active { color:#fff; background:#2b3240; box-shadow:inset 0 0 0 1px rgba(255,255,255,.04); }
  .nav-count { display:none; margin-left:6px; min-width:19px; height:19px; padding:0 6px;
    align-items:center; justify-content:center; border-radius:10px; color:#251800;
    background:var(--warn); font-size:10px; font-weight:800; }
  main { display:grid; gap:18px; }
  section { animation:none; }
  .section-head { display:flex; align-items:end; justify-content:space-between; gap:14px; margin:0 2px 14px; }
  .section-head h2 { margin:0; font-size:20px; letter-spacing:-.4px; }
  .section-head p { margin:2px 0 0; color:var(--muted); font-size:12px; }
  .card { background:var(--panel);
    border:1px solid var(--line); border-radius:16px; padding:18px; box-shadow:var(--shadow); }
  .card:hover { border-color:#30394d; }
  .hero { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:18px; align-items:center;
    padding:22px; overflow:hidden; position:relative; background:var(--panel2);
    border-left:3px solid var(--brand); }
  .hero h2 { margin:0 0 4px; font-size:22px; letter-spacing:-.45px; }
  .hero p { margin:0; color:#aeb7c8; }
  .hero-state { display:flex; align-items:center; gap:8px; z-index:1; padding:9px 13px;
    border:1px solid var(--line2); border-radius:8px; background:var(--panel); }
  .overview-stack { display:grid; gap:14px; }
  .stat-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
  .stat { padding:16px; min-height:104px; display:flex; flex-direction:column; justify-content:space-between; }
  .stat-label,.label { color:var(--muted); font-size:11px; font-weight:700; letter-spacing:.5px; }
  .stat-value { font-size:23px; line-height:1; font-weight:760; letter-spacing:-.5px; }
  .stat-note { color:var(--muted); font-size:11px; }
  .two-col { display:grid; grid-template-columns:1fr 1fr; gap:14px; align-items:start; }
  .card-title { margin:0 0 13px; font-size:14px; font-weight:720; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; align-items:start; }
  .row { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; align-items:center; }
  .tool { font-size:14px; font-weight:680; }
  .badge { flex:0 0 auto; font-size:10px; font-weight:800; letter-spacing:.35px; padding:4px 9px;
    border-radius:999px; border:1px solid var(--line2); color:#bac3d4; background:rgba(255,255,255,.025); }
  .badge.read,.badge.completed { color:#78e7b5; border-color:rgba(78,217,155,.28); background:rgba(78,217,155,.07); }
  .badge.write,.badge.approved,.badge.executing { color:#8dc0ff; border-color:rgba(94,156,255,.28); background:rgba(94,156,255,.08); }
  .badge.admin,.badge.pending { color:#f7c96c; border-color:rgba(245,185,76,.3); background:rgba(245,185,76,.08); }
  .badge.destructive,.badge.failed,.badge.expired,.badge.denied,.badge.cancelled { color:#ff929e;
    border-color:rgba(255,107,122,.3); background:rgba(255,107,122,.08); }
  .badge.sensitive { color:#dea8ff; border-color:rgba(203,132,255,.3); background:rgba(203,132,255,.08); }
  #pending { display:grid; gap:12px; }
  .card.pending { padding:19px; border-color:#30394c; box-shadow:0 15px 45px rgba(0,0,0,.2); }
  .request-head { display:flex; gap:12px; align-items:center; min-width:0; }
  .request-icon { width:39px; height:39px; border-radius:11px; display:grid; place-items:center; flex:0 0 auto;
    background:#242b39; color:#b7c0d2; border:1px solid var(--line2); font-size:15px; font-weight:750; }
  .request-title { margin:0; font-size:16px; font-weight:730; letter-spacing:-.15px; }
  .target { color:var(--muted); margin:12px 0 0; font-size:12px; }
  details.tech { margin-top:13px; border-top:1px solid var(--line); padding-top:11px; }
  details.tech summary { width:max-content; color:var(--muted); cursor:pointer; font-size:12px; user-select:none; }
  details.tech summary:hover { color:var(--text); }
  pre { background:#090c13; border:1px solid var(--line); border-radius:11px; padding:13px; overflow:auto;
    max-height:310px; color:#b7c0d1; font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace; }
  .actions { display:flex; gap:9px; flex-wrap:wrap; margin-top:15px; align-items:center; }
  button { border-radius:10px; border:1px solid var(--line2); background:#222938; color:var(--text);
    padding:9px 15px; cursor:pointer; font:650 13px/1.2 inherit; transition:.16s ease; }
  button:hover { transform:translateY(-1px); border-color:#46526b; }
  button.ok { border-color:#6874f4; background:var(--brand); color:#fff; box-shadow:none; }
  button.no { background:transparent; border-color:#3b3440; color:#c7aab0; }
  button.no:hover { color:#ff9ba5; border-color:#73424c; background:rgba(255,107,122,.05); }
  button:disabled { opacity:.42; cursor:not-allowed; transform:none; }
  input[type=text],input[type=number],select { width:100%; min-height:38px; color:var(--text); background:#0c1018;
    border:1px solid var(--line); border-radius:9px; padding:8px 11px; font:13px ui-sans-serif,system-ui,sans-serif;
    outline:none; transition:border-color .15s,box-shadow .15s; }
  input:focus,select:focus { border-color:#665bd1; box-shadow:0 0 0 3px rgba(139,124,255,.1); }
  input[type=checkbox] { width:38px; height:21px; margin:0; appearance:none; border-radius:20px; cursor:pointer;
    background:#303747; border:1px solid #414a5e; position:relative; transition:.18s; }
  input[type=checkbox]:before { content:""; position:absolute; top:2px; left:2px; width:15px; height:15px;
    border-radius:50%; background:#aab3c2; transition:.18s; }
  input[type=checkbox]:checked { background:var(--brand); border-color:#6975f4; }
  input[type=checkbox]:checked:before { transform:translateX(17px); background:white; }
  input[type=checkbox]:disabled { opacity:.45; cursor:not-allowed; }
  .activity-grid { display:grid; grid-template-columns:1.15fr .85fr; gap:14px; align-items:start; }
  .activity-card { padding:0; overflow:hidden; }
  .activity-card > .card-title { padding:17px 18px 13px; margin:0; border-bottom:1px solid var(--line); }
  .list { padding:4px 18px 8px; max-height:620px; overflow:auto; }
  .entry { border-top:1px solid var(--line); padding:12px 0; }
  .entry:first-child { border-top:0; }
  .entry .row { cursor:pointer; flex-wrap:nowrap; }
  .entry .row:hover .tool { color:#c2baff; }
  .entry pre { margin-bottom:0; }
  .settings-stack { display:grid; gap:14px; }
  .settings-group { padding:0; overflow:hidden; }
  .settings-group-head { padding:16px 18px 12px; border-bottom:1px solid var(--line); }
  .settings-group-head h3 { margin:0; font-size:14px; }
  .settings-group-head p { margin:3px 0 0; color:var(--muted); font-size:11px; }
  .setting-row { min-height:64px; display:grid; grid-template-columns:minmax(0,1fr) minmax(120px,190px);
    gap:18px; align-items:center; padding:12px 18px; border-top:1px solid rgba(37,44,59,.72); }
  .setting-row:first-child { border-top:0; }
  .setting-row.bool { grid-template-columns:minmax(0,1fr) auto; }
  .setting-name { display:block; font-weight:650; }
  .setting-help { display:block; margin-top:2px; color:var(--muted); font-size:11px; }
  .settings-save { display:flex; justify-content:space-between; gap:14px; align-items:center; padding:16px 18px; }
  .settings-save .actions { margin:0; }
  .confirm-wrap { max-width:360px; flex:1; }
  .kv { display:grid; grid-template-columns:max-content minmax(0,1fr); gap:7px 14px; margin:11px 0 0; }
  .kv dt { color:var(--muted); font-size:11px; }
  .kv dd { margin:0; color:#c2c9d6; font:11px ui-monospace,Consolas,monospace; word-break:break-all; }
  .empty { color:var(--muted); text-align:center; padding:42px 14px; }
  .empty-mark { width:45px; height:45px; margin:0 auto 11px; border:1px solid var(--line); border-radius:14px;
    display:grid; place-items:center; color:#697386; font-size:20px; background:#0e121b; }
  .toast { position:fixed; right:22px; bottom:22px; z-index:50; max-width:460px; display:none;
    padding:11px 15px; border:1px solid #3d485d; border-radius:11px; color:#eef1f7;
    background:rgba(26,31,44,.96); box-shadow:0 16px 44px rgba(0,0,0,.4); backdrop-filter:blur(12px); }
  .toast.show { display:block; animation:toast-in .18s ease-out; }
  @keyframes toast-in { from { transform:translateY(8px); opacity:0; } }
  footer { color:#697386; font-size:11px; padding:5px 2px 0; text-align:center; }
  code { font-family:ui-monospace,Consolas,monospace; }
  [hidden] { display:none !important; }
  @media (max-width:760px) {
    header { padding:20px 16px 16px; align-items:flex-start; }
    .header-actions { align-items:flex-end; flex-direction:column-reverse; }
    .status-chip { max-width:100%; } .workspace { padding:0 14px 28px; }
    nav { width:100%; } nav button { min-width:auto; flex:1; }
    .stat-grid { grid-template-columns:1fr 1fr; }
    .two-col,.activity-grid { grid-template-columns:1fr; }
    .hero { grid-template-columns:1fr; } .hero-state { width:max-content; }
    .setting-row { grid-template-columns:1fr; gap:8px; }
    .setting-row.bool { grid-template-columns:1fr auto; }
    .settings-save { align-items:stretch; flex-direction:column; }
    .confirm-wrap { max-width:none; }
  }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="brand-mark">MCP</div>
    <div>
      <h1>Discord MCP</h1>
      <div class="brand-copy" data-i18n="app.subtitle">本機安全控制台</div>
    </div>
  </div>
  <div class="header-actions">
    <select id="language" class="language-select" aria-label="Language">
      <option value="zh-TW">繁體中文</option>
      <option value="en">English</option>
    </select>
    <div class="status-chip"><span class="status-dot"></span><span id="status" data-i18n="status.connecting">正在連線&hellip;</span></div>
  </div>
</header>
<div class="workspace">
  <nav>
    <button data-tab="overview" data-i18n="nav.overview">總覽</button>
    <button data-tab="approvals"><span data-i18n="nav.approvals">待處理</span><span class="nav-count" id="nav-count">0</span></button>
    <button data-tab="activity" data-i18n="nav.activity">活動</button>
    <button data-tab="settings" data-i18n="nav.settings">設定</button>
  </nav>
  <main>
    <section id="tab-overview" hidden><div id="overview" class="overview-stack"></div></section>
    <section id="tab-approvals" hidden>
      <div class="section-head"><div><h2 data-i18n="approvals.title">待處理請求</h2><p data-i18n="approvals.subtitle">檢查內容後，選擇允許或拒絕。</p></div></div>
      <div id="pending"></div>
    </section>
    <section id="tab-activity" hidden>
      <div class="section-head"><div><h2 data-i18n="activity.title">活動記錄</h2><p data-i18n="activity.subtitle">查看最近的允許結果與安全稽核記錄。</p></div></div>
      <div class="activity-grid">
        <div class="card activity-card"><h3 class="card-title" data-i18n="activity.history">請求記錄</h3><div id="history" class="list"></div></div>
        <div class="card activity-card"><h3 class="card-title" data-i18n="activity.audit">系統記錄</h3><div id="audit" class="list"></div></div>
      </div>
    </section>
    <section id="tab-settings" hidden>
      <div class="section-head"><div><h2 data-i18n="settings.title">設定</h2><p data-i18n="settings.subtitle">調整安全、允許與連線行為。</p></div></div>
      <div id="settings"></div>
    </section>
  </main>
  <footer data-i18n="footer">每個允許請求都只能使用一次並會自動逾時。AI 無法自行允許操作。</footer>
</div>
<div class="toast" id="toast"></div>
<script>
const token = new URLSearchParams(location.search).get('t') || '';
const TAB_NAMES = ['overview', 'approvals', 'activity', 'settings'];
const state = {tab: 'overview', settings: null, pendingSignature: '', historySignature: '', auditSignature: ''};
const statusEl = document.getElementById('status');
const toastEl = document.getElementById('toast');

const STRINGS = {
  'zh-TW': {
    'app.subtitle':'本機安全控制台', 'status.connecting':'正在連線…',
    'nav.overview':'總覽', 'nav.approvals':'待處理', 'nav.activity':'活動', 'nav.settings':'設定',
    'approvals.title':'待處理請求', 'approvals.subtitle':'檢查內容後，選擇允許或拒絕。',
    'activity.title':'活動記錄', 'activity.subtitle':'最近的允許結果與安全稽核記錄。',
    'activity.history':'請求記錄', 'activity.audit':'系統記錄',
    'settings.title':'設定', 'settings.subtitle':'調整安全、允許與連線行為。',
    'footer':'每個允許請求都只能使用一次並會自動逾時。AI 無法自行允許操作。',
    'field.readOnly':'唯讀模式', 'field.readOnlyHelp':'啟用後，所有會變更 Discord 狀態的操作都會被拒絕。',
    'field.audit':'安全稽核記錄', 'field.auditHelp':'記錄允許請求、決策與執行結果；內容會先遮蔽敏感資料。',
    'field.authCheck':'啟動時驗證 Token', 'field.authCheckHelp':'確認登入身分是否有效；變更後需重新啟動。',
    'field.approvalTtl':'允許請求有效時間', 'field.approvalTtlHelp':'逾時後請求無法再被執行（30–3600 秒）。',
    'field.uploads':'允許上傳附件', 'field.uploadsHelp':'仍會受到允許目錄與檔案大小限制。',
    'field.uploadBytes':'單次上傳大小上限', 'field.uploadBytesHelp':'以 bytes 計算。',
    'field.uploadFiles':'單次檔案數量上限', 'field.httpTimeout':'HTTP 逾時時間',
    'field.networkRetries':'網路錯誤重試次數', 'field.rateRetries':'速率限制重試次數',
    'field.logLevel':'系統記錄等級',
    'group.security':'安全控制', 'group.securityHelp':'控制寫入權限、Token 驗證與稽核行為。',
    'group.approval':'允許與附件', 'group.approvalHelp':'設定請求的有效時間及附件限制。',
    'group.network':'連線與診斷', 'group.networkHelp':'調整網路容錯與伺服器診斷等級。',
    'risk.read':'唯讀', 'risk.write':'一般寫入', 'risk.admin':'管理權限',
    'risk.destructive':'高風險', 'risk.sensitive':'敏感操作',
    'approval.pending':'等待允許', 'approval.approved':'已允許', 'approval.executing':'執行中',
    'approval.completed':'已完成', 'approval.failed':'執行失敗', 'approval.denied':'已拒絕',
    'approval.expired':'已逾時', 'approval.cancelled':'已取消',
    'event.requested':'建立允許請求', 'event.granted':'允許請求', 'event.denied':'拒絕請求',
    'event.cancelled':'取消請求', 'event.expired':'請求逾時', 'event.tampered':'參數完整性驗證失敗',
    'event.completed':'執行完成', 'event.failed':'執行失敗', 'event.settings':'控制台設定已更新',
    'event.unknown':'系統事件',
    'target.none':'未指定', 'target.guild':'伺服器 ', 'target.channel':'頻道 ', 'target.message':'訊息 ',
    'target.user':'使用者 ', 'target.member':'成員 ', 'target.role':'身分組 ',
    'target.thread':'討論串 ', 'target.event':'活動 ',
    'duration.seconds':'{value} 秒', 'duration.minutes':'{value} 分鐘',
    'duration.hours':'{value} 小時', 'duration.days':'{value} 天',
    'overview.attention':'有操作等待確認', 'overview.healthy':'安全控制正常',
    'overview.readOnlyDesc':'目前為唯讀模式，所有變更操作都會被拒絕。',
    'overview.gateDesc':'所有 Discord 變更在送出前都需要人工允許。',
    'overview.readOnlyProtection':'唯讀保護', 'overview.gateEnabled':'允許閘門已啟用',
    'overview.pending':'待處理', 'overview.needsDecision':'需要人工決策', 'overview.noPending':'目前無待辦',
    'overview.mode':'執行模式', 'overview.readOnly':'唯讀', 'overview.controlledWrite':'受控寫入',
    'overview.auditOn':'稽核記錄開啟', 'overview.auditOff':'稽核記錄關閉',
    'overview.tools':'可用工具', 'overview.endpointCount':'{value} 個 API endpoint',
    'overview.uptime':'運作時間', 'overview.version':'版本 {value}',
    'overview.account':'帳號與驗證', 'overview.identity':'目前身分',
    'overview.notVerified':'本次工作階段尚未驗證', 'overview.unknownUser':'未知使用者', 'overview.tokenSource':'Token 來源',
    'overview.tokenFingerprint':'Token 指紋', 'overview.credentialType':'憑證類型',
    'overview.credentialValue':'Discord User Token（不支援 Bot Token）',
    'overview.system':'系統與安全', 'overview.approvalTtl':'允許有效時間',
    'overview.uploads':'附件上傳', 'common.enabled':'啟用', 'common.disabled':'停用',
    'overview.rateRoutes':'追蹤速率限制', 'overview.routes':'{value} 個 route',
    'overview.globalLimit':'全域限制', 'common.none':'無', 'common.unset':'未設定', 'overview.registry':'Endpoint registry',
    'overview.registryValue':'{total}（{implemented} 已實作）', 'overview.auditPath':'稽核記錄位置',
    'request.targetLine':'目標：{target}  •  {time}後逾時  •  ID {id}',
    'request.technical':'查看技術細節', 'request.allow':'允許並執行', 'request.deny':'拒絕',
    'request.highRiskPlaceholder':'高風險操作：輸入 {phrase}',
    'request.highRiskHelp':'必須輸入 {phrase} 才能執行。',
    'request.approved':'已允許，伺服器正在執行此操作。',
    'request.denied':'已拒絕，未向 Discord 傳送任何變更。',
    'request.empty':'目前沒有等待處理的請求', 'history.empty':'目前沒有請求記錄',
    'audit.empty':'目前沒有系統記錄', 'audit.disabled':'安全稽核目前已停用；下方仍會保留舊有記錄。',
    'settings.readOnlyLocked':'已由環境變數 DISCORD_MCP_READ_ONLY 鎖定。',
    'settings.protected':'受保護的進階設定', 'settings.tokenSource':'Token 來源',
    'settings.tokenFingerprint':'Token 指紋', 'settings.apiBase':'Discord API 位址',
    'settings.consoleUrl':'控制台位址', 'settings.stateDir':'狀態資料夾',
    'settings.protectedHelp':'Token、API 位址、控制台綁定與狀態資料夾只能透過環境變數或 .env 修改。',
    'settings.confirmLabel':'啟用寫入確認文字', 'settings.confirmPlaceholder':'輸入 {phrase} 以啟用寫入',
    'settings.confirmHelp':'關閉唯讀模式前，必須明確輸入 {phrase}。', 'settings.save':'儲存設定',
    'settings.noChanges':'沒有需要儲存的變更。', 'settings.confirmRequired':'請輸入 ENABLE WRITES 才能關閉唯讀模式。',
    'settings.saved':'已儲存：{fields}', 'settings.savedNone':'沒有變更。',
    'settings.restart':'{fields} 會在重新啟動後生效。',
    'status.running':'運作中 · {pending} 個待處理 · 已運作 {uptime}',
    'status.disconnected':'控制台連線中斷：{message}',
    'error.settingsLocked':'此設定只能透過環境變數或 .env 修改。',
    'error.settingsInvalid':'設定值無效，請檢查輸入範圍與格式。',
    'error.readOnlyLocked':'唯讀模式已由環境變數鎖定。',
    'error.settingsConfirmation':'必須輸入 ENABLE WRITES 才能啟用寫入。',
    'error.settingsNotSaved':'無法將設定寫入狀態資料夾。',
    'error.approvalConfirmation':'此高風險操作需要輸入 APPROVE。',
    'error.alreadyDecided':'此請求已經處理，不能再次使用。',
    'error.expired':'此請求已逾時，無法執行。',
    'error.notFound':'找不到此允許請求。', 'error.tampered':'請求參數完整性驗證失敗。',
    'error.approvalFailed':'無法完成此允許決策。'
  },
  'en': {
    'app.subtitle':'Local security console', 'status.connecting':'Connecting…',
    'nav.overview':'Overview', 'nav.approvals':'Requests', 'nav.activity':'Activity', 'nav.settings':'Settings',
    'approvals.title':'Pending requests', 'approvals.subtitle':'Review each operation before allowing or denying it.',
    'activity.title':'Activity', 'activity.subtitle':'Recent approval outcomes and redacted security events.',
    'activity.history':'Request history', 'activity.audit':'System audit',
    'settings.title':'Settings', 'settings.subtitle':'Configure security, approvals, and connectivity.',
    'footer':'Every approval is single-use and expires. The AI cannot approve its own operations.',
    'field.readOnly':'Read-only mode', 'field.readOnlyHelp':'Reject every operation that would change Discord state.',
    'field.audit':'Security audit log', 'field.auditHelp':'Record approval requests, decisions, and executions with redaction.',
    'field.authCheck':'Verify token at startup', 'field.authCheckHelp':'Verify the authenticated identity; requires a restart.',
    'field.approvalTtl':'Approval lifetime', 'field.approvalTtlHelp':'Expired requests can never execute (30–3600 seconds).',
    'field.uploads':'Allow attachments', 'field.uploadsHelp':'Upload roots and file-size limits still apply.',
    'field.uploadBytes':'Maximum upload bytes', 'field.uploadBytesHelp':'Measured in bytes.',
    'field.uploadFiles':'Maximum files per request', 'field.httpTimeout':'HTTP timeout',
    'field.networkRetries':'Network-error retries', 'field.rateRetries':'Rate-limit retries',
    'field.logLevel':'Log level',
    'group.security':'Security controls', 'group.securityHelp':'Write access, token verification, and auditing.',
    'group.approval':'Approvals and uploads', 'group.approvalHelp':'Request lifetime and attachment limits.',
    'group.network':'Connectivity and diagnostics', 'group.networkHelp':'Network resilience and server diagnostics.',
    'risk.read':'Read-only', 'risk.write':'Write', 'risk.admin':'Administrator',
    'risk.destructive':'High risk', 'risk.sensitive':'Sensitive',
    'approval.pending':'Pending', 'approval.approved':'Approved', 'approval.executing':'Executing',
    'approval.completed':'Completed', 'approval.failed':'Failed', 'approval.denied':'Denied',
    'approval.expired':'Expired', 'approval.cancelled':'Cancelled',
    'event.requested':'Approval requested', 'event.granted':'Request approved', 'event.denied':'Request denied',
    'event.cancelled':'Request cancelled', 'event.expired':'Request expired', 'event.tampered':'Argument integrity check failed',
    'event.completed':'Execution completed', 'event.failed':'Execution failed', 'event.settings':'Dashboard settings changed',
    'event.unknown':'System event',
    'target.none':'Not specified', 'target.guild':'Guild ', 'target.channel':'Channel ', 'target.message':'Message ',
    'target.user':'User ', 'target.member':'Member ', 'target.role':'Role ',
    'target.thread':'Thread ', 'target.event':'Event ',
    'duration.seconds':'{value}s', 'duration.minutes':'{value}m', 'duration.hours':'{value}h', 'duration.days':'{value}d',
    'overview.attention':'Operations require review', 'overview.healthy':'Security controls operational',
    'overview.readOnlyDesc':'Read-only mode is active. All mutating operations are rejected.',
    'overview.gateDesc':'Every Discord change requires human approval before it is sent.',
    'overview.readOnlyProtection':'Read-only protection', 'overview.gateEnabled':'Approval gate enabled',
    'overview.pending':'Pending', 'overview.needsDecision':'Requires a human decision', 'overview.noPending':'No action required',
    'overview.mode':'Execution mode', 'overview.readOnly':'Read-only', 'overview.controlledWrite':'Controlled writes',
    'overview.auditOn':'Audit logging enabled', 'overview.auditOff':'Audit logging disabled',
    'overview.tools':'Available tools', 'overview.endpointCount':'{value} API endpoints',
    'overview.uptime':'Uptime', 'overview.version':'Version {value}',
    'overview.account':'Account and authentication', 'overview.identity':'Identity',
    'overview.notVerified':'Not verified in this session', 'overview.unknownUser':'Unknown user', 'overview.tokenSource':'Token source',
    'overview.tokenFingerprint':'Token fingerprint', 'overview.credentialType':'Credential type',
    'overview.credentialValue':'Discord User Token (bot tokens unsupported)',
    'overview.system':'System and security', 'overview.approvalTtl':'Approval lifetime',
    'overview.uploads':'Attachments', 'common.enabled':'Enabled', 'common.disabled':'Disabled',
    'overview.rateRoutes':'Tracked rate limits', 'overview.routes':'{value} routes',
    'overview.globalLimit':'Global limit', 'common.none':'None', 'common.unset':'Not configured', 'overview.registry':'Endpoint registry',
    'overview.registryValue':'{total} ({implemented} implemented)', 'overview.auditPath':'Audit log path',
    'request.targetLine':'Target: {target}  •  expires in {time}  •  ID {id}',
    'request.technical':'View technical details', 'request.allow':'Allow and execute', 'request.deny':'Deny',
    'request.highRiskPlaceholder':'High-risk operation: type {phrase}',
    'request.highRiskHelp':'Type {phrase} before this operation can execute.',
    'request.approved':'Approved. The server is executing the operation.',
    'request.denied':'Denied. No change was sent to Discord.',
    'request.empty':'No requests are waiting for review', 'history.empty':'No request history yet',
    'audit.empty':'No system events yet', 'audit.disabled':'Auditing is disabled. Existing events remain visible below.',
    'settings.readOnlyLocked':'Locked by the DISCORD_MCP_READ_ONLY environment variable.',
    'settings.protected':'Protected advanced settings', 'settings.tokenSource':'Token source',
    'settings.tokenFingerprint':'Token fingerprint', 'settings.apiBase':'Discord API base',
    'settings.consoleUrl':'Console URL', 'settings.stateDir':'State directory',
    'settings.protectedHelp':'The token, API base, console bind address, and state directory can only be changed through the environment or .env.',
    'settings.confirmLabel':'Write-access confirmation', 'settings.confirmPlaceholder':'Type {phrase} to enable writes',
    'settings.confirmHelp':'You must explicitly type {phrase} before disabling read-only mode.', 'settings.save':'Save settings',
    'settings.noChanges':'There are no changes to save.', 'settings.confirmRequired':'Type ENABLE WRITES to disable read-only mode.',
    'settings.saved':'Saved: {fields}', 'settings.savedNone':'No changes.',
    'settings.restart':'{fields} will take effect after restart.',
    'status.running':'Running · {pending} pending · up {uptime}',
    'status.disconnected':'Dashboard disconnected: {message}',
    'error.settingsLocked':'This setting can only be changed through the environment or .env.',
    'error.settingsInvalid':'A setting value is invalid. Check its range and format.',
    'error.readOnlyLocked':'Read-only mode is locked by the environment.',
    'error.settingsConfirmation':'Type ENABLE WRITES before enabling writes.',
    'error.settingsNotSaved':'The settings could not be written to the state directory.',
    'error.approvalConfirmation':'This high-risk operation requires the phrase APPROVE.',
    'error.alreadyDecided':'This request has already been decided and cannot be reused.',
    'error.expired':'This request has expired and cannot execute.',
    'error.notFound':'The approval request was not found.', 'error.tampered':'The request argument integrity check failed.',
    'error.approvalFailed':'The approval decision could not be completed.'
  }
};

function initialLocale() {
  try {
    const saved = localStorage.getItem('discord-mcp-language');
    if (saved && STRINGS[saved]) return saved;
  } catch (_) {}
  try {
    const item = document.cookie.split('; ').find(value => value.startsWith('discord_mcp_language='));
    const saved = item ? decodeURIComponent(item.split('=').slice(1).join('=')) : '';
    if (saved && STRINGS[saved]) return saved;
  } catch (_) {}
  return String(navigator.language || '').toLowerCase().startsWith('zh') ? 'zh-TW' : 'en';
}
let locale = initialLocale();

function t(key, values) {
  let text = (STRINGS[locale] && STRINGS[locale][key]) || STRINGS.en[key] || key;
  Object.entries(values || {}).forEach(([name, value]) => {
    text = text.replaceAll('{' + name + '}', String(value));
  });
  return text;
}

function applyStaticTranslations() {
  document.documentElement.lang = locale;
  document.querySelectorAll('[data-i18n]').forEach(node => {
    node.textContent = t(node.dataset.i18n);
  });
  const select = document.getElementById('language');
  if (select) select.value = locale;
}

function changeLocale(next) {
  if (!STRINGS[next] || next === locale) return;
  locale = next;
  try { localStorage.setItem('discord-mcp-language', locale); } catch (_) {}
  try {
    document.cookie = 'discord_mcp_language=' + encodeURIComponent(locale) +
      '; Max-Age=31536000; Path=/; SameSite=Strict';
  } catch (_) {}
  applyStaticTranslations();
  state.pendingSignature = '';
  state.historySignature = '';
  state.auditSignature = '';
  refreshStatus();
  if (state.tab === 'approvals') loadApprovals();
  if (state.tab === 'activity') { loadHistory(); loadAudit(); }
  if (state.tab === 'settings') loadSettings();
}

const FIELD_DEFS = [
  {key:'read_only', group:'security', label:'field.readOnly', help:'field.readOnlyHelp', type:'bool'},
  {key:'audit_enabled', group:'security', label:'field.audit', help:'field.auditHelp', type:'bool'},
  {key:'require_startup_auth_check', group:'security', label:'field.authCheck', help:'field.authCheckHelp', type:'bool'},
  {key:'approval_ttl_seconds', group:'approval', label:'field.approvalTtl', help:'field.approvalTtlHelp',
   type:'number', min:30, max:3600},
  {key:'uploads_enabled', group:'approval', label:'field.uploads', help:'field.uploadsHelp', type:'bool'},
  {key:'upload_max_bytes', group:'approval', label:'field.uploadBytes', help:'field.uploadBytesHelp', type:'number', min:1},
  {key:'upload_max_files', group:'approval', label:'field.uploadFiles', type:'number', min:1, max:10},
  {key:'http_timeout_seconds', group:'network', label:'field.httpTimeout', type:'number', min:1, max:300},
  {key:'http_max_retries', group:'network', label:'field.networkRetries', type:'number', min:0, max:10},
  {key:'http_max_429_retries', group:'network', label:'field.rateRetries', type:'number', min:0, max:20},
  {key:'log_level', group:'network', label:'field.logLevel', type:'select',
   options:['DEBUG','INFO','WARNING','ERROR']}
];

const GROUPS = {
  security: ['group.security', 'group.securityHelp'],
  approval: ['group.approval', 'group.approvalHelp'],
  network: ['group.network', 'group.networkHelp']
};
const RISK_LABELS = {read:'risk.read', write:'risk.write', admin:'risk.admin', destructive:'risk.destructive', sensitive:'risk.sensitive'};
const STATUS_LABELS = {pending:'approval.pending', approved:'approval.approved', executing:'approval.executing',
  completed:'approval.completed', failed:'approval.failed', denied:'approval.denied',
  expired:'approval.expired', cancelled:'approval.cancelled'};
const EVENT_LABELS = {approval_requested:'event.requested', approval_granted:'event.granted',
  approval_denied:'event.denied', approval_cancelled:'event.cancelled', approval_expired:'event.expired',
  approval_tampered:'event.tampered', execution_completed:'event.completed',
  execution_failed:'event.failed', dashboard_settings_changed:'event.settings'};
const ERROR_LABELS = {settings_locked:'error.settingsLocked', settings_invalid:'error.settingsInvalid',
  read_only_locked:'error.readOnlyLocked', settings_confirmation_required:'error.settingsConfirmation',
  settings_not_saved:'error.settingsNotSaved', approval_confirmation_required:'error.approvalConfirmation',
  approval_already_decided:'error.alreadyDecided', approval_expired:'error.expired',
  approval_not_found:'error.notFound', approval_arguments_tampered:'error.tampered',
  approval_failed:'error.approvalFailed'};
const TOOL_LABELS_ZH = {accept_friend_request:'接受好友邀請', send_friend_request:'傳送好友邀請',
  add_role_to_member:'指派成員身分組', remove_role_from_member:'移除成員身分組',
  mark_channel_read:'將頻道標為已讀', trigger_typing:'顯示輸入中狀態',
  rsvp_event:'參加排定活動', unrsvp_event:'取消參加排定活動',
  remove_relationship:'移除好友關係', ack_notification:'確認通知',
  update_channel_permissions:'更新頻道權限', delete_channel_permission:'刪除頻道權限'};
const ACTION_LABELS = {accept:'接受', ack:'確認', add:'新增', ban:'封禁', block:'封鎖', cancel:'取消',
  check:'查看', close:'關閉', create:'建立', delete:'刪除', edit:'編輯', forward:'轉寄', join:'加入',
  kick:'移出', leave:'離開', mark:'標記', open:'開啟', pin:'釘選', remove:'移除', reorder:'重新排序',
  rsvp:'參加', search:'搜尋', send:'傳送', set:'設定', start:'建立', trigger:'顯示', unban:'解除封禁',
  unpin:'取消釘選', unrsvp:'取消參加', update:'更新', vote:'投票'};
const OBJECT_LABELS = {friend_request:'好友邀請', notification:'通知', group_dm_recipient:'群組私訊成員',
  reaction:'表情回應', role_to_member:'成員身分組', thread_member:'討論串成員', guild_member:'伺服器成員',
  channel_invite:'頻道邀請', group_dm:'群組私訊', guild_channel:'伺服器頻道', guild_role:'伺服器身分組',
  scheduled_event:'排定活動', event:'排定活動', thread:'討論串', channel:'頻道',
  channel_permission:'頻道權限', channel_permissions:'頻道權限', channel_read:'頻道已讀狀態',
  invite:'邀請', message:'訊息', all_reactions:'所有表情回應', emoji_reactions:'指定表情回應',
  own_reaction:'自己的表情回應', relationship:'好友關係', role_from_member:'成員身分組',
  user_reaction:'使用者表情回應', channels:'頻道順序', guild_roles:'伺服器身分組順序',
  custom_status:'自訂狀態', my_guild_nickname:'伺服器暱稱', relationship_nickname:'好友暱稱',
  user:'使用者', guild:'伺服器', dm:'私訊', user_note:'使用者備註',
  thread_from_message:'訊息討論串', typing:'輸入中狀態', my_account:'帳號',
  my_notification_settings:'通知設定', my_profile:'個人資料', my_settings:'使用者設定', poll:'投票'};

function toast(msg, bad) {
  toastEl.textContent = msg;
  toastEl.style.borderColor = bad ? '#7a2a2a' : '#1f6b3c';
  toastEl.classList.add('show');
  setTimeout(() => toastEl.classList.remove('show'), 5000);
}

async function api(path, options) {
  const opts = options || {};
  opts.headers = Object.assign({'X-Approval-Token': token}, opts.headers || {});
  const res = await fetch(path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const key = ERROR_LABELS[body.code];
    throw new Error(key ? t(key) : (body.message || ('HTTP ' + res.status)));
  }
  return body;
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function friendlyTool(name, fallback) {
  const raw = String(name || '');
  if (locale === 'zh-TW') {
    if (TOOL_LABELS_ZH[raw]) return TOOL_LABELS_ZH[raw];
    const parts = raw.split('_');
    const action = ACTION_LABELS[parts[0]];
    const object = OBJECT_LABELS[parts.slice(1).join('_')];
    if (action && object) return action + object;
  } else if (fallback && !String(fallback).includes('{')) {
    return String(fallback);
  }
  return raw.split('_').map(word => word ? word[0].toUpperCase() + word.slice(1) : '')
    .join(' ') || (locale === 'zh-TW' ? '未知操作' : 'Unknown operation');
}

function friendlyTarget(value) {
  if (!value) return t('target.none');
  return String(value)
    .replaceAll('guild_id=', t('target.guild'))
    .replaceAll('channel_id=', t('target.channel'))
    .replaceAll('message_id=', t('target.message'))
    .replaceAll('user_id=', t('target.user'))
    .replaceAll('member_id=', t('target.member'))
    .replaceAll('role_id=', t('target.role'))
    .replaceAll('thread_id=', t('target.thread'))
    .replaceAll('event_id=', t('target.event'));
}

function formatTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(locale, {month:'2-digit', day:'2-digit', hour:'2-digit',
    minute:'2-digit', second:'2-digit', hour12:false}).format(date);
}

function formatDuration(seconds) {
  const total = Math.max(0, Number(seconds) || 0);
  if (total < 60) return t('duration.seconds', {value:Math.floor(total)});
  if (total < 3600) return t('duration.minutes', {value:Math.floor(total / 60)});
  if (total < 86400) return t('duration.hours', {value:Math.floor(total / 3600)});
  return t('duration.days', {value:Math.floor(total / 86400)});
}

function formatList(items) {
  if (!items.length) return '';
  return new Intl.ListFormat(locale, {style:'long', type:'conjunction'}).format(items);
}

function emptyState(message) {
  const box = el('div', 'empty');
  box.appendChild(el('div', 'empty-mark', '✓'));
  box.appendChild(el('div', null, message));
  return box;
}

function activate(name) {
  if (name === 'history' || name === 'audit') name = 'activity';
  if (TAB_NAMES.indexOf(name) === -1) name = 'overview';
  state.tab = name;
  TAB_NAMES.forEach(t => {
    document.getElementById('tab-' + t).hidden = t !== name;
    const btn = document.querySelector('[data-tab="' + t + '"]');
    if (btn) btn.classList.toggle('active', t === name);
  });
  if (location.hash !== '#' + name) {
    window.history.replaceState(null, '', location.pathname + location.search + '#' + name);
  }
  if (name === 'settings') loadSettings();
  if (name === 'activity') { loadHistory(); loadAudit(); }
  if (name === 'approvals') loadApprovals();
}

function card(title, pairs) {
  const box = el('div', 'card');
  box.appendChild(el('h3', 'card-title', title));
  const dl = el('dl', 'kv');
  pairs.forEach(pair => {
    dl.appendChild(el('dt', null, pair[0]));
    dl.appendChild(el('dd', null, pair[1]));
  });
  box.appendChild(dl);
  return box;
}

function statCard(label, value, note) {
  const box = el('div', 'card stat');
  box.appendChild(el('div', 'stat-label', label));
  box.appendChild(el('div', 'stat-value', value));
  box.appendChild(el('div', 'stat-note', note));
  return box;
}

function renderOverview(s) {
  const root = document.getElementById('overview');
  root.textContent = '';
  const identity = s.identity
    ? (s.identity.username || t('overview.unknownUser')) + ' (' + (s.identity.user_id || '?') + ')'
    : t('overview.notVerified');
  const registry = s.registry || {};
  const byStatus = registry.by_status || {};

  const hero = el('div', 'card hero');
  const copy = el('div');
  copy.appendChild(el('h2', null, s.approvals.pending ? t('overview.attention') : t('overview.healthy')));
  copy.appendChild(el('p', null, s.mode.read_only
    ? t('overview.readOnlyDesc') : t('overview.gateDesc')));
  hero.appendChild(copy);
  const mode = el('div', 'hero-state');
  mode.appendChild(el('span', 'status-dot'));
  mode.appendChild(el('span', null, s.mode.read_only ? t('overview.readOnlyProtection') : t('overview.gateEnabled')));
  hero.appendChild(mode);
  root.appendChild(hero);

  const stats = el('div', 'stat-grid');
  stats.appendChild(statCard(t('overview.pending'), String(s.approvals.pending),
    s.approvals.pending ? t('overview.needsDecision') : t('overview.noPending')));
  stats.appendChild(statCard(t('overview.mode'),
    s.mode.read_only ? t('overview.readOnly') : t('overview.controlledWrite'),
    s.mode.audit_enabled ? t('overview.auditOn') : t('overview.auditOff')));
  stats.appendChild(statCard(t('overview.tools'), String(s.tools.registered),
    t('overview.endpointCount', {value:byStatus.implemented || 0})));
  stats.appendChild(statCard(t('overview.uptime'), formatDuration(s.server.uptime_seconds),
    t('overview.version', {value:s.server.version})));
  root.appendChild(stats);

  const columns = el('div', 'two-col');
  columns.appendChild(card(t('overview.account'), [
    [t('overview.identity'), identity],
    [t('overview.tokenSource'), s.token.source],
    [t('overview.tokenFingerprint'), s.token.fingerprint],
    [t('overview.credentialType'), t('overview.credentialValue')]
  ]));
  columns.appendChild(card(t('overview.system'), [
    [t('overview.approvalTtl'), t('duration.seconds', {value:s.mode.approval_ttl_seconds})],
    [t('overview.uploads'), s.mode.uploads_enabled ? t('common.enabled') : t('common.disabled')],
    [t('overview.rateRoutes'), t('overview.routes', {value:s.rate_limits.tracked_routes})],
    [t('overview.globalLimit'), s.rate_limits.global_blocked_for_seconds > 0
      ? t('duration.seconds', {value:s.rate_limits.global_blocked_for_seconds}) : t('common.none')],
    [t('overview.registry'), t('overview.registryValue', {
      total:registry.total || 0, implemented:byStatus.implemented || 0})],
    [t('overview.auditPath'), s.mode.audit_path || t('common.unset')]
  ]));
  root.appendChild(columns);
}

function targetLine(a) {
  return t('request.targetLine', {target:friendlyTarget(a.target),
    time:formatDuration(a.expires_in_seconds), id:a.approval_id.slice(0, 12)});
}

function renderPending(a) {
  const box = el('div', 'card pending');
  const row = el('div', 'row');
  const left = el('div', 'request-head');
  const copy = el('div');
  copy.appendChild(el('div', 'request-title', friendlyTool(a.tool, a.summary)));
  left.appendChild(copy);
  row.appendChild(left);
  row.appendChild(el('span', 'badge ' + a.risk, RISK_LABELS[a.risk] ? t(RISK_LABELS[a.risk]) : a.risk));
  box.appendChild(row);
  box.appendChild(el('div', 'target', targetLine(a)));

  const technical = el('details', 'tech');
  technical.appendChild(el('summary', null, t('request.technical')));
  const pre = el('pre');
  pre.textContent = JSON.stringify({
    tool: a.tool,
    endpoint: a.endpoint,
    summary: a.summary,
    approval_id: a.approval_id,
    risk: a.risk,
    args_hash: a.args_hash,
    arguments: a.args
  }, null, 2);
  technical.appendChild(pre);
  box.appendChild(technical);

  const actions = el('div', 'actions');
  const approve = el('button', 'ok', t('request.allow'));
  const deny = el('button', 'no', t('request.deny'));
  let confirmInput = null;
  if (a.requires_typed_confirmation) {
    const confirmWrap = el('div', 'confirm-wrap');
    confirmInput = el('input');
    confirmInput.type = 'text';
    confirmInput.placeholder = t('request.highRiskPlaceholder', {phrase:a.approval_phrase});
    confirmInput.setAttribute('aria-label', confirmInput.placeholder);
    confirmWrap.appendChild(confirmInput);
    confirmWrap.appendChild(el('div', 'help warn',
      t('request.highRiskHelp', {phrase:a.approval_phrase})));
    actions.appendChild(confirmWrap);
    approve.disabled = true;
    confirmInput.addEventListener('input', () => {
      approve.disabled = confirmInput.value.trim() !== a.approval_phrase;
    });
  }
  approve.addEventListener('click', async () => {
    approve.disabled = true;
    try {
      await api('/api/approve', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: a.approval_id, confirmation: confirmInput ? confirmInput.value : null})
      });
      toast(t('request.approved'));
      loadApprovals();
    } catch (err) { toast(err.message, true); approve.disabled = false; }
  });
  deny.addEventListener('click', async () => {
    deny.disabled = true; approve.disabled = true;
    try {
      await api('/api/deny', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: a.approval_id, reason: 'denied in dashboard'})
      });
      toast(t('request.denied'));
      loadApprovals();
    } catch (err) { toast(err.message, true); deny.disabled = false; }
  });
  actions.appendChild(approve);
  actions.appendChild(deny);
  box.appendChild(actions);
  return box;
}

function detailEntry(left, badge, payload) {
  const entry = el('div', 'entry');
  const row = el('div', 'row');
  row.appendChild(left);
  if (badge) row.appendChild(badge);
  entry.appendChild(row);
  const pre = el('pre');
  pre.hidden = true;
  pre.textContent = JSON.stringify(payload, null, 2);
  row.addEventListener('click', () => { pre.hidden = !pre.hidden; });
  entry.appendChild(pre);
  return entry;
}

function renderHistory(items) {
  const root = document.getElementById('history');
  root.textContent = '';
  if (!items.length) { root.appendChild(emptyState(t('history.empty'))); return; }
  items.forEach(a => {
    const left = el('div');
    const title = el('div', 'tool', friendlyTool(a.tool, a.summary));
    left.appendChild(title);
    left.appendChild(el('div', 'sub',
      friendlyTarget(a.target) + ' \u2022 ' + formatTime(a.decided_at || a.created_at) +
      ' \u2022 ID ' + a.approval_id.slice(0, 12)));
    root.appendChild(detailEntry(left, el('span', 'badge ' + a.status,
      STATUS_LABELS[a.status] ? t(STATUS_LABELS[a.status]) : a.status), {
      approval_id: a.approval_id,
      tool: a.tool,
      endpoint: a.endpoint,
      risk: a.risk,
      status: a.status,
      target: a.target,
      args: a.args,
      args_hash: a.args_hash,
      created_at: a.created_at,
      decided_at: a.decided_at,
      decided_by: a.decided_by,
      decision_note: a.decision_note,
      executed_at: a.executed_at,
      result: a.result,
      error: a.error
    }));
  });
}

function renderAudit(payload) {
  const root = document.getElementById('audit');
  root.textContent = '';
  if (!payload.enabled) {
    root.appendChild(el('div', 'help warn',
      t('audit.disabled')));
  }
  if (!payload.entries.length) { root.appendChild(emptyState(t('audit.empty'))); return; }
  payload.entries.slice().reverse().forEach(entry => {
    const left = el('div');
    left.appendChild(el('div', 'tool', EVENT_LABELS[entry.event] ? t(EVENT_LABELS[entry.event]) :
      (entry.event ? String(entry.event).split('_').join(' ') : t('event.unknown'))));
    const bits = [];
    if (entry.tool) bits.push(friendlyTool(entry.tool));
    if (entry.risk) bits.push(RISK_LABELS[entry.risk] ? t(RISK_LABELS[entry.risk]) : entry.risk);
    if (entry.actor) bits.push(entry.actor);
    if (entry.approval_id) bits.push(String(entry.approval_id).slice(0, 12));
    left.appendChild(el('div', 'sub', bits.join(' \u2022 ')));
    root.appendChild(detailEntry(left, el('span', 'sub', formatTime(entry.ts)), entry));
  });
}

function renderSettings(payload) {
  state.settings = payload.settings;
  const root = document.getElementById('settings');
  root.textContent = '';
  root.className = 'settings-stack';

  Object.keys(GROUPS).forEach(groupName => {
    const box = el('div', 'card settings-group');
    const head = el('div', 'settings-group-head');
    head.appendChild(el('h3', null, t(GROUPS[groupName][0])));
    head.appendChild(el('p', null, t(GROUPS[groupName][1])));
    box.appendChild(head);
    const body = el('div');
    FIELD_DEFS.filter(def => def.group === groupName).forEach(def => {
      const row = el('label', 'setting-row' + (def.type === 'bool' ? ' bool' : ''));
      const copy = el('span');
      copy.appendChild(el('span', 'setting-name', t(def.label)));
      if (def.help) copy.appendChild(el('span', 'setting-help', t(def.help)));
      row.appendChild(copy);
      let input;
      if (def.type === 'bool') {
        input = el('input');
        input.type = 'checkbox';
        input.checked = !!payload.settings[def.key];
      } else if (def.type === 'select') {
        input = el('select');
        def.options.forEach(option => {
          const node = el('option', null, option);
          node.value = option;
          input.appendChild(node);
        });
        input.value = payload.settings[def.key];
      } else {
        input = el('input');
        input.type = 'number';
        input.min = def.min;
        input.max = def.max;
        input.step = def.step || '1';
        input.value = payload.settings[def.key];
      }
      input.id = 'set-' + def.key;
      input.setAttribute('aria-label', t(def.label));
      if (def.key === 'read_only' && payload.read_only_locked) {
        input.disabled = true;
        copy.appendChild(el('span', 'setting-help', t('settings.readOnlyLocked')));
      }
      row.appendChild(input);
      body.appendChild(row);
    });
    box.appendChild(body);
    root.appendChild(box);
  });

  const lockedBox = el('details', 'card tech');
  lockedBox.appendChild(el('summary', null, t('settings.protected')));
  const dl = el('dl', 'kv');
  const lockedLabels = {token_source:'settings.tokenSource', token_fingerprint:'settings.tokenFingerprint',
    api_base:'settings.apiBase', console_url:'settings.consoleUrl', state_dir:'settings.stateDir'};
  Object.keys(payload.locked).forEach(key => {
    if (key === 'reason') return;
    dl.appendChild(el('dt', null, lockedLabels[key] ? t(lockedLabels[key]) : key));
    dl.appendChild(el('dd', null, String(payload.locked[key])));
  });
  lockedBox.appendChild(dl);
  lockedBox.appendChild(el('div', 'help', t('settings.protectedHelp')));
  root.appendChild(lockedBox);

  const saveBox = el('div', 'card settings-save');
  const confirmWrap = el('div', 'confirm-wrap');
  const confirm = el('input');
  confirm.type = 'text';
  confirm.id = 'settings-confirm';
  confirm.setAttribute('aria-label', t('settings.confirmLabel'));
  confirm.placeholder = t('settings.confirmPlaceholder', {phrase:payload.confirmation_phrase});
  confirmWrap.appendChild(confirm);
  confirmWrap.appendChild(el('div', 'help warn',
    t('settings.confirmHelp', {phrase:payload.confirmation_phrase})));
  const save = el('button', 'ok', t('settings.save'));
  save.addEventListener('click', saveSettings);
  const actions = el('div', 'actions');
  actions.appendChild(save);
  saveBox.appendChild(confirmWrap);
  saveBox.appendChild(actions);
  root.appendChild(saveBox);

  const readOnly = document.getElementById('set-read_only');
  const updateConfirmation = () => {
    confirmWrap.hidden = !(state.settings.read_only && readOnly && !readOnly.checked);
  };
  if (readOnly) readOnly.addEventListener('change', updateConfirmation);
  updateConfirmation();
}

async function saveSettings() {
  if (!state.settings) return;
  const patch = {};
  FIELD_DEFS.forEach(def => {
    const input = document.getElementById('set-' + def.key);
    let value;
    if (def.type === 'bool') value = input.checked;
    else if (def.type === 'select') value = input.value;
    else value = Number(input.value);
    if (value !== state.settings[def.key]) patch[def.key] = value;
  });
  if (!Object.keys(patch).length) { toast(t('settings.noChanges')); return; }
  if (state.settings.read_only && patch.read_only === false) {
    const typed = (document.getElementById('settings-confirm').value || '').trim();
    if (typed !== 'ENABLE WRITES') {
      toast(t('settings.confirmRequired'), true);
      return;
    }
    patch.confirmation = typed;
  }
  try {
    const result = await api('/api/settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(patch)
    });
    renderSettings(result);
    const changedLabels = result.changed.map(key => {
      const def = FIELD_DEFS.find(item => item.key === key);
      return def ? t(def.label) : key;
    });
    const restartLabels = result.restart_required.map(key => {
      const def = FIELD_DEFS.find(item => item.key === key);
      return def ? t(def.label) : key;
    });
    const changed = changedLabels.length
      ? t('settings.saved', {fields:formatList(changedLabels)}) : t('settings.savedNone');
    const restart = result.restart_required.length
      ? ' ' + t('settings.restart', {fields:formatList(restartLabels)})
      : '';
    toast(changed + restart);
    refreshStatus();
  } catch (err) { toast(err.message, true); }
}

async function loadApprovals() {
  try {
    const data = await api('/api/approvals?status=pending&limit=50');
    const signature = data.approvals.map(a => a.approval_id).join('|');
    const root = document.getElementById('pending');
    // Rebuild only when the set of requests changes, so a button under the
    // pointer never detaches mid-click. Countdowns are refreshed in place.
    if (signature === state.pendingSignature && root.childElementCount) {
      const lines = root.querySelectorAll('.target');
      data.approvals.forEach((a, index) => {
        if (lines[index]) lines[index].textContent = targetLine(a);
      });
      return;
    }
    state.pendingSignature = signature;
    root.textContent = '';
    if (!data.approvals.length) {
      const empty = el('div', 'card');
      empty.appendChild(emptyState(t('request.empty')));
      root.appendChild(empty);
    } else {
      data.approvals.forEach(a => root.appendChild(renderPending(a)));
    }
  } catch (err) { toast(err.message, true); }
}

async function loadHistory() {
  try {
    const data = await api('/api/approvals?limit=100');
    const signature = data.approvals.map(a => a.approval_id + ':' + a.status).join('|');
    if (signature === state.historySignature) return;
    state.historySignature = signature;
    renderHistory(data.approvals);
  } catch (err) { toast(err.message, true); }
}

async function loadAudit() {
  try {
    const data = await api('/api/audit?limit=100');
    const last = data.entries.length ? (data.entries[data.entries.length - 1].ts || '') : '';
    const signature = data.count + ':' + last;
    if (signature === state.auditSignature) return;
    state.auditSignature = signature;
    renderAudit(data);
  } catch (err) { toast(err.message, true); }
}

async function loadSettings() {
  try {
    renderSettings(await api('/api/settings'));
  } catch (err) { toast(err.message, true); }
}

async function refreshStatus() {
  try {
    const s = await api('/api/status');
    statusEl.textContent = t('status.running', {
      pending:s.approvals.pending, uptime:formatDuration(s.server.uptime_seconds)});
    const navCount = document.getElementById('nav-count');
    navCount.textContent = String(s.approvals.pending);
    navCount.style.display = s.approvals.pending ? 'inline-flex' : 'none';
    renderOverview(s);
    if (state.tab === 'approvals') loadApprovals();
    if (state.tab === 'activity') { loadHistory(); loadAudit(); }
  } catch (err) {
    statusEl.textContent = t('status.disconnected', {message:err.message});
  }
}

document.querySelectorAll('nav button').forEach(btn => {
  btn.addEventListener('click', () => activate(btn.dataset.tab));
});
document.getElementById('language').addEventListener('change', event => changeLocale(event.target.value));
window.addEventListener('hashchange', () => activate(location.hash.slice(1)));
applyStaticTranslations();
activate(location.hash.slice(1));
refreshStatus();
setInterval(refreshStatus, 3000);
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "DiscordMCPApproval/1.1"
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # Never log the query string: it carries the console token.
        path = urlparse(self.path).path
        logger.debug("approval console %s %s", self.command, path)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self._send(status, body, "application/json")

    def _error(self, status: int, message: str, code: str = "console_error") -> None:
        self._json(status, {"code": code, "message": message})

    def _auth_ok(self) -> bool:
        console = self.server.console  # type: ignore[attr-defined]
        if console.locked_out(self.client_address[0]):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "Too many failed attempts; wait a minute.")
            return False
        supplied = self.headers.get("X-Approval-Token") or ""
        if not supplied:
            query = parse_qs(urlparse(self.path).query)
            supplied = (query.get("t") or [""])[0]
        if hmac.compare_digest(supplied, console.token):
            console.note_success(self.client_address[0])
            return True
        console.note_failure(self.client_address[0])
        self._error(HTTPStatus.UNAUTHORIZED, "Missing or invalid approval console token.")
        return False

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise ValueError("body must be JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("body must be a JSON object")
        return payload

    def _call_manager(self, coro: Any) -> tuple[bool, Any]:
        console = self.server.console  # type: ignore[attr-defined]
        future = asyncio.run_coroutine_threadsafe(coro, console.loop)
        try:
            return True, future.result(timeout=20)
        except DiscordUserMCPError as exc:
            return False, exc
        except Exception as exc:  # noqa: BLE001
            return False, exc

    @staticmethod
    def _int_param(query: dict[str, list[str]], name: str, default: int, *, low: int = 1, high: int = 200) -> int:
        raw = (query.get(name) or [""])[0]
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        return max(low, min(high, value))

    # -- routes ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path in {"/", "/index.html"}:
            if not self._auth_ok():
                return
            self._send(HTTPStatus.OK, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._json(HTTPStatus.OK, {"ok": True})
            return
        if path not in {"/api/state", "/api/status", "/api/approvals", "/api/audit", "/api/settings"}:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        if not self._auth_ok():
            return
        console = self.server.console  # type: ignore[attr-defined]

        if path == "/api/state":
            pending = console.manager.list(statuses=["pending"], limit=50)
            recent = [
                item
                for item in console.manager.list(limit=20)
                if item["status"] != "pending"
            ][:12]
            self._json(
                HTTPStatus.OK,
                {
                    "server": {
                        "tool_count": console.tool_count,
                        "read_only": console.settings.read_only,
                        "approval_ttl_seconds": console.settings.approval.ttl_seconds,
                    },
                    "pending": pending,
                    "recent": recent,
                },
            )
            return

        if path == "/api/status":
            self._json(HTTPStatus.OK, console.status_snapshot())
            return

        if path == "/api/approvals":
            status = (query.get("status") or [""])[0].strip().lower()
            if status and status not in APPROVAL_STATUSES:
                self._error(HTTPStatus.BAD_REQUEST, f"unknown approval status {status!r}")
                return
            try:
                limit = self._int_param(query, "limit", 50)
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            records = console.manager.list(statuses=[status] if status else None, limit=limit)
            self._json(HTTPStatus.OK, {"count": len(records), "approvals": records})
            return

        if path == "/api/audit":
            try:
                limit = self._int_param(query, "limit", 100)
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            audit = console.manager.audit
            entries = audit.tail(limit=limit)
            self._json(
                HTTPStatus.OK,
                {"count": len(entries), "entries": entries, "enabled": audit.enabled},
            )
            return

        self._json(HTTPStatus.OK, console.settings_snapshot())

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path not in {"/api/approve", "/api/deny", "/api/cancel", "/api/settings"}:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        if not self._auth_ok():
            return
        try:
            payload = self._body()
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return

        if path == "/api/settings":
            self._update_settings(payload)
            return

        approval_id = payload.get("id")
        if not isinstance(approval_id, str) or not approval_id.startswith("ap_"):
            self._error(HTTPStatus.BAD_REQUEST, "id must be an approval id")
            return
        actor = f"console:{self.client_address[0]}"
        console = self.server.console  # type: ignore[attr-defined]
        manager: ApprovalManager = console.manager

        if path == "/api/approve":
            ok, result = self._call_manager(
                manager.approve(
                    approval_id,
                    actor=actor,
                    confirmation=payload.get("confirmation"),
                    note=payload.get("note"),
                )
            )
        elif path == "/api/deny":
            ok, result = self._call_manager(
                manager.deny(approval_id, actor=actor, reason=payload.get("reason"))
            )
        else:
            ok, result = self._call_manager(manager.cancel(approval_id, actor=actor))

        if ok:
            self._json(HTTPStatus.OK, result)
            return
        if isinstance(result, ApprovalError):
            self._json(HTTPStatus.CONFLICT, result.to_dict())
            return
        self._error(HTTPStatus.BAD_REQUEST, str(result), "approval_failed")

    # -- settings ----------------------------------------------------------

    def _update_settings(self, payload: dict[str, Any]) -> None:
        console = self.server.console  # type: ignore[attr-defined]
        confirmation = payload.pop("confirmation", None)
        current = dashboard_settings_from(console.settings)

        locked = sorted(set(payload) & set(DASHBOARD_LOCKED_KEYS))
        if locked:
            self._error(
                HTTPStatus.BAD_REQUEST,
                f"{', '.join(locked)} cannot be changed from the dashboard; "
                "edit the environment or .env file instead.",
                "settings_locked",
            )
            return
        try:
            candidate = DashboardSettings.model_validate(
                {**current.model_dump(), **payload}
            )
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, f"invalid settings: {exc}", "settings_invalid")
            return

        changed = [key for key in payload if getattr(candidate, key) != getattr(current, key)]
        if not changed:
            self._json(
                HTTPStatus.OK,
                {**console.settings_snapshot(), "changed": [], "restart_required": []},
            )
            return

        if current.read_only and not candidate.read_only:
            if console.read_only_locked:
                self._error(
                    HTTPStatus.CONFLICT,
                    "Read-only mode is forced on by DISCORD_MCP_READ_ONLY. "
                    "Remove that variable before enabling writes.",
                    "read_only_locked",
                )
                return
            if (confirmation or "").strip() != DASHBOARD_CONFIRMATION_PHRASE:
                self._json(
                    HTTPStatus.CONFLICT,
                    {
                        "code": "settings_confirmation_required",
                        "message": (
                            "Turning read-only off lets mutating tools create approvals again. "
                            f"Type {DASHBOARD_CONFIRMATION_PHRASE} to confirm."
                        ),
                        "confirmation_phrase": DASHBOARD_CONFIRMATION_PHRASE,
                    },
                )
                return

        restart_required = [
            key for key in changed if key in {"require_startup_auth_check"}
        ]
        actor = f"dashboard:{self.client_address[0]}"
        try:
            console.save_and_apply(candidate, actor=actor, changed=changed)
        except OSError as exc:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"could not save dashboard settings: {exc}",
                "settings_not_saved",
            )
            return
        self._json(
            HTTPStatus.OK,
            {
                **console.settings_snapshot(),
                "changed": changed,
                "restart_required": restart_required,
            },
        )


class _ConsoleServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that can also bind the IPv6 loopback."""

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        super().__init__(address, handler)


class ApprovalConsole:
    def __init__(
        self,
        settings: Settings,
        manager: ApprovalManager,
        *,
        token: str | None = None,
        tool_count: int = 0,
    ) -> None:
        self.settings = settings
        self.manager = manager
        self.token = token or console_token_from_env() or secrets.token_urlsafe(32)
        self.tool_count = tool_count
        self.read_only = settings.read_only
        self.ttl_seconds = settings.approval.ttl_seconds
        self.started_at = time.time()
        self.loop: asyncio.AbstractEventLoop | None = None
        # Filled in by server.run once the app context exists; tests may leave
        # it unset, in which case the dashboard reports what it can.
        self.context: Any = None
        self.read_only_locked = False
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._settings_lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._server is not None

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._server is not None:
            return
        self.loop = loop
        host = self.settings.approval.console_host
        if host == "localhost":
            host = "127.0.0.1"
        server = _ConsoleServer((host, self.settings.approval.console_port), _Handler)
        server.daemon_threads = True
        server.console = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="approval-console", daemon=True)
        self._thread.start()
        self._write_token_file()
        logger.warning("Approval dashboard ready: %s", self.url)
        logger.warning(
            "Open that URL to approve or deny pending Discord operations and to change "
            "server settings. The token in it is the only way in; it is never exposed to the AI."
        )

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def port(self) -> int:
        if self._server is None:
            return 0
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        host = self.settings.approval.console_host
        if host == "localhost":
            host = "127.0.0.1"
        if ":" in host:
            return f"http://[{host}]:{self.port}/"
        return f"http://{host}:{self.port}/"

    @property
    def url(self) -> str:
        return f"{self.base_url}?t={self.token}"

    @property
    def safe_url(self) -> str:
        return self.base_url

    def _write_token_file(self) -> None:
        if not self.settings.approval.write_token_file:
            return
        path = Path(self.settings.state_dir) / "approval-console.json"
        payload = {
            "url": self.url,
            "token": self.token,
            "pid": os.getpid(),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note": "Anyone who can read this file can approve operations. Keep it private.",
        }
        try:
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError as exc:  # pragma: no cover
            logger.warning("could not write approval console token file: %s", exc)

    # -- dashboard data ----------------------------------------------------

    def locked_settings(self) -> dict[str, Any]:
        fingerprint = "unset"
        context = self.context
        if context is not None:
            try:
                fingerprint = context.client.token_fingerprint()
            except Exception:  # noqa: BLE001 - status must never break the page
                pass
        return {
            "token_source": self.settings.token_source,
            "token_fingerprint": fingerprint,
            "api_base": self.settings.http.base_url,
            "console_url": self.safe_url,
            "state_dir": str(self.settings.state_dir),
            "reason": (
                "The token, API host and console bind address are fixed when the server "
                "starts. Change them in the environment or .env file."
            ),
        }

    def status_snapshot(self) -> dict[str, Any]:
        settings = self.settings
        context = self.context
        identity = None
        fingerprint = "unset"
        uptime = int(time.time() - self.started_at)
        rate_limits: dict[str, Any] = {
            "global_blocked_for_seconds": 0.0,
            "tracked_routes": 0,
        }
        if context is not None:
            identity = getattr(context, "identity", None)
            uptime = int(time.time() - getattr(context, "started_at", self.started_at))
            try:
                fingerprint = context.client.token_fingerprint()
            except Exception:  # noqa: BLE001
                pass
            try:
                limiter = context.client.limiter
                rate_limits = {
                    "global_blocked_for_seconds": limiter.global_blocked_for,
                    "tracked_routes": len(limiter.snapshot()),
                }
            except Exception:  # noqa: BLE001
                pass
        try:
            from ..api.registry import get_registry

            registry = get_registry().stats()
        except Exception:  # noqa: BLE001 - dashboard must still render
            registry = {"total": 0, "by_status": {}, "implemented_endpoints": 0}
        audit = self.manager.audit
        return {
            "server": {
                "version": __version__,
                "uptime_seconds": uptime,
                "started_at": iso(self.started_at),
            },
            "identity": identity,
            "token": {
                "configured": settings.token is not None,
                "source": settings.token_source,
                "fingerprint": fingerprint,
                "bot_tokens_supported": False,
            },
            "mode": {
                "read_only": settings.read_only,
                "approval_ttl_seconds": settings.approval.ttl_seconds,
                "uploads_enabled": settings.upload.enabled,
                "audit_enabled": audit.enabled,
                "audit_path": str(audit.path),
            },
            "tools": {"registered": self.tool_count},
            "registry": registry,
            "approvals": {
                "pending": len(self.manager.list(statuses=["pending"], limit=200)),
            },
            "rate_limits": rate_limits,
            "console": {
                "url_without_token": self.safe_url,
                "token_required": True,
                "read_only_locked": self.read_only_locked,
            },
        }

    def settings_snapshot(self) -> dict[str, Any]:
        return {
            "settings": dashboard_settings_from(self.settings).model_dump(),
            "locked": self.locked_settings(),
            "confirmation_phrase": DASHBOARD_CONFIRMATION_PHRASE,
            "read_only_locked": self.read_only_locked,
        }

    def save_and_apply(
        self, candidate: DashboardSettings, *, actor: str, changed: list[str]
    ) -> None:
        """Persist, audit, then apply. Saving first means a disk error changes nothing."""
        with self._settings_lock:
            save_dashboard_settings(self.settings.state_dir, candidate)
            audit = self.manager.audit
            # Record the change even when auditing is being switched on or off.
            audit.set_enabled(True)
            try:
                audit.record(
                    "dashboard_settings_changed",
                    actor=actor,
                    changed=changed,
                    read_only=candidate.read_only,
                    approval_ttl_seconds=candidate.approval_ttl_seconds,
                    audit_enabled=candidate.audit_enabled,
                )
            finally:
                audit.set_enabled(candidate.audit_enabled)
            apply_dashboard_settings(self.settings, candidate)
            self.read_only = candidate.read_only
            self.ttl_seconds = candidate.approval_ttl_seconds
            context = self.context
            if context is not None:
                apply_settings = getattr(context.client, "apply_settings", None)
                if callable(apply_settings):
                    apply_settings()
            if "log_level" in changed:
                configure_logging(candidate.log_level)
            logger.info("dashboard settings changed by %s: %s", actor, ", ".join(changed))

    # -- brute force protection -------------------------------------------

    def locked_out(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            attempts = [t for t in self._failures.get(ip, []) if now - t < FAILED_WINDOW_SECONDS]
            self._failures[ip] = attempts
            return len(attempts) >= MAX_FAILED_ATTEMPTS

    def note_failure(self, ip: str) -> None:
        with self._lock:
            self._failures.setdefault(ip, []).append(time.time())

    def note_success(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)
