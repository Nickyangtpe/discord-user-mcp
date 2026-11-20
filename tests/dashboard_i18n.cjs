// Exercise the shipped dashboard script with a small, local DOM test fixture.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(0, 'utf8');
const nodes = [];
class Element {
  constructor(tag) {
    this.tagName = tag; this.dataset = {}; this.children = []; this.attributes = {};
    this.textContent = ''; this.value = ''; this.listeners = {};
    this.classes = new Set(); nodes.push(this);
    this.classList = {toggle:(name, on) => {
      if (on) this.classes.add(name); else this.classes.delete(name);
    }, add:name => this.classes.add(name), remove:name => this.classes.delete(name)};
  }
  set className(value) { this.classes = new Set(value.split(' ')); }
  get className() { return [...this.classes].join(' '); }
  appendChild(node) { this.children.push(node); return node; }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  focus() {}
  click() { this.listeners.click({preventDefault(){}, stopPropagation(){}}); }
}
const document = {
  documentElement:{}, cookie:'',
  createElement:tag => new Element(tag),
  createTextNode:text => new Element('#text'),
  getElementById:id => nodes.find(n => n.id === id),
  querySelectorAll:selector => nodes.filter(n => {
    if (selector.startsWith('.')) return n.classes.has(selector.slice(1));
    const attribute = selector.match(/^\[data-([a-z0-9-]+)\]$/)[1];
    const key = attribute.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    return key in n.dataset;
  })
};
for (const id of ['language','status','toast','settings','pending','history','audit','access-token','error','unlock']) {
  const n = new Element('div'); n.id = id; n.style = {};
}
const context = vm.createContext({document, Node:Element, URLSearchParams, URL, Intl,
  navigator:{language:'en'}, localStorage:{getItem:() => null,setItem(){}},
  location:{search:'',href:'http://127.0.0.1/'}, setTimeout(){}, console});
if (process.argv[2] === 'locked') {
  vm.runInContext(script, context);
  const title = new Element('h1'); title.dataset.i18n = 'title';
  document.getElementById('unlock').click();
  const language = document.getElementById('language');
  language.value = 'zh-TW'; language.listeners.change({target:language});
  assert.equal(title.textContent, '控制台已鎖定');
  assert.equal(document.getElementById('error').textContent, '請輸入存取權杖。');
  const token = document.getElementById('access-token'); token.value = 'local-test-value';
  language.value = 'en'; language.listeners.change({target:language});
  assert.equal(title.textContent, 'Dashboard locked');
  assert.equal(document.getElementById('error').textContent, 'Enter the access token.');
  assert.equal(token.value, 'local-test-value');
  console.log('locked page locale regression checks passed');
  process.exit(0);
}
vm.runInContext(script.slice(0, script.lastIndexOf("document.querySelectorAll('nav button')")), context);
vm.runInContext(`
  refreshStatus = () => {};
  locale = 'en';
  renderPending({approval_id:'ap_test',tool:'delete_message',risk:'destructive',
    target:'channel_id=123',expires_in_seconds:120,requires_typed_confirmation:true,
    approval_phrase:'APPROVE',args:{},summary:'Delete a message'});
  renderHistory([]);
  emptyState('request.empty');
  renderAudit({enabled:false,entries:[]});
  renderSettings({settings:{read_only:true,log_level:'WARNING',approval_ttl_seconds:300},
    locked:{state_dir:'test-state'},confirmation_phrase:'ENABLE WRITES'});
`, context);
const findClass = name => nodes.find(n => n.classes.has(name));
const confirmation = nodes.find(n => n.dataset.i18nPlaceholder === 'request.highRiskPlaceholder');
confirmation.value = 'APPROVE'; confirmation.listeners.input();
const ttl = document.getElementById('set-approval_ttl_seconds'); ttl.value = '125';
const readOnly = document.getElementById('set-read_only'); readOnly.checked = false;
readOnly.listeners.change();
document.getElementById('settings-confirm').value = 'ENABLE WRITES';
const protectedNode = findClass('protected-value'); protectedNode.click();
const technical = nodes.find(n => n.tagName === 'details'); technical.open = true;
vm.runInContext("toast(() => t('settings.noChanges')); changeLocale('zh-TW');", context);
assert.equal(findClass('request-title').textContent, '刪除訊息');
assert.equal(confirmation.placeholder, '高風險操作：輸入 APPROVE');
assert.equal(confirmation.value, 'APPROVE');
assert.equal(findClass('countdown').textContent, '2 分鐘後逾時');
assert.equal(protectedNode.textContent, '頻道 123');
assert.equal(protectedNode.attributes['aria-label'], '點擊再次隱藏');
assert.equal(technical.open, true);
assert.equal(ttl.value, '125');
assert.equal(readOnly.checked, false);
assert.equal(document.getElementById('settings-confirm').value, 'ENABLE WRITES');
assert.equal(document.getElementById('toast').textContent, '沒有需要儲存的變更。');
assert.equal(nodes.find(n => n.dataset.i18n === 'history.empty').textContent, '目前沒有請求記錄');
assert.equal(nodes.find(n => n.dataset.i18n === 'request.empty').textContent, '目前沒有等待處理的請求');
assert.equal(nodes.find(n => n.dataset.i18n === 'audit.empty').textContent, '目前沒有系統記錄');
assert.equal(nodes.find(n => n.dataset.i18n === 'log.WARNING').textContent, '警告');
assert.equal(nodes.find(n => n.dataset.i18n === 'log.WARNING').value, 'WARNING');
vm.runInContext("changeLocale('en');", context);
assert.equal(findClass('request-title').textContent, 'Delete Message');
assert.equal(protectedNode.textContent, 'Channel 123');
assert.equal(confirmation.placeholder, 'High-risk operation: type APPROVE');
assert.equal(findClass('countdown').textContent, 'expires in 2m');
assert.equal(nodes.find(n => n.dataset.i18n === 'history.empty').textContent, 'No request history yet');
assert.equal(nodes.find(n => n.dataset.i18n === 'log.WARNING').textContent, 'Warning');
vm.runInContext(`
  for (const language of Object.keys(STRINGS)) {
    const expected = Object.keys(STRINGS.en).sort().join('|');
    if (Object.keys(STRINGS[language]).sort().join('|') !== expected) throw Error('Catalog mismatch');
  }
  const error = localizedError('error.unauthorized');
  locale = 'zh-TW';
  if (!error.message.includes('重新解鎖')) throw Error('Missing translated error');
  locale = 'en';
  if (!error.message.includes('Unlock it again')) throw Error('Error failed to switch locale');
`, context);
console.log('dashboard locale regression checks passed');
