// Node-only behavior checks; verifies service worker state transitions but not
// actual Microsoft Edge browser behavior or MV3 redirect compatibility.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const source = fs.readFileSync('edge-extension/background.js','utf8');
const handlers = {};
let websiteEnabled = false;
let online = true;
let paused = false;
let rules = [];
let attempts = [];
const chrome = {
  declarativeNetRequest: {
    getDynamicRules: async () => [...rules],
    updateDynamicRules: async ({removeRuleIds,addRules}) => {
      rules = rules.filter(r => !removeRuleIds.includes(r.id)).concat(addRules);
    }
  },
  storage: {
    local: {
      get: async (defaults) => ({ssg8_paused: paused}),
      set: async (data) => {paused = data.ssg8_paused}
    },
    session: {
      set: async () => {},
      get: async () => ({ssg8_last_domain: 'youtube.com'})
    }
  },
  webNavigation: {onBeforeNavigate:{addListener: fn => handlers.navigation = fn}},
  alarms: {create:()=>{},onAlarm:{addListener: fn => handlers.alarm = fn}},
  runtime: {
    onInstalled:{addListener:fn=>handlers.installed = fn},
    onStartup:{addListener:fn=>handlers.startup = fn},
    onMessage:{addListener:fn=>handlers.message = fn}
  }
};
const fetchMock = async (url, options = {}) => {
  if (!online) throw Error('offline');
  if (url.endsWith('/status')) {
    return {ok:true,json:async () => ({online:true,website_enabled:websiteEnabled,token:'test-token'})};
  }
  if (url.endsWith('/attempt')) {
    attempts.push(JSON.parse(options.body).url);
    return {ok:true};
  }
  throw Error('bad fetch '+url);
};
const context = vm.createContext({chrome,fetch:fetchMock,AbortSignal,URL,Promise,Boolean,Error});
vm.runInContext(source,context);
const later = () => new Promise(resolve=>setTimeout(resolve,25));
function message(input){return new Promise(resolve=>handlers.message(input,{},resolve));}
(async ()=> {
  await later();
  assert.equal(rules.length,0,'OFF when app website module OFF');
  websiteEnabled = true;
  handlers.alarm({name:'ssg8-status-sync'});
  await later();
  assert.equal(rules.length,1,'ON after app website module ON');
  assert.equal(rules[0].action.type,'redirect');
  assert.equal(rules[0].condition.resourceTypes[0],'main_frame');
  handlers.navigation({frameId:0,url:'https://youtube.com/watch?v=secret'});
  await later();
  assert.deepEqual(attempts,['https://youtube.com/'],'hostname only');
  const state = await message({type:'pause',value:true});
  assert.equal(state.paused,true);
  assert.equal(rules.length,0,'paused by user');
  await message({type:'pause',value:false});
  assert.equal(rules.length,1,'resumes');
  online = false;
  handlers.alarm({name:'ssg8-status-sync'});
  await later();
  assert.equal(rules.length,0,'fail-open when app offline');
  console.log('Edge extension worker smoke tests passed');
})().catch(e=>{console.error(e);process.exit(1)});
