// Comprehensive Verification Suite for ComplianceShield Extended Engine
const fs = require('fs');
const assert = require('assert');

// Load app.js by extracting variables or simulating DOM
const appJsContent = fs.readFileSync('D:/compliance-checker/app.js', 'utf8');

// Create sandbox to execute data structures from app.js
const sandbox = {
  window: {},
  document: {
    addEventListener: () => {},
    getElementById: () => ({ addEventListener: () => {}, classList: { add: () => {}, remove: () => {} } }),
    querySelectorAll: () => []
  },
  localStorage: { getItem: () => null, setItem: () => {} },
  navigator: { clipboard: { writeText: () => Promise.resolve() } }
};

const vm = require('vm');
const context = vm.createContext(sandbox);
vm.runInContext(appJsContent, context);

const { CONTROLS, CODE_VULN_RULES, CODE_PRESETS, JURISDICTIONS, PRESETS } = vm.runInContext(
  '({ CONTROLS, CODE_VULN_RULES, CODE_PRESETS, JURISDICTIONS, PRESETS })',
  context
);

console.log('====================================================');
console.log('🔍 ComplianceShield Engine Extended Verification Suite');
console.log('====================================================\n');

// 1. Controls Verification
console.log('1. Checking Master Controls Database...');
const requiredControlIds = ['PRIV-06', 'PRIV-07', 'PRIV-08', 'COMM-01'];
requiredControlIds.forEach(id => {
  const ctrl = CONTROLS.find(c => c.id === id);
  assert(ctrl, `Control ${id} must exist in CONTROLS`);
  assert(ctrl.title, `Control ${id} must have a title`);
  assert(ctrl.citations, `Control ${id} must have regulatory citations`);
  assert(ctrl.remediationTip, `Control ${id} must have a remediationTip`);
  console.log(`  ✓ Control [${id}]: "${ctrl.title}" verified`);
});

// 2. Rules Verification
console.log('\n2. Checking Static Analysis Rules...');
const ruleIds = [
  'SEC-PRIV-COPPA-AGEGATE',
  'SEC-PRIV-GOOGLE-FONTS',
  'SEC-PRIV-SESSION-REPLAY',
  'SEC-COMM-EMAIL-COMPLIANCE'
];
ruleIds.forEach(id => {
  const rule = CODE_VULN_RULES.find(r => r.id === id);
  assert(rule, `Rule ${id} must exist in CODE_VULN_RULES`);
  assert(rule.cwe, `Rule ${id} must have CWE mapping`);
  assert(rule.owasp, `Rule ${id} must have OWASP mapping`);
  assert(rule.exploit, `Rule ${id} must have exploit explanation`);
  assert(rule.goodCode, `Rule ${id} must have goodCode remediation`);
  console.log(`  ✓ Rule [${id}]: "${rule.title}" verified`);
});

// 3. Testing Rule Execution & Edge Cases
console.log('\n3. Testing Rule Scans & Edge Cases...');

// Helper runner
function scanCode(code) {
  const lines = code.split('\n');
  const findings = [];
  lines.forEach((lineText, idx) => {
    CODE_VULN_RULES.forEach(rule => {
      if (rule.test(lineText, code, idx, lines)) {
        findings.push({ line: idx + 1, ruleId: rule.id, title: rule.title, rule });
      }
    });
  });
  return findings;
}

// 3a. COPPA Age Gate Rule
console.log('  Testing COPPA Age Gate Rule...');
const vulnerableCoppa = `
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  const user = await db.users.create({ username, email, password });
  res.json(user);
});`;
const coppaFindings = scanCode(vulnerableCoppa).filter(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
assert(coppaFindings.length > 0, 'Must flag missing COPPA age gate in registration route');

const safeCoppa = `
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, birthdate } = req.body;
  const age = calculateAge(birthdate);
  if (age < 13) return res.status(403).json({ error: 'Parental consent required' });
  const user = await db.users.create({ username, email, password, birthdate });
  res.json(user);
});`;
const safeCoppaFindings = scanCode(safeCoppa).filter(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
assert.strictEqual(safeCoppaFindings.length, 0, 'Must NOT flag COPPA when birthdate / age gate is present');
console.log('  ✓ COPPA Age Gate detection and pass-through confirmed');

// 3b. Google Fonts Dynamic Fetch Rule
console.log('  Testing Google Fonts Dynamic Fetch Rule...');
const flutterBadFonts = `
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

void main() {
  runApp(MyApp());
}
Text('Hi', style: GoogleFonts.roboto());`;
const fontFindings = scanCode(flutterBadFonts).filter(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
assert(fontFindings.length > 0, 'Must flag Flutter GoogleFonts when allowRuntimeFetching = false is missing');

const flutterGoodFonts = `
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  GoogleFonts.config.allowRuntimeFetching = false;
  runApp(MyApp());
}
Text('Hi', style: GoogleFonts.roboto());`;
const safeFontFindings = scanCode(flutterGoodFonts).filter(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
assert.strictEqual(safeFontFindings.length, 0, 'Must NOT flag Flutter GoogleFonts when allowRuntimeFetching = false is set');

const webBadFonts = `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto">`;
const webFontFindings = scanCode(webBadFonts).filter(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
assert(webFontFindings.length > 0, 'Must flag Web fonts.googleapis.com stylesheet links');
console.log('  ✓ Google Fonts dynamic fetch detection confirmed for both Flutter and Web');

// 3c. Session Replay Rule
console.log('  Testing Session Replay SDK Detection Rule...');
const badReplay1 = `import LogRocket from 'logrocket';\nLogRocket.init('org/app');`;
const badReplay2 = `window['_fs_namespace'] = 'FS';\nFS.identify('123');`;
const badReplay3 = `clarity("init", "abc123xyz");`;
const badReplay4 = `smartlookClient.init('KEY123');`;
const badReplay5 = `hj('init', 123456, 6);`;

[badReplay1, badReplay2, badReplay3, badReplay4, badReplay5].forEach(snippet => {
  const hits = scanCode(snippet).filter(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
  assert(hits.length > 0, `Must flag unconsented session replay: ${snippet.split('\n')[0]}`);
});

const safeReplay = `
if (userConsentState.hasConsent === true) {
  LogRocket.init('org/app', { dom: { inputSanitizer: true } });
}`;
const safeReplayHits = scanCode(safeReplay).filter(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
assert.strictEqual(safeReplayHits.length, 0, 'Must NOT flag session replay when guarded by consent');
console.log('  ✓ Session Replay detection confirmed for LogRocket, FullStory, Clarity, Smartlook, Hotjar');

// 3d. Email Unsubscribe & Postal Address Rule
console.log('  Testing Commercial Email Unsubscribe & Address Rule...');
const badEmailNoUnsub = `
await transporter.sendMail({
  from: 'news@brand.com',
  to: user.email,
  subject: 'Discounts',
  html: '<h1>Discounts</h1><p>123 Main St, Austin, TX 78701</p>'
});`;
const badEmailNoAddress = `
await transporter.sendMail({
  from: 'news@brand.com',
  to: user.email,
  subject: 'Discounts',
  html: '<h1>Discounts</h1><a href="{{unsubscribe_url}}">Unsubscribe</a>'
});`;
assert(scanCode(badEmailNoUnsub).some(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE'), 'Must flag email missing unsubscribe token');
assert(scanCode(badEmailNoAddress).some(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE'), 'Must flag email missing physical postal address');

const safeEmail = `
await transporter.sendMail({
  from: 'news@brand.com',
  to: user.email,
  subject: 'Discounts',
  html: '<h1>Discounts</h1><footer><a href="{{unsubscribe_url}}">Unsubscribe</a><br>100 Market St, Suite 400, San Francisco, CA 94105, USA</footer>'
});`;
assert.strictEqual(scanCode(safeEmail).filter(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE').length, 0, 'Must NOT flag compliant email');
console.log('  ✓ Email Unsubscribe and physical postal address enforcement confirmed');

// 4. Presets Verification
console.log('\n4. Checking Code Presets...');
const presetsKeys = ['coppa', 'fonts', 'replay', 'email', 'flutter_bundle'];
presetsKeys.forEach(key => {
  assert(CODE_PRESETS[key], `Preset ${key} must exist in CODE_PRESETS`);
  const hits = scanCode(CODE_PRESETS[key]);
  assert(hits.length > 0, `Preset ${key} must produce findings when scanned`);
  console.log(`  ✓ Preset [${key}] produces ${hits.length} finding(s)`);
});

// 5. Global Jurisdictions & Worldwide Launch Readiness Engine Verification
console.log('\n5. Checking Global Jurisdictions Database...');
assert(JURISDICTIONS.length >= 10, 'Must have at least 10 major global jurisdictions');
let totalCountriesAcrossAll = new Set();
JURISDICTIONS.forEach(j => {
  assert(j.id, 'Jurisdiction must have id');
  assert(j.name, 'Jurisdiction must have name');
  assert(j.flag, 'Jurisdiction must have flag');
  assert(j.countries && j.countries.length > 0, `Jurisdiction ${j.name} must list countries`);
  assert(j.governingLaws, `Jurisdiction ${j.name} must list governing laws`);
  assert(j.statutoryPenalties, `Jurisdiction ${j.name} must list statutory penalties`);
  assert(typeof j.evaluate === 'function', `Jurisdiction ${j.name} must have evaluate function`);
  j.countries.forEach(c => totalCountriesAcrossAll.add(c));
  console.log(`  ✓ [${j.flag} ${j.name}]: covers ${j.countries.length} country/territory target(s) (${j.statutoryPenalties})`);
});
console.log(`  Total unique country targets covered: ${totalCountriesAcrossAll.size}`);
assert(totalCountriesAcrossAll.size >= 195, 'Should cover 195+ countries across jurisdictions');

// 6. Jurisdictional Evaluation Scenarios
console.log('\n6. Testing Global Launch Readiness Evaluation Scenarios...');

// Scenario A: Clean App (zero findings, all controls compliant)
const cleanEvaluation = JURISDICTIONS.map(j => j.evaluate([], {}));
const cleanBlocked = cleanEvaluation.filter(r => r.status === 'blocked');
assert.strictEqual(cleanBlocked.length, 0, 'Clean app must have 0 blocked jurisdictions');
console.log('  ✓ Scenario A: Clean code passes in 100% of global jurisdictions');

// Scenario B: Google Fonts Dynamic Fetch
const fontFindingsMock = [{ ruleId: 'SEC-PRIV-GOOGLE-FONTS', category: 'Privacy & Data Sovereignty' }];
const euEvalWithFonts = JURISDICTIONS.find(j => j.id === 'eu').evaluate(fontFindingsMock, {});
assert.strictEqual(euEvalWithFonts.status, 'blocked', 'Google Fonts leak must block European Union');
assert(euEvalWithFonts.blockers.some(b => b.desc.includes('Munich')), 'Must cite Munich Regional Court ruling');
assert(euEvalWithFonts.blockers[0].fix.includes('allowRuntimeFetching = false'), 'Must provide Flutter allowRuntimeFetching fix');
console.log('  ✓ Scenario B: Google Fonts dynamic fetch blocks EU with Munich Court citation & actionable fix');

// Scenario C: Missing COPPA Age Gate
const coppaFindingsMock = [{ ruleId: 'SEC-PRIV-COPPA-AGEGATE', category: 'Privacy & Child Safety' }];
const usFedEval = JURISDICTIONS.find(j => j.id === 'us-fed').evaluate(coppaFindingsMock, {});
const indiaEval = JURISDICTIONS.find(j => j.id === 'india').evaluate(coppaFindingsMock, {});
const ukEval = JURISDICTIONS.find(j => j.id === 'uk').evaluate(coppaFindingsMock, {});
const caEvalCoppa = JURISDICTIONS.find(j => j.id === 'canada').evaluate(coppaFindingsMock, {});
const auEvalCoppa = JURISDICTIONS.find(j => j.id === 'australia').evaluate(coppaFindingsMock, {});
const jpEvalCoppa = JURISDICTIONS.find(j => j.id === 'japan').evaluate(coppaFindingsMock, {});
const sgEvalCoppa = JURISDICTIONS.find(j => j.id === 'singapore').evaluate(coppaFindingsMock, {});
const chEvalCoppa = JURISDICTIONS.find(j => j.id === 'switzerland').evaluate(coppaFindingsMock, {});

assert.strictEqual(usFedEval.status, 'blocked', 'Missing COPPA must block US Federal');
assert(usFedEval.blockers.some(b => b.law.includes('COPPA')), 'Must cite COPPA statute');
assert.strictEqual(indiaEval.status, 'blocked', 'Missing minor age gate must block India');
assert(indiaEval.blockers.some(b => b.law.includes('DPDP')), 'Must cite DPDP Act 2023 Section 9');
assert.strictEqual(ukEval.status, 'blocked', 'Missing age assurance must block UK');
assert(ukEval.blockers.some(b => b.law.includes('Children\'s Code')), 'Must cite ICO Children\'s Code');
assert.strictEqual(caEvalCoppa.status, 'blocked', 'Missing minor age gate must block Canada');
assert(caEvalCoppa.blockers.some(b => b.law.includes('PIPEDA')), 'Must cite PIPEDA child consent guidance');
assert.strictEqual(auEvalCoppa.status, 'blocked', 'Missing minor age gate must block Australia');
assert(auEvalCoppa.blockers.some(b => b.law.includes('Privacy Act')), 'Must cite Australia Privacy Act');
assert.strictEqual(jpEvalCoppa.status, 'blocked', 'Missing minor age gate must block Japan');
assert(jpEvalCoppa.blockers.some(b => b.law.includes('APPI')), 'Must cite Japan APPI');
assert.strictEqual(sgEvalCoppa.status, 'blocked', 'Missing minor age gate must block Singapore');
assert(sgEvalCoppa.blockers.some(b => b.law.includes('PDPA')), 'Must cite Singapore PDPA');
assert.strictEqual(chEvalCoppa.status, 'blocked', 'Missing minor age gate must block Switzerland');
assert(chEvalCoppa.blockers.some(b => b.law.includes('FADP')), 'Must cite Swiss FADP');
console.log('  ✓ Scenario C: Missing age gate blocks US (COPPA), India (DPDP Sec 9), UK, CA, AU, JP, SG, CH');

// Scenario D: Unconsented Session Replay
const replayFindingsMock = [{ ruleId: 'SEC-PRIV-SESSION-REPLAY', category: 'Privacy & Wiretapping Risk' }];
const wiretapEval = JURISDICTIONS.find(j => j.id === 'us-wiretap').evaluate(replayFindingsMock, {});
const caEval = JURISDICTIONS.find(j => j.id === 'us-ca').evaluate(replayFindingsMock, {});
assert.strictEqual(wiretapEval.status, 'blocked', 'Session replay must trigger PA/FL two-party wiretap blocker');
assert(wiretapEval.blockers.some(b => b.law.includes('Wiretap')), 'Must cite wiretap doctrine');
assert.strictEqual(caEval.status, 'blocked', 'Session replay must trigger CPRA behavioral sharing blocker');
console.log('  ✓ Scenario D: Unconsented session replay triggers PA/FL wiretap and California CPRA blockers');

// Scenario E: Missing Email Unsubscribe
const emailFindingsMock = [{ ruleId: 'SEC-COMM-EMAIL-COMPLIANCE', category: 'Commercial Messaging Compliance' }];
const canadaEval = JURISDICTIONS.find(j => j.id === 'canada').evaluate(emailFindingsMock, {});
const ausEval = JURISDICTIONS.find(j => j.id === 'australia').evaluate(emailFindingsMock, {});
assert.strictEqual(canadaEval.status, 'blocked', 'Missing email unsubscribe must block Canada under CASL');
assert(canadaEval.blockers.some(b => b.law.includes('CASL')), 'Must cite CASL Section 6');
assert.strictEqual(ausEval.status, 'blocked', 'Missing email unsubscribe must block Australia under Spam Act');
assert(ausEval.blockers.some(b => b.law.includes('Spam Act')), 'Must cite Australia Spam Act');
console.log('  ✓ Scenario E: Missing email unsubscribe blocks Canada (CASL $10M) and Australia (Spam Act)');

// 7. Full 195-Nation Master Launch Matrix Verification
console.log('\n7. Testing Worldwide 195-Nation Master Launch Matrix...');
const { GLOBAL_COUNTRY_CATALOGUE } = vm.runInContext('({ GLOBAL_COUNTRY_CATALOGUE })', context);
assert.strictEqual(GLOBAL_COUNTRY_CATALOGUE.length, 195, 'Must have exactly 195 sovereign countries in catalogue');

function eval195(findings) {
  const jMap = new Map();
  JURISDICTIONS.forEach(j => jMap.set(j.id, j.evaluate(findings, {})));
  let blocked = 0, allowed = 0;
  GLOBAL_COUNTRY_CATALOGUE.forEach(c => {
    const jIds = c.jId === 'us-composite' ? ['us-fed', 'us-ca', 'us-wiretap'] : [c.jId];
    let isBlocked = false;
    jIds.forEach(id => {
      const ev = jMap.get(id);
      if (ev && ev.status === 'blocked') isBlocked = true;
    });
    if (isBlocked) blocked++; else allowed++;
  });
  return { blocked, allowed };
}

const clean195 = eval195([]);
assert.strictEqual(clean195.allowed, 195, 'Clean app must be 100% launchable worldwide (195/195)');
assert.strictEqual(clean195.blocked, 0, 'Clean app must have 0 blockers');
console.log('  ✓ Clean code: 195 / 195 countries Allowed (100% Worldwide Launch Allowed)');

const fonts195 = eval195(fontFindingsMock);
assert.strictEqual(fonts195.blocked, 32, 'Google Fonts leak must block exactly 32 countries (30 EU + CH + CN)');
assert.strictEqual(fonts195.allowed, 163, 'Google Fonts leak must leave 163 countries allowed');
console.log('  ✓ Google Fonts violation: 32 countries Blocked (EU/EEA + Switzerland + China), 163 countries Allowed');

const replay195 = eval195(replayFindingsMock);
assert.strictEqual(replay195.blocked, 34, 'Session replay leak must block 34 countries');
assert.strictEqual(replay195.allowed, 161, 'Session replay leak must leave 161 countries allowed');
console.log('  ✓ Session Replay violation: 34 countries Blocked, 161 countries Allowed');

const email195 = eval195(emailFindingsMock);
assert.strictEqual(email195.blocked, 6, 'Email unsubscribe leak must block 6 countries (US, UK, CA, AU, SG, ZA)');
assert.strictEqual(email195.allowed, 189, 'Email unsubscribe leak must leave 189 countries allowed');
console.log('  ✓ Email Unsubscribe violation: 6 countries Blocked, 189 countries Allowed');

const coppa195 = eval195(coppaFindingsMock);
assert.strictEqual(coppa195.blocked, 195, 'Missing minor age gate must block all 195 countries worldwide');
assert.strictEqual(coppa195.allowed, 0, 'Missing minor age gate must allow 0 countries worldwide');
console.log('  ✓ COPPA Age Gate violation: 195 / 195 countries Blocked Worldwide (Universal Child Privacy Mandate), 0 Allowed');

console.log('\n====================================================');
console.log('🎉 ALL ENGINE & JURISDICTIONAL TESTS PASSED PERFECTLY!');
console.log('====================================================');

