const vm = require('vm');
const fs = require('fs');

const appJs = fs.readFileSync('D:/compliance-checker/app.js', 'utf8');
const sandbox = {
  window: {},
  document: { addEventListener: () => {}, getElementById: () => null, querySelectorAll: () => [] },
  localStorage: { getItem: () => null, setItem: () => {} }
};
const ctx = vm.createContext(sandbox);
vm.runInContext(appJs, ctx);

const { GLOBAL_COUNTRY_CATALOGUE, JURISDICTIONS } = vm.runInContext('({ GLOBAL_COUNTRY_CATALOGUE, JURISDICTIONS })', ctx);

const coppaFindings = [{ ruleId: 'SEC-PRIV-COPPA-AGEGATE', category: 'Privacy & Child Safety' }];
const coppaJMap = new Map();
JURISDICTIONS.forEach(j => {
  coppaJMap.set(j.id, j.evaluate(coppaFindings, {}));
});

let coppaBlockedCountries = [];
GLOBAL_COUNTRY_CATALOGUE.forEach(c => {
  const jIds = c.jId === 'us-composite' ? ['us-fed', 'us-ca', 'us-wiretap'] : [c.jId];
  let isBlocked = false;
  jIds.forEach(id => {
    const ev = coppaJMap.get(id);
    if (ev && ev.status === 'blocked') isBlocked = true;
  });
  if (isBlocked) coppaBlockedCountries.push(c.name);
});
console.log('COPPA: Blocked countries count:', coppaBlockedCountries.length);
console.log('COPPA: Sample blocked:', coppaBlockedCountries.slice(0, 8));
