const fs = require('fs');
const appJs = fs.readFileSync('D:/compliance-checker/app.js', 'utf8');
const html = fs.readFileSync('D:/compliance-checker/index.html', 'utf8');

// Check all button/input IDs in HTML to see if they are referenced in app.js
const idRegex = /id=["']([a-zA-Z0-9_-]+)["']/g;
let m;
const htmlIds = [];
while ((m = idRegex.exec(html)) !== null) {
  htmlIds.push(m[1]);
}

const unreferenced = htmlIds.filter(id => !appJs.includes(id));
console.log('HTML IDs unreferenced in app.js:', unreferenced);
