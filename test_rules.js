// Test harness for ComplianceShield extended rules
const assert = require('assert');

// 1. COPPA Rule Test
const coppaTest = (line, rawCode, idx, lines) => {
  const isAuthOrReg = /(app|router)\.(post|put)\s*\(\s*['"][^'"]*(register|signup|create-account|users)['"]/i.test(line) ||
    /function\s+(register|signUp|createUser|handleRegistration)\b/i.test(line) ||
    /class\s+(Register|SignUp|Registration)\w*\s+extends/i.test(line) ||
    /auth\.signUp\s*\(/i.test(line) ||
    /<form[^>]*action=["'][^"']*(register|signup)["']/i.test(line) ||
    /const\s+(register|signup|createUser)\s*=\s*(async\s*)?\(/i.test(line);

  if (!isAuthOrReg) return false;

  const start = Math.max(0, idx - 5);
  const end = Math.min(lines.length, idx + 35);
  const surrounding = lines.slice(start, end).join('\n');

  const hasAgeGate = /(dob|birth_?date|date_?of_?birth|age_?gate|parental_?consent|under_?13|min_?age|verify_?age|is_?adult)/i.test(surrounding);
  return !hasAgeGate;
};

// 2. Google Fonts Rule Test
const fontsTest = (line, rawCode, idx, lines) => {
  const isGoogleFontUsage = /GoogleFonts\.[a-zA-Z0-9_]+\s*\(/i.test(line) ||
    /import\s+['"]package:google_fonts\/google_fonts\.dart['"]/i.test(line) ||
    /google_fonts:\s*\^[0-9.]+/i.test(line) ||
    /<link[^>]*href=["']https?:\/\/fonts\.(googleapis|gstatic)\.com/i.test(line) ||
    /@import\s+url\(['"]?https?:\/\/fonts\.(googleapis|gstatic)\.com/i.test(line);

  if (!isGoogleFontUsage) return false;

  // If Flutter code sets allowRuntimeFetching = false, it's safe!
  if (/allowRuntimeFetching\s*=\s*false/i.test(rawCode)) {
    return false;
  }
  return true;
};

// 3. Session Replay Rule Test
const replayTest = (line, rawCode, idx, lines) => {
  const isReplaySdk = /(LogRocket\.init\s*\(|FS\.identify\s*\(|FS\.restart\s*\(|window\['_fs_namespace'\]|fullstory\.com\/s\/fs\.js|smartlookClient\.init\s*\(|smartlook\s*\(\s*['"]init['"]|clarity\s*\(\s*['"]init['"]|clarity\.ms|hotjar\.com|hj\s*\(\s*['"]init['"]|_hjSettings|heap\.load\s*\()/i.test(line);

  if (!isReplaySdk) return false;

  const start = Math.max(0, idx - 10);
  const end = Math.min(lines.length, idx + 10);
  const surrounding = lines.slice(start, end).join('\n');

  const hasConsent = /(if\s*\([^)]*(consent|cookieConsent|optIn|hasUserConsent|consent_status)|consentGranted|userConsentState)/i.test(surrounding);
  return !hasConsent;
};

// 4. Email Unsubscribe Rule Test
const emailTest = (line, rawCode, idx, lines) => {
  const isMailSend = /(transporter|mailer|mail|client|sgMail|resend\.emails|mailgun\.messages|ses)\.(sendMail|sendEmail|send|create)\s*\(/i.test(line) ||
    /const\s+(mailOptions|emailData|messageData|emailPayload|newsletterOptions)\s*=\s*\{/i.test(line) ||
    /(sendWeeklyDigest|sendNewsletter|sendMarketingEmail|sendEmailNotification|dispatchEmail)\s*\(/i.test(line);

  if (!isMailSend) return false;

  const start = Math.max(0, idx - 5);
  const end = Math.min(lines.length, idx + 35);
  const surrounding = lines.slice(start, end).join('\n');

  const hasUnsub = /(unsubscribe|List-Unsubscribe|\{\{\s*unsubscribe|\<%asm_group_unsubscribe_url%\>|optout|opt-out)/i.test(surrounding);
  const hasAddress = /(address|street|suite|p\.?o\.?\s*box|postal\s*code|zip\s*code|\b\d{5}\b)/i.test(surrounding);

  return (!hasUnsub || !hasAddress);
};

// Run verification tests
console.log('Testing Rule 1: COPPA');
const badCoppaCode = `app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  const user = await db.users.create({ username, email, password });
  res.json(user);
});`;
const coppaLines = badCoppaCode.split('\n');
const coppaHits = coppaLines.filter((l, i) => coppaTest(l, badCoppaCode, i, coppaLines));
assert(coppaHits.length > 0, 'Should detect bad COPPA registration');

const goodCoppaCode = `app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, birthdate } = req.body;
  if (calculateAge(birthdate) < 13) return res.status(403).json({ error: 'Parental consent required' });
  const user = await db.users.create({ username, email, password, birthdate });
  res.json(user);
});`;
const goodCoppaLines = goodCoppaCode.split('\n');
const goodCoppaHits = goodCoppaLines.filter((l, i) => coppaTest(l, goodCoppaCode, i, goodCoppaLines));
assert.strictEqual(goodCoppaHits.length, 0, 'Should NOT flag COPPA with age gate');
console.log('✅ COPPA Rule Passed');

console.log('Testing Rule 2: Google Fonts');
const badFontsCode = `import 'package:google_fonts/google_fonts.dart';
void main() {
  runApp(MyApp());
}
Text('Hello', style: GoogleFonts.roboto());`;
const fontsLines = badFontsCode.split('\n');
const fontHits = fontsLines.filter((l, i) => fontsTest(l, badFontsCode, i, fontsLines));
assert(fontHits.length > 0, 'Should flag dynamic Google Fonts without allowRuntimeFetching = false');

const goodFontsCode = `import 'package:google_fonts/google_fonts.dart';
void main() {
  GoogleFonts.config.allowRuntimeFetching = false;
  runApp(MyApp());
}
Text('Hello', style: GoogleFonts.roboto());`;
const goodFontsLines = goodFontsCode.split('\n');
const goodFontHits = goodFontsLines.filter((l, i) => fontsTest(l, goodFontsCode, i, goodFontsLines));
assert.strictEqual(goodFontHits.length, 0, 'Should NOT flag Google Fonts when allowRuntimeFetching = false');
console.log('✅ Google Fonts Rule Passed');

console.log('Testing Rule 3: Session Replay');
const badReplayCode = `import LogRocket from 'logrocket';
LogRocket.init('app/org');`;
const replayLines = badReplayCode.split('\n');
const replayHits = replayLines.filter((l, i) => replayTest(l, badReplayCode, i, replayLines));
assert(replayHits.length > 0, 'Should flag unconsented LogRocket');

const goodReplayCode = `if (userConsentState.hasConsent) {
  LogRocket.init('app/org');
}`;
const goodReplayLines = goodReplayCode.split('\n');
const goodReplayHits = goodReplayLines.filter((l, i) => replayTest(l, goodReplayCode, i, goodReplayLines));
assert.strictEqual(goodReplayHits.length, 0, 'Should NOT flag consented LogRocket');
console.log('✅ Session Replay Rule Passed');

console.log('Testing Rule 4: Email Unsubscribe');
const badEmailCode = `await resend.emails.send({
  from: 'news@co.com',
  to: user.email,
  subject: 'Weekly Promo',
  html: '<h1>Huge discount!</h1>'
});`;
const emailLines = badEmailCode.split('\n');
const emailHits = emailLines.filter((l, i) => emailTest(l, badEmailCode, i, emailLines));
assert(emailHits.length > 0, 'Should flag email missing unsubscribe and postal address');

const goodEmailCode = `await resend.emails.send({
  from: 'news@co.com',
  to: user.email,
  subject: 'Weekly Promo',
  html: '<h1>Huge discount!</h1><footer><a href="{{unsubscribe_url}}">Unsubscribe</a><br>100 Market St, Suite 200, San Francisco, CA 94105</footer>'
});`;
const goodEmailLines = goodEmailCode.split('\n');
const goodEmailHits = goodEmailLines.filter((l, i) => emailTest(l, goodEmailCode, i, goodEmailLines));
assert.strictEqual(goodEmailHits.length, 0, 'Should NOT flag email with unsubscribe & address');
console.log('✅ Email Unsubscribe Rule Passed');

console.log('ALL RULES PASSED INITIAL HARNESS!');
