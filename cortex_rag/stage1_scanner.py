"""Stage 1: Polyglot Fast Deterministic SAST Scanner.

Ports all deterministic vulnerability rules from app.js CODE_VULN_RULES into Python
and expands them across ALL major enterprise languages:
Python, JS/TS, Dart/Flutter, Java, Kotlin, C#/.NET, C/C++, Rust, Go, Ruby, PHP, Swift, Scala, and SQL.
"""

from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cortex_rag.state import SeverityLevel, Stage1Finding


RuleTestFn = Callable[[str, str, int, List[str]], bool]


class RuleDefinition:
    """Specification for a deterministic polyglot SAST rule."""

    def __init__(
        self,
        rule_id: str,
        category: str,
        title: str,
        severity: SeverityLevel,
        cwe: str,
        owasp: str,
        compliance_control: str,
        test_fn: RuleTestFn,
        exploit: str,
        bad_code: str,
        good_code: str,
        supported_languages: Optional[List[str]] = None,
    ):
        self.rule_id = rule_id
        self.category = category
        self.title = title
        self.severity = severity
        self.cwe = cwe
        self.owasp = owasp
        self.compliance_control = compliance_control
        self.test_fn = test_fn
        self.exploit = exploit
        self.bad_code = bad_code
        self.good_code = good_code
        self.supported_languages = supported_languages or ["polyglot"]


# ---------------------------------------------------------------------------
# 1. SQL INJECTION (CWE-89) - POLYGLOT IMPLEMENTATION
# ---------------------------------------------------------------------------

def _test_sqli_polyglot(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects SQL Injection flaws across JS/TS, Python, Java, Kotlin, C#, Go, Rust, Ruby, PHP, Swift, Scala."""
    # Common SQL DDL/DML keywords
    has_sql_verb = bool(
        re.search(
            r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE)\b",
            line,
            re.IGNORECASE,
        )
    )

    # JavaScript / TypeScript / Dart concatenation
    if has_sql_verb and re.search(r"(\+\s*[\w\$\.]+|\$\{[^\}]+\}|\%s|\.format\(|f\"|f')", line, re.IGNORECASE):
        return True

    # Python direct query f-string or string formatting
    if re.search(r"(cursor|db|connection|conn)\.execute\s*\(\s*(f[\"']|[\"'].*\%s|\.format\()", line, re.IGNORECASE):
        return True
    if re.search(r"(db|pool|client|conn|cursor)\.query\s*\(\s*[`'\"][^)]*(\+|\$\{)", line, re.IGNORECASE):
        return True

    # Java & Kotlin: statement.executeQuery("..." + var), connection.prepareStatement("..." + var)
    if re.search(r"(statement|stmt)\.execute(Query|Update)?\s*\(\s*[\"'].*?\+\s*\w+", line, re.IGNORECASE):
        return True
    if re.search(r"prepareStatement\s*\(\s*[\"'].*?\+\s*\w+", line, re.IGNORECASE):
        return True
    if re.search(r"(statement|stmt|connection)\.execute(Query|Update)?\s*\(\s*\"[^\"]*\$[a-zA-Z0-9_]+", line):
        return True

    # C# / .NET: new SqlCommand("..." + var), ExecuteReader("..." + var)
    if re.search(r"new\s+SqlCommand\s*\(\s*(\$?\".*?(\+|\{)|@?\".*?\+\s*\w+)", line, re.IGNORECASE):
        return True
    if re.search(r"\.Execute(Reader|NonQuery|Scalar)\s*\(\s*\$?\".*?(\+|\{)", line, re.IGNORECASE):
        return True

    # Go: fmt.Sprintf SQL queries
    if has_sql_verb and re.search(r"fmt\.Sprintf\s*\(\s*[\"'].*?%[svdq]", line):
        return True
    if re.search(r"(db|tx)\.Query(Row)?\s*\(\s*fmt\.Sprintf", line):
        return True

    # Rust: sqlx::query with format!
    if re.search(r"sqlx::query\s*!\s*\(\s*&?format!\s*\(", line):
        return True
    if has_sql_verb and re.search(r"format!\s*\(\s*[\"'].*?\{\}", line):
        return True

    # Ruby: ActiveRecord .where with string interpolation or find_by_sql
    if re.search(r"\.where\s*\(\s*[\"'].*?#\{", line):
        return True
    if re.search(r"find_by_sql\s*\(\s*[\"'].*?#\{", line):
        return True

    # PHP: mysql_query / mysqli_query / PDO query with string concatenation
    if re.search(r"(mysql_query|mysqli_query)\s*\([^,)]*,\s*[\"'].*?\.\s*\$[a-zA-Z0-9_]+", line, re.IGNORECASE):
        return True
    if re.search(r"->query\s*\(\s*[\"'][^\"']*SELECT.*?(\.\s*\$|\$[a-zA-Z0-9_]+)", line, re.IGNORECASE):
        return True

    # Swift: String(format:) SQL injection
    if has_sql_verb and re.search(r"String\s*\(\s*format:\s*[\"'].*?%[@ds]", line):
        return True

    # Scala: String interpolation in Slick/JDBC (sqlu"...", sql"...", s"SELECT ... $var")
    if re.search(r"(sqlu|sql)\"[^\"]*\$[a-zA-Z0-9_]+", line):
        return True
    if has_sql_verb and re.search(r"s\"[^\"]*\$[a-zA-Z0-9_]+", line):
        return True

    return False


# ---------------------------------------------------------------------------
# 2. COMMAND INJECTION & RCE (CWE-78, CWE-95) - POLYGLOT IMPLEMENTATION
# ---------------------------------------------------------------------------

def _test_rce_polyglot(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects Remote Code Execution / Dynamic Eval across Python, JS/TS, Ruby, PHP, Java, etc."""
    # JavaScript / TypeScript eval & Function constructor
    if re.search(r"\b(eval|new\s+Function|vm\.runInThisContext)\s*\(", line):
        return True

    # Python dynamic execution
    if re.search(r"\b(eval|exec|compile)\s*\(\s*[\w\$\.]+", line) and not re.search(r"test_|mock|fixture", line, re.IGNORECASE):
        return True

    # Ruby eval
    if re.search(r"\b(eval|instance_eval|class_eval)\s*\(\s*[\"']?#\{|\b(eval)\s*\(\s*[a-zA-Z0-9_]+", line):
        return True

    # PHP eval
    if re.search(r"\beval\s*\(\s*\$[a-zA-Z0-9_]+", line):
        return True

    return False


def _test_cmd_inject_polyglot(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects Command Injection sinks across Python, JS/TS, Java, Kotlin, C#, C/C++, Go, Rust, Ruby, PHP, Swift."""
    # Node.js: child_process.exec with concatenation
    if re.search(r"(child_process\.exec|exec\s*\(|execSync)\s*\([^)]*(\+|\$\{)", line):
        return True

    # Python: os.system, subprocess with shell=True
    if re.search(r"(os\.system|os\.popen)\s*\([^)]*(\+|\%|f[\"']|\.format)", line):
        return True
    if re.search(r"subprocess\.(Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True[^)]*(\+|f[\"']|\%|\.format)", line):
        return True

    # Java & Kotlin: Runtime.getRuntime().exec() with dynamic concat
    if re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[\"'].*?\+", line):
        return True
    if re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(\s*\"[^\"]*\$", line):
        return True
    if re.search(r"ProcessBuilder\s*\(\s*\"[^\"]*\"\s*\+\s*\w+", line):
        return True

    # C# / .NET: Process.Start with raw string concat
    if re.search(r"Process\.Start\s*\(\s*[\"'].*?\+\s*\w+", line):
        return True
    if re.search(r"ProcessStartInfo\s*\(\s*[\"'].*?\+\s*\w+", line):
        return True

    # C / C++: system() or popen() with concatenated input
    if re.search(r"\b(system|popen)\s*\(\s*[\w\.\->]+\s*\)", line) and not re.search(r"system\s*\(\s*[\"'][a-zA-Z0-9_\-\s]+[\"']\s*\)", line):
        # dynamic variable passed to system()
        return True

    # Go: exec.Command with sh -c and fmt.Sprintf
    if re.search(r"exec\.Command\s*\(\s*[\"'](sh|bash|cmd|powershell)[\"'],\s*[\"'](-c|/c)[\"'],\s*(fmt\.Sprintf|\w+\s*\+)", line):
        return True

    # Rust: Command::new("sh").arg("-c").arg(format!(...))
    if re.search(r"Command::new\s*\(\s*[\"'](sh|bash|cmd)[\"']\).*?arg\s*\(\s*format!", line):
        return True

    # Ruby: system(), `` backticks, exec() with string interpolation
    if re.search(r"(system|exec)\s*\(\s*\"[^\"]*#\{[^\}]+\}\"", line):
        return True
    if re.search(r"`[^`]*#\{[^\}]+\}`", line):
        return True

    # PHP: exec, shell_exec, system, passthru with variables
    if re.search(r"\b(shell_exec|exec|system|passthru|popen)\s*\(\s*(\$[a-zA-Z0-9_]+|[\"'].*?\.\s*\$)", line):
        return True

    # Swift: Process() / NSTask with shell command or raw process execution
    if re.search(r"(Process\(\)|NSTask\(\)|NSTask\.launchedProcess).*?(arguments|launchPath|executableURL)", line) or re.search(r"Process\(\).*?arguments\s*=\s*\[[\"']-c[\"'],\s*[\w\.\+]+", line):
        return True
    if re.search(r"\bNSTask\.launchedProcess\s*\(", line):
        return True

    # Scala: sys.process or Process(...) execution
    if re.search(r"\b(import\s+scala\.sys\.process|sys\.process)\b", line):
        return True
    if re.search(r"\bProcess\s*\(\s*(Seq\s*\([^)]*\)|[\"'].*?\+\s*\w+|\w+)\s*\)\.(run|!)", line):
        return True
    if re.search(r"(\"|'|\)|\w+)\s*\.\s*(!|!!)", line):
        return True

    return False


# ---------------------------------------------------------------------------
# 3. BUFFER OVERFLOW & DANGEROUS C/C++ FUNCTIONS (CWE-120, CWE-242, CWE-134)
# ---------------------------------------------------------------------------

def _test_c_buffer_overflow(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects unsafe C/C++ functions: gets, strcpy, strcat, sprintf without bounds, format string."""
    # gets() is unconditionally banned (removed in C11)
    if re.search(r"\bgets\s*\(", line):
        return True
    # strcpy / strcat without bounds checking
    if re.search(r"\b(strcpy|strcat)\s*\(", line) and not re.search(r"strncpy|strncat", line):
        return True
    # sprintf without size limit
    if re.search(r"\bsprintf\s*\(", line) and not re.search(r"snprintf", line):
        return True
    # Format string attack: printf(user_input) instead of printf("%s", user_input)
    if re.search(r"\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)", line):
        return True
    return False


# ---------------------------------------------------------------------------
# 4. RUST UNSAFE & CRITICAL ERROR SUPPRESSION (CWE-20, CWE-248)
# ---------------------------------------------------------------------------

def _test_rust_unsafe_unwrap(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects uninspected unsafe {} blocks or .unwrap() in production request handlers."""
    # Rust unsafe blocks
    if re.search(r"\bunsafe\s*\{", line):
        return True
    # Direct .unwrap() in request or auth handlers, or on user input variables
    if re.search(r"(req|request|param|payload|input|header|query|body|token|user_id|data)\b.*?\.unwrap\(\)", line, re.IGNORECASE):
        return True
    if re.search(r"\.unwrap\(\)", line) and any(
        kw in raw_code.lower() for kw in ("request", "payload", "handler", "auth", "token", "actix_web", "warp", "axum")
    ):
        return True
    return False


# ---------------------------------------------------------------------------
# 5. BROKEN CRYPTOGRAPHY (CWE-328) - POLYGLOT IMPLEMENTATION
# ---------------------------------------------------------------------------

def _test_crypto_weak_polyglot(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects MD5 and SHA-1 in Python, JS, Java, Kotlin, C#, Go, Rust, Ruby, PHP, Swift, C/C++."""
    # Node.js
    if re.search(r"createHash\(['\"](md5|sha1)['\"]\)", line, re.IGNORECASE):
        return True

    # Python
    if re.search(r"hashlib\.(md5|sha1)\(", line, re.IGNORECASE):
        return True

    # Java & Kotlin: MessageDigest.getInstance("MD5" / "SHA-1")
    if re.search(r"MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-1|SHA1)[\"']\)", line, re.IGNORECASE):
        return True

    # C# / .NET: MD5.Create(), SHA1.Create()
    if re.search(r"(MD5|SHA1)\.(Create|ComputeHash)\s*\(", line):
        return True
    if re.search(r"new\s+(MD5|SHA1)CryptoServiceProvider\s*\(", line):
        return True

    # Go: md5.New(), sha1.New(), md5.Sum()
    if re.search(r"\b(md5|sha1)\.(New|Sum)\s*\(", line):
        return True

    # Ruby: Digest::MD5, Digest::SHA1
    if re.search(r"Digest::(MD5|SHA1)", line):
        return True

    # PHP: md5($pass), sha1($pass)
    if re.search(r"\b(md5|sha1)\s*\(\s*\$[a-zA-Z0-9_]+", line, re.IGNORECASE):
        return True

    # Swift: CC_MD5, Insecure.MD5
    if re.search(r"\b(CC_MD5|Insecure\.MD5|Insecure\.SHA1)\b", line):
        return True

    # C/C++: MD5_Init, SHA1_Init
    if re.search(r"\b(MD5_Init|SHA1_Init|MD5_Update)\b", line):
        return True

    # Generic md5/sha1 function invocation
    if re.search(r"\b(md5|sha1)\s*\(", line, re.IGNORECASE) and not re.search(r"test|spec|assert", line, re.IGNORECASE):
        return True

    return False


# ---------------------------------------------------------------------------
# 6. HARDCODED SECRETS (CWE-798) - POLYGLOT IMPLEMENTATION
# ---------------------------------------------------------------------------

def _test_secret_aws(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    return bool(re.search(r"(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", line))


def _test_secret_openai(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    return bool(re.search(r"(sk-[a-zA-Z0-9_\-]{20,})", line))


def _test_secret_github(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    return bool(re.search(r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})", line))


def _test_secret_db(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    # Standard DB URI
    if re.search(
        r"(postgres|mysql|mongodb|redis|mariadb|sqlserver):\/\/[a-zA-Z0-9_\-\.]+:[^@\s'\"]+@[a-zA-Z0-9_\-\.]+",
        line,
        re.IGNORECASE,
    ):
        return True
    # Java / .NET / Spring connection strings with explicit passwords
    if re.search(r"spring\.datasource\.password\s*=\s*[^\s]{4,}", line, re.IGNORECASE):
        return True
    if re.search(r"(Password|Pwd)\s*=\s*[^;'\"]{5,};", line, re.IGNORECASE) and "Data Source" in line:
        return True
    return False


def _test_secret_jwt(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    if re.search(r"BEGIN (RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY", line):
        return True
    return bool(re.search(r"(JWT_SECRET|jwtSecret|TOKEN_SECRET)\s*=\s*['\"][^'\"]{8,}['\"]", line, re.IGNORECASE))


# ---------------------------------------------------------------------------
# 7. XSS & CLIENT INJECTION (CWE-79) - POLYGLOT IMPLEMENTATION
# ---------------------------------------------------------------------------

def _test_xss_polyglot(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects XSS sinks in JS/TS, PHP, Python templates, Ruby on Rails."""
    # JS / React / DOM
    if re.search(r"(dangerouslySetInnerHTML|\.innerHTML\s*=)", line):
        return True

    # PHP unescaped echo / print
    if re.search(r"\b(echo|print|printf)\s+.*(\$_GET|\$_POST|\$_REQUEST)", line, re.IGNORECASE) and not re.search(r"(htmlspecialchars|htmlentities|strip_tags)\s*\(", line, re.IGNORECASE):
        return True

    # Python Jinja | safe filter or Markup()
    if re.search(r"\{\{[^\}]+?\|\s*safe\s*\}\}", line) or re.search(r"Markup\s*\(\s*f?[\"'].*?\+", line):
        return True

    # Ruby on Rails .html_safe or raw()
    if re.search(r"(\.html_safe\b|raw\s*\(\s*params\[)", line):
        return True

    return False


# ---------------------------------------------------------------------------
# 8. PRIVACY, COPPA, GOOGLE FONTS, REPLAY, CAN-SPAM, SUPABASE
# ---------------------------------------------------------------------------

def _test_coppa_agegate(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    is_auth_or_reg = (
        re.search(r"(app|router)\.(post|put)\s*\(\s*['\"][^'\"]*(register|signup|create-account|users)['\"]", line, re.IGNORECASE)
        or re.search(r"function\s+(register|signUp|createUser|handleRegistration|registration|signupScreen|signupPage|registerScreen|registerPage)\w*\b", line, re.IGNORECASE)
        or re.search(r"class\s+(Register|SignUp|Registration|CreateAccount)\w*\s+extends", line, re.IGNORECASE)
        or re.search(r"(auth\.signUp|createUserWithEmailAndPassword)\s*\(", line, re.IGNORECASE)
        or re.search(r"<form[^>]+(id|class|name|action)=[\"'][^\"']*(register|signup|create-account)", line, re.IGNORECASE)
        or re.search(r"const\s+(register|signup|createUser|registerPage|signupScreen|registration)\w*\s*=\s*(async\s*)?\(", line, re.IGNORECASE)
        or re.search(r"func\s+(Register|SignUp|CreateUser)\b", line)
        or re.search(r"def\s+(register|sign_up|create_user)\b", line)
    )
    if not is_auth_or_reg:
        return False

    code_arr = lines if lines else (raw_code.split("\n") if raw_code else [])
    start = max(0, idx - 5)
    end = min(len(code_arr), idx + 80)
    code_only = "\n".join(
        l for l in code_arr[start:end]
        if not l.strip().startswith("//") and not l.strip().startswith("*") and not l.strip().startswith("#")
    )
    has_age_gate = re.search(
        r"(dob|birth_?date|birthday|bday|date_?of_?birth|birth_?year|age_?gate|parental_?consent|parent_?consent|coppa|under_?13|under_?16|under_?18|min_?age|verify_?age|age_?verif|is_?adult|is_?over_?13|is_?over_?18|over_?13|over_?18|user_?age|age_?check)",
        code_only,
        re.IGNORECASE,
    )
    return not bool(has_age_gate)


def _test_google_fonts(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    is_google_font = (
        re.search(r"GoogleFonts\.[a-zA-Z0-9_]+\s*\(", line, re.IGNORECASE)
        or re.search(r"import\s+['\"]package:google_fonts\/google_fonts\.dart['\"]", line, re.IGNORECASE)
        or re.search(r"google_fonts\s*:\s*.+", line, re.IGNORECASE)
        or re.search(r"<link[^>]+href=[\"']https?:\/\/(fonts\.googleapis\.com|fonts\.gstatic\.com)", line, re.IGNORECASE)
        or re.search(r"@import\s+(url\()?[`'\"]https?:\/\/(fonts\.googleapis\.com|fonts\.gstatic\.com)", line, re.IGNORECASE)
        or re.search(r"src:\s*url\([`'\"]?https?:\/\/(fonts\.googleapis\.com|fonts\.gstatic\.com)", line, re.IGNORECASE)
    )
    if not is_google_font:
        return False

    is_flutter_line = bool(re.search(r"GoogleFonts|google_fonts", line, re.IGNORECASE))
    if is_flutter_line:
        code_arr = lines if lines else (raw_code.split("\n") if raw_code else [])
        has_active_config = any(
            re.search(r"allowRuntimeFetching\s*=\s*false", l, re.IGNORECASE)
            for l in code_arr
            if not l.strip().startswith("//") and not l.strip().startswith("#")
        )
        has_bundled_fonts = any(
            re.search(r"-\s+.*(fonts\/|google_fonts\/|\.(ttf|otf|woff2))", l, re.IGNORECASE)
            for l in code_arr
            if not l.strip().startswith("//") and not l.strip().startswith("#")
        )
        if has_active_config or has_bundled_fonts:
            return False
        return True

    return True


def _test_session_replay(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    is_replay_sdk = re.search(
        r"(LogRocket\.init\s*\(|FS\.identify\s*\(|FS\.restart\s*\(|FS\.init\s*\(|FullStory\.init\s*\(|window\[[\"']_fs_namespace[\"']\]|window\._fs_namespace|fullstory\.com\/s\/fs\.js|smartlookClient\.init\s*\(|smartlook\s*\(\s*['\"]init['\"]|Smartlook\.(instance\.)?(start|init|setup)\s*\(|clarity\s*\(\s*['\"]init['\"]|clarity\.ms|hotjar\.com|hj\s*\(\s*['\"]init['\"]|_hjSettings|heap\.load\s*\()",
        line,
        re.IGNORECASE,
    )
    if not is_replay_sdk:
        return False

    code_arr = lines if lines else (raw_code.split("\n") if raw_code else [])
    start = max(0, idx - 25)
    end = min(len(code_arr), idx + 15)
    surrounding = "\n".join(code_arr[start:end])

    has_consent = re.search(
        r"(if\s*\([^)]*(consent|cookieConsent|optIn|hasUserConsent|consent_status|analyticsConsent|trackingConsent|isConsented)|consentGranted|userConsentState|onConsent|consent\.granted|clarity\(['\"]consent['\"]|hj\(['\"]consent['\"]|FS\(['\"]consent['\"]|Smartlook\.(instance\.)?setConsent)",
        surrounding,
        re.IGNORECASE,
    )
    return not bool(has_consent)


def _test_email_compliance(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    is_mail_send = (
        re.search(r"(transporter|mailer|mail|client|sgMail|sendgrid|resend\.emails|mailgun\.messages|ses|nodemailer)\.(sendMail|sendEmail|send|create)\s*\(", line, re.IGNORECASE)
        or re.search(r"const\s+(mailOptions|emailData|messageData|emailPayload|newsletterOptions)\s*=\s*\{", line, re.IGNORECASE)
        or re.search(r"(sendWeeklyDigest|sendNewsletter|sendMarketingEmail|sendEmailNotification|dispatchEmail)\s*\(", line, re.IGNORECASE)
        or re.search(r"<(table|div|section|body)[^>]*(id|class)=[\"'][^\"']*(email|newsletter|mail-content|marketing)[\"']", line, re.IGNORECASE)
        or re.search(r"Mail::(to|send)\s*\(", line)
    )
    if not is_mail_send:
        return False

    code_arr = lines if lines else (raw_code.split("\n") if raw_code else [])
    start = max(0, idx - 5)
    end = min(len(code_arr), idx + 50)
    code_only = "\n".join(
        l for l in code_arr[start:end]
        if not l.strip().startswith("//") and not l.strip().startswith("*") and not l.strip().startswith("#")
    )
    has_unsub = bool(re.search(r"(unsubscribe|List-Unsubscribe|\{\{\s*unsubscribe|\<%asm_group_unsubscribe_url%\>|optout|opt-out|manage-preferences)", code_only, re.IGNORECASE))
    has_address = bool(re.search(r"(address|street|suite|p\.?o\.?\s*box|postal\s*code|zip\s*code|\b\d{5}\b|\{\{\s*(company|sender|physical)?_?address\s*\}\})", code_only, re.IGNORECASE))
    return not (has_unsub and has_address)


def _test_supabase_service_key(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    if re.search(r"(SUPABASE_SERVICE_KEY|SUPABASE_SERVICE_ROLE_KEY|supabase_service_role)\s*=\s*['\"][^'\"]+['\"]", line, re.IGNORECASE):
        return True
    if "eyJhbGciOi" in line and '"role":"service_role"' in line:
        return True
    return False


def _test_flutter_shared_prefs_pii(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    return bool(re.search(r"prefs\.setString(List)?\s*\(\s*['\"](token|auth|jwt|password|secret|access_token|refresh_token|ssn|apiKey)['\"]", line, re.IGNORECASE))


def _test_supabase_rls_disabled(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    return bool(re.search(r"ALTER\s+TABLE\s+.*\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY", line, re.IGNORECASE))


def _test_csharp_missing_authorize(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects missing [Authorize] attribute on C#/.NET ASP.NET Core controllers/action methods."""
    is_sensitive_action = (
        re.search(r"^\s*\[Http(Post|Put|Delete|Patch)\]", line, re.IGNORECASE)
        or re.search(r"public\s+(async\s+)?(Task<)?(IActionResult|ActionResult|IResult)[>\s]+(Delete|Update|Admin|Transfer|Reset|Create|Modify|Remove|SetRole)\w*\s*\(", line)
    )
    if not is_sensitive_action:
        return False

    code_arr = lines if lines else (raw_code.split("\n") if raw_code else [])
    start = max(0, idx - 15)
    surrounding = "\n".join(code_arr[start:idx + 1])
    if re.search(r"\[(Authorize|AllowAnonymous)\]", surrounding):
        return False

    class_scope = "\n".join(code_arr[:idx])
    if re.search(r"\[Authorize\][\s\r\n]*public\s+class", class_scope):
        return False

    return True


def _test_go_unchecked_error(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects Go unchecked error conditions using blank identifier '_ =' on critical operations."""
    if re.search(r"^\s*_\s*,\s*_\s*=\s*[\w\.\$]+\.(Write|Read|Exec|Query)", line):
        return True
    if re.search(r"^\s*_\s*=\s*(db|tx|stmt|conn|client|session)\.(Exec|Query|QueryRow|Commit|Rollback|Close)\s*\(", line):
        return True
    if re.search(r"^\s*_\s*=\s*(os|io|file|resp\.Body|w)\.(Remove|RemoveAll|Close|Write|WriteString)\s*\(", line):
        return True
    if re.search(r"^\s*_\s*=\s*(bcrypt|crypto|jwt|hash|token)\.\w+\s*\(", line):
        return True
    if re.search(r"^\s*_\s*=\s*(http|server)\.ListenAndServe\s*\(", line):
        return True
    if re.search(r"^\s*_\s*=\s*json\.Unmarshal\s*\(", line):
        return True
    return False


def _test_swift_keychain_storage(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects sensitive credentials stored in cleartext UserDefaults instead of Apple Keychain."""
    return bool(
        re.search(
            r"UserDefaults\.standard\.(set|setValue)\s*\([^)]*(password|token|secret|apiKey|auth|jwt|privateKey|credential)[^)]*",
            line,
            re.IGNORECASE,
        )
    )


def _test_hardcoded_passwords_and_secrets(line: str, raw_code: str, idx: int, lines: List[str]) -> bool:
    """Detects hardcoded passwords in C/C++ and secrets in .properties / .env files."""
    trimmed = line.strip()
    if trimmed.startswith("//") or trimmed.startswith("#") or trimmed.startswith("/*") or trimmed.startswith("*"):
        return False

    # C/C++: char *pass = "...", const char* password = "...", #define DB_PASS "..."
    if re.search(
        r"(char\s*\*|char\s+\w+\[\d*\]|std::string|const\s+char\s*\*)\s*(password|passwd|pwd|secret|api_?key|auth_?token)\s*=\s*[\"'][^\"']{4,}[\"']",
        line,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"#define\s+(DB_PASS|PASSWORD|PASSWD|SECRET_KEY|API_KEY|AUTH_TOKEN)\s+[\"'][^\"']{4,}[\"']",
        line,
        re.IGNORECASE,
    ):
        return True

    # Java / Spring / Config .properties / .env / .ini: password=..., secret=...
    prop_m = re.match(
        r"^\s*([a-zA-Z0-9_\.]*(password|secret|api_?key|auth_?token|jwt_?secret))\s*=\s*['\"]?([^\s'\"#\$]{5,})['\"]?",
        line,
        re.IGNORECASE,
    )
    if prop_m:
        val = prop_m.group(3).lower()
        if not val.startswith("${") and val not in ("change_me", "changeme", "todo", "example", "none", "false", "true", "null"):
            return True

    return False


# Master Registry of Polyglot Rules
RULES: List[RuleDefinition] = [
    RuleDefinition(
        rule_id="SEC-SQLI-01",
        category="Database Attacks",
        title="SQL Injection Flaw (Raw Concatenation into Query)",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        owasp="OWASP Top 10 A03:2021 - Injection",
        compliance_control="DATA-03",
        test_fn=_test_sqli_polyglot,
        exploit="Attackers can inject malicious SQL payloads (e.g. `' OR 1=1 --`) to bypass authorization or dump database tables.",
        bad_code='const sql = "SELECT * FROM users WHERE user = \'" + input + "\'";',
        good_code="const sql = 'SELECT * FROM users WHERE user = $1';\nconst result = await db.query(sql, [input]);",
        supported_languages=["python", "javascript", "typescript", "dart", "java", "kotlin", "csharp", "go", "rust", "ruby", "php", "swift", "scala"],
    ),
    RuleDefinition(
        rule_id="SEC-SECRET-AWS",
        category="Secret Leak",
        title="Hardcoded AWS Access Key ID Detected",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-798: Use of Hard-coded Credentials",
        owasp="OWASP Top 10 A07:2021 - Identification & Authentication Failures",
        compliance_control="IAM-01",
        test_fn=_test_secret_aws,
        exploit="Automated crawlers scan public repositories. Leaked AWS keys grant unauthorized cloud infrastructure access.",
        bad_code='const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
        good_code="const AWS_KEY = process.env.AWS_ACCESS_KEY_ID;",
        supported_languages=["polyglot"],
    ),
    RuleDefinition(
        rule_id="SEC-SECRET-OPENAI",
        category="Secret Leak",
        title="Exposed OpenAI / LLM API Key",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-798: Hardcoded Credentials",
        owasp="OWASP Top 10 A07:2021 - Identification & Authentication Failures",
        compliance_control="DATA-02",
        test_fn=_test_secret_openai,
        exploit="Attackers drain API credit quotas, fine-tune unauthorized models, or access prompt telemetry.",
        bad_code='const client = new OpenAI({ apiKey: "sk-proj-xyz1234567890abcdef123" });',
        good_code="const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });",
        supported_languages=["polyglot"],
    ),
    RuleDefinition(
        rule_id="SEC-SECRET-GITHUB",
        category="Secret Leak",
        title="Exposed GitHub Personal Access Token",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-798: Hardcoded Credentials",
        owasp="OWASP Top 10 A07:2021 - Identification & Authentication Failures",
        compliance_control="OPS-01",
        test_fn=_test_secret_github,
        exploit="Allows attackers to push backdoors to source code, tamper with releases, or hijack CI/CD workflows.",
        bad_code='const GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuv";',
        good_code="const GH_TOKEN = process.env.GITHUB_TOKEN;",
        supported_languages=["polyglot"],
    ),
    RuleDefinition(
        rule_id="SEC-SECRET-DB",
        category="Secret Leak",
        title="Hardcoded Database URI with Embedded Password",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-798: Hardcoded Credentials",
        owasp="OWASP Top 10 A07:2021 - Identification & Authentication Failures",
        compliance_control="DATA-02",
        test_fn=_test_secret_db,
        exploit="Exposure of database connection credentials allows external attackers to dump production tables directly.",
        bad_code='const DB_URI = "postgres://admin:P@ssw0rd123@prod-db.internal:5432/main";',
        good_code="const DB_URI = process.env.DATABASE_URL;",
        supported_languages=["polyglot"],
    ),
    RuleDefinition(
        rule_id="SEC-SECRET-JWT",
        category="Secret Leak",
        title="Hardcoded JWT Secret or Private Encryption Key",
        severity=SeverityLevel.HIGH,
        cwe="CWE-321: Use of Hard-coded Cryptographic Key",
        owasp="OWASP Top 10 A02:2021 - Cryptographic Failures",
        compliance_control="DATA-01",
        test_fn=_test_secret_jwt,
        exploit="Allows attackers to forge administrative tokens with arbitrary claims and impersonate users.",
        bad_code='jwt.sign(payload, "my_static_secret_key_12345");',
        good_code="jwt.sign(payload, process.env.JWT_SIGNING_KEY);",
        supported_languages=["polyglot"],
    ),
    RuleDefinition(
        rule_id="SEC-RCE-EVAL",
        category="Remote Code Execution",
        title="Dangerous Dynamic Evaluation (eval / Function constructor)",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        owasp="OWASP Top 10 A03:2021 - Injection",
        compliance_control="OPS-01",
        test_fn=_test_rce_polyglot,
        exploit="Enables Remote Code Execution (RCE). Arbitrary attacker code executes within system permissions.",
        bad_code='const output = eval("calculate(" + req.query.expr + ")");',
        good_code="// Avoid eval! Use safe parser libraries like mathjs or JSON.parse",
        supported_languages=["javascript", "typescript", "python", "ruby", "php"],
    ),
    RuleDefinition(
        rule_id="SEC-CMD-INJECT",
        category="Remote Code Execution",
        title="Command Injection Sink (child_process.exec / os.system / Process.Start)",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        owasp="OWASP Top 10 A03:2021 - Injection",
        compliance_control="OPS-01",
        test_fn=_test_cmd_inject_polyglot,
        exploit="Attackers append command separators (; or |) to execute arbitrary host commands.",
        bad_code='exec("ping -c 1 " + req.query.target);',
        good_code="execFile('ping', ['-c', '1', req.query.target]);",
        supported_languages=["python", "javascript", "typescript", "java", "kotlin", "csharp", "c", "cpp", "go", "rust", "ruby", "php", "swift", "scala"],
    ),
    RuleDefinition(
        rule_id="SEC-XSS-DOM",
        category="Injection & XSS",
        title="Cross-Site Scripting (XSS) via innerHTML / Raw Echo",
        severity=SeverityLevel.HIGH,
        cwe="CWE-79: Improper Neutralization of Input During Web Page Generation",
        owasp="OWASP Top 10 A03:2021 - Injection",
        compliance_control="OPS-01",
        test_fn=_test_xss_polyglot,
        exploit="Attackers can inject malicious script tags that hijack sessions or steal cookies.",
        bad_code='container.innerHTML = "<div>" + userInput + "</div>";',
        good_code="container.textContent = userInput; // or use DOMPurify.sanitize(userInput)",
        supported_languages=["javascript", "typescript", "html", "php", "python", "ruby"],
    ),
    RuleDefinition(
        rule_id="SEC-CRYPTO-WEAK",
        category="Cryptographic Weakness",
        title="Insecure Hashing Algorithm (MD5 / SHA1) for Passwords or Signatures",
        severity=SeverityLevel.HIGH,
        cwe="CWE-328: Use of Weak Hash",
        owasp="OWASP Top 10 A02:2021 - Cryptographic Failures",
        compliance_control="DATA-01",
        test_fn=_test_crypto_weak_polyglot,
        exploit="MD5 and SHA-1 have known collision attacks and are rapidly reversible via rainbow tables.",
        bad_code="const hash = crypto.createHash('md5').update(password).digest('hex');",
        good_code="const hash = await bcrypt.hash(password, 12);",
        supported_languages=["python", "javascript", "typescript", "java", "kotlin", "csharp", "go", "ruby", "php", "swift", "c", "cpp"],
    ),
    RuleDefinition(
        rule_id="SEC-C-BUFFER-OVERFLOW",
        category="Memory Safety & Buffer Overflow",
        title="Unsafe C/C++ Function Vulnerable to Buffer Overflow (gets / strcpy / sprintf)",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-120: Buffer Copy without Checking Size of Input",
        owasp="OWASP Top 10 A03:2021 - Injection",
        compliance_control="OPS-01",
        test_fn=_test_c_buffer_overflow,
        exploit="Unbounded memory copy functions allow buffer overflow, stack smashing, and arbitrary shellcode execution.",
        bad_code="char buf[64]; gets(buf); // or strcpy(dest, src);",
        good_code="fgets(buf, sizeof(buf), stdin); // or strncpy(dest, src, sizeof(dest)-1);",
        supported_languages=["c", "cpp"],
    ),
    RuleDefinition(
        rule_id="SEC-RUST-UNSAFE-UNWRAP",
        category="Memory & Concurrency Safety",
        title="Unchecked Rust unsafe block or .unwrap() on untrusted boundary",
        severity=SeverityLevel.HIGH,
        cwe="CWE-248: Uncaught Exception / Panic",
        owasp="OWASP Top 10 A04:2021 - Insecure Design",
        compliance_control="OPS-01",
        test_fn=_test_rust_unsafe_unwrap,
        exploit="Unsafe blocks bypass Rust borrow checker invariants; unwrap() causes panic DoS on untrusted input.",
        bad_code="let data = unsafe { *ptr }; // or let user_id = req.param.unwrap();",
        good_code="let user_id = req.param.ok_or(AppError::BadRequest)?;",
        supported_languages=["rust"],
    ),
    RuleDefinition(
        rule_id="SEC-PRIV-COPPA-AGEGATE",
        category="Privacy & Child Safety",
        title="Missing COPPA / Minor Age Gate in Registration or Authentication Flow",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-359: Exposure of Private Personal Information",
        owasp="OWASP Top 10 A04:2021 - Insecure Design",
        compliance_control="PRIV-06",
        test_fn=_test_coppa_agegate,
        exploit="Collecting personal info without neutral age gate violates US COPPA ($51k FTC fine) and GDPR Art 8 (€20M).",
        bad_code="app.post('/api/auth/register', async (req, res) => { const user = await db.users.create(req.body); });",
        good_code="app.post('/api/auth/register', async (req, res) => { if (calculateAge(req.body.birthdate) < 13) return res.status(403); });",
        supported_languages=["polyglot"],
    ),
    RuleDefinition(
        rule_id="SEC-PRIV-GOOGLE-FONTS",
        category="Privacy & Data Sovereignty",
        title="Unconsented Dynamic Google Fonts Runtime Fetch (GDPR / Munich Court Violation)",
        severity=SeverityLevel.HIGH,
        cwe="CWE-359: Privacy Violation / External Data Transmission",
        owasp="OWASP Top 10 A01:2021 - Broken Access Control",
        compliance_control="PRIV-07",
        test_fn=_test_google_fonts,
        exploit="Dynamic font fetching transmits IP addresses to third-party US servers without consent (LG München Az. 3 O 17493/20).",
        bad_code="Text('Welcome', style: GoogleFonts.roboto());",
        good_code="GoogleFonts.config.allowRuntimeFetching = false;\n// Bundle font assets in pubspec.yaml",
        supported_languages=["dart", "html", "css"],
    ),
    RuleDefinition(
        rule_id="SEC-PRIV-SESSION-REPLAY",
        category="Privacy & Wiretapping Risk",
        title="Session Replay SDK Initialized Without Prior Consent or Input Masking",
        severity=SeverityLevel.HIGH,
        cwe="CWE-359: Exposure of Private Information via Wiretapping",
        owasp="OWASP Top 10 A04:2021 - Insecure Design",
        compliance_control="PRIV-08",
        test_fn=_test_session_replay,
        exploit="Session capture violates state wiretap laws (PA, FL, CA CIPA: $1,000–$5,000 per visitor).",
        bad_code="LogRocket.init('app-id/my-org');",
        good_code="if (userConsentState.analyticsOptIn) { LogRocket.init('app-id/my-org', { dom: { inputSanitizer: true } }); }",
        supported_languages=["javascript", "typescript", "dart", "html"],
    ),
    RuleDefinition(
        rule_id="SEC-COMM-EMAIL-COMPLIANCE",
        category="Commercial Messaging Compliance",
        title="Missing Unsubscribe Token or Physical Address in Mail Dispatch / Template",
        severity=SeverityLevel.HIGH,
        cwe="CWE-1059: Incomplete Regulatory Message Requirements",
        owasp="OWASP Top 10 A04:2021 - Insecure Design",
        compliance_control="COMM-01",
        test_fn=_test_email_compliance,
        exploit="Violates US CAN-SPAM ($50k fine) and Canada CASL ($10M CAD penalty) for commercial emails.",
        bad_code="await resend.emails.send({ to: user.email, subject: 'Promo', html: '<h1>Sale</h1>' });",
        good_code="await resend.emails.send({ ...headers: {'List-Unsubscribe': url}, html: '<footer>Unsubscribe<br>Postal Address</footer>' });",
        supported_languages=["polyglot"],
    ),
    RuleDefinition(
        rule_id="SEC-SUPABASE-SERVICE-KEY",
        category="Secret Leak",
        title="Exposed Supabase Service Role Key in Client App",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-798: Use of Hard-coded Credentials",
        owasp="OWASP Top 10 A07:2021 - Identification & Authentication Failures",
        compliance_control="IAM-01",
        test_fn=_test_supabase_service_key,
        exploit="Service role keys bypass all Supabase Row Level Security (RLS) rules, granting full unrestricted DB access.",
        bad_code='const supabase = createClient(URL, "SUPABASE_SERVICE_ROLE_KEY_SECRET");',
        good_code="const supabase = createClient(URL, process.env.SUPABASE_ANON_KEY);",
        supported_languages=["polyglot"],
    ),
    RuleDefinition(
        rule_id="SEC-FLUTTER-SHARED-PREFS-PII",
        category="Privacy & Storage Security",
        title="Unencrypted Sensitive Token Stored in SharedPreferences",
        severity=SeverityLevel.HIGH,
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        owasp="OWASP Top 10 A02:2021 - Cryptographic Failures",
        compliance_control="DATA-01",
        test_fn=_test_flutter_shared_prefs_pii,
        exploit="SharedPreferences stores unencrypted XML/plist files easily readable on jailbroken devices or backups.",
        bad_code='prefs.setString("jwt_token", authToken);',
        good_code="await flutterSecureStorage.write(key: 'jwt_token', value: authToken);",
        supported_languages=["dart"],
    ),
    RuleDefinition(
        rule_id="SEC-SUPABASE-RLS-DISABLED",
        category="Database Access Control",
        title="Supabase Row Level Security Explicitly Disabled",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-284: Improper Access Control",
        owasp="OWASP Top 10 A01:2021 - Broken Access Control",
        compliance_control="DATA-03",
        test_fn=_test_supabase_rls_disabled,
        exploit="Disabling RLS allows any anonymous user possessing the public anon key to read and alter all rows.",
        bad_code="ALTER TABLE accounts DISABLE ROW LEVEL SECURITY;",
        good_code="ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;",
        supported_languages=["sql"],
    ),
    RuleDefinition(
        rule_id="SEC-CSHARP-MISSING-AUTHORIZE",
        category="Broken Access Control",
        title="Missing [Authorize] Attribute on C# Controller Endpoint",
        severity=SeverityLevel.HIGH,
        cwe="CWE-306: Missing Authentication for Critical Function",
        owasp="OWASP Top 10 A01:2021 - Broken Access Control",
        compliance_control="IAM-02",
        test_fn=_test_csharp_missing_authorize,
        exploit="Unprotected ASP.NET endpoints allow unauthenticated users to execute sensitive operations or administrative actions.",
        bad_code="[HttpPost]\npublic IActionResult DeleteUser(int id) { ... }",
        good_code="[Authorize(Roles = \"Admin\")]\n[HttpPost]\npublic IActionResult DeleteUser(int id) { ... }",
        supported_languages=["csharp"],
    ),
    RuleDefinition(
        rule_id="SEC-GO-UNCHECKED-ERROR",
        category="Error Handling & Robustness",
        title="Unchecked Error Condition (Go Blank Identifier '_ =')",
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-391: Unchecked Error Condition",
        owasp="OWASP Top 10 A04:2021 - Insecure Design",
        compliance_control="OPS-02",
        test_fn=_test_go_unchecked_error,
        exploit="Discarding errors on critical operations (database commits, file writes, crypto) leads to silent corruption or bypass.",
        bad_code="_ = db.Exec(\"DELETE FROM sessions WHERE id = ?\", id)",
        good_code="if err := db.Exec(\"DELETE FROM sessions WHERE id = ?\", id); err != nil { return err }",
        supported_languages=["go"],
    ),
    RuleDefinition(
        rule_id="SEC-SWIFT-KEYCHAIN-INSECURE-STORAGE",
        category="Data Protection & Mobile Security",
        title="Sensitive Credential Stored in UserDefaults Instead of Keychain",
        severity=SeverityLevel.HIGH,
        cwe="CWE-312: Cleartext Storage of Sensitive Information",
        owasp="OWASP Top 10 A02:2021 - Cryptographic Failures",
        compliance_control="DATA-01",
        test_fn=_test_swift_keychain_storage,
        exploit="UserDefaults stores data in plaintext property lists easily readable from device backups or jailbroken devices.",
        bad_code="UserDefaults.standard.set(authToken, forKey: \"password\")",
        good_code="// Store securely in iOS Keychain via SecItemAdd / KeychainAccess library",
        supported_languages=["swift"],
    ),
    RuleDefinition(
        rule_id="SEC-SECRET-HARDCODED-CREDENTIALS",
        category="Secret Leak",
        title="Hardcoded Password or Secret in Properties/C/C++ Source",
        severity=SeverityLevel.CRITICAL,
        cwe="CWE-798: Use of Hard-coded Credentials",
        owasp="OWASP Top 10 A07:2021 - Identification & Authentication Failures",
        compliance_control="IAM-01",
        test_fn=_test_hardcoded_passwords_and_secrets,
        exploit="Hardcoded passwords and secrets in source files or configuration properties are easily extracted and abused.",
        bad_code="char *password = \"admin123\"; // or db.password=secret in .properties",
        good_code="const char *password = getenv(\"DB_PASSWORD\"); // or ${DB_PASSWORD} in properties",
        supported_languages=["c", "cpp", "properties", "env", "java", "polyglot"],
    ),
]


def _detect_file_language(file_path: str) -> str:
    """Identify language from file extension for rule scoping."""
    ext = Path(file_path).suffix.lower()
    mapping = {
        ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
        ".mjs": "javascript", ".dart": "dart", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
        ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".h": "c", ".hpp": "cpp",
        ".rs": "rust", ".go": "go", ".rb": "ruby", ".php": "php", ".swift": "swift", ".scala": "scala",
        ".sql": "sql", ".html": "html", ".properties": "properties", ".env": "env",
    }
    return mapping.get(ext, "unknown")


def scan_code_string(raw_code: str, file_path: str = "inline_code") -> List[Stage1Finding]:
    """Scan a code string line by line and return structured Stage1Findings."""
    findings: List[Stage1Finding] = []
    lines = raw_code.split("\n")
    file_lang = _detect_file_language(file_path)

    for idx, line_text in enumerate(lines):
        line_num = idx + 1
        trimmed = line_text.strip()

        # Skip comment lines unless they might conceal hardcoded secrets
        if (trimmed.startswith("//") or trimmed.startswith("#") or trimmed.startswith("/*") or trimmed.startswith("*")) and not any(
            k in trimmed for k in ("AKIA", "sk-", "postgres://", "ghp_")
        ):
            continue

        for rule in RULES:
            # Language scope filter
            if file_lang != "unknown" and "polyglot" not in rule.supported_languages and file_lang not in rule.supported_languages:
                continue
            try:
                if rule.test_fn(line_text, raw_code, idx, lines):
                    # Deduplicate line + rule_id
                    already = any(f.line == line_num and f.rule_id == rule.rule_id for f in findings)
                    if not already:
                        fid = f"{rule.rule_id}-{Path(file_path).name}-{line_num}-{uuid.uuid4().hex[:6]}"
                        findings.append(
                            Stage1Finding(
                                finding_id=fid,
                                file_path=file_path,
                                line=line_num,
                                rule_id=rule.rule_id,
                                category=rule.category,
                                title=rule.title,
                                severity=rule.severity,
                                cwe=rule.cwe,
                                owasp=rule.owasp,
                                compliance_control=rule.compliance_control,
                                exploit=rule.exploit,
                                snippet=trimmed,
                                bad_code=rule.bad_code,
                                good_code=rule.good_code,
                            )
                        )
            except Exception:
                continue

    return findings


def scan_file(file_path: Path) -> List[Stage1Finding]:
    """Scan an individual file from disk."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return scan_code_string(content, file_path=str(file_path))
    except Exception as exc:
        print(f"[Stage1] Error reading {file_path}: {exc}", file=sys.stderr)
        return []


def scan_directory(dir_path: Path, extensions: Optional[List[str]] = None) -> List[Stage1Finding]:
    """Scan an entire directory recursively across all supported polyglot languages."""
    import os

    if extensions is None:
        extensions = [
            ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".dart",
            ".java", ".kt", ".kts", ".cs", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
            ".rs", ".go", ".rb", ".php", ".swift", ".scala",
            ".sql", ".html", ".htm", ".css", ".yaml", ".yml", ".json", ".properties",
        ]
    ext_set = set(extensions)
    ignored_dirs = {".git", "node_modules", ".dart_tool", "build", ".venv", "__pycache__", ".lancedb", ".pytest_cache"}

    findings: List[Stage1Finding] = []
    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]
        for f in files:
            p = Path(root) / f
            if p.suffix.lower() in ext_set:
                findings.extend(scan_file(p))
    return findings


def main() -> None:
    """CLI Entrypoint for Stage 1 Scanner."""
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    target_path = Path(target)
    if target_path.is_file():
        findings = scan_file(target_path)
    else:
        findings = scan_directory(target_path)

    print(f"[*] Stage 1 Polyglot Scanner completed. Found {len(findings)} potential violations.")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.rule_id} at {f.file_path}:{f.line} - {f.title}")


if __name__ == "__main__":
    main()
