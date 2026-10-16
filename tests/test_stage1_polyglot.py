"""Tests for Stage 1 Polyglot SAST Scanner."""

from cortex_rag.stage1_scanner import scan_code_string


def test_java_vulnerabilities():
    java_sqli = 'Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE user = " + username);'
    findings = scan_code_string(java_sqli, "UserController.java")
    assert any(f.rule_id == "SEC-SQLI-01" for f in findings)

    java_md5 = 'MessageDigest md = MessageDigest.getInstance("MD5");'
    findings = scan_code_string(java_md5, "HashUtil.java")
    assert any(f.rule_id == "SEC-CRYPTO-WEAK" for f in findings)


def test_csharp_vulnerabilities():
    csharp_sqli = 'var cmd = new SqlCommand("SELECT * FROM accounts WHERE id = " + accountId, conn);'
    findings = scan_code_string(csharp_sqli, "AccountService.cs")
    assert any(f.rule_id == "SEC-SQLI-01" for f in findings)

    csharp_rce = 'Process.Start("ping.exe " + host);'
    findings = scan_code_string(csharp_rce, "Network.cs")
    assert any(f.rule_id == "SEC-CMD-INJECT" for f in findings)


def test_go_vulnerabilities():
    go_sqli = 'query := fmt.Sprintf("SELECT * FROM items WHERE name = \'%s\'", userInput)'
    findings = scan_code_string(go_sqli, "repo.go")
    assert any(f.rule_id == "SEC-SQLI-01" for f in findings)

    go_md5 = 'h := md5.New()'
    findings = scan_code_string(go_md5, "crypto.go")
    assert any(f.rule_id == "SEC-CRYPTO-WEAK" for f in findings)


def test_rust_vulnerabilities():
    rust_unsafe = 'fn deref(p: *const i32) { unsafe { println!("{}", *p); } }'
    findings = scan_code_string(rust_unsafe, "main.rs")
    assert any(f.rule_id == "SEC-RUST-UNSAFE-UNWRAP" for f in findings)


def test_c_cpp_vulnerabilities():
    c_code = 'void func() { char buf[32]; gets(buf); }'
    findings = scan_code_string(c_code, "vuln.c")
    assert any(f.rule_id == "SEC-C-BUFFER-OVERFLOW" for f in findings)


def test_ruby_vulnerabilities():
    rb_sqli = 'User.where("email = \'#{params[:email]}\'")'
    findings = scan_code_string(rb_sqli, "users_controller.rb")
    assert any(f.rule_id == "SEC-SQLI-01" for f in findings)


def test_php_vulnerabilities():
    php_sqli = 'mysqli_query($conn, "SELECT * FROM posts WHERE id = " . $_GET["id"]);'
    findings = scan_code_string(php_sqli, "post.php")
    assert any(f.rule_id == "SEC-SQLI-01" for f in findings)


def test_dart_and_supabase():
    dart_fonts = 'Text("Hello", style: GoogleFonts.lato());'
    findings = scan_code_string(dart_fonts, "view.dart")
    assert any(f.rule_id == "SEC-PRIV-GOOGLE-FONTS" for f in findings)

    supa_rls = 'ALTER TABLE users DISABLE ROW LEVEL SECURITY;'
    findings = scan_code_string(supa_rls, "migration.sql")
    assert any(f.rule_id == "SEC-SUPABASE-RLS-DISABLED" for f in findings)


def test_csharp_missing_authorize():
    unprotected = """public class AdminController : ControllerBase {
    [HttpPost]
    public IActionResult DeleteUser(int id) {
        return Ok();
    }
}"""
    findings = scan_code_string(unprotected, "AdminController.cs")
    assert any(f.rule_id == "SEC-CSHARP-MISSING-AUTHORIZE" for f in findings)

    protected_code = """[Authorize]
public class AdminController : ControllerBase {
    [HttpPost]
    public IActionResult DeleteUser(int id) {
        return Ok();
    }
}"""
    clean_findings = scan_code_string(protected_code, "AdminController.cs")
    assert not any(f.rule_id == "SEC-CSHARP-MISSING-AUTHORIZE" for f in clean_findings)


def test_go_unchecked_errors():
    go_err = '_ = db.Exec("DELETE FROM sessions WHERE id = ?", id)'
    findings = scan_code_string(go_err, "auth.go")
    assert any(f.rule_id == "SEC-GO-UNCHECKED-ERROR" for f in findings)

    go_clean = 'if err := db.Exec("DELETE FROM sessions WHERE id = ?", id); err != nil { return err }'
    clean_findings = scan_code_string(go_clean, "auth.go")
    assert not any(f.rule_id == "SEC-GO-UNCHECKED-ERROR" for f in clean_findings)


def test_swift_keychain_storage_and_nstack():
    swift_storage = 'UserDefaults.standard.set(authToken, forKey: "password")'
    findings = scan_code_string(swift_storage, "LoginManager.swift")
    assert any(f.rule_id == "SEC-SWIFT-KEYCHAIN-INSECURE-STORAGE" for f in findings)

    swift_nstack = 'let task = NSTask.launchedProcess(launchPath: "/bin/sh", arguments: ["-c", input])'
    findings2 = scan_code_string(swift_nstack, "CommandRunner.swift")
    assert any(f.rule_id == "SEC-CMD-INJECT" for f in findings2)


def test_scala_process_and_slick_sql():
    scala_sql = 'val query = sqlu"DELETE FROM accounts WHERE id = $accountId"'
    findings = scan_code_string(scala_sql, "AccountRepo.scala")
    assert any(f.rule_id == "SEC-SQLI-01" for f in findings)

    scala_proc = 'val exitCode = ("ping -c 1 " + host).!'
    findings2 = scan_code_string(scala_proc, "NetworkProbe.scala")
    assert any(f.rule_id == "SEC-CMD-INJECT" for f in findings2)


def test_cpp_hardcoded_passwords_and_buffer():
    cpp_pass = 'const char* password = "ProductionSuperSecretKey123";'
    findings = scan_code_string(cpp_pass, "security.cpp")
    assert any(f.rule_id == "SEC-SECRET-HARDCODED-CREDENTIALS" for f in findings)

    cpp_fmt = 'printf(userInput);'
    findings2 = scan_code_string(cpp_fmt, "log.c")
    assert any(f.rule_id == "SEC-C-BUFFER-OVERFLOW" for f in findings2)


def test_properties_secrets():
    prop = "app.secret.key=AKIAIOSFODNN7EXAMPLE\ndb.password=superSecretP@ssw0rd!"
    findings = scan_code_string(prop, "application.properties")
    assert any(f.rule_id in ("SEC-SECRET-AWS", "SEC-SECRET-HARDCODED-CREDENTIALS") for f in findings)


def test_rust_unwrap_user_input():
    rust_code = 'let user_id = req.param("user").unwrap();'
    findings = scan_code_string(rust_code, "handler.rs")
    assert any(f.rule_id == "SEC-RUST-UNSAFE-UNWRAP" for f in findings)


def test_php_unsanitized_get_post():
    php_vuln = 'echo $_POST["user_comment"];'
    findings = scan_code_string(php_vuln, "view.php")
    assert any(f.rule_id == "SEC-XSS-DOM" for f in findings)

    php_safe = 'echo htmlspecialchars($_POST["user_comment"]);'
    clean = scan_code_string(php_safe, "view.php")
    assert not any(f.rule_id == "SEC-XSS-DOM" for f in clean)

