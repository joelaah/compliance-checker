# Regulatory Compliance Policy: Flutter & Supabase Security Architecture

**Identifier**: `POL-FLUTTER-SUPABASE-V1`  
**Standard**: Mobile Security Testing Guide (OWASP MSTG), Supabase Architecture Security, SOC2 CC6.1 / CC6.6  
**Classification**: High-Priority Client & Cloud Security  
**Enforcement Authority**: App Store Review Guidelines, Google Play Policy, SOC2 Audit Framework

---

## 1. Scope & Objective
This policy defines rigorous security architecture rules for Flutter applications (Cross-platform Web, iOS, Android, Desktop) communicating with Supabase PostgreSQL backends, edge functions, and vector memory.

---

## 2. Supabase Cloud & PostgreSQL Security Rules

### Rule SUPA-RLS-01: Universal Row Level Security (RLS)
- **Requirement**: Every table created in the `public` schema MUST have Row Level Security enabled.
- **SQL Violation**:
  ```sql
  -- NON-COMPLIANT: Table created without RLS enabled allows public write/read
  CREATE TABLE public.user_profiles (
    id UUID PRIMARY KEY,
    email TEXT,
    ssn TEXT
  );
  ```
- **Remediation Standard**:
  ```sql
  -- COMPLIANT: Explicit RLS activation + PoLP Policies
  CREATE TABLE public.user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id),
    email TEXT NOT NULL,
    ssn TEXT
  );

  ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;

  CREATE POLICY "Users can only view their own profile"
    ON public.user_profiles FOR SELECT
    USING (auth.uid() = id);

  CREATE POLICY "Users can only update their own profile"
    ON public.user_profiles FOR UPDATE
    USING (auth.uid() = id);
  ```

### Rule SUPA-KEY-01: Service Role Key Isolation
- **Requirement**: The Supabase `service_role` key bypasses all Row Level Security policies. It MUST NEVER be placed in client code, Flutter dart files, git repositories, or mobile bundles.
- **Rule ID**: `SEC-SUPABASE-SERVICE-KEY`
- **Detection Pattern**: Look for `eyJhbGciOi...` JWT containing `"role":"service_role"` or variable names `SUPABASE_SERVICE_KEY`, `supabase_service_role` in client files.
- **Remediation**: Use exclusively the `anon` public key in client Flutter apps:
  ```dart
  // COMPLIANT: Use anon key only in client
  await Supabase.initialize(
    url: const String.fromEnvironment('SUPABASE_URL'),
    anonKey: const String.fromEnvironment('SUPABASE_ANON_KEY'),
  );
  ```

---

## 3. Flutter Client Security Rules

### Rule FLUTTER-STORAGE-01: Zero Plaintext PII in SharedPreferences
- **Requirement**: Flutter `shared_preferences` writes data into unencrypted XML files on Android (`/data/data/<package>/shared_prefs`) and unencrypted plist files on iOS. Storing session tokens, passwords, medical data, or PII in `SharedPreferences` violates GDPR Art 32 and SOC2 CC6.1.
- **Rule ID**: `SEC-FLUTTER-SHARED-PREFS-PII`
- **Detection Pattern**: `SharedPreferences.getInstance()` paired with writes (`setString`, `setStringList`) containing keys matching `(token|auth|jwt|password|secret|ssn|credit_card|refresh_token)`.
- **Remediation**: Use `flutter_secure_storage` which utilizes Android Keystore and iOS Keychain with hardware-backed AES encryption:
  ```dart
  // COMPLIANT: Secure Keystore storage
  import 'package:flutter_secure_storage/flutter_secure_storage.dart';

  final storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  await storage.write(key: 'auth_jwt_token', value: sessionToken);
  ```

### Rule FLUTTER-FONTS-01: Static Google Fonts Bundling (Munich Privacy Ruling)
- **Requirement**: Flutter apps using `google_fonts` must NOT fetch TTF/WOFF files dynamically over HTTP at runtime from Google servers.
- **Rule ID**: `SEC-PRIV-GOOGLE-FONTS`
- **Remediation**:
  1. Set `GoogleFonts.config.allowRuntimeFetching = false;` in `main()` before `runApp()`.
  2. Declare local TTF font assets inside `pubspec.yaml`.

### Rule FLUTTER-NETWORK-01: TLS Pinning & Safe Deep Linking
- **Requirement**: Network clients communicating with backend APIs must enforce TLS 1.3 encryption. Deep link routing must validate redirect URIs to prevent OAuth token hijacking.

---

## 4. Policy Enforcement Matrix

| Rule ID | Severity | Target File Types | Core Requirement |
| :--- | :--- | :--- | :--- |
| `SEC-SUPABASE-SERVICE-KEY` | Critical | `.dart`, `.ts`, `.js`, `.html` | Never leak Supabase `service_role` key in frontend |
| `SEC-SUPABASE-RLS-DISABLED`| Critical | `.sql` | Every table must execute `ENABLE ROW LEVEL SECURITY` |
| `SEC-FLUTTER-SHARED-PREFS-PII` | High | `.dart` | Replace `SharedPreferences` with `FlutterSecureStorage` |
| `SEC-PRIV-GOOGLE-FONTS` | High | `.dart`, `.yaml`, `.html` | Enforce `allowRuntimeFetching = false` & asset bundling |
