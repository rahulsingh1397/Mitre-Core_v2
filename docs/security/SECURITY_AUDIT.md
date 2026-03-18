# Security Audit Report

**Generated:** 2026-03-15T19:01:23.014664
**Files Scanned:** 159
**Total Issues:** 69

## Summary by Severity

- **HIGH:** 64 issues
- **MEDIUM:** 4 issues
- **LOW:** 1 issues

## Detailed Findings

### HIGH Severity

**Hardcoded Credential** in `security.py:369`
- Possible hardcoded credential containing 'token'
```python
"""Decorator: require a valid JWT access token."""
```

**Hardcoded Credential** in `security.py:51`
- Possible hardcoded credential containing 'secret'
```python
SECRET_KEY: str = _env("SECRET_KEY", secrets.token_hex(32))
```

**Hardcoded Credential** in `security.py:55`
- Possible hardcoded credential containing 'secret'
```python
JWT_SECRET_KEY: str = _env("JWT_SECRET_KEY", secrets.token_hex(32))
```

**Hardcoded Credential** in `security.py:56`
- Possible hardcoded credential containing 'token'
```python
JWT_ACCESS_EXPIRES: int = _env_int("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", 60)
```

**Hardcoded Credential** in `security.py:57`
- Possible hardcoded credential containing 'token'
```python
JWT_REFRESH_EXPIRES: int = _env_int("JWT_REFRESH_TOKEN_EXPIRES_DAYS", 30)
```

**Hardcoded Credential** in `security.py:82`
- Possible hardcoded credential containing 'password'
```python
ADMIN_PASSWORD: str = _env("ADMIN_PASSWORD", "")
```

**Hardcoded Credential** in `security.py:85`
- Possible hardcoded credential containing 'key'
```python
SIEM_ENCRYPTION_KEY: str = _env("SIEM_ENCRYPTION_KEY", "")
```

**Hardcoded Credential** in `security.py:141`
- Possible hardcoded credential containing 'key'
```python
dbapi_conn.execute("PRAGMA foreign_keys=ON")
```

**Hardcoded Credential** in `security.py:336`
- Possible hardcoded credential containing 'token'
```python
logger.error("Failed to revoke token in DB: %s", exc)
```

**Hardcoded Credential** in `security.py:241`
- Possible hardcoded credential containing 'password'
```python
text("INSERT INTO users (username, password, role, created_at) VALUES (:u, :p, :r, :
```

**Hardcoded Credential** in `security.py:247`
- Possible hardcoded credential containing 'password'
```python
"Auto-generated admin password: %s  — change it immediately!", pw
```

**Hardcoded Credential** in `security.py:304`
- Possible hardcoded credential containing 'token'
```python
text("SELECT id FROM revoked_tokens WHERE jti = :j"), {"j": jti}
```

**Hardcoded Credential** in `security.py:327`
- Possible hardcoded credential containing 'token'
```python
text("INSERT INTO revoked_tokens (jti, revoked_at) VALUES (:j, :t) ON CONFLICT (
```

**Hardcoded Credential** in `security.py:332`
- Possible hardcoded credential containing 'token'
```python
text("INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (:j, :t)"),
```

**Hardcoded Credential** in `security.py:379`
- Possible hardcoded credential containing 'token'
```python
return jsonify({"success": False, "error": "Invalid token type"}), 401
```

**Hardcoded Credential** in `security.py:381`
- Possible hardcoded credential containing 'token'
```python
return jsonify({"success": False, "error": "Token has been revoked"}), 401
```

**Hardcoded Credential** in `security.py:385`
- Possible hardcoded credential containing 'token'
```python
return jsonify({"success": False, "error": "Token expired"}), 401
```

**Hardcoded Credential** in `security.py:387`
- Possible hardcoded credential containing 'token'
```python
return jsonify({"success": False, "error": "Invalid token"}), 401
```

**SQL Injection** in `security.py:204`
- Possible SQL injection - parameterized query recommended
```python
conn.execute(text(f"""
```

**SQL Injection** in `security.py:215`
- Possible SQL injection - parameterized query recommended
```python
conn.execute(text(f"""
```

**SQL Injection** in `security.py:225`
- Possible SQL injection - parameterized query recommended
```python
conn.execute(text(f"""
```

**Hardcoded Credential** in `reporting\compare_hgnn_baseline.py:317`
- Possible hardcoded credential containing 'key'
```python
logger.info(f"\nKey Findings:")
```

**Hardcoded Credential** in `reporting\generate_comparison_report.py:131`
- Possible hardcoded credential containing 'key'
```python
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
```

**Hardcoded Credential** in `scripts\generate_evaluation_report.py:346`
- Possible hardcoded credential containing 'key'
```python
"**Key Findings:**\n",
```

**Hardcoded Credential** in `scripts\generate_evaluation_report.py:442`
- Possible hardcoded credential containing 'key'
```python
"Key areas for improvement:\n",
```

**Dangerous Function** in `scripts\production_validation.py:159`
- Use of dangerous function '__import__'
```python
module = __import__(module_name, fromlist=[class_name])
```

**Hardcoded Credential** in `scripts\security_scanner.py:56`
- Possible hardcoded credential containing 'password'
```python
'hardcoded_password': ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key'],
```

**Hardcoded Credential** in `scripts\security_scanner.py:133`
- Possible hardcoded credential containing 'password'
```python
for pattern in self.DANGEROUS_PATTERNS['hardcoded_password']:
```

**Dangerous Function** in `scripts\security_scanner.py:224`
- Use of dangerous function '__import__'
```python
f"**Generated:** {__import__('datetime').datetime.now().isoformat()}",
```

**Hardcoded Credential** in `siem\connectors.py:133`
- Possible hardcoded credential containing 'key'
```python
"config_keys": list(self.config.keys()),
```

**Hardcoded Credential** in `siem\connectors.py:303`
- Possible hardcoded credential containing 'secret'
```python
self.client_secret = config.get("client_secret", "")
```

**Hardcoded Credential** in `siem\connectors.py:313`
- Possible hardcoded credential containing 'token'
```python
url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
```

**Hardcoded Credential** in `siem\connectors.py:317`
- Possible hardcoded credential containing 'secret'
```python
"client_secret": self.client_secret,
```

**Hardcoded Credential** in `siem\connectors.py:381`
- Possible hardcoded credential containing 'token'
```python
self.api_token = config.get("api_token", "")
```

**Hardcoded Credential** in `siem\connectors.py:635`
- Possible hardcoded credential containing 'secret'
```python
provided = (headers or {}).get("X-Webhook-Secret", "")
```

**Hardcoded Credential** in `training\download_datasets.py:199`
- Possible hardcoded credential containing 'passwd'
```python
'guess_passwd': 'Credential Access',
```

**Hardcoded Credential** in `transformer\debug_training.py:52`
- Possible hardcoded credential containing 'key'
```python
print(f"Batch keys: {batch.keys()}")
```

**Hardcoded Credential** in `utils\cross_domain_fusion.py:69`
- Possible hardcoded credential containing 'key'
```python
'registry': ['registry_key', 'registry_value'],
```

**Hardcoded Credential** in `utils\explainability.py:341`
- Possible hardcoded credential containing 'key'
```python
parts.append("\nKey Contributing Factors:")
```

**Hardcoded Credential** in `utils\explainability.py:404`
- Possible hardcoded credential containing 'key'
```python
print(f"Key Entities: {len(explanation.key_entities)}")
```

**Hardcoded Credential** in `utils\explainability.py:268`
- Possible hardcoded credential containing 'key'
```python
parts.append(f"- Key Source IP: {primary_ip['value']} "
```

**Hardcoded Credential** in `utils\mitre_complete.py:124`
- Possible hardcoded credential containing 'key'
```python
'registry_run_keys': 'Persistence',
```

**Hardcoded Credential** in `utils\mitre_complete.py:135`
- Possible hardcoded credential containing 'token'
```python
'token_impersonation': 'Privilege Escalation',
```

**Hardcoded Credential** in `utils\mitre_complete.py:136`
- Possible hardcoded credential containing 'token'
```python
'access_token_manipulation': 'Privilege Escalation',
```

**Hardcoded Credential** in `utils\mitre_complete.py:183`
- Possible hardcoded credential containing 'key'
```python
'keylogger': 'Credential Access',
```

**Hardcoded Credential** in `utils\mitre_complete.py:234`
- Possible hardcoded credential containing 'key'
```python
'keylogging': 'Collection',
```

**Hardcoded Credential** in `utils\mitre_complete.py:362`
- Possible hardcoded credential containing 'password'
```python
'Credential Access': 'Adversary stealing account names and passwords',
```

**Hardcoded Credential** in `utils\mitre_tactic_mapper.py:105`
- Possible hardcoded credential containing 'password'
```python
'description': 'Stealing account names and passwords',
```

**Hardcoded Credential** in `utils\mitre_tactic_mapper.py:330`
- Possible hardcoded credential containing 'passwd'
```python
'guess_passwd': 'Credential Access',
```

**Hardcoded Credential** in `archive\synthetic_utilities\soc_log_generator.py:107`
- Possible hardcoded credential containing 'key'
```python
'signatures': ['RegistryRunKeys', 'ScheduledTask', 'CreateAccount', 'WebShell'],
```

**Hardcoded Credential** in `archive\synthetic_utilities\soc_log_generator.py:112`
- Possible hardcoded credential containing 'token'
```python
'signatures': ['ProcessInjection', 'TokenImpersonation', 'BypassUAC'],
```

**Hardcoded Credential** in `scripts\analysis\run_mitre_analysis.py:613`
- Possible hardcoded credential containing 'key'
```python
This report consolidates the findings from end-to-end MITRE-CORE analysis across {len(results)} cybe
```

**Hardcoded Credential** in `scripts\security\security_scan.py:79`
- Possible hardcoded credential containing 'secret'
```python
print("  Check: Hardcoded Secrets")
```

**Hardcoded Credential** in `scripts\security\security_scan.py:190`
- Possible hardcoded credential containing 'secret'
```python
results["hardcoded_secrets"] = check_hardcoded_secrets()
```

**Hardcoded Credential** in `scripts\security\security_scan.py:82`
- Possible hardcoded credential containing 'password'
```python
(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "hardcoded password"),
```

**Hardcoded Credential** in `scripts\security\security_scan.py:82`
- Possible hardcoded credential containing 'password'
```python
(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "hardcoded password"),
```

**Hardcoded Credential** in `scripts\security\security_scan.py:83`
- Possible hardcoded credential containing 'secret'
```python
(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']', "hardcoded API key"),
```

**Hardcoded Credential** in `scripts\security\security_scan.py:83`
- Possible hardcoded credential containing 'key'
```python
(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']', "hardcoded API key"),
```

**Hardcoded Credential** in `scripts\security\security_scan.py:84`
- Possible hardcoded credential containing 'secret'
```python
(r'(?:secret_key|SECRET_KEY)\s*=\s*["\'][^"\']{8,}["\']', "hardcoded secret key"),
```

**Hardcoded Credential** in `scripts\security\security_scan.py:84`
- Possible hardcoded credential containing 'secret'
```python
(r'(?:secret_key|SECRET_KEY)\s*=\s*["\'][^"\']{8,}["\']', "hardcoded secret key"),
```

**Hardcoded Credential** in `scripts\security\security_scan.py:85`
- Possible hardcoded credential containing 'token'
```python
(r'(?:token)\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']', "hardcoded token"),
```

**Hardcoded Credential** in `scripts\security\security_scan.py:85`
- Possible hardcoded credential containing 'token'
```python
(r'(?:token)\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']', "hardcoded token"),
```

**Hardcoded Credential** in `scripts\security\security_scan.py:112`
- Possible hardcoded credential containing 'secret'
```python
print("[WARN] Potential hardcoded secrets found (review manually):")
```

**Dangerous Function** in `validation\archive\run_accuracy_validation.py:162`
- Use of dangerous function '__import__'
```python
module = __import__(module_name, fromlist=[class_name])
```

### MEDIUM Severity

**Path Traversal** in `scripts\security_scanner.py:160`
- Possible path traversal vulnerability
```python
if '..' in line and ('open(' in line or 'read' in line or 'write' in line):
```

**Weak Cryptography** in `scripts\security_scanner.py:178`
- MD5/SHA1 considered weak - use SHA256 or better
```python
if 'hashlib.md5' in line or 'hashlib.sha1' in line:
```

**Dangerous Function** in `scripts\maintenance\cleanup_old_data.py:145`
- Use of dangerous function 'input'
```python
response = input("Proceed with cleanup? (yes/no): ")
```

**Weak Cryptography** in `transformer\preprocessing\alert_preprocessor.py:81`
- MD5/SHA1 considered weak - use SHA256 or better
```python
hash_val = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
```

### LOW Severity

**Debug Mode** in `scripts\security_scanner.py:169`
- Debug mode enabled - disable in production
```python
if 'debug=True' in line.lower() or 'debug = True' in line:
```

## Recommendations

### Immediate Actions
1. Review all CRITICAL and HIGH severity issues
2. Replace pickle with JSON for serialization
3. Use parameterized queries for all database operations
4. Remove or secure any debug endpoints

### Best Practices
- Use `yaml.safe_load()` instead of `yaml.load()`
- Use `ast.literal_eval()` instead of `eval()`
- Store credentials in environment variables or secure vaults
- Use SHA-256 or stronger for hashing
- Validate all file paths to prevent traversal

## False Positives

Some issues may be false positives if:
- The code is for internal/testing use only
- The 'hardcoded' value is actually a default/example
- The SQL is properly parameterized (pattern matching limitation)

Please review each finding to confirm validity.