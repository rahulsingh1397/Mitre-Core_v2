"""
Security Vulnerability Scanner for MITRE-CORE
Scans codebase for common security issues
"""

import ast
import logging
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security_scanner")


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityIssue:
    file: str
    line: int
    severity: Severity
    category: str
    description: str
    code_snippet: str


class SecurityScanner:
    """Scan Python code for security vulnerabilities."""
    
    DANGEROUS_FUNCTIONS = {
        'eval': Severity.CRITICAL,
        'exec': Severity.CRITICAL,
        'compile': Severity.HIGH,
        '__import__': Severity.HIGH,
        'pickle.load': Severity.CRITICAL,
        'pickle.loads': Severity.CRITICAL,
        'yaml.load': Severity.HIGH,  # Safe to use yaml.safe_load
        'yaml.unsafe_load': Severity.CRITICAL,
        'marshal.load': Severity.CRITICAL,
        'marshal.loads': Severity.CRITICAL,
        'os.system': Severity.HIGH,
        'subprocess.call': Severity.MEDIUM,
        'subprocess.Popen': Severity.MEDIUM,
        'input': Severity.MEDIUM,  # Python 2 input is dangerous
    }
    
    DANGEROUS_PATTERNS = {
        'hardcoded_password': ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key'],
        'sql_injection': ['execute', 'executemany', 'raw', 'query'],
        'path_traversal': ['../', '..\\', '/etc/', 'C:\\Windows'],
        'weak_crypto': ['md5', 'sha1', 'DES', 'RC4'],
    }
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.issues: List[SecurityIssue] = []
        self.files_scanned = 0
        
    def scan_all(self) -> List[SecurityIssue]:
        """Scan all Python files in the project."""
        logger.info(f"Starting security scan of {self.base_path}")
        
        py_files = list(self.base_path.rglob("*.py"))
        py_files = [f for f in py_files if '.venv' not in str(f) and '__pycache__' not in str(f)]
        
        for py_file in py_files:
            self._scan_file(py_file)
        
        self._print_summary()
        return self.issues
    
    def _scan_file(self, file_path: Path):
        """Scan a single Python file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            self.files_scanned += 1
            
            # AST-based scanning
            try:
                tree = ast.parse(content)
                self._check_ast(tree, str(file_path), lines)
            except SyntaxError:
                pass  # Skip files with syntax errors
            
            # Pattern-based scanning
            self._check_patterns(content, str(file_path), lines)
            
        except Exception as e:
            logger.warning(f"Could not scan {file_path}: {e}")
    
    def _check_ast(self, tree: ast.AST, file_path: str, lines: List[str]):
        """Check AST for dangerous constructs."""
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in self.DANGEROUS_FUNCTIONS:
                        severity = self.DANGEROUS_FUNCTIONS[func_name]
                        self._add_issue(
                            file_path, node.lineno, severity,
                            "Dangerous Function",
                            f"Use of dangerous function '{func_name}'",
                            lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        )
                
                # Check for pickle usage
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['load', 'loads']:
                        if isinstance(node.func.value, ast.Name):
                            if node.func.value.id == 'pickle':
                                self._add_issue(
                                    file_path, node.lineno, Severity.CRITICAL,
                                    "Deserialization",
                                    "Unsafe pickle deserialization - can execute arbitrary code",
                                    lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                                )
            
            # Check for hardcoded credentials
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.lower()
                for pattern in self.DANGEROUS_PATTERNS['hardcoded_password']:
                    if pattern in value and len(value) > 8:  # Likely a password
                        # Skip if it's just a variable name in the code
                        line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        if '=' in line or ':' in line:
                            self._add_issue(
                                file_path, node.lineno, Severity.HIGH,
                                "Hardcoded Credential",
                                f"Possible hardcoded credential containing '{pattern}'",
                                line[:100]  # Truncate for safety
                            )
                            break
    
    def _check_patterns(self, content: str, file_path: str, lines: List[str]):
        """Check for dangerous patterns in content."""
        for i, line in enumerate(lines, 1):
            # Check for SQL injection patterns
            if any(pattern in line.lower() for pattern in ['.execute(', '.executemany(', 'raw_sql']):
                if 'f"' in line or "f'" in line or '%s' in line or '{}' in line:
                    self._add_issue(
                        file_path, i, Severity.HIGH,
                        "SQL Injection",
                        "Possible SQL injection - parameterized query recommended",
                        line[:100]
                    )
            
            # Check for path traversal
            if '..' in line and ('open(' in line or 'read' in line or 'write' in line):
                self._add_issue(
                    file_path, i, Severity.MEDIUM,
                    "Path Traversal",
                    "Possible path traversal vulnerability",
                    line[:100]
                )
            
            # Check for debug mode
            if 'debug=True' in line.lower() or 'debug = True' in line:
                self._add_issue(
                    file_path, i, Severity.LOW,
                    "Debug Mode",
                    "Debug mode enabled - disable in production",
                    line[:100]
                )
            
            # Check for weak crypto
            if 'hashlib.md5' in line or 'hashlib.sha1' in line:
                self._add_issue(
                    file_path, i, Severity.MEDIUM,
                    "Weak Cryptography",
                    "MD5/SHA1 considered weak - use SHA256 or better",
                    line[:100]
                )
    
    def _add_issue(self, file: str, line: int, severity: Severity, 
                   category: str, description: str, code_snippet: str):
        """Add a security issue to the list."""
        issue = SecurityIssue(
            file=file,
            line=line,
            severity=severity,
            category=category,
            description=description,
            code_snippet=code_snippet.strip()[:200]  # Limit length
        )
        self.issues.append(issue)
    
    def _print_summary(self):
        """Print scan summary."""
        logger.info("\n" + "=" * 80)
        logger.info("SECURITY SCAN SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Files scanned: {self.files_scanned}")
        logger.info(f"Issues found: {len(self.issues)}")
        
        by_severity = {}
        for issue in self.issues:
            by_severity[issue.severity] = by_severity.get(issue.severity, 0) + 1
        
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if sev in by_severity:
                logger.info(f"  {sev.value}: {by_severity[sev]}")
        
        logger.info("\n" + "=" * 80)
    
    def generate_report(self, output_path: str = "docs/security/SECURITY_AUDIT.md"):
        """Generate markdown report."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        lines = [
            "# Security Audit Report",
            "",
            f"**Generated:** {__import__('datetime').datetime.now().isoformat()}",
            f"**Files Scanned:** {self.files_scanned}",
            f"**Total Issues:** {len(self.issues)}",
            "",
            "## Summary by Severity",
            ""
        ]
        
        by_severity = {}
        for issue in self.issues:
            by_severity[issue.severity] = by_severity.get(issue.severity, [])
            by_severity[issue.severity].append(issue)
        
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if sev in by_severity:
                lines.append(f"- **{sev.value}:** {len(by_severity[sev])} issues")
        
        lines.extend(["", "## Detailed Findings", ""])
        
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if sev in by_severity:
                lines.append(f"### {sev.value} Severity")
                lines.append("")
                for issue in by_severity[sev]:
                    lines.append(f"**{issue.category}** in `{issue.file}:{issue.line}`")
                    lines.append(f"- {issue.description}")
                    if issue.code_snippet:
                        lines.append(f"```python")
                        lines.append(f"{issue.code_snippet}")
                        lines.append(f"```")
                    lines.append("")
        
        lines.extend([
            "## Recommendations",
            "",
            "### Immediate Actions",
            "1. Review all CRITICAL and HIGH severity issues",
            "2. Replace pickle with JSON for serialization",
            "3. Use parameterized queries for all database operations",
            "4. Remove or secure any debug endpoints",
            "",
            "### Best Practices",
            "- Use `yaml.safe_load()` instead of `yaml.load()`",
            "- Use `ast.literal_eval()` instead of `eval()`",
            "- Store credentials in environment variables or secure vaults",
            "- Use SHA-256 or stronger for hashing",
            "- Validate all file paths to prevent traversal",
            "",
            "## False Positives",
            "",
            "Some issues may be false positives if:",
            "- The code is for internal/testing use only",
            "- The 'hardcoded' value is actually a default/example",
            "- The SQL is properly parameterized (pattern matching limitation)",
            "",
            "Please review each finding to confirm validity.",
        ])
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        
        logger.info(f"Security report saved to: {output_path}")


if __name__ == "__main__":
    import sys
    base_path = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = SecurityScanner(base_path)
    issues = scanner.scan_all()
    scanner.generate_report()
    
    # Exit with error code if critical issues found
    critical_count = sum(1 for i in issues if i.severity == Severity.CRITICAL)
    if critical_count > 0:
        logger.error(f"Found {critical_count} CRITICAL security issues!")
        sys.exit(1)
