"""
Code Duplication and Redundancy Scanner
Finds duplicate functions, classes, and code blocks across the codebase
"""

import ast
import hashlib
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Set
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("duplication_scanner")


class CodeDuplicationScanner:
    """Scan codebase for duplicate code."""
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.functions: Dict[str, List[Tuple[str, int]]] = defaultdict(list)  # name -> [(file, line)]
        self.classes: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
        self.code_hashes: Dict[str, List[Tuple[str, int, str]]] = defaultdict(list)  # hash -> [(file, line, name)]
        
    def scan_all(self):
        """Scan all Python files for duplication."""
        logger.info(f"Scanning {self.base_path} for code duplication...")
        
        py_files = list(self.base_path.rglob("*.py"))
        py_files = [f for f in py_files if '.venv' not in str(f) and '__pycache__' not in str(f)]
        
        for py_file in py_files:
            self._scan_file(py_file)
        
        self._print_duplicates()
        return self._generate_report()
    
    def _scan_file(self, file_path: Path):
        """Scan a single file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            try:
                tree = ast.parse(content)
            except SyntaxError:
                return
            
            for node in ast.walk(tree):
                # Track function definitions
                if isinstance(node, ast.FunctionDef):
                    func_name = node.name
                    self.functions[func_name].append((str(file_path), node.lineno))
                    
                    # Hash function body for content comparison
                    func_hash = self._hash_function(node)
                    if func_hash:
                        self.code_hashes[func_hash].append((str(file_path), node.lineno, func_name))
                
                # Track class definitions
                elif isinstance(node, ast.ClassDef):
                    class_name = node.name
                    self.classes[class_name].append((str(file_path), node.lineno))
                    
                    # Hash class body
                    class_hash = self._hash_class(node)
                    if class_hash:
                        self.code_hashes[class_hash].append((str(file_path), node.lineno, class_name))
                        
        except Exception as e:
            logger.warning(f"Could not scan {file_path}: {e}")
    
    def _hash_function(self, node: ast.FunctionDef) -> str:
        """Create hash of function body (excluding name and docstring)."""
        try:
            # Get function body without first docstring
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                body = body[1:]  # Skip docstring
            
            # Normalize: remove variable names, keep structure
            normalized = ast.dump(ast.Module(body=body, type_ignores=[]))
            # Remove specific names to catch renamed duplicates
            normalized = ' '.join([w for w in normalized.split() if not w.startswith("'") and not w.startswith('"')])
            
            return hashlib.md5(normalized.encode()).hexdigest()[:16]
        except:
            return None
    
    def _hash_class(self, node: ast.ClassDef) -> str:
        """Create hash of class methods and structure."""
        try:
            method_names = [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
            normalized = ','.join(sorted(method_names))
            return hashlib.md5(normalized.encode()).hexdigest()[:16]
        except:
            return None
    
    def _print_duplicates(self):
        """Print duplicate findings."""
        logger.info("\n" + "=" * 80)
        logger.info("DUPLICATE ANALYSIS RESULTS")
        logger.info("=" * 80)
        
        # Functions with same name in multiple files
        duplicate_funcs = {k: v for k, v in self.functions.items() if len(v) > 1}
        if duplicate_funcs:
            logger.info(f"\nFunctions with SAME NAME in multiple files: {len(duplicate_funcs)}")
            for func_name, locations in sorted(duplicate_funcs.items(), key=lambda x: len(x[1]), reverse=True)[:20]:
                logger.info(f"  {func_name}: {len(locations)} locations")
                for file, line in locations[:3]:
                    logger.info(f"    - {file}:{line}")
        
        # Classes with same name
        duplicate_classes = {k: v for k, v in self.classes.items() if len(v) > 1}
        if duplicate_classes:
            logger.info(f"\nClasses with SAME NAME in multiple files: {len(duplicate_classes)}")
            for class_name, locations in sorted(duplicate_classes.items(), key=lambda x: len(x[1]), reverse=True)[:20]:
                logger.info(f"  {class_name}: {len(locations)} locations")
                for file, line in locations[:3]:
                    logger.info(f"    - {file}:{line}")
        
        # Functions with same body (likely copied)
        identical_funcs = {k: v for k, v in self.code_hashes.items() if len(v) > 1}
        if identical_funcs:
            logger.info(f"\nFunctions/Classes with IDENTICAL BODIES: {len(identical_funcs)}")
            for hash_val, locations in list(identical_funcs.items())[:10]:
                names = set(loc[2] for loc in locations)
                if len(names) > 1:  # Different names but same body
                    logger.info(f"  Same body, different names: {', '.join(names)}")
                else:
                    logger.info(f"  Duplicated: {list(names)[0]}")
                for file, line, name in locations[:3]:
                    logger.info(f"    - {file}:{line}")
    
    def _generate_report(self) -> str:
        """Generate markdown report."""
        lines = [
            "# Code Duplication Analysis Report",
            "",
            "## Summary",
            "",
        ]
        
        duplicate_funcs = {k: v for k, v in self.functions.items() if len(v) > 1}
        duplicate_classes = {k: v for k, v in self.classes.items() if len(v) > 1}
        
        lines.extend([
            f"- **Total Functions Scanned:** {len(self.functions)}",
            f"- **Duplicate Function Names:** {len(duplicate_funcs)}",
            f"- **Total Classes Scanned:** {len(self.classes)}",
            f"- **Duplicate Class Names:** {len(duplicate_classes)}",
            "",
            "## Duplicate Functions (Same Name)",
            "",
        ])
        
        for func_name, locations in sorted(duplicate_funcs.items(), key=lambda x: len(x[1]), reverse=True):
            lines.append(f"### `{func_name}` ({len(locations)} locations)")
            for file, line in locations:
                lines.append(f"- `{file}:{line}`")
            lines.append("")
        
        if duplicate_classes:
            lines.extend([
                "## Duplicate Classes (Same Name)",
                "",
            ])
            for class_name, locations in sorted(duplicate_classes.items(), key=lambda x: len(x[1]), reverse=True):
                lines.append(f"### `{class_name}` ({len(locations)} locations)")
                for file, line in locations:
                    lines.append(f"- `{file}:{line}`")
                lines.append("")
        
        lines.extend([
            "## Recommendations",
            "",
            "1. **Consolidate duplicate functions** into shared utility modules",
            "2. **Rename ambiguous functions** to be more descriptive",
            "3. **Create base classes** for duplicate class structures",
            "4. **Add tests** before refactoring to prevent regressions",
            "",
        ])
        
        return '\n'.join(lines)
    
    def save_report(self, output_path: str = "docs/analysis/DUPLICATION_REPORT.md"):
        """Save report to file."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        report = self._generate_report()
        with open(output_path, 'w') as f:
            f.write(report)
        logger.info(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    import sys
    base_path = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = CodeDuplicationScanner(base_path)
    scanner.scan_all()
    scanner.save_report()
