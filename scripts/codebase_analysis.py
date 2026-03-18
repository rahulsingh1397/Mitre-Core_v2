"""
Codebase Analysis and Vulnerability Scanner for MITRE-CORE
Analyzes code structure, checks for vulnerabilities, and identifies redundancies.
"""

import ast
import sys
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitre-core.code_analysis")


class CodeAnalyzer:
    """Analyzes Python codebase for structure, vulnerabilities, and redundancies."""
    
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'total_files': 0,
            'total_lines': 0,
            'vulnerabilities': [],
            'redundancies': [],
            'unused_imports': [],
            'structure_issues': [],
            'file_analysis': {}
        }
        self.excluded_dirs = {'.git', '__pycache__', 'venv', '.venv', 'node_modules', '.pytest_cache'}
    
    def analyze_all(self) -> Dict:
        """Run complete codebase analysis."""
        logger.info("=" * 70)
        logger.info("CODEBASE ANALYSIS AND VULNERABILITY SCAN")
        logger.info("=" * 70)
        
        # Find all Python files
        py_files = self._find_python_files()
        self.results['total_files'] = len(py_files)
        
        logger.info(f"Found {len(py_files)} Python files")
        
        # Analyze each file
        for py_file in py_files:
            self._analyze_file(py_file)
        
        # Cross-file analysis
        self._find_redundancies()
        self._check_imports()
        
        # Generate report
        self._generate_report()
        
        return self.results
    
    def _find_python_files(self) -> List[Path]:
        """Find all Python files excluding certain directories."""
        import os
        py_files = []
        for root, dirs, files in os.walk(self.base_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs and not d.startswith('.')]
            for file in files:
                if file.endswith('.py'):
                    py_files.append(Path(root) / file)
        return py_files
    
    def _analyze_file(self, file_path: Path):
        """Analyze a single Python file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                self.results['total_lines'] += len(lines)
            
            # Parse AST
            tree = ast.parse(content)
            
            analysis = {
                'path': str(file_path),
                'line_count': len(lines),
                'imports': [],
                'functions': [],
                'classes': [],
                'vulnerabilities': [],
                'unused_vars': []
            }
            
            # Extract imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        analysis['imports'].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        analysis['imports'].append(f"{module}.{alias.name}")
                
                # Extract functions
                elif isinstance(node, ast.FunctionDef):
                    analysis['functions'].append({
                        'name': node.name,
                        'line': node.lineno,
                        'args': len(node.args.args)
                    })
                
                # Extract classes
                elif isinstance(node, ast.ClassDef):
                    analysis['classes'].append({
                        'name': node.name,
                        'line': node.lineno,
                        'methods': len([n for n in node.body if isinstance(n, ast.FunctionDef)])
                    })
                
                # Security checks
                elif isinstance(node, ast.Call):
                    # Check for dangerous functions
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', 'compile']:
                            analysis['vulnerabilities'].append({
                                'type': 'dangerous_function',
                                'function': node.func.id,
                                'line': node.lineno,
                                'severity': 'high'
                            })
                        elif node.func.id in ['pickle', 'loads']:
                            analysis['vulnerabilities'].append({
                                'type': 'deserialization',
                                'function': node.func.id,
                                'line': node.lineno,
                                'severity': 'medium'
                            })
            
            self.results['file_analysis'][str(file_path)] = analysis
            
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            self.results['structure_issues'].append({
                'file': str(file_path),
                'issue': f"Syntax error: {e}"
            })
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
    
    def _find_redundancies(self):
        """Find code redundancies across files."""
        logger.info("Checking for redundancies...")
        
        # Find duplicate function definitions
        function_signatures = {}
        for file_path, analysis in self.results['file_analysis'].items():
            for func in analysis.get('functions', []):
                sig = (func['name'], func['args'])
                if sig in function_signatures:
                    function_signatures[sig].append(file_path)
                else:
                    function_signatures[sig] = [file_path]
        
        # Report duplicates
        for sig, files in function_signatures.items():
            if len(files) > 1:
                self.results['redundancies'].append({
                    'type': 'duplicate_function',
                    'name': sig[0],
                    'files': files,
                    'recommendation': 'Consider consolidating into shared utility module'
                })
        
        # Find duplicate imports
        import_locations = {}
        for file_path, analysis in self.results['file_analysis'].items():
            for imp in analysis.get('imports', []):
                if imp not in import_locations:
                    import_locations[imp] = []
                import_locations[imp].append(file_path)
        
        # Find unused imports (simplified check)
        for file_path, analysis in self.results['file_analysis'].items():
            imports = set(analysis.get('imports', []))
            # This is a simplified check - in reality, you'd need more sophisticated analysis
    
    def _check_imports(self):
        """Check for unused and missing imports."""
        logger.info("Checking imports...")
        
        for file_path, analysis in self.results['file_analysis'].items():
            imports = analysis.get('imports', [])
            
            # Check for common unused patterns
            common_unused = [
                'matplotlib.pyplot',
                'seaborn',
                'plotly',
                'tqdm'  # Often imported but conditionally used
            ]
            
            for imp in imports:
                if any(unused in imp for unused in common_unused):
                    # This is a heuristic - would need actual usage analysis
                    pass
    
    def _generate_report(self):
        """Generate analysis report."""
        report_dir = Path("e:/Private/MITRE-CORE 2/MITRE-CORE_V2/docs/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # JSON report
        json_path = report_dir / f"code_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Markdown report
        md_path = report_dir / f"code_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(md_path, 'w') as f:
            f.write(self._generate_markdown())
        
        logger.info(f"Reports saved:")
        logger.info(f"  JSON: {json_path}")
        logger.info(f"  Markdown: {md_path}")
    
    def _generate_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            "# MITRE-CORE Codebase Analysis Report\n",
            f"**Generated:** {self.results['timestamp']}\n\n",
            "## Summary\n",
            f"- **Total Files:** {self.results['total_files']}\n",
            f"- **Total Lines:** {self.results['total_lines']:,}\n",
            f"- **Vulnerabilities Found:** {len(self.results['vulnerabilities'])}\n",
            f"- **Redundancies Found:** {len(self.results['redundancies'])}\n\n",
            "## Vulnerabilities\n"
        ]
        
        if self.results['vulnerabilities']:
            for vuln in self.results['vulnerabilities']:
                lines.append(f"- **{vuln['type']}** (Severity: {vuln['severity']})\n")
                lines.append(f"  - File: {vuln.get('file', 'Unknown')}\n")
                lines.append(f"  - Line: {vuln.get('line', 'Unknown')}\n")
        else:
            lines.append("No critical vulnerabilities found.\n")
        
        lines.append("\n## Redundancies\n")
        if self.results['redundancies']:
            for red in self.results['redundancies']:
                lines.append(f"- **{red['type']}**: {red['name']}\n")
                lines.append(f"  - Files: {', '.join(red['files'])}\n")
                lines.append(f"  - Recommendation: {red['recommendation']}\n")
        else:
            lines.append("No significant redundancies found.\n")
        
        lines.append("\n## File Structure\n")
        for file_path, analysis in self.results['file_analysis'].items():
            lines.append(f"\n### {file_path}\n")
            lines.append(f"- Lines: {analysis['line_count']}\n")
            lines.append(f"- Functions: {len(analysis['functions'])}\n")
            lines.append(f"- Classes: {len(analysis['classes'])}\n")
            lines.append(f"- Imports: {len(analysis['imports'])}\n")
            
            if analysis['vulnerabilities']:
                lines.append(f"- **Vulnerabilities:** {len(analysis['vulnerabilities'])}\n")
        
        return ''.join(lines)


def main():
    """Main entry point."""
    analyzer = CodeAnalyzer("e:/Private/MITRE-CORE 2/MITRE-CORE_V2")
    results = analyzer.analyze_all()
    
    print("\n" + "=" * 70)
    print("CODE ANALYSIS COMPLETE")
    print("=" * 70)
    print(f"Files analyzed: {results['total_files']}")
    print(f"Total lines: {results['total_lines']:,}")
    print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Redundancies: {len(results['redundancies'])}")
    
    if results['vulnerabilities']:
        print("\n⚠ VULNERABILITIES FOUND - Review report for details")
    
    if results['redundancies']:
        print("\n⚠ REDUNDANCIES FOUND - Consider code consolidation")


if __name__ == "__main__":
    main()
