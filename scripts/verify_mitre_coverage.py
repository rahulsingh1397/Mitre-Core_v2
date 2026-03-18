"""
MITRE ATT&CK Coverage Verification Script
Validates that all 14 tactics are properly covered by the mapping system.
"""

import pandas as pd
import json
from utils.mitre_complete import MITRECompleteMapper


def verify_mitre_coverage():
    """Verify 100% MITRE ATT&CK coverage."""
    mapper = MITRECompleteMapper()
    
    print("=" * 80)
    print("MITRE ATT&CK Coverage Verification")
    print("=" * 80)
    
    # Get all tactics
    all_tactics = mapper.all_tactics
    print(f"\nTotal MITRE ATT&CK Tactics: {len(all_tactics)}")
    print(f"Expected: 14")
    
    # Verify each tactic has mappings
    coverage_report = {}
    for tactic in all_tactics:
        # Count how many attack signatures map to this tactic
        count = sum(1 for sig, t in mapper.complete_mapping.items() if t == tactic)
        coverage_report[tactic] = {
            'mapped_signatures': count,
            'status': 'COVERED' if count > 0 else 'MISSING'
        }
        print(f"\n{tactic}: {count} attack signatures mapped")
    
    # Calculate coverage percentage
    covered = sum(1 for t in all_tactics if coverage_report[t]['mapped_signatures'] > 0)
    percentage = (covered / len(all_tactics)) * 100
    
    print(f"\n{'='*80}")
    print(f"COVERAGE: {covered}/{len(all_tactics)} tactics = {percentage:.1f}%")
    print(f"{'='*80}")
    
    # Save report
    report = {
        'timestamp': pd.Timestamp.now().isoformat(),
        'total_tactics': len(all_tactics),
        'covered_tactics': covered,
        'coverage_percentage': percentage,
        'tactics': coverage_report
    }
    
    with open('docs/reports/mitre_coverage_verification.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\nReport saved to: docs/reports/mitre_coverage_verification.json")
    
    # Assert for CI/CD
    assert percentage == 100.0, f"Coverage not 100%: {percentage}%"
    print("\n✓ VERIFICATION PASSED: 100% MITRE ATT&CK coverage confirmed")
    
    return report


if __name__ == "__main__":
    verify_mitre_coverage()
