#!/usr/bin/env python3
"""
BreachPilot Legacy File Cleanup Script
Removes redundant documentation and scripts after CrewAI redesign
"""

import os
import sys
from pathlib import Path

def cleanup_legacy_files():
    """
    Remove legacy files that are no longer needed after CrewAI redesign
    """
    
    # Files to be removed (redundant documentation and scripts)
    files_to_remove = [
        # Legacy Documentation Files
        "CHANGELOG_FIX.md",
        "CLEANUP.md", 
        "CLEANUP_INSTRUCTIONS.md",
        "CODE_REVIEW.md",
        "ENHANCED_REPORTING_README.md",
        "NMAP_FIX_CHANGELOG.md",
        "PDF_DOWNLOAD_COMPLETE_FIX.md",
        "PDF_DOWNLOAD_FIX.md",
        "PDF_DOWNLOAD_QUICK_FIX.md",
        "POC_ENHANCEMENT_REPORT.md",
        "TROUBLESHOOTING.md",
        "CLEANUP_REPORT.md",
        
        # Legacy Development Scripts
        "cleanup.sh",
        "fix_dependencies.sh",
        "fix_pdf_download_now.sh",
        "install_tools.sh",
        "quick_setup.sh",
        "setup.sh",
        "test_pdf_download.sh",
        "test_pdf_download_complete.sh",
        
        # Test Files
        "frontend_test_section.html",
    ]
    
    print("🧹 BreachPilot Legacy File Cleanup")
    print("=====================================")
    print()
    
    removed_count = 0
    total_size = 0
    errors = []
    
    for file_path in files_to_remove:
        try:
            if os.path.exists(file_path):
                # Get file size before removal
                size = os.path.getsize(file_path)
                total_size += size
                
                # Remove the file
                os.remove(file_path)
                removed_count += 1
                print(f"✅ Removed: {file_path} ({size:,} bytes)")
            else:
                print(f"⚠️  Not found: {file_path}")
        except Exception as e:
            errors.append(f"❌ Error removing {file_path}: {e}")
            print(f"❌ Error removing {file_path}: {e}")
    
    print()
    print("📊 Cleanup Summary:")
    print(f"Files removed: {removed_count}")
    print(f"Total size freed: {total_size:,} bytes ({total_size/1024:.1f} KB)")
    
    if errors:
        print(f"Errors: {len(errors)}")
        for error in errors:
            print(f"  {error}")
    else:
        print("✅ Cleanup completed successfully!")
    
    print()
    print("🎯 Next Steps:")
    print("1. Verify the application still works: python app.py")
    print("2. Test CrewAI functionality with your API keys")
    print("3. Remove this cleanup script: rm cleanup_legacy_files.py")
    print()
    print("📁 Clean project structure maintained in:")
    print("   - README.md (main documentation)")
    print("   - CHANGELOG.md (version history)")
    print("   - FINAL_CLEANUP_REPORT.md (cleanup details)")

if __name__ == "__main__":
    print("This script will remove legacy files from the BreachPilot project.")
    print("Make sure you're in the project root directory.")
    print()
    
    response = input("Continue with cleanup? (y/N): ").strip().lower()
    
    if response == 'y' or response == 'yes':
        cleanup_legacy_files()
    else:
        print("Cleanup cancelled.")
        sys.exit(0)
