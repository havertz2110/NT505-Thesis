#!/usr/bin/env python3
"""
Organize CWE testcases into OWASP Top 10 2021 categories
Usage: python sort_juliet.py
"""

import os
import shutil
from pathlib import Path

# OWASP 2021 mapping - hardcoded for simplicity
OWASP_MAPPING = {
    'A01_2021_Broken_Access_Control': [
        'CWE23_Relative_Path_Traversal',
        'CWE284_Improper_Access_Control',
        'CWE377_Insecure_Temporary_File'
    ],
    'A02_2021_Cryptographic_Failures': [
        'CWE319_Cleartext_Tx_Sensitive_Info',
        'CWE321_Hard_Coded_Cryptographic_Key',
        'CWE325_Missing_Required_Cryptographic_Step',
        'CWE327_Use_Broken_Crypto',
        'CWE328_Reversible_One_Way_Hash',
        'CWE338_Weak_PRNG',
        'CWE780_Use_of_RSA_Algorithm_Without_OAEP'
    ],
    'A03_2021_Injection': [
        'CWE78_OS_Command_Injection',
        'CWE90_LDAP_Injection'
    ],
    'A04_2021_Insecure_Design': [
        'CWE256_Plaintext_Storage_of_Password'
    ],
    'A05_2021_Security_Misconfiguration': [
        'CWE15_External_Control_of_System_or_Configuration_Setting',
        'CWE526_Info_Exposure_Environment_Variables'
    ],
    'A07_2021_Identification_and_Authentication_Failures': [
        'CWE259_Hard_Coded_Password',
        'CWE620_Unverified_Password_Change'
    ],
    'A08_2021_Software_and_Data_Integrity_Failures': [
        'CWE426_Untrusted_Search_Path'
    ],
    'A09_2021_Security_Logging_and_Monitoring_Failures': [
        'CWE223_Omission_of_Security_Relevant_Information'
    ]
}

def find_testcases_dir():
    """Auto-detect testcases directory"""
    possible_paths = [
        './testcases',
        '../testcases',
        '../dataset/juliet-dynamic-master/testcases',
        '../../dataset/juliet-dynamic-master/testcases'
    ]
    
    for path in possible_paths:
        if os.path.exists(path) and os.path.isdir(path):
            return os.path.abspath(path)
    
    return None

def organize_cwes(testcase_dir, output_dir='./owasp_organized', mode='copy'):
    """Organize CWE folders into OWASP categories"""
    
    # Validate testcases directory
    if not os.path.exists(testcase_dir):
        print(f"❌ Error: Testcases directory not found: {testcase_dir}")
        return
    
    print(f"📂 Source directory: {testcase_dir}")
    
    # List available CWE folders for debugging
    available_cwes = [d for d in os.listdir(testcase_dir) 
                     if os.path.isdir(os.path.join(testcase_dir, d)) 
                     and d.startswith('CWE')]
    print(f"🔍 Found {len(available_cwes)} CWE folders in source")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    print(f"📁 Output directory: {os.path.abspath(output_dir)}\n")
    
    # Stats
    stats = {'processed': 0, 'skipped': 0, 'errors': []}
    
    # Process each OWASP category
    for category, cwes in OWASP_MAPPING.items():
        category_short = category.split('_')[0]  # A01, A02, etc.
        category_path = os.path.join(output_dir, category_short)
        os.makedirs(category_path, exist_ok=True)
        
        # Create README
        readme_path = os.path.join(category_path, 'README.md')
        with open(readme_path, 'w') as f:
            f.write(f"# {category.replace('_', ' ')}\n\n")
            f.write(f"Contains {len(cwes)} CWE categories:\n\n")
            for cwe in cwes:
                f.write(f"- {cwe}\n")
        
        print(f"📦 {category_short}: {category.replace('_', ' ')}")
        
        # Process each CWE
        for cwe_folder in cwes:
            src = os.path.join(testcase_dir, cwe_folder)
            dst = os.path.join(category_path, cwe_folder)
            
            if not os.path.exists(src):
                print(f"  ⚠️  {cwe_folder} - NOT FOUND")
                stats['skipped'] += 1
                stats['errors'].append(f"{cwe_folder} not found in testcases")
                continue
            
            try:
                # Remove destination if exists
                if os.path.exists(dst):
                    if os.path.islink(dst):
                        os.unlink(dst)
                    elif os.path.isdir(dst):
                        shutil.rmtree(dst)
                
                # Copy, symlink, or move
                if mode == 'copy':
                    shutil.copytree(src, dst, symlinks=True)
                    print(f"  ✅ {cwe_folder}")
                elif mode == 'symlink':
                    rel_src = os.path.relpath(src, os.path.dirname(dst))
                    os.symlink(rel_src, dst, target_is_directory=True)
                    print(f"  🔗 {cwe_folder}")
                elif mode == 'move':
                    shutil.move(src, dst)
                    print(f"  ➡️  {cwe_folder}")
                
                stats['processed'] += 1
                
            except Exception as e:
                print(f"  ❌ {cwe_folder} - ERROR: {str(e)}")
                stats['errors'].append(f"{cwe_folder}: {str(e)}")
        
        print()  # Empty line between categories
    
    # Summary
    print("=" * 60)
    print(f"✨ Summary:")
    print(f"  ✅ Processed: {stats['processed']} CWEs")
    print(f"  ⚠️  Skipped: {stats['skipped']} CWEs")
    
    if stats['errors']:
        print(f"\n⚠️  Issues encountered:")
        for err in stats['errors'][:10]:
            print(f"    - {err}")
        if len(stats['errors']) > 10:
            print(f"    ... and {len(stats['errors']) - 10} more")
    
    print(f"\n✅ Done! Check: {os.path.abspath(output_dir)}")

if __name__ == "__main__":
    import sys
    
    # Get testcases directory
    if len(sys.argv) > 1:
        testcase_dir = sys.argv[1]
    else:
        testcase_dir = find_testcases_dir()
        if not testcase_dir:
            print("❌ Could not find testcases directory!")
            print("\nUsage: python sort_juliet.py [testcases_path]")
            print("Example: python sort_juliet.py ../dataset/juliet-dynamic-master/testcases")
            sys.exit(1)
    
    # Get mode (optional)
    mode = sys.argv[2] if len(sys.argv) > 2 else 'copy'
    
    print("🚀 CyberJutsu Juliet Organizer")
    print("=" * 60)
    organize_cwes(testcase_dir, mode=mode)