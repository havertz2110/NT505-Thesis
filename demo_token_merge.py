#!/usr/bin/env python3
"""
Demo script to show how to merge tokens from multiple source files
Usage: python demo_token_merge.py <file1.c> <file2.c> ...
"""

import sys
from pathlib import Path
from slice import TokenRegistry, CVulnerabilityFramework

def main():
    if len(sys.argv) < 2:
        print("Usage: python demo_token_merge.py <file1.c> <file2.c> ...")
        print("Example: python demo_token_merge.py sample.c another.c")
        sys.exit(1)

    # Initialize shared token registry
    token_registry = TokenRegistry(Path("token.json"))
    print(f"📚 Loaded token registry with {len(token_registry.id_to_token)} existing tokens")
    print("=" * 70)

    for file_path_str in sys.argv[1:]:
        file_path = Path(file_path_str)

        if not file_path.exists():
            print(f"⚠️  Skipping {file_path}: File not found")
            continue

        print(f"\n🔍 Processing: {file_path}")
        print("-" * 70)

        try:
            source_code = file_path.read_text(encoding="utf-8", errors="ignore")

            # Create framework with shared registry
            framework = CVulnerabilityFramework(token_registry)

            # Analyze the file
            analysis = framework.generate_hierarchical_representation(source_code)

            # Count tokens for this file
            total_tokens = sum(
                len(sb['tokens'])
                for module in analysis['modules']
                for func in module['functions']
                for sb in func['statement_blocks']
            )

            print(f"✓ Analyzed {file_path.name}")
            print(f"  Total tokens in file: {total_tokens}")
            print(f"  Registry size: {len(token_registry.id_to_token)} unique tokens")

            # Save analysis for this file
            output_path = file_path.with_suffix('.json')
            import json
            output_path.write_text(
                json.dumps(analysis, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8'
            )
            print(f"  Saved: {output_path}")

        except Exception as e:
            print(f"❌ Error processing {file_path}: {e}")
            continue

    # Save final token registry
    print("\n" + "=" * 70)
    print("📝 Saving final token registry...")
    token_registry.save_registry()

    print(f"\n✅ Token Registry Summary:")
    print(f"  Total unique tokens: {len(token_registry.id_to_token)}")
    print(f"  Token distribution:")
    for token_type, count in sorted(token_registry.statistics.items()):
        print(f"    - {token_type}: {count}")
    print(f"\n  Registry saved to: {token_registry.registry_path}")

if __name__ == "__main__":
    main()
