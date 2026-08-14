import argparse
from collections import Counter
from model import SCLModel
from analyzer import Analyzer


def main():
    parser = argparse.ArgumentParser(description="Test IEC 61850 SCL parser")
    parser.add_argument("scl_file", help="Path to the SCL/CID/SCD/ICD file")
    parser.add_argument("--no-cei016", action="store_true", help="Disable CEI 0-16 checks")
    args = parser.parse_args()

    print("=" * 70)
    print("SCL ANALYZER TEST")
    print("=" * 70)
    print(f"File: {args.scl_file}")

    model = SCLModel(args.scl_file)
    try:
        model.load()
    except Exception as exc:
        print("ERROR loading SCL:")
        print(exc)
        raise SystemExit(1)

    analyzer = Analyzer(model, cei016_enabled=not args.no_cei016)
    issues = analyzer.run()

    counts = Counter(i.severity for i in issues)
    print(f"IEDs: {len(model.ieds)}")
    print(f"Errors: {counts.get('ERROR', 0)}")
    print(f"Warnings: {counts.get('WARNING', 0)}")
    print(f"Info: {counts.get('INFO', 0)}")
    print("-" * 70)

    for issue in issues:
        print(" | ".join(issue.as_tuple()))


if __name__ == "__main__":
    main()
