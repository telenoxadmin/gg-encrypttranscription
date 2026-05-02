"""
local_test.py  —  Test the redactor locally before deploying to Lambda.

Usage:
    pip install presidio-analyzer presidio-anonymizer spacy names-dataset
    python -m spacy download en_core_web_lg
    python local_test.py --input transcript.txt --mode tokenize
"""
import sys
import json
import argparse
from pathlib import Path

# Add lambda_function to path
sys.path.insert(0, str(Path(__file__).parent / "lambda_function"))
from redactor import HotelPIIRedactor


def main():
    p = argparse.ArgumentParser(description="Local test for Hotel PII Redactor")
    p.add_argument("--input",  "-i", required=True, help="Input transcript .txt file")
    p.add_argument("--output", "-o", default=None,  help="Output file (default: <input>_redacted.txt)")
    p.add_argument("--mode",   "-m", choices=["redact", "tokenize"], default="redact")
    p.add_argument("--confidence", "-c", type=float, default=0.6)
    p.add_argument("--model",  default="en_core_web_lg", help="spaCy model name")
    args = p.parse_args()

    inp = Path(args.input).resolve()
    out = Path(args.output).resolve() if args.output else \
          inp.parent / (inp.stem + "_redacted" + inp.suffix)
    map_out = inp.parent / (inp.stem + "_token_map.json")

    print(f"\n{'='*55}")
    print(f"  Hotel PII Redactor — Local Test")
    print(f"  Mode       : {args.mode.upper()}")
    print(f"  Model      : {args.model}")
    print(f"  Confidence : {args.confidence}")
    print(f"  Input      : {inp}")
    print(f"  Output     : {out}")
    print(f"{'='*55}\n")

    redactor = HotelPIIRedactor(
        mode=args.mode,
        confidence_threshold=args.confidence,
        spacy_model=args.model,
    )

    text = inp.read_text(encoding="utf-8", errors="replace")
    redacted, token_map = redactor.process(text)

    out.write_text(redacted, encoding="utf-8")
    print(f"  Redacted file -> {out}")

    if token_map:
        map_out.write_text(json.dumps(token_map, indent=2), encoding="utf-8")
        print(f"  Token map     -> {map_out}")

    print(f"\n  PII counts:")
    for label, count in sorted(redactor.last_stats.items(), key=lambda x: -x[1]):
        print(f"    {label:<25} {count}")
    print()


if __name__ == "__main__":
    main()
