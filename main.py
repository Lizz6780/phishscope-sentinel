import argparse
from pathlib import Path

from detector.pipeline import process_email

DEFAULT_EMAIL_PATH = "emails/sample.eml"
DEFAULT_EMAIL_DIR = "emails/liji_inbox"

def parse_args():
    parser = argparse.ArgumentParser(description="Phishing detection pipeline runner.")
    parser.add_argument(
        "--email-path",
        default=DEFAULT_EMAIL_PATH,
        help="Path to one .eml file for single-email mode.",
    )
    parser.add_argument(
        "--email-dir",
        default=DEFAULT_EMAIL_DIR,
        help="Directory containing .eml files for batch mode.",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Process all .eml files from --email-dir.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.batch:
        email_dir = Path(args.email_dir)
        if not email_dir.exists():
            print(f"[ERROR] Email directory not found: {email_dir}")
            return

        eml_files = sorted(email_dir.glob("*.eml"))
        if not eml_files:
            print(f"[ERROR] No .eml files found in: {email_dir}")
            return

        print(f"[INFO] Processing {len(eml_files)} email(s) from {email_dir}")
        for eml in eml_files:
            path = process_email(str(eml))
            print(f"[OK] {eml} -> {path}")
        return

    path = process_email(args.email_path)
    print(f"[OK] {args.email_path} -> {path}")


if __name__ == "__main__":
    main()
