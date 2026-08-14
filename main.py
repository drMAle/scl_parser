import argparse
import tkinter as tk

from gui import SCLAnalyzerApp


def main():
    parser = argparse.ArgumentParser(description="IEC 61850 SCL Analyzer")
    parser.add_argument("scl_file", nargs="?", help="Optional SCL/CID/SCD/ICD file to analyze on startup")
    args = parser.parse_args()

    root = tk.Tk()
    app = SCLAnalyzerApp(root)

    if args.scl_file:
        root.after(100, lambda: app.analyze_file(args.scl_file))

    root.mainloop()


if __name__ == "__main__":
    main()
