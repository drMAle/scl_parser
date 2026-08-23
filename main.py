from __future__ import annotations

import argparse
import tkinter as tk
from pathlib import Path

from gui import SCLAnalyzerApp


def main():
    parser = argparse.ArgumentParser(description="IEC 61850 SCL / PCAP Analyzer")
    parser.add_argument("file", nargs="?", help="SCL/CID/ICD/SCD or PCAP/PCAPNG file to open")
    parser.add_argument("--pcap", action="store_true", help="Treat the positional file as PCAP/PCAPNG")
    args = parser.parse_args()

    root = tk.Tk()
    app = SCLAnalyzerApp(root)
    if args.file:
        path = Path(args.file)
        if args.pcap:
            app.open_path(path, "pcap")
        else:
            suffix = path.suffix.lower()
            app.open_path(path, "pcap" if suffix in (".pcap", ".pcapng") else "scl")
    root.mainloop()


if __name__ == "__main__":
    main()
