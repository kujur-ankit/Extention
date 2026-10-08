#!/usr/bin/env python3
"""
package_extension.py
─────────────────────────────────────────────────────────────────────────────
Packages the Chrome Extension files into a downloadable zip file:
  forntend/AgentFirewall-Extension.zip
─────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import zipfile

# Windows console encoding safeguard
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

EXTENSION_FILES = [
    "manifest.json",
    "background.js",
    "content.js",
    "firewall-engine.js",
    "popup.html",
    "popup.js",
    "popup.css",
    "README.md"
]

def create_extension_zip():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_zip = os.path.join(base_dir, "forntend", "AgentFirewall-Extension.zip")
    
    print(f"📦 Packaging Chrome Extension into {output_zip}...")
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for fname in EXTENSION_FILES:
            fpath = os.path.join(base_dir, fname)
            if os.path.exists(fpath):
                zipf.write(fpath, arcname=fname)
                print(f"   + Added: {fname}")
            else:
                print(f"   ! Missing: {fname}")
                
    print(f"✅ Extension successfully packaged: {output_zip} ({os.path.getsize(output_zip):,} bytes)")

if __name__ == "__main__":
    create_extension_zip()
