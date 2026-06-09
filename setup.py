from pathlib import Path
from setuptools import setup, find_packages

# Single source of truth: requirements.txt drives both pip install and setup.py
_reqs = [
    line.strip()
    for line in Path("requirements.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="apkanalyzer",
    version="1.0.0",
    description="Advanced static analysis engine for Android APKs",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=_reqs,
    entry_points={
        "console_scripts": [
            "apkanalyzer=main:cli",
        ],
    },
)
