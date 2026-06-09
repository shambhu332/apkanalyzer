from setuptools import setup, find_packages

setup(
    name="apkanalyzer",
    version="1.0.0",
    description="Advanced static analysis engine for Android APKs",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "androguard>=3.3.5,<5.0",
        "lxml>=4.9.0",
        "pyyaml>=6.0",
        "networkx>=3.0",
        "jinja2>=3.1.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "requests>=2.28.0",
        "packaging>=23.0",
        "python-magic>=0.4.27",
    ],
    entry_points={
        "console_scripts": [
            "apkanalyzer=main:cli",
        ],
    },
)
