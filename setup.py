"""
setup.py - NetPhantom Package Configuration
Enables 'netphantom' CLI command after: pip install -e .
"""

from setuptools import setup

setup(
    name="netphantom",
    version="3.0.0",
    description="NetPhantom — Professional Network Packet Sniffer & Analyzer",
    author="Luckyverse",
    license="Apache-2.0",
    py_modules=["main", "gui", "capture", "analyzer"],
    python_requires=">=3.10",
    install_requires=[
        "scapy>=2.5.0",
        "colorama>=0.4.6",
        "psutil>=5.9.0",
    ],
    entry_points={
        "console_scripts": [
            "netphantom=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: Apache Software License",
    ],
)
