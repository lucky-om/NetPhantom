"""
setup.py - NetPhantom Package Configuration
Enables 'netphantom' CLI command after: pip install -e .
"""

from setuptools import setup, find_packages

setup(
    name="netphantom",
    version="3.3.1",
    description="NetPhantom — Professional Network Packet Sniffer & Analyzer",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Luckyverse",
    url="https://github.com/lucky-om/NetPhantom",
    license="Apache-2.0",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "scapy>=2.5.0",
        "colorama>=0.4.6",
        "psutil>=5.9.0",
        "pywifi>=1.1.12",
        "Pillow>=9.5.0",
    ],
    entry_points={
        "console_scripts": [
            "netphantom=netphantom.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: Apache Software License",
    ],
)
