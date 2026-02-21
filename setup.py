from setuptools import setup, find_packages
from pathlib import Path

long_desc = (Path(__file__).parent / "README.md").read_text(encoding="utf-8") \
    if (Path(__file__).parent / "README.md").exists() else ""

setup(
    name="nexsus",
    version="2.3.0",
    description="Advanced Bug Hunting Framework for Modern Web Applications",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    author="ElDoree4",
    license="Proprietary - Authorized Use Only",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*"]),
    package_data={
        "nexsus": [
            "payloads/*.txt",
            "wordlists/*.txt",
            "reporting/templates/*.html",
            "reporting/templates/*.md",
        ],
    },
    install_requires=[
        "aiohttp>=3.9.5",
        "aiohttp-socks>=0.8.4",
        "dnspython>=2.6.0",
        "beautifulsoup4>=4.12.3",
        "lxml>=5.2.0",
        "orjson>=3.10.0",
        "pyyaml>=6.0.1",
        "pyjwt>=2.8.0",
        "cryptography>=42.0.0",
        "jinja2>=3.1.4",
        "rich>=13.7.0",
        "colorama>=0.4.6",
        "click>=8.1.7",
        "prompt_toolkit>=3.0.43",
    ],
    extras_require={
        "browser": [
            "selenium>=4.21.0",
            "webdriver-manager>=4.0.2",
            "playwright>=1.44.0",
        ],
        "screenshots": ["Pillow>=10.3.0"],
        "dev": [
            "pytest>=8.2.0",
            "pytest-asyncio>=0.23.7",
            "pytest-cov>=5.0.0",
        ],
        "full": [
            "selenium>=4.21.0",
            "webdriver-manager>=4.0.2",
            "playwright>=1.44.0",
            "Pillow>=10.3.0",
            "paramiko>=3.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "nexsus=nexsus.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
