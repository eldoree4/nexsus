from setuptools import setup, find_packages

setup(
    name="nexsus",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'aiohttp>=3.9.0',
        'colorama>=0.4.6',
        'pyjwt>=2.8.0'
    ],
    entry_points={
        'console_scripts': [
            'nexsus = nexsus.cli:main'
        ]
    },
    author="Bug Bounty Elite",
    description="Advanced Bug Hunting Framework",
    license="Proprietary - Authorized Use Only"
)
