from setuptools import setup, find_packages
from tmxcaliber import __version__ as tmxcaliber_version

def readme():
    with open('README.md') as f:
        return f.read()

def get_license():
    with open('LICENSE') as f:
        return f.read()

setup(
    name='tmxcaliber',
    version=tmxcaliber_version,
    description=(
        'CLI utility to filter down a TrustOnCloud ThreatModel and '
        'get more refined information.'
    ),
    long_description=readme(),
    long_description_content_type='text/markdown',
    author='TrustOnCloud',
    author_email='dev@trustoncloud.com',
    python_requires='>=3.8',
    install_requires=[],
    packages=find_packages(exclude=[
        "*.tests", "*.tests.*", "tests.*", "tests"
    ]),
    license=get_license(),
    entry_points={'console_scripts': ['tmxcaliber=tmxcaliber.cli:main']}
)
