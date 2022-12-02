from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt', 'r') as fh:
    requirements = fh.readlines()

s = setup(
    name="cccs_yara_validator",
    version="1.0.0",
    description="A utility for YARA rule metadata validation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=requirements,
    entry_points="""
    [console_scripts]
    yara_validator=yara_validator.cli:main
    """,
    package_data={'yara_validator': ['validator_cfg.yml']},
    include_package_data=True,
)