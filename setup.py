from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt', 'r') as fh:
    requirements = fh.readlines()

s = setup(
    name="cccs-yara",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    description="A CCCS utility for YARA rule metadata validation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=requirements,
    entry_points="""
    [console_scripts]
    yara_validator=yara_validator.cli:main
    """,
    package_data={'yara_validator': ['*.yml']},
    include_package_data=True,
)
