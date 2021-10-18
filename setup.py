import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="Security Hub Controls CLI",
    version="1.0.1",
    author="Michael Füllbier",
    author_email="fuellbie@amazon.com",
    description="A CLI tool to disable and enable security standards controls in AWS Security Hub.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "boto3",
        "pyyaml",
        "natsort==3.3.0"
    ],
    python_requires='>=3.8',
    entry_points={
        "console_scripts": ["shc_cli=src.main:main"]
    }
)
