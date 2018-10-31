"""setup.py for microkubes python library.
"""
import setuptools


with open('README.md', 'r') as readmef:
    long_description = readmef.read()


with open('requirements.txt') as reqf:
    required_dependencies = [req.strip() for req in reqf.readlines()]

setuptools.setup(
    name="microkubes-python",
    version="0.0.1",
    author="Pavle Jonoski",
    author_email="jonoski.pavle@gmail.com",
    description="Microkubes Python Library - tools for building microservices on top of Microkubes platform.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Microkubes/microkubes-python",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries",
        "Topic :: Utilities",
        "Framework :: Microkubes",
    ),
    install_requires=required_dependencies,
)
