#!/usr/bin/env python

from setuptools import setup

with open("requirements.txt") as f:
    requirements = f.readlines()


setup(
    name="rain-api-core",
    author="Alaska Satellite Facility",
    url="https://github.com/asfadmin/rain-api-core",
    packages=["rain_api_core"],
    install_requires=requirements
)
