import os

from setuptools import setup


def read(*paths):
    """Build a file path from paths and return the contents"""
    with open(os.path.join(*paths), 'r') as f:
        return f.read()

setup(
    name='rocket_league_api',
    version='0.0.1',
    description="Documents how the Rocket League client communicates with Psyonix's servers",
    long_description=read('.', 'README.md'),
    url='https://github.com/e00E/Rocket-League-Api',
    packages=['rocket_league_api'],
    license='',
    author='',
    author_email='',
    include_package_data=True,
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3'
    ]
)
