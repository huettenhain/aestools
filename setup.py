# coding=utf8

from setuptools import setup, find_packages

with open('README.txt') as f:
    long_description = f.read()


setup_args = dict(
    name="aestools",
    version='0.1.1',
    description='AES tools (GCM weak key checker / safe key generator)',
    long_description=long_description,
    author="Jesko Hüttenhain",
    author_email="rattle@nullteilerfrei.de",
    url="https://github.com/lichtkegel/aestools",
    license="PSF License",
    keywords="crypto aes gcm weak key checker safe key generator",
    platforms="any",
    classifiers="""\
Development Status :: 3 - Alpha
Environment :: Console
Intended Audience :: Developers
Intended Audience :: Science/Research
License :: OSI Approved :: Python Software Foundation License
Operating System :: OS Independent
Programming Language :: Python
Programming Language :: Python :: 2
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3
Programming Language :: Python :: 3.4
Programming Language :: Python :: 3.5
Topic :: Security :: Cryptography""".splitlines(),
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=['pycrypto', ],
    entry_points={
        'console_scripts': [
            'aestools = aestools.cli:main',
        ]
    },
)


if __name__ == '__main__':
    setup(**setup_args)
