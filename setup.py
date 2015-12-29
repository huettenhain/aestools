from setuptools import setup


with open('README.txt') as f:
    long_description = f.read()


setup_args = dict(
    name="weakkey",
    version='0.0.0',
    description='AES GCM weak key checker',
    long_description=long_description,
    author="tbd",
    author_email="tbd",
    url="tbd",
    license="PSF license",
    keywords="aes gcm weak key check crypto",
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
Topic :: Security :: Cryptography""".splitlines(),
    py_modules=['weakkey'],
    install_requires=['pycrypto', ],
)


if __name__ == '__main__':
    setup(**setup_args)

