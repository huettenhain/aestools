from setuptools import setup


with open('README.txt') as f:
    long_description = f.read()


setup_args = dict(
    name="aestools",
    version='0.0.0',
    description='AES GCM weak key checker',
    long_description=long_description,
    author="Jesko Hüttenhain",
    author_email="rattle@nullteilerfrei.de",
    url="https://github.com/lichtkegel/WeakAESGCM",
    license="PSF License",
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
    py_modules=['aestools'],
    install_requires=['pycrypto', ],
)


if __name__ == '__main__':
    setup(**setup_args)

