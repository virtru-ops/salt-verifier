from setuptools import setup, find_packages

VERSION = '0.1.0'

LONG_DESCRIPTION = open('README.rst').read()

setup(
    name='salt-verifier',
    version=VERSION,
    description="salt-verifier - The salt verifier",
    long_description=LONG_DESCRIPTION,
    keywords='',
    author='Reuven V. Gonzales',
    author_email='reuven@virtru.com',
    url="https://github.com/virtru-ops/salt-verifier",
    license='MIT',
    platforms='*nix',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'm2crypto',
        'pyzmq'
    ],
    entry_points={
        'console_scripts': [
            'salt-verifier-server=saltverifier.server:run',
            'salt-verifier-server-upstart-script=saltverifier.upstart:generate_upstart_script',
        ],
    },
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Operating System :: POSIX',
        'Topic :: Software Development :: Build Tools',
    ]
)
