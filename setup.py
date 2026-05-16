from setuptools import setup, find_packages

setup(
    name='VulnFinder60',
    version='1.0.0',
    author='Zoya',
    description='Automated Reconnaissance and Vulnerability Scanner',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'requests',
        'beautifulsoup4',
        'colorama',
        'jinja2',
        'dnspython'
    ],
    entry_points={
        'console_scripts': [
            'vulnfinder60=vulnfinder:main'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)
