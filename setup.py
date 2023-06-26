from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.readlines()

setup(
    name='devav',
    version='0.1',
    packages=find_packages(),
    author='Sergio Benlloch @sg1o',
    description='',
    install_requires=requirements,
    entry_points=dict(console_scripts=[
        'devav = devav.__init__:main'
    ])
)
