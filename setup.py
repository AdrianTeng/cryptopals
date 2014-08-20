from distutils.core import setup
from pip.req import parse_requirements


install_reqs = parse_requirements("requirements.txt")
reqs = [str(ir.req) for ir in install_reqs]


setup(
    name='Cryptopals',
    version='1.0',
    packages=['ateng', 'tests'],
    url='http://github.com/AdrianTeng/Cryptopals',
    license='',
    author='ateng',
    author_email='adrian@teng.io',
    description='Cryptopals solution in Python',
    install_requires=reqs
)
