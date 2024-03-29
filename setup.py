from setuptools import setup

setup(
    name='msksidekick',
    version='1.1.4',
    py_modules=['msksidekick'],
    install_requires=[
        'wheel',
        'altgraph',
        'certifi',
        'chardet',
        'Click',
        'docutils',
        'idna',
        'macholib',
        'psutil',
        'pyinstaller',
        'pyinstaller-hooks-contrib',
        'termcolor',
        'requests',
        'statistics',
        'colorama',
        'setuptools',
        'urllib3'
    ],
    entry_points='''
        [console_scripts]
        msksidekick=msksidekick:cli
    ''',
)
