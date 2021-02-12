from setuptools import setup

setup(
    name='mskaiagnt',
    version='1.0',
    py_modules=['mskaiagnt'],
    install_requires=[
        'Click',
		'termcolor',
		'requests',
        'psutil',
        'statistics'
    ],
    entry_points='''
        [console_scripts]
        mskaiagnt=mskaiagnt:cli
    ''',
)
