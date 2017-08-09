from setuptools import setup

setup(name='bthomehub_client',
      version='0.1',
      description='Accessing BT Home Hub data',
      url='https://github.com/onegambler/bthomehub_client',
      author='oneGambler',
      author_email='',
      license='MIT',
      packages=['bthomehub'],
      install_requires=[
          'hashlib',
          'random',
          'threading',
          'urllib',
          'requests'
      ],
      zip_safe=False)