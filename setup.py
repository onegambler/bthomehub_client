from setuptools import setup

setup(name='bthomehub_client',
      version='0.1',
      description='A Python client that can interact with BT Home Hub routers.',
      url='https://github.com/onegambler/bthomehub_client',
      author='oneGambler',
      author_email='',
      license='MIT',
      packages=['bthomehub'],
      install_requires=[
          'requests'
      ],
      zip_safe=False)
