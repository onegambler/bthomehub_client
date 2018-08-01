from setuptools import setup

setup(name='bthomehub',
      packages=["bthomehub"],
      version='2.0.1',
      description='A Python client that can interact with BT Home Hub routers.',
      url='https://github.com/onegambler/bthomehub_client',
      download_url='https://github.com/onegambler/bthomehub_client/archive/1.0.tar.gz',
      author='oneGambler',
      author_email='',
      license='UNLICENSE',
      install_requires=[
          'requests==2.18.3'
      ],
      keywords=['bt home hub', 'devices list'],
      zip_safe=False)
