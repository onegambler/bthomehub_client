from setuptools import setup

setup(name='bthomehub',
      packages=["bthomehub"],
      version='1.0',
      description='A Python client that can interact with BT Home Hub routers.',
      url='https://github.com/onegambler/bthomehub_client',
      download_url='https://github.com/onegambler/bthomehub_client/archive/1.0.tar.gz',
      author='oneGambler',
      author_email='onegambler@outlook.com',
      license='MIT',
      install_requires=[
          'requests'
      ],
      keywords=['bt home hub', 'devices list'],
      zip_safe=False)
