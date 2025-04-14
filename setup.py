#!/usr/bin/env python
import platform
import shutil
import os.path
from distutils.command.build_ext import build_ext
from setuptools import setup, Extension, find_packages


class build_ext(build_ext):
    def run(self):
        pass

    def output_dir(self):
        if not self.inplace:
            return os.path.join(self.get_finalized_command('build').build_platlib, 'har2mp4')

        build_py = self.get_finalized_command('build_py')
        package_dir = os.path.abspath(build_py.get_package_dir('har2mp4'))
        return package_dir

content = ""
try:
    descriptor = open("readme.md", "r")
    content = descriptor.read()
    descriptor.close()
except:
    content = ""
requirements = []
requirements.append("bounded_pool_executor")
requirements.append("mpegdash")
setup(name="har2mp4",
      version="1.0",
      maintainer="Pierce L. Brooks",
      maintainer_email="piercebrks@gmail.com",
      author="Pierce L. Brooks",
      author_email="piercebrks@gmail.com",
      url="https://github.com/PierceLBrooks/har2mp4",
      description="har2mp4: Convert .har files with cached media inside to .mp4 containers",
      long_description=content,
      long_description_content_type="text/markdown",
      classifiers=["Environment :: Console",
                   "License :: OSI Approved :: MIT License",
                   "Intended Audience :: Developers",
                   "Topic :: Software Development"],
      license="MIT",
      entry_points={
          'console_scripts': [
              'har2mp4 = har2mp4.command_line:main',
              ]},
      packages=find_packages(),
      install_requires=requirements,
      zip_safe=True,
      cmdclass={'build_ext': build_ext})
