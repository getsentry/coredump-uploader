Coredump Uploader
=========

Requirements:
-------

GDB

elfutils


Usage:
--------

````
$ export SENTRY_DSN=https://something@your-sentry-dsn/42
$ python upload-coredump.py /path/to/core /path/to/executable
````

OR

````
$ python upload-coredump.py /path/to/core /path/to/executable https://something@your-sentry-dsn/42
````