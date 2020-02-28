# Coredump Uploader

This utility can upload core dumps to Sentry.  It can either upload a single core dump or watch a folder
for incoming core dumps to automatically upload them as they happen.

## Requirements

- python
- poetry
- gdb
- elfutils

## Usage

### Upload coredump

````
$ export SENTRY_DSN=https://something@your-sentry-dsn/42
$ upload_coredump /path/to/core upload /path/to/executable
````

OR

````
$ upload_coredump --sentry-dsn https://something@your-sentry-dsn/42 /path/to/executable upload /path/to/core 
````

### Watch for coredumps

````
$ upload_coredump --sentry-dsn https://something@your-sentry-dsn/42 /path/to/executable watch /path/to/dir 
````

## Development

We use Poetry for development. To get started, first install dependencies: 

```
poetry install
```

To run tests, use:

```
poetry run pytest tests/
```

To run the application:

```
poetry run upload_coredump ...
```
