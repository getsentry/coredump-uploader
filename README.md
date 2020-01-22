# Coredump Uploader

## Requirements

- python
- poetry
- gdb
- elfutils

## Usage

````
$ export SENTRY_DSN=https://something@your-sentry-dsn/42
$ upload_coredump /path/to/core /path/to/executable
````

OR

````
$ upload_coredump /path/to/core /path/to/executable --sentry-dsn https://something@your-sentry-dsn/42
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
