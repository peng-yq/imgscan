# Image Command

The `image` command is a subcommand of the `imgscan` tool. And it provides a `analyze` subcommand to retrieve image metadata and checks for potential security issues such as sensitive environment variables, root user usage, and exposed ports.

## Features

- **Sensitive Environment Variables Detection**: Scans environment variables for common sensitive keywords like `PASSWORD`, `SECRET`, `API_KEY`, etc.
- **Root User Check**: Warns if the Docker image is configured to run as the root user.
- **Exposed Ports Listing**: Displays all ports exposed by the Docker image.

## Usage

> `image` command needs root permission.

Run the `analyze` command followed by the Docker image identifier (tag or SHA256):

```bash
imagescan image analyze <image_identifier>
```

### Example

```bash
imagescan image analyze nginx:latest
```

This command will output a table with any detected sensitive information, including environment variables, user configuration, and exposed ports of `nginx:latest`.