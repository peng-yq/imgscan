# imagescan

`imagescan` is a tool designed to scan Docker images and Dockerfiles to analyze sensitive information and potential security risks.

## How to Use

```shell
# Clone this project
git clone https://github.com/peng-yq/imgscan

# Compile the project
make all
```

The `imagescan` CLI provides two subcommands:

- **`dockerfile`**: Use this subcommand to analyze your Dockerfile for sensitive information. For more details, refer to the [Dockerfile command manual](docs/dockerfile.md).
- **`image`**: Use this subcommand to analyze Docker images on your computer for sensitive information. For more details, refer to the [Image command manual](docs/image.md).

## References

- [dockerfile-security](https://github.com/cr0hn/dockerfile-security)
- [dockerscan](https://github.com/cr0hn/dockerscan)

## License

This project is licensed under the [MIT License](LICENSE).