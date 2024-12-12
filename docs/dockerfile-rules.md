# Dockerfile Analysis Rules

This document provides detailed descriptions of the default rules used for analyzing Dockerfiles to identify potential security issues and best practice violations. Each rule includes a description, rationale, regular expression used for matching, severity level, and reference for further reading.

## Rules Overview

### Core Rule List

core.yaml contains a set of regex-based rules designed to detect sensitive information in the dockerfile, mainly based to [Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/).

1. **Missing USER Statement**
    - **ID**: `core-001`
    - **Description**: It is recommended to use a non-root user in Dockerfiles to enhance security.
    - **Rationale**: By default, Docker containers run as the root user, which can pose security risks if the container is compromised. Running as a non-root user minimizes the potential damage an attacker can do if they gain access to the container.
    - **Regex**: `^(USER[\s]+[\w\d_]+)`
    - **Severity**: Medium
    - **Reference**: [Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/)

2. **Plain Text Password Detected**
    - **ID**: `core-002`
    - **Description**: Detects potential plaintext passwords or secrets in Dockerfiles.
    - **Rationale**: Storing passwords or secrets in plaintext within Dockerfiles can lead to security breaches if unauthorized users gain access to the files. It's crucial to use environment variables or secret management tools to handle sensitive information securely.
    - **Regex**: `(password|secret)`
    - **Severity**: High
    - **Reference**: [Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/)

3. **Recursive Copy Detected**
    - **ID**: `core-003`
    - **Description**: Identifies recursive copy operations that might include unintended files.
    - **Rationale**: Using `COPY . .` can unintentionally include files that are not meant to be part of the image, such as build artifacts, configuration files, or sensitive data. It's better to specify exactly what you need to copy.
    - **Regex**: `(COPY[\s]+\.[\s]+\.)`
    - **Severity**: Medium
    - **Reference**: [Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/)

4. **Use of ADD Instead of COPY**
    - **ID**: `core-004`
    - **Description**: Encourages the use of `COPY` over `ADD` for clarity and security.
    - **Rationale**: The `ADD` instruction has more functionality than `COPY`, such as extracting tar files, which can lead to unintended behaviors. `COPY` is preferred as it is more explicit and predictable.
    - **Regex**: `(ADD.)`
    - **Severity**: Low
    - **Reference**: [Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/)

5. **Use Image Tag Instead of SHA256**
    - **ID**: `core-005`
    - **Description**: Recommends using image tags for better readability and management.
    - **Rationale**: While SHA256 hashes ensure exact image versions, using a SHA256 reference can be risky, if the image changes that hash might not exist anymore.
    - **Regex**: `^(?!(FROM[\s]+[\w\d_]+@sha256:[\d\w]{64}))`
    - **Severity**: Medium
    - **Reference**: [Container Deployments](https://medium.com/@tariq.m.islam/container-deployments-a-lesson-in-deterministic-ops-a4a467b14a03)

6. **Avoid Using Latest Tag**
    - **ID**: `core-006`
    - **Description**: Advises against using the `latest` tag due to unpredictability.
    - **Rationale**: The `latest` tag can change over time, leading to inconsistencies in builds and deployments. Specifying a version tag ensures that the same image version is used consistently.
    - **Regex**: `^(FROM[\s]+[\w\W]+:latest)`
    - **Severity**: Medium
    - **Reference**: [Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/)

7. **Deprecated MAINTAINER Statement**
    - **ID**: `core-007`
    - **Description**: The `MAINTAINER` instruction is deprecated; use labels instead.
    - **Rationale**: The `MAINTAINER` instruction has been deprecated in favor of using `LABEL` for metadata, which provides more flexibility and is part of the OCI specification.
    - **Regex**: `^(MAINTAINER[\s]+[\w\d_\s]+)`
    - **Severity**: Low
    - **Reference**: [Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/)

8. **Insecure Option in RUN Statement**
    - **ID**: `core-008`
    - **Description**: Flags the use of `--insecurity=insecure` in `RUN` commands.
    - **Rationale**: Using insecure options in Dockerfiles can expose the container to vulnerabilities. It's important to ensure that all commands and options used are secure and follow best practices.
    - **Regex**: `(RUN[\s]+.*[\s]+--insecurity=insecure)`
    - **Reference**: [Dockerfile RUN Command](https://docs.docker.com/reference/dockerfile/#run---security)

9. **Avoid Using ARG for Secrets**
    - **ID**: `core-009`
    - **Description**: Discourages using `ARG` for passing sensitive information.
    - **Rationale**: Build arguments (`ARG`) are not safe for passing secrets as they can be exposed in the image history. Instead, use environment variables (`ENV`) or secret management solutions to handle sensitive data securely.
    - **Regex**: `(ARG[\s]+(password|token|secret|key|aws_secret|aws_key|pass|aws_access_key_id|aws_secret_access_key|aws_session_token))`
    - **Severity**: High
    - **Reference**: [Dockerfile ARG Instruction](https://docs.docker.com/reference/dockerfile/#arg)

10. **Sensitive Information in HEALTHCHECK**
    - **ID**: `core-010`
    - **Description**: Detects sensitive information in `HEALTHCHECK` commands.
    - **Rationale**: Including sensitive information in health checks can expose secrets if the Dockerfile or logs are accessed by unauthorized users. It's important to sanitize any commands used in `HEALTHCHECK` to avoid leaking secrets.
    - **Regex**: `(HEALTHCHECK[\s]+.*[\s]+(password|bearer|Bearer|token|key|secret|apitoken|Authentication|Basic|Token))`
    - **Severity**: High
    - **Reference**: [Dockerfile HEALTHCHECK Instruction](https://docs.docker.com/reference/dockerfile/#healthcheck)

11. **Multi-stage Builds**
    - **ID**: `core-011`
    - **Description**: Ensure multi-stage builds are used to minimize image size and avoid sensitive data.
    - **Rationale**: By leveraging Docker support for multi-stage builds, fetch and manage secrets in an intermediate image layer that is later disposed of so that no sensitive data reaches the image build.
    - **Regex**: `(FROM[\s]+[\w\W]+AS[\s]+[\w\W]+)`
    - **Severity**: Low
    - **Reference**: [Docker Image Security Best Practices](https://snyk.io/blog/10-docker-image-security-best-practices/)

12. **Ensure WORKDIR is Set**
    - **ID**: `core-012`
    - **Description**: Ensure WORKDIR is set before RUN instructions.
    - **Rationale**: Setting WORKDIR before executing RUN instructions ensures that all commands are executed in the intended directory context, reducing errors and improving the clarity and maintainability of the Dockerfile.
    - **Regex**: `(RUN[\s]+.*?WORKDIR[\s]+)`
    - **Severity**: Low
    - **Reference**: [Dockerfile WORKDIR Instruction](https://docs.docker.com/engine/reference/builder/#workdir)

### Credential Rule List

credentials.yaml contains a set of regex-based rules designed to detect sensitive information within codebases. Each rule is crafted to identify specific patterns that are commonly associated with credentials or keys, such as AWS access keys, Google API keys, and Slack webhooks.

1. **Generic Credential**
   - **Description**: Detects common credential-related keywords such as `dbpasswd`, `password`, `apikey`, etc.
   - **Regex**: `(dbpasswd|dbuser|dbname|dbhost|api_key|apikey|secret|key|password|guid|hostname|pw|auth)(.{0,20})`
   - **Rationale**: This rule aims to identify common keywords that may contain sensitive information, helping to prevent credential leaks. Such information, if exposed, could lead to unauthorized access.
   - **Recommendation**: Use environment variables or secret management tools (e.g., HashiCorp Vault, AWS Secrets Manager) to store and manage sensitive information.
   - **Severity**: Medium

2. **AWS Manager ID**
   - **Description**: Detects potential AWS Access Key IDs.
   - **Regex**: `((A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`
   - **Rationale**: AWS Access Key IDs, if leaked, could lead to unauthorized access to AWS accounts, posing a significant security risk.
   - **Recommendation**: Use IAM roles instead of long-term keys and rotate keys regularly. Ensure keys are stored securely.
   - **Severity**: High

3. **AWS MWS Key**
   - **Description**: Detects potential AWS Marketplace Web Service (MWS) keys.
   - **Regex**: `(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`
   - **Rationale**: MWS keys are used to access AWS Marketplace APIs, and their exposure could lead to unauthorized access to sensitive marketplace data.
   - **Recommendation**: Ensure MWS keys are used only in secure environments and stored using encryption.
   - **Severity**: High

4. **EC Private Key**
   - **Description**: Detects the beginning of an EC private key.
   - **Regex**: `(-----BEGIN EC PRIVATE KEY-----)`
   - **Rationale**: Private keys are central to encryption operations, and their exposure could compromise encrypted data and authentication mechanisms.
   - **Recommendation**: Use secure storage solutions (like hardware security modules or encrypted storage systems) to manage private keys.
   - **Severity**: High

5. **Google API Key**
   - **Description**: Detects potential Google API keys.
   - **Regex**: `(AIza[0-9A-Za-z\\-_]{35})`
   - **Rationale**: Google API keys are used to access Google services and APIs. Exposure could lead to quota overages or service abuse.
   - **Recommendation**: Use Google Cloud Platform's API key management features to restrict the scope and permissions of keys.
   - **Severity**: High

6. **Slack Webhook**
   - **Description**: Detects potential Slack webhook URLs.
   - **Regex**: `(https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})`
   - **Rationale**: Leaked webhook URLs could allow unauthorized messages to be sent to Slack channels, potentially leading to information leaks or abuse.
   - **Recommendation**: Regularly rotate webhook URLs and use Slack's IP whitelisting feature to restrict access.
   - **Severity**: High