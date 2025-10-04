# Secret Management

This document explains how to properly manage secrets for the Threat Intelligence Graph application.

## Security Issue Resolved

The original `k8s/secret.yaml` file contained base64-encoded secrets that were being tracked in git, which is a security risk. This has been fixed by:

1. Replacing the actual secrets with placeholder values
2. Creating a template file (`k8s/secret.yaml.template`)
3. Adding secret files to `.gitignore`

## Setting Up Secrets

### 1. Create Your Secret File

Copy the template and fill in your actual secrets:

```bash
cp k8s/secret.yaml.template k8s/secret.yaml
```

### 2. Generate Base64 Encoded Values

For each secret, generate the base64 encoded value:

```bash
# Example for Neo4j password
echo -n "your_actual_neo4j_password" | base64

# Example for API key
echo -n "your_actual_api_key" | base64
```

### 3. Update secret.yaml

Replace the placeholder values in `k8s/secret.yaml` with your base64 encoded secrets:

```yaml
data:
  neo4j-password: <your_base64_encoded_password>
  misp-api-key: <your_base64_encoded_misp_key>
  otx-api-key: <your_base64_encoded_otx_key>
  virustotal-api-key: <your_base64_encoded_virustotal_key>
  secret-key: <your_base64_encoded_secret_key>
```

## Important Security Notes

- **Never commit `k8s/secret.yaml`** - it's in `.gitignore`
- **Use strong, unique passwords** for production
- **Rotate secrets regularly**
- **Use a proper secret management system** (like HashiCorp Vault) for production
- **The template file is safe to commit** - it contains no real secrets

## Environment Variables

For local development, you can also use environment variables instead of Kubernetes secrets. See `env.example` for the required variables.

## Deployment

The deployment script will check for the existence of `k8s/secret.yaml` and provide helpful instructions if it's missing.
