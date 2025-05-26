## 0.3.0 (2025-05-26)

### Breaking Changes

#### Add explicit unlock endpoints

Adds explicit `[POST] /unlock` and `[PUT] /lock` endpoints to remove the need for storing secrets in the config file. The secret can still be loaded at runtime in the environment variable or config file to unlock the vault at startup.

The first call to `[POST] /unlock` will set the secret and initialize the vault.

### Features

- Add [GET] /seeds endpoint to return a list of seed IDs

## 0.2.0 (2025-04-17)

### Breaking Changes

- Add spend policy to seed key response

## 0.1.1 (2025-03-28)

### Fixes

- Fixed HTTP flag in Dockerfile
- Removed RPC port from Dockerfile.
