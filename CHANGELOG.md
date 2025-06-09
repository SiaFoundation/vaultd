## 0.3.5 (2025-06-09)

### Fixes

- Update coreutils from v0.15.2 to v0.16.0.

## 0.3.4 (2025-06-04)

### Fixes

- Fixed [GET] /seeds/:id `lastIndex` field always returning 0.

## 0.3.3 (2025-06-03)

### Features

- Check for proper seed lengths.
- Harden legacy seed generation.

## 0.3.2 (2025-05-29)

### Fixes

- Vault secret is no longer required at startup.
- Update core to v0.13.1 and coreutils to v0.15.2

## 0.3.1 (2025-05-29)

### Features

- Added `[POST] /blind/sign`

#### The `state` and `network` fields are now optional for `[POST] /v2/sign` and `[POST] /sign`

When `state` and `network` are not provided, the current state will be polled from SiaScan.

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
