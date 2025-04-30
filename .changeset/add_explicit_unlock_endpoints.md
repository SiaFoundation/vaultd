---
default: major
---

# Add explicit unlock endpoints

Adds explicit `[POST] /unlock` and `[PUT] /lock` endpoints to remove the need for storing secrets in the config file. The secret can still be loaded at runtime in the environment variable or config file to unlock the vault at startup.

The first call to `[POST] /unlock` will set the secret and initialize the vault.