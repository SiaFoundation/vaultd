---
default: minor
---

# The `state` and `network` fields are now optional for `[POST] /v2/sign` and `[POST] /sign`

When `state` and `network` are not provided, the current state will be polled from SiaScan.
