# greymatter-cue
Grey Matter schema objects in CUE.

## Prerequisites

- [CUE](https://cuelang.org/docs/install/)
- [fetch](https://github.com/gruntwork-io/fetch)

## Updating greymatter.io Filter Schemas

Set your github auth token:
```bash
export GITHUB_OAUTH_TOKEN=$your_oauth_token
```

> Note: this token requires read access to the gm-proxy repo.

Fetch the latest filter definitions:
```bash
./scripts/update
```

Update the filter CUE definitions:
```bash
./scripts/build
```