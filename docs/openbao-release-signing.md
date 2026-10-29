# Configure application release signing

The tagged application release workflow signs the package's canonical manifest
using ordinary Ed25519 in OpenBao Transit. The manifest binds the executable and
all declared resources. A separate job verifies the completed `.xpk` with an
independently pinned public key before publication. Pull request packages stay
unsigned and do not access NetBird or OpenBao. This does not provision an
installer trust root or enable signature enforcement in Xila.

## Prerequisites

- OpenBao is reachable as `https://vault.xila.dev` from a NetBird peer, with a
  TLS certificate trusted by GitHub-hosted Ubuntu runners. OpenBao must reach
  GitHub's OIDC discovery/JWKS endpoint.
- NetBird is reachable at `https://netbird.anneraud.fr`. Create a **reusable,
  ephemeral-peer** setup key for the CI group (six packages may be signed in
  sequence). Restrict that group's NetBird policy to the OpenBao service and
  arrange internal DNS for `vault.xila.dev`. Give the key an appropriate
  expiry and usage limit; rotate it as needed.
- Protect the Applications `main` branch, release workflow, and `v*` tags.
  Signing checks that the tagged commit is an ancestor of main. The OIDC role
  also binds the caller workflow, tag, event and pinned reusable workflow.
- Run the following from an administrator shell authenticated to OpenBao, with
  `bao`, `jq` and `gh` installed. Do not put private keys or tokens in Git.

## OpenBao

If `transit/` or `jwt/` already exist, do not enable them a second time. In
particular, the JWT configuration affects **every role on that auth mount**;
use a separate mount if it already serves another issuer, and update the
workflow and policy to match.

```sh
export BAO_ADDR=https://vault.xila.dev
bao secrets enable -path=transit transit
bao write transit/keys/xila-applications type=ed25519
bao auth enable -path=jwt jwt
bao write auth/jwt/config \
  oidc_discovery_url=https://token.actions.githubusercontent.com \
  bound_issuer=https://token.actions.githubusercontent.com

bao policy write xila-app-sign - <<'POLICY'
path "transit/sign/xila-applications" {
  capabilities = ["update"]
}
POLICY
```

Set `SIGNING_SHA` to the **exact 40-character commit** of the package-manager
workflow used by the Applications release PR. This value also appears in the
`uses:` and `builder-ref:` fields of that PR. After the PRs are created it can
be obtained using `gh pr view <package-manager-pr-number> --repo
xila-project/package_manager --json headRefOid --jq .headRefOid`.

```sh
SIGNING_SHA='<package-manager-workflow-commit>'
export SIGNING_SHA
jq -n --arg sha "$SIGNING_SHA" '{
  role_type: "jwt",
  user_claim: "repository",
  bound_audiences: ["https://vault.xila.dev"],
  bound_claims_type: "glob",
  bound_claims: {
    repository: "xila-project/applications",
    event_name: "push",
    ref_type: "tag",
    ref: "refs/tags/v*",
    sub: "repo:xila-project/applications:ref:refs/tags/v*",
    workflow_ref: "xila-project/applications/.github/workflows/release.yml@refs/tags/v*",
    job_workflow_ref: ("xila-project/package_manager/.github/workflows/package-wasm.yml@" + $sha)
  },
  token_policies: ["xila-app-sign"],
  token_no_default_policy: true,
  token_ttl: "10m",
  token_max_ttl: "15m"
}' > /tmp/xila-openbao-role.json
bao write auth/jwt/role/xila-app-release @/tmp/xila-openbao-role.json
rm /tmp/xila-openbao-role.json
```

The role grants no key read, export, key creation or policy administration. The
workflow requests version 1 explicitly, and must be updated together with the
pinned public key when the Transit key is rotated. The public key is **not**
secret, but authenticate and preserve it independently of OpenBao: it is the
trust anchor used to check what OpenBao signed.

## GitHub settings

```sh
# Enter the NetBird setup key without echoing it; do not paste it in chat.
read -r -s -p 'NetBird setup key: ' xila_netbird_setup_key; echo
printf '%s' "$xila_netbird_setup_key" | gh secret set NETBIRD_SETUP_KEY --repo xila-project/applications
unset xila_netbird_setup_key

# Public, non-secret values. Confirm the pinned SHA matches the PR's release workflow.
gh variable set XILA_SIGNING_BUILDER_SHA --repo xila-project/applications --body "$SIGNING_SHA"
gh variable set XILA_OPENBAO_KEY_VERSION --repo xila-project/applications --body 1
bao read -format=json transit/keys/xila-applications \
  | jq -er '.data.keys["1"].public_key' \
  | gh variable set XILA_SIGNING_PUBLIC_KEY_B64 --repo xila-project/applications
```

Configure a separate copy of that 32-byte public key as the verifier's trusted
key through its trust policy. Merely publishing signed files does not make the
current runtime reject untrusted packages. If you change the pinned reusable
workflow commit, update the OpenBao role's `job_workflow_ref` binding and the
GitHub builder SHA together. If the key rotates, publish and deploy the new
trusted public key and update the key-version variable in a coordinated change.
