# Mobile-first five-minute quickstart

This quickstart starts a local Latchway gateway and prepares the control plane
for a React Native, iOS, or Android application. It proves the local software
path with debug attestation. Production App Attest and Play Integrity require
the separately documented physical-device release gates.

## 1. Start the gateway

From the core repository:

```bash
cp .env.example .env
printf 'LATCHWAY_MASTER_KEY=%s\n' "$(openssl rand -base64 32)" >> .env
docker compose up -d --build
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

Generate the master key once. Keep it with the database backup; changing or
losing it makes stored provider credentials and signing keys unusable. The
example bootstrap token is for local development only.

Open `http://127.0.0.1:8080` and consume the bootstrap token from `.env` to
create the first owner. Latchway permanently closes the bootstrap endpoint
after the first owner exists.

## 2. Complete the setup wizard

The embedded wizard writes only through the canonical Admin API. Complete its
steps in order:

1. Create the organization, application, and environment.
2. Select the application's existing identity provider.
3. Select `debug` attestation for this local run.
4. create a write-only upstream secret.
5. Configure the upstream, physical model, pricing, feature, route, and limit
   plan.
6. Validate, plan, and activate the immutable configuration revision.
7. Run the local self-test and copy the generated SDK values.

Use the generated `app_...` application resource ID in every SDK. A display
name, bundle ID, or Android package name is not interchangeable with it.

For an automated isolated proof instead of a persistent local environment:

```bash
export LATCHWAY_DATABASE_URL='postgres://...'
latchway verify local --timeout 2m --junit /tmp/latchway-local.xml
```

The verifier creates and destroys a temporary PostgreSQL schema and exercises
identity, DPoP, sessions, authenticated Chat streaming, trusted accounting,
quotas, fallback, recovery, header filtering, SSRF protection, activation, and
rollback. Repository protocol suites separately cover Responses, Embeddings,
Anthropic Messages, and restricted opaque HTTP.

## 3. Connect React Native first

React Native uses the JavaScript fetch-shaped API while delegating installation
keys, session state, DPoP signing, and attestation to the native iOS and Android
SDKs.

```typescript
import { createLatchwayClient } from "@latchway/react-native";

const latchway = createLatchwayClient({
  baseURL: "http://127.0.0.1:8080",
  applicationID: "app_...",
  environment: "development",
  getIdentityToken: async () => applicationIdentity.currentToken(),
  android: {
    playIntegrityCloudProjectNumber: applicationConfiguration.googleCloudProjectNumber,
  },
});

const response = await latchway.fetch("/v1/responses", {
  method: "POST",
  latchwayFeature: "assistant",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    model: "client-placeholder",
    input: "Hello from React Native",
    max_output_tokens: 64,
  }),
});
```

The server replaces the model and injects the provider credential. The app
must never contain that credential. Loopback HTTP is a development-only SDK
option; production clients require the exact configured HTTPS origin.

The React Native package supports the New Architecture baseline documented in
the SDK repository. Its native installation guide covers CocoaPods, Gradle,
entitlements, Play configuration, and local source overrides.

## 4. Connect native iOS or Android

Native iOS links `Latchway` plus `LatchwayAppAttest`, constructs a
`LatchwayClient`, authorizes a `URLRequest`, and streams it through the SDK's
hardened `URLSession`. Native Android aligns modules with the Latchway BOM,
constructs `LatchwayClient`, and installs its interceptor, origin guard, and
authenticator into OkHttp.

Use the complete, version-matched examples in:

- `latchway-ios-sdk/README.md`
- `latchway-android/README.md`
- `latchway-react-native-sdk/README.md`

Debug attestation is sufficient only for this local exercise. Before enabling
a production environment, switch to App Attest or Play Integrity, pin the
bundle/package and signing identifiers in the server configuration, and pass
the physical-device conformance workflow.

## 5. Confirm enforcement

From the console or CLI, verify:

```bash
latchway users list --environment env_...
latchway installations list --environment env_...
latchway requests list --environment env_...
latchway usage summary --environment env_...
latchway routes simulate rev_... --feature assistant \
  --platform react_native_ios --trust-level debug --claims-file claims.json
```

The request view should show the selected route, upstream, physical model,
attempt order, timing, usage provenance, and cost provenance without prompt
bodies, identity subjects, proofs, or credentials.

## Production checkpoint

Local success does not establish a v1 release. Production requires the exact
candidate image and SDK commits to pass live provider, live SDK, physical
device, cloud deployment, multi-replica/failure, backup/restore/upgrade, scan,
SBOM, signature, provenance, tag, registry, and post-publication gates. See
`docs/implementation/COMPLETION_REPORT.md` for the current evidence ledger.
