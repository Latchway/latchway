# Identity and attestation guide

Latchway intentionally separates who the user is from what application
instance is making the request. A session is issued only after both decisions
have passed the active environment policy, and the resulting access token is
bound to the installation's P-256 key with DPoP.

## Identity providers

The application continues using its existing login system and gives the SDK a
fresh identity token through a callback. Latchway verifies the token on the
server and maps it to a pseudonymous internal user.

Supported v1 configurations are:

- Firebase Authentication
- Supabase Auth
- Clerk
- strict generic OIDC/JWT with bounded issuer, audience, algorithm, and claim
  mapping
- a pinned static public key
- HS256 only when explicitly enabled with a server-owned secret

Issuer, audience, algorithm, time, and key selection are fail-closed. JWKS
rotation is cached and refreshed by bounded PostgreSQL-coordinated work so an
unknown key cannot create an unbounded refresh storm. The external subject is
never stored raw; Latchway derives a stable HMAC lookup value within the
organization and environment boundary.

Configure identity in the setup wizard or the Authentication providers editor.
Keep provider service credentials in the deployment secret manager. Never put
an identity provider's administrator credential into a client application.

## Platform attestation choices

| Client | Production verifier | Maximum normalized trust |
| --- | --- | --- |
| Native iOS | Apple App Attest | `app_verified` or policy-approved hardware level |
| Native Android | Google Play Integrity | verdict-derived hardware/application level |
| React Native iOS | Native iOS App Attest bridge | same as the native iOS verifier |
| React Native Android | Native Android Play Integrity bridge | same as the native Android verifier |
| Web | Firebase App Check or Cloudflare Turnstile | `web_risk_verified` |
| Local test | Signed debug attestation | `debug` |

Web signals are deliberately weaker than hardware-backed native attestation.
They cannot satisfy a policy requiring a native trust level.

### Apple App Attest

Configure the accepted application identifier and environment on the server,
enable the App Attest entitlement, and use a physical supported device. The
server validates Apple's certificate chain, application identity, challenge
nonce, attested key, assertion signature, and monotonic counter. Development
and production credentials cannot be mixed. Simulators and fixtures are useful
for tests but cannot produce release evidence.

Follow `latchway-ios-sdk/docs/real-device-conformance.md` for the protected
physical run and `latchway-react-native-sdk/docs/physical-device-evidence.md`
for the corresponding bridge proof.

### Google Play Integrity

Configure the numeric Google Cloud project, package name, accepted signing
certificate digests, recognition policy, licensing requirement, and device
verdict policy. The Android SDK warms a Standard token provider and sends the
server-provided canonical challenge binding directly as Play `requestHash`.
The server performs the Google decode call and validates the returned request,
application, account, and device details.

Release evidence must come from an exact signed application installed through
the configured Google Play track. A sideloaded APK is insufficient. Follow
`latchway-android/docs/real-device-conformance.md` and the React Native physical
evidence guide.

### Firebase App Check and Turnstile

Firebase App Check pins the Google project number and an allow-list of Firebase
app IDs. Turnstile pins exact HTTPS hostnames and an action and uses a
server-owned validation secret. Web environments also require exact canonical
HTTPS Origin allow-lists; client headers cannot expand them.

Tokens are exchanged only as short-lived challenge evidence. Raw App Check or
Turnstile tokens are not stored in normal request records or emitted to logs.

## Session and revocation behavior

The client generates a non-exportable or hardware-backed P-256 installation
key where the platform supports it. Session challenges bind identity,
attestation evidence, application/environment, platform, and the DPoP JWK
thumbprint. Access tokens are short lived; refresh credentials rotate on every
use and reuse revokes the affected family.

Identity reauthentication or attestation step-up starts a new challenge and
session exchange. Refresh itself carries only the rotating refresh token and a
fresh endpoint-bound DPoP proof. Administrator or client installation
revocation invalidates grants and refresh state and causes native SDKs to erase
local installation material at the terminal boundary.

## Production checklist

Before activating a native production environment:

1. Pin the exact public gateway HTTPS origin.
2. Pin identity issuer, audience, algorithms, and normalized claim mappings.
3. Pin Apple application identifiers or Android package/signing identifiers.
4. Require a trust level that matches the selected platform.
5. Keep debug attestation disabled.
6. Run the exact candidate's physical-device and live SDK workflows, including
   both the Firebase App Check and Turnstile JavaScript matrix entries.
7. Confirm revocation, refresh rotation, replay rejection, quota, streaming,
   and protocol-version rejection in the retained evidence.
