---
name: configure-upstream
description: Configure a server-owned AI upstream, model, pricing, routing, and bounded verification in Latchway. Use when adding or rotating a provider connection; do not use it to place provider credentials in client code.
---

# Configure an upstream

## Keep credentials server-side

Use the write-only secret workflow in [Configuration](/administration/configuration)
and [Admin console](/administration/console). Never put the provider key in an
application, SDK option, framework placeholder, configuration export, shell
history, diagnostic bundle, or log. Do not ask the user to reveal it in chat.

## Build the complete dependency chain

Read the generated [configuration schema](/reference/config-schema) for the exact
source version. Configure the upstream destination and authentication reference,
physical model capability, trusted input accounting, pricing, client-facing
feature, ordered routes, and limit plan as one coherent revision. The client
selects only the feature; the server owns the provider, physical model, price,
route, and credential.

Use the exact protocol and destination constraints in
[Providers and protocols](/concepts/providers-and-protocols). Do not enable a
private destination, redirect, arbitrary opaque path, unsupported provider field,
or fallback/retry behavior that the schema and protocol adapter do not permit.

## Stage and verify safely

Follow the documented immutable-revision lifecycle: pull a redaction-safe base,
create a draft, validate, inspect the plan and diff, simulate representative
claims/platforms/trust, then activate under the current strong ETag. Do not invent
CLI flags or configuration fields; use the exact commands on the configuration
and [CLI reference](/reference/cli) pages.

Use [Self-tests](/operations/self-tests) to choose between an ephemeral CLI-owned
provider check and a server-owned check. Apply the documented cost bound. Verify
the selected route, usage and cost provenance, request status, and redacted
request ID. If activation changes behavior unexpectedly, reactivate the reviewed
prior revision rather than editing active state in place.
