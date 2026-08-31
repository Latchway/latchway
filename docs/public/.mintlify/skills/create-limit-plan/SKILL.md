---
name: create-limit-plan
description: Create or revise a Latchway limit plan with trusted reserve-execute-settle accounting. Use for request, token, cost, concurrency, or scoped quota policy and its operator verification.
---

# Create a limit plan

## Define the enforced policy

Read [Routing and quotas](/concepts/routing-and-quotas),
[Configuration](/administration/configuration), and the generated
[configuration schema](/reference/config-schema). Use only dimensions, periods,
scopes, and bounds present in that exact schema; do not infer a field from client
usage or provider terminology.

Specify who and what the plan applies to, the bounded period, and the intended
request, input, output, total-token, cost, or concurrency behavior. Keep plan
selection server-side. A client cannot submit its plan, price, usage, normalized
claims, or trusted token count.

## Preserve conservative accounting

Latchway reserves before upstream dispatch, executes without holding a database
transaction open, and settles from trusted usage. Hard input, total-token, or
input-priced cost limits require model-aware trusted input accounting and active
pricing. Unsupported rich input must fail closed; missing provider usage is
settled conservatively rather than refunded as zero.

Include the plan and all referenced accounting, pricing, model, feature, and
route resources in one valid immutable revision. Validate, inspect the plan and
diff, and simulate the exact claims, platform, trust level, feature, and request
bounds before activation. Simulation does not reserve quota or dispatch traffic.

## Verify and roll back

After activation, test one request below the bound and one deterministic denial
at the bound. Confirm the effective plan, reservation, settlement, remaining
allowance, `quota_exceeded` or `concurrency_exceeded` result, retry guidance,
usage view, and safe request ID. Reactivate the prior reviewed revision if the
effective policy is wrong; do not edit counters or active state to force a pass.
