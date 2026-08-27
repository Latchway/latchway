# Version 1 non-goals

Latchway version 1 deliberately excludes:

- agent orchestration;
- retrieval-augmented generation and vector databases;
- MCP execution;
- prompt playgrounds, version management, hosting, or fine-tuning;
- semantic caching and AI evaluation platforms;
- subscription billing or customer-application authentication UI;
- multi-region strongly consistent quotas;
- Redis, Kafka, ClickHouse, or Elasticsearch requirements;
- runtime Go shared-object plugins or untrusted operator code;
- a proprietary AI request framework.

These exclusions keep the critical path on identity, application integrity, proof-of-possession sessions, feature authorization, safe routing, accurate quotas and usage, a canonical control plane, portable deployment, and idiomatic HTTP integration.

A future proposal may add an excluded capability only when it does not weaken the product boundary, make PostgreSQL correctness optional, expose upstream credentials, or force SDK users into a framework. Such a change requires an ADR and must not be represented as unfinished version-1 work.
