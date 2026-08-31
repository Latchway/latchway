# Locked SDK documentation bundles

This directory vendors the exact compressed bytes named by
`docs/sdk-bundles.lock`. Keeping the small archives in the core repository lets
documentation CI verify manifests, checksums, provenance, and generated output
without checking out or trusting the mutable default branches of four other
repositories.

Do not extract, replace, or edit these files by hand. Build a bundle in its
owning SDK repository, then import it with one of:

```sh
scripts/docs-sync-sdk ios 1.0.0
scripts/docs-sync-sdk android 1.0.0
scripts/docs-sync-sdk js 1.0.0
scripts/docs-sync-sdk react-native 1.0.0
```

Before a release, commit each SDK source tree first, build its bundle with the
producer's `--require-clean` option, import all four final archives, and then
commit the core lock and generated documentation. A local candidate bundle may
record `source_tree_clean: false`; that value is intentionally visible in the
lock and public generated manifest and is not publication evidence.
