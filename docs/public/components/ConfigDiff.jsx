function renderValue(value) {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

export function ConfigDiff({ before, after, effectiveBehavior, rollback }) {
  return (
    <section aria-labelledby="config-diff-title">
      <h2 id="config-diff-title">Configuration effect</h2>
      <div className="config-diff-columns">
        <section><h3>Before</h3><pre><code>{renderValue(before)}</code></pre></section>
        <section><h3>After</h3><pre><code>{renderValue(after)}</code></pre></section>
      </div>
      <h3>Effective behavior</h3><p>{effectiveBehavior}</p>
      <h3>Rollback</h3><p>{rollback}</p>
    </section>
  );
}
