export function CompatibilityMatrix({ rows = [] }) {
  const [ecosystem, setEcosystem] = React.useState("all");
  const [framework, setFramework] = React.useState("");
  const [minimum, setMinimum] = React.useState("");
  const [streaming, setStreaming] = React.useState(false);
  const [tools, setTools] = React.useState(false);
  const [structured, setStructured] = React.useState(false);
  const [extensions, setExtensions] = React.useState(false);
  const [fullDpop, setFullDpop] = React.useState(false);
  const filtered = React.useMemo(() => rows.filter((row) =>
    (ecosystem === "all" || row.ecosystem === ecosystem)
    && row.name.toLowerCase().includes(framework.trim().toLowerCase())
    && (minimum.trim() === "" || row.minimum === minimum.trim())
    && (!streaming || row.streaming)
    && (!tools || row.tools !== "No")
    && (!structured || row.structured !== "No")
    && (!extensions || row.appExtensions !== "No")
    && (!fullDpop || row.dpop === "Full")
  ), [rows, ecosystem, framework, minimum, streaming, tools, structured, extensions, fullDpop]);
  const ecosystems = [...new Set(rows.map((row) => row.ecosystem))].sort();
  return (
    <section aria-labelledby="compatibility-filter-title">
      <h2 id="compatibility-filter-title">Filter compatibility evidence</h2>
      <p>The registry currently records ecosystem, not a separate browser-runtime claim. A JavaScript row therefore does not by itself prove browser support.</p>
      <label>Platform or ecosystem
        <select value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}>
          <option value="all">All</option>
          {ecosystems.map((value) => <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <label>Framework name <input value={framework} onChange={(event) => setFramework(event.target.value)} /></label>
      <label>Exact minimum version <input value={minimum} onChange={(event) => setMinimum(event.target.value)} placeholder="For example, 7.8.0" /></label>
      <fieldset>
        <legend>Required capabilities</legend>
        <label><input type="checkbox" checked={streaming} onChange={(event) => setStreaming(event.target.checked)} /> Streaming</label>
        <label><input type="checkbox" checked={tools} onChange={(event) => setTools(event.target.checked)} /> Tools</label>
        <label><input type="checkbox" checked={structured} onChange={(event) => setStructured(event.target.checked)} /> Structured output</label>
        <label><input type="checkbox" checked={extensions} onChange={(event) => setExtensions(event.target.checked)} /> App extensions</label>
        <label><input type="checkbox" checked={fullDpop} onChange={(event) => setFullDpop(event.target.checked)} /> Full DPoP</label>
      </fieldset>
      <table>
        <caption>Generated compatibility registry rows matching the selected filters</caption>
        <thead><tr><th>Framework</th><th>Ecosystem</th><th>Support</th><th>Tested range</th><th>DPoP</th><th>Streaming</th><th>Tools</th><th>Structured output</th><th>App extensions</th></tr></thead>
        <tbody>{filtered.map((row) => <tr key={row.id}><td>{row.name}</td><td>{row.ecosystem}</td><td>{row.support}</td><td>{row.tested}</td><td>{row.dpop}</td><td>{row.streaming ? "Yes" : "No"}</td><td>{row.tools}</td><td>{row.structured}</td><td>{row.appExtensions}</td></tr>)}</tbody>
      </table>
      {filtered.length === 0 ? <p>No registry row matches these filters.</p> : null}
    </section>
  );
}
