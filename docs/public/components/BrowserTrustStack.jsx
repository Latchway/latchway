const layers = [
  ["identity", "User identity", "Identifies the signed-in application user.", "Does not prove the browser or origin is trustworthy."],
  ["key", "Browser component key", "Proves possession of the WebCrypto key bound to the session.", "Does not prevent same-origin JavaScript from invoking the key."],
  ["signal", "Browser trust signal", "Adds the configured App Check or Turnstile verdict.", "Does not provide native device attestation."],
  ["origin", "Origin policy", "Restricts browser requests to an exact configured origin.", "Does not remove XSS or malicious extension risk."],
  ["feature", "Feature policy", "Limits the client to a server-configured application feature.", "Does not let the browser choose a provider, route, or model."],
  ["quota", "Quota policy", "Reserves and settles authoritative usage before and after dispatch.", "Does not guarantee upstream availability."],
];

export function BrowserTrustStack() {
  const [selected, setSelected] = React.useState("identity");
  const layer = layers.find(([id]) => id === selected) ?? layers[0];
  return (
    <section aria-labelledby="browser-trust-stack-title">
      <h2 id="browser-trust-stack-title">Browser trust stack</h2>
      <ol>{layers.map(([id, label]) => <li key={id}><button type="button" aria-pressed={selected === id} onClick={() => setSelected(id)}>{label}</button></li>)}</ol>
      <div aria-live="polite"><h3>{layer[1]}</h3><p><strong>Contributes:</strong> {layer[2]}</p><p><strong>Does not prove:</strong> {layer[3]}</p></div>
    </section>
  );
}
