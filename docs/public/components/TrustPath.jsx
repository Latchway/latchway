const trustNodes = {
  root: {
    label: "Directly trusted root",
    key: "Platform-owned P-256 key",
    trust: "Direct attestation or configured browser trust",
    session: "Independent rotating session family",
    features: "Active root-component feature grant",
    quota: "Attributed to the root component",
    revocation: "Root or family revocation ends every component in the family",
  },
  delegated: {
    label: "Delegated component",
    key: "Component-owned P-256 key",
    trust: "Delegated from a trusted root; not independently attested",
    session: "Independent rotating session family",
    features: "Sealed subset authorized by the parent and Component Definition",
    quota: "Attributed to the delegated component",
    revocation: "Component revocation leaves the parent and siblings active",
  },
  identity: {
    label: "Identity-only component",
    key: "Component-owned P-256 key",
    trust: "Verified user identity without an application or risk verdict",
    session: "Independent, policy-bounded session family",
    features: "Only features that explicitly allow identity-only trust",
    quota: "Attributed to this component and user",
    revocation: "Component, identity, or family state can end the session",
  },
  browser: {
    label: "Web-risk-verified browser",
    key: "Non-exportable WebCrypto P-256 key",
    trust: "Identity plus configured App Check or Turnstile risk signal",
    session: "Origin-scoped IndexedDB state and refresh lease",
    features: "Only features whose policy accepts browser risk",
    quota: "Attributed to this browser component",
    revocation: "Server revocation ends it; cleared site data enrolls a new component",
  },
};

export function TrustPath() {
  const [selected, setSelected] = React.useState("root");
  const node = trustNodes[selected];
  return (
    <section aria-labelledby="trust-path-title">
      <h2 id="trust-path-title">Explore component trust</h2>
      <div role="group" aria-label="Select a client trust path">
        {Object.entries(trustNodes).map(([id, item]) => (
          <button key={id} type="button" aria-pressed={selected === id} onClick={() => setSelected(id)}>{item.label}</button>
        ))}
      </div>
      <dl aria-live="polite">
        <div><dt>Key location</dt><dd>{node.key}</dd></div>
        <div><dt>Trust source</dt><dd>{node.trust}</dd></div>
        <div><dt>Session family</dt><dd>{node.session}</dd></div>
        <div><dt>Feature scope</dt><dd>{node.features}</dd></div>
        <div><dt>Quota attribution</dt><dd>{node.quota}</dd></div>
        <div><dt>Revocation</dt><dd>{node.revocation}</dd></div>
      </dl>
    </section>
  );
}
