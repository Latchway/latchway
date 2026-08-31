const clientPaths = {
  ios: {
    label: "iOS",
    package: "Local Latchway + LatchwayAppAttest Swift products",
    quickstart: "/clients/ios/quickstart",
    security: "/clients/ios/app-attest",
    production: "/clients/ios/production-checklist",
  },
  android: {
    label: "Android",
    package: "Local dev.latchway BOM, OkHttp, and Play Integrity modules",
    quickstart: "/clients/android/quickstart",
    security: "/clients/android/play-integrity",
    production: "/clients/android/production-checklist",
  },
  web: {
    label: "Web",
    package: "Local @latchway/client 1.0.0 archive",
    quickstart: "/clients/web/quickstart",
    security: "/clients/web/browser-trust",
    production: "/clients/web/production-checklist",
  },
  "react-native": {
    label: "React Native",
    package: "Version-locked @latchway/react-native source workspace",
    quickstart: "/clients/react-native/quickstart",
    security: "/mobile/react-native",
    production: "/clients/react-native/production-checklist",
  },
};

const integrationPaths = {
  raw: ["Raw transport", "/integrations/raw-http"],
  openai: ["OpenAI", "/integrations/openai-js"],
  foundation: ["Foundation Models", "/integrations/foundation-models"],
  vercel: ["Vercel AI SDK", "/integrations/vercel-ai-sdk"],
  langchain: ["LangChain", "/integrations/langchain-js"],
};

const webFrameworkPaths = {
  vanilla: ["Vanilla TypeScript", "/clients/web/quickstart"],
  react: ["React", "/clients/web/react"],
  nextjs: ["Next.js client component", "/clients/web/nextjs"],
  vite: ["Vite", "/clients/web/vite"],
  other: ["Other browser framework", "/clients/web/server-rendering"],
};

const webTrustPaths = {
  firebase: ["Firebase App Check", "/clients/web/firebase-app-check"],
  turnstile: ["Cloudflare Turnstile", "/clients/web/turnstile"],
  identity: ["Identity-only development", "/clients/web/browser-trust"],
};

const authenticationPaths = {
  firebase: ["Firebase", "/clients/authentication-providers#firebase"],
  supabase: ["Supabase", "/clients/authentication-providers#supabase"],
  clerk: ["Clerk", "/clients/authentication-providers#clerk"],
  custom: ["Custom JWT", "/clients/authentication-providers#custom-jwt"],
};

const deploymentPaths = {
  local: ["Local source candidate", "/operate/quickstart"],
  "cloud-run": ["Google Cloud Run source template (provider proof open)", "/operations/deployment#implemented-deployment-templates"],
  aws: ["AWS ECS/Fargate source template (provider proof open)", "/operations/deployment#implemented-deployment-templates"],
  fly: ["Fly.io source template (provider proof open)", "/operations/deployment#implemented-deployment-templates"],
};

export function SetupPath() {
  const [role, setRole] = React.useState("client");
  const [platform, setPlatform] = React.useState("web");
  const [authentication, setAuthentication] = React.useState("firebase");
  const [integration, setIntegration] = React.useState("raw");
  const [deployment, setDeployment] = React.useState("local");
  const [webFramework, setWebFramework] = React.useState("vanilla");
  const [webTrust, setWebTrust] = React.useState("firebase");

  const result = React.useMemo(() => {
    const selectedDeployment = deploymentPaths[deployment];
    if (role === "operator") return {
      label: "Operate Latchway",
      package: "Core source checkout and matching CLI",
      pages: [[selectedDeployment[0], selectedDeployment[1]], ["Production readiness", "/operations/production-readiness"]],
      production: "/operations/production-readiness",
      verification: "latchway verify local",
      deployment: selectedDeployment[0],
    };
    if (role === "security") return {
      label: "Review the security boundary",
      package: "No client package required",
      pages: [["Security boundary", "/concepts/security-boundary"], ["Trust provenance", "/concepts/trust-provenance"]],
      production: "/release-status",
      verification: "Confirm the exact release and compatibility evidence.",
    };
    const selected = clientPaths[platform];
    const selectedAuthentication = authenticationPaths[authentication];
    const pages = [
      [`${selected.label} quickstart`, selected.quickstart],
      [selectedAuthentication[0], selectedAuthentication[1]],
      ["Platform security boundary", selected.security],
    ];
    if (platform === "web") {
      pages.push(webFrameworkPaths[webFramework], webTrustPaths[webTrust], ["Origin policy", "/clients/web/origins-and-cors"], ["CSP", "/clients/web/content-security-policy"]);
    } else {
      pages.push(integrationPaths[integration]);
    }
    return {
      label: `Build for ${selected.label}`,
      package: selected.package,
      pages: [...pages, [selectedDeployment[0], selectedDeployment[1]]],
      production: selected.production,
      verification: "Correlate one successful feature-bound request in the Console.",
      authentication: selectedAuthentication[0],
      deployment: selectedDeployment[0],
    };
  }, [role, platform, authentication, integration, deployment, webFramework, webTrust]);

  return (
    <section className="setup-path" aria-labelledby="setup-path-title">
      <h2 id="setup-path-title">Choose your path</h2>
      <div className="setup-path-controls">
        <label>Role
          <select value={role} onChange={(event) => setRole(event.target.value)}>
            <option value="client">Client developer</option>
            <option value="operator">Operator</option>
            <option value="security">Security reviewer</option>
          </select>
        </label>
        {role === "client" ? <label>Platform
          <select value={platform} onChange={(event) => setPlatform(event.target.value)}>
            {Object.entries(clientPaths).map(([value, item]) => <option key={value} value={value}>{item.label}</option>)}
          </select>
        </label> : null}
        {role === "client" ? <label>Authentication
          <select value={authentication} onChange={(event) => setAuthentication(event.target.value)}>
            <option value="firebase">Firebase</option>
            <option value="supabase">Supabase</option>
            <option value="clerk">Clerk</option>
            <option value="custom">Custom JWT</option>
          </select>
        </label> : null}
        {role === "client" && platform !== "web" ? <label>AI integration
          <select value={integration} onChange={(event) => setIntegration(event.target.value)}>
            {Object.entries(integrationPaths).map(([value, item]) => <option key={value} value={value}>{item[0]}</option>)}
          </select>
        </label> : null}
        {role === "client" && platform === "web" ? <label>Web framework
          <select value={webFramework} onChange={(event) => setWebFramework(event.target.value)}>
            {Object.entries(webFrameworkPaths).map(([value, item]) => <option key={value} value={value}>{item[0]}</option>)}
          </select>
        </label> : null}
        {role === "client" && platform === "web" ? <label>Browser trust
          <select value={webTrust} onChange={(event) => setWebTrust(event.target.value)}>
            {Object.entries(webTrustPaths).map(([value, item]) => <option key={value} value={value}>{item[0]}</option>)}
          </select>
        </label> : null}
        {role !== "security" ? <label>Deployment
          <select value={deployment} onChange={(event) => setDeployment(event.target.value)}>
            <option value="local">Local</option>
            <option value="cloud-run">Cloud Run</option>
            <option value="aws">AWS</option>
            <option value="fly">Fly.io</option>
          </select>
        </label> : null}
      </div>
      <div className="setup-path-result" aria-live="polite">
        <h3>{result.label}</h3>
        <p><strong>Package:</strong> {result.package}</p>
        {result.authentication ? <p><strong>Authentication:</strong> {result.authentication}.</p> : null}
        {result.deployment ? <p><strong>Deployment:</strong> {result.deployment}.</p> : null}
        <ol>{result.pages.map(([label, href]) => <li key={`${label}-${href}`}><a href={href}>{label}</a></li>)}</ol>
        <p><strong>Verification:</strong> <code>{result.verification}</code></p>
        <p><a href={result.production}>Open production hardening</a></p>
      </div>
    </section>
  );
}
