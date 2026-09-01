const STORAGE_KEY = "latchway.docs.setup-preferences.v1";

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

const DEFAULT_PREFERENCES = {
  role: "client",
  platform: "react-native",
  authentication: "firebase",
  integration: "raw",
  deployment: "local",
  webFramework: "vanilla",
  webTrust: "firebase",
  gatewayURL: "",
  consoleURL: "",
  applicationID: "",
  consoleApplication: "",
  environment: "development",
  featureID: "habit-assistant",
  componentDefinitionID: "",
  sdkVersion: "1.0.0",
  serverVersion: "1.0.0",
};

const OPTION_FIELDS = {
  role: ["client", "operator", "security"],
  platform: Object.keys(clientPaths),
  authentication: Object.keys(authenticationPaths),
  integration: Object.keys(integrationPaths),
  deployment: Object.keys(deploymentPaths),
  webFramework: Object.keys(webFrameworkPaths),
  webTrust: Object.keys(webTrustPaths),
};

// This is the complete URL-personalization allowlist. Values outside this map
// are never read from or written to a personalized documentation URL.
const SAFE_URL_FIELDS = {
  role: "lw_role",
  platform: "lw_platform",
  authentication: "lw_authentication",
  integration: "lw_integration",
  deployment: "lw_deployment",
  webFramework: "lw_web_framework",
  webTrust: "lw_web_trust",
  gatewayURL: "lw_gateway",
  consoleURL: "lw_console",
  applicationID: "lw_application_id",
  consoleApplication: "lw_application_slug",
  environment: "lw_environment",
  featureID: "lw_feature",
  componentDefinitionID: "lw_component_definition",
  sdkVersion: "lw_sdk_version",
  serverVersion: "lw_server_version",
};

const IDENTIFIER = /^[a-z][a-z0-9_-]{0,62}$/u;
const APPLICATION_ID = /^app_[0-7][0-9A-HJKMNP-TV-Z]{25}$/u;
const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/u;

function optionValue(field, value) {
  return OPTION_FIELDS[field]?.includes(value) ? value : "";
}

function identifierValue(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  return IDENTIFIER.test(trimmed) ? trimmed : "";
}

function applicationIDValue(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  return APPLICATION_ID.test(trimmed) ? trimmed : "";
}

function versionValue(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  return trimmed.length <= 64 && VERSION.test(trimmed) ? trimmed : "";
}

function loopbackHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

function publicOrigin(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (!trimmed || trimmed.length > 2048) return "";
  try {
    const url = new URL(trimmed);
    const safeProtocol = url.protocol === "https:" || (url.protocol === "http:" && loopbackHost(url.hostname));
    if (!safeProtocol || url.username || url.password || url.search || url.hash) return "";
    if (url.pathname !== "/" && url.pathname !== "") return "";
    return url.origin;
  } catch {
    return "";
  }
}

function normalizedValue(field, value) {
  if (OPTION_FIELDS[field]) return optionValue(field, value);
  if (field === "gatewayURL" || field === "consoleURL") return publicOrigin(value);
  if (field === "applicationID") return applicationIDValue(value);
  if (field === "sdkVersion" || field === "serverVersion") return versionValue(value);
  if (["consoleApplication", "environment", "featureID", "componentDefinitionID"].includes(field)) {
    return identifierValue(value);
  }
  return "";
}

function safePreferences(preferences) {
  const safe = {};
  for (const field of Object.keys(SAFE_URL_FIELDS)) {
    const value = normalizedValue(field, preferences[field]);
    if (value) safe[field] = value;
  }
  return safe;
}

function applyCandidate(base, candidate) {
  const next = { ...base };
  let rejected = 0;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return { next, rejected };
  for (const field of Object.keys(SAFE_URL_FIELDS)) {
    if (typeof candidate[field] !== "string") continue;
    const value = normalizedValue(field, candidate[field]);
    if (value) next[field] = value;
    else if (candidate[field].trim()) rejected += 1;
  }
  return { next, rejected };
}

function candidateFromSearch(search) {
  const candidate = {};
  for (const [field, parameter] of Object.entries(SAFE_URL_FIELDS)) {
    if (search.has(parameter)) candidate[field] = search.get(parameter) ?? "";
  }
  return candidate;
}

function personalizedDocsHref(path, preferences) {
  const url = new URL(path, "https://docs.latchway.invalid");
  const safe = safePreferences(preferences);
  for (const [field, parameter] of Object.entries(SAFE_URL_FIELDS)) {
    if (safe[field]) url.searchParams.set(parameter, safe[field]);
  }
  return `${url.pathname}${url.search}${url.hash}`;
}

function useSetupPreferences() {
  const [preferences, setPreferences] = React.useState(DEFAULT_PREFERENCES);
  const [ready, setReady] = React.useState(false);
  const [rejectedURLValues, setRejectedURLValues] = React.useState(0);

  React.useEffect(() => {
    let next = { ...DEFAULT_PREFERENCES };
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (stored) next = applyCandidate(next, JSON.parse(stored)).next;
    } catch {
      // Storage denial or malformed legacy state leaves anonymous defaults.
    }
    const fromURL = applyCandidate(next, candidateFromSearch(new URLSearchParams(window.location.search)));
    setPreferences(fromURL.next);
    setRejectedURLValues(fromURL.rejected);
    setReady(true);
  }, []);

  React.useEffect(() => {
    if (!ready) return;
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(safePreferences(preferences)));
    } catch {
      // The page remains complete when storage is unavailable or denied.
    }
  }, [preferences, ready]);

  function reset() {
    setPreferences(DEFAULT_PREFERENCES);
    setRejectedURLValues(0);
    try {
      window.localStorage.removeItem(STORAGE_KEY);
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.hash}`);
    } catch {
      // Resetting in-memory preferences still succeeds without browser storage.
    }
  }

  return { preferences, ready, rejectedURLValues, reset, setPreferences };
}

function updatePreference(setPreferences, field, value) {
  setPreferences((previous) => ({ ...previous, [field]: value }));
}

function fieldIssue(field, value) {
  if (!value.trim() || normalizedValue(field, value)) return "";
  if (field === "gatewayURL" || field === "consoleURL") {
    return "Use one HTTPS origin, or HTTP only for localhost. Credentials, paths, query strings, and fragments are rejected.";
  }
  if (field === "applicationID") return "Use the canonical 30-character app_ resource ID returned by the Admin API.";
  if (field === "sdkVersion" || field === "serverVersion") return "Use a semantic version such as 1.0.0 or 1.0.0-rc.1.";
  return "Use a Latchway identifier: lowercase letters, digits, underscores, or hyphens.";
}

function platformSearchValue(platform) {
  if (platform === "ios" || platform === "android" || platform === "web") return platform;
  return "";
}

function consoleHref(path, preferences, extra = {}) {
  const safe = safePreferences(preferences);
  const origin = safe.consoleURL || safe.gatewayURL;
  if (!origin) return "";
  const url = new URL(path, `${origin}/`);
  if (safe.consoleApplication) url.searchParams.set("application", safe.consoleApplication);
  if (safe.environment) url.searchParams.set("environment", safe.environment);
  for (const [name, value] of Object.entries(extra)) {
    if (value) url.searchParams.set(name, value);
  }
  return url.toString();
}

function ConsoleActions({ platform, preferences }) {
  const safe = safePreferences(preferences);
  const requestFilters = {
    feature: safe.featureID,
    platform: platformSearchValue(platform),
  };
  const actions = [
    ["Continue first-run setup", consoleHref("/setup", preferences)],
    ["Open feature workspace", consoleHref("/features", preferences)],
    ["Inspect matching requests", consoleHref("/requests", preferences, requestFilters)],
    ["Open limit plans", consoleHref("/limit-plans", preferences)],
    ["Open route simulator", consoleHref("/route-simulator", preferences)],
  ];
  if (safe.componentDefinitionID) {
    actions.splice(3, 0, ["Open component definitions", consoleHref("/component-definitions", preferences)]);
  }
  const available = actions.filter(([, href]) => href);
  if (!available.length) {
    return <p>Add a valid gateway or Console origin to enable task-oriented Console links.</p>;
  }
  return <ul>{available.map(([label, href]) => <li key={label}><a href={href} rel="noreferrer">{label}</a></li>)}</ul>;
}

function CoordinateSummary({ platform, preferences }) {
  const safe = safePreferences(preferences);
  return (
    <>
      <dl>
        <div><dt>Gateway origin</dt><dd><code>{safe.gatewayURL || "<GATEWAY_ORIGIN>"}</code></dd></div>
        <div><dt>Console origin</dt><dd><code>{safe.consoleURL || safe.gatewayURL || "<CONSOLE_ORIGIN>"}</code></dd></div>
        <div><dt>Application resource ID</dt><dd><code>{safe.applicationID || "<APPLICATION_ID>"}</code></dd></div>
        <div><dt>Console application slug</dt><dd><code>{safe.consoleApplication || "<APPLICATION_SLUG>"}</code></dd></div>
        <div><dt>Environment</dt><dd><code>{safe.environment || "<ENVIRONMENT>"}</code></dd></div>
        <div><dt>Feature</dt><dd><code>{safe.featureID || "<FEATURE_ID>"}</code></dd></div>
        <div><dt>Component definition</dt><dd><code>{safe.componentDefinitionID || "<COMPONENT_DEFINITION_ID>"}</code></dd></div>
        <div><dt>SDK / server</dt><dd><code>{safe.sdkVersion || "<SDK_VERSION>"}</code> / <code>{safe.serverVersion || "<SERVER_VERSION>"}</code></dd></div>
      </dl>
      <p>
        The application resource ID configures the SDK. The optional Console
        application slug selects a workspace; they are intentionally separate.
      </p>
      <ConsoleActions platform={platform} preferences={preferences} />
    </>
  );
}

export function SetupCoordinates({ platform = "react-native" }) {
  const { preferences, ready, rejectedURLValues } = useSetupPreferences();
  return (
    <aside className="setup-coordinates" aria-label="Personalized setup coordinates">
      <p><strong>{ready ? "Safe setup coordinates" : "Loading safe setup coordinates"}</strong></p>
      {rejectedURLValues ? <p role="alert">Ignored {rejectedURLValues} invalid or unsafe URL value{rejectedURLValues === 1 ? "" : "s"}.</p> : null}
      <CoordinateSummary platform={platform} preferences={preferences} />
      <p>
        These optional values contain no credentials. Change them in the
        <a href={personalizedDocsHref("/#build-your-path", preferences)}> setup-path chooser</a>.
      </p>
    </aside>
  );
}

export function SetupPath() {
  const { preferences, ready, rejectedURLValues, reset, setPreferences } = useSetupPreferences();
  const [copyStatus, setCopyStatus] = React.useState("");
  const {
    role, platform, authentication, integration, deployment, webFramework, webTrust,
  } = preferences;

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

  async function copySafeLink() {
    try {
      const relative = personalizedDocsHref(window.location.pathname, preferences);
      await navigator.clipboard.writeText(new URL(relative, window.location.origin).toString());
      setCopyStatus("Copied a URL containing only the allowlisted non-secret fields.");
    } catch {
      setCopyStatus("Copy is unavailable. Open the safe URL link instead.");
    }
  }

  const inputFields = [
    ["gatewayURL", "Gateway origin", "https://gateway.example.com"],
    ["consoleURL", "Console origin (optional)", "https://gateway.example.com"],
    ["applicationID", "Application resource ID", "app_01H00000000000000000000000"],
    ["consoleApplication", "Console application slug (optional)", "my-application"],
    ["environment", "Environment identifier", "development"],
    ["featureID", "Feature ID", "habit-assistant"],
    ["componentDefinitionID", "Component Definition ID (optional)", "ios-main"],
    ["sdkVersion", "SDK version", "1.0.0"],
    ["serverVersion", "Server version", "1.0.0"],
  ];
  const currentPath = typeof window === "undefined" ? "/" : window.location.pathname;

  return (
    <section className="setup-path" aria-labelledby="setup-path-title">
      <h2 id="setup-path-title">Choose your path</h2>
      <div className="setup-path-controls">
        <label>Role
          <select value={role} onChange={(event) => updatePreference(setPreferences, "role", event.target.value)}>
            <option value="client">Client developer</option>
            <option value="operator">Operator</option>
            <option value="security">Security reviewer</option>
          </select>
        </label>
        {role === "client" ? <label>Platform
          <select value={platform} onChange={(event) => updatePreference(setPreferences, "platform", event.target.value)}>
            {Object.entries(clientPaths).map(([value, item]) => <option key={value} value={value}>{item.label}</option>)}
          </select>
        </label> : null}
        {role === "client" ? <label>Authentication
          <select value={authentication} onChange={(event) => updatePreference(setPreferences, "authentication", event.target.value)}>
            <option value="firebase">Firebase</option>
            <option value="supabase">Supabase</option>
            <option value="clerk">Clerk</option>
            <option value="custom">Custom JWT</option>
          </select>
        </label> : null}
        {role === "client" && platform !== "web" ? <label>AI integration
          <select value={integration} onChange={(event) => updatePreference(setPreferences, "integration", event.target.value)}>
            {Object.entries(integrationPaths).map(([value, item]) => <option key={value} value={value}>{item[0]}</option>)}
          </select>
        </label> : null}
        {role === "client" && platform === "web" ? <label>Web framework
          <select value={webFramework} onChange={(event) => updatePreference(setPreferences, "webFramework", event.target.value)}>
            {Object.entries(webFrameworkPaths).map(([value, item]) => <option key={value} value={value}>{item[0]}</option>)}
          </select>
        </label> : null}
        {role === "client" && platform === "web" ? <label>Browser trust
          <select value={webTrust} onChange={(event) => updatePreference(setPreferences, "webTrust", event.target.value)}>
            {Object.entries(webTrustPaths).map(([value, item]) => <option key={value} value={value}>{item[0]}</option>)}
          </select>
        </label> : null}
        {role !== "security" ? <label>Deployment
          <select value={deployment} onChange={(event) => updatePreference(setPreferences, "deployment", event.target.value)}>
            <option value="local">Local</option>
            <option value="cloud-run">Cloud Run</option>
            <option value="aws">AWS</option>
            <option value="fly">Fly.io</option>
          </select>
        </label> : null}
      </div>

      <details>
        <summary>Personalize safe setup coordinates</summary>
        <p id="setup-personalization-policy">
          Valid values are stored only in this browser and may appear in the
          shareable URL. This form has no field for a token, credential, DPoP
          proof, attestation evidence, request body, or upstream key. Do not
          paste any of those values here.
        </p>
        <div className="setup-path-controls">
          {inputFields.map(([field, label, placeholder]) => {
            const issue = fieldIssue(field, preferences[field]);
            return <label key={field}>{label}
              <input
                aria-describedby="setup-personalization-policy"
                aria-invalid={issue ? "true" : "false"}
                autoComplete="off"
                maxLength={field === "gatewayURL" || field === "consoleURL" ? 2048 : 128}
                placeholder={placeholder}
                spellCheck={false}
                type={field === "gatewayURL" || field === "consoleURL" ? "url" : "text"}
                value={preferences[field]}
                onChange={(event) => updatePreference(setPreferences, field, event.target.value)}
              />
              {issue ? <small role="alert">{issue}</small> : null}
            </label>;
          })}
        </div>
        {rejectedURLValues ? <p role="alert">Ignored {rejectedURLValues} invalid or unsafe URL value{rejectedURLValues === 1 ? "" : "s"}.</p> : null}
        <p>{ready ? "Validated values are saved locally." : "Loading saved preferences."}</p>
        <div>
          <button type="button" onClick={() => void copySafeLink()}>Copy safe setup URL</button>{" "}
          <a href={personalizedDocsHref(currentPath, preferences)}>Open safe setup URL</a>{" "}
          <button type="button" onClick={reset}>Reset saved values</button>
        </div>
        {copyStatus ? <p role="status">{copyStatus}</p> : null}
      </details>

      <div className="setup-path-result" aria-live="polite">
        <h3>{result.label}</h3>
        <p><strong>Package:</strong> {result.package}</p>
        {result.authentication ? <p><strong>Authentication:</strong> {result.authentication}.</p> : null}
        {result.deployment ? <p><strong>Deployment:</strong> {result.deployment}.</p> : null}
        <ol>{result.pages.map(([label, href]) => <li key={`${label}-${href}`}><a href={personalizedDocsHref(href, preferences)}>{label}</a></li>)}</ol>
        <p><strong>Verification:</strong> <code>{result.verification}</code></p>
        <p><a href={personalizedDocsHref(result.production, preferences)}>Open production hardening</a></p>
        <h4>Current non-secret coordinates and Console tasks</h4>
        <CoordinateSummary platform={platform} preferences={preferences} />
      </div>
    </section>
  );
}
