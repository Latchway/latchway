import type { IconName } from "../ui";

export type ConsoleRoute =
  | "/"
  | "/account"
  | "/applications"
  | "/setup"
  | "/administrators"
  | "/api-tokens"
  | "/admin-sessions"
  | "/roles"
  | "/authentication-providers"
  | "/client-sessions"
  | "/attestation"
  | "/users"
  | "/installation-families"
  | "/installations"
  | "/component-definitions"
  | "/features"
  | "/routes"
  | "/upstreams"
  | "/models-pricing"
  | "/secrets"
  | "/configuration"
  | "/limit-plans"
  | "/plan-by-feature"
  | "/user-overrides"
  | "/protections"
  | "/requests"
  | "/usage"
  | "/cost"
  | "/performance"
  | "/reliability"
  | "/changes"
  | "/configuration-revisions"
  | "/configuration-compare"
  | "/route-simulator"
  | "/self-tests"
  | "/audit"
  | "/system-health"
  | "/settings";

export interface SectionTab {
  description: string;
  label: string;
  to: ConsoleRoute;
}

/** One sidebar destination. Areas with tabs group related pages; the first tab is where the sidebar link goes. */
export interface NavArea {
  description: string;
  icon: IconName;
  label: string;
  tabs?: readonly SectionTab[];
  to: ConsoleRoute;
}

export interface NavGroup {
  areas: readonly NavArea[];
  collapsible?: boolean;
  title?: string;
}

/** Environment scope: everything here reads or changes the selected application environment. */
export const environmentNavigation: readonly NavGroup[] = [
  { areas: [{ description: "Gateway operating posture and setup progress", icon: "overview", label: "Overview", to: "/" }] },
  {
    areas: [
      { description: "Request outcomes, attempts and metadata", icon: "requests", label: "Requests", to: "/requests" },
      {
        description: "Usage, cost, performance and reliability",
        icon: "analytics",
        label: "Analytics",
        tabs: [
          { description: "Requests, people and tokens", label: "Usage", to: "/usage" },
          { description: "Cost at your configured prices", label: "Cost", to: "/cost" },
          { description: "Latency and time to first token", label: "Performance", to: "/performance" },
          { description: "Failures, quota denials, app verification and fallbacks", label: "Reliability", to: "/reliability" }
        ],
        to: "/usage"
      }
    ],
    title: "Traffic"
  },
  {
    areas: [
      { description: "Client-visible AI capabilities", icon: "features", label: "Features", to: "/features" },
      { description: "Ordered conditional resolution", icon: "split", label: "Routing", to: "/routes" },
      {
        description: "Provider connections, models and credentials",
        icon: "connections",
        label: "AI Connections",
        tabs: [
          { description: "Provider and gateway destinations", label: "Connections", to: "/upstreams" },
          { description: "Physical models and rates", label: "Models & pricing", to: "/models-pricing" },
          { description: "Write-only credentials", label: "Secrets", to: "/secrets" }
        ],
        to: "/upstreams"
      },
      {
        description: "Who may call the gateway and from which apps",
        icon: "trust",
        label: "Client Trust",
        tabs: [
          { description: "Issuer and claim trust", label: "User sign-in", to: "/authentication-providers" },
          { description: "Platform app verification", label: "App verification", to: "/attestation" },
          { description: "Allowed roots, children and feature grants", label: "Components", to: "/component-definitions" },
          { description: "How long app users' sessions last", label: "Sessions", to: "/client-sessions" }
        ],
        to: "/authentication-providers"
      },
      { description: "Guided first-run checklist", icon: "rocket", label: "Setup wizard", to: "/setup" }
    ],
    title: "Build"
  },
  {
    areas: [
      {
        description: "Pseudonymous users and their installations",
        icon: "users",
        label: "Users & Installs",
        tabs: [
          { description: "Pseudonymous identities and controls", label: "Users", to: "/users" },
          { description: "Component trust and revocation", label: "Installations", to: "/installation-families" },
          { description: "Legacy root installation records", label: "Older installs", to: "/installations" }
        ],
        to: "/users"
      },
      {
        description: "Quotas, authorization and protective controls",
        icon: "policies",
        label: "Policies & Limits",
        tabs: [
          { description: "How much each user, device and feature can use", label: "Limit plans", to: "/limit-plans" },
          { description: "Which plan each feature selects for whom", label: "Plan by feature", to: "/plan-by-feature" },
          { description: "Live per-user plan exceptions", label: "Overrides", to: "/user-overrides" },
          { description: "Limits per installation, device or trust source", label: "Protections", to: "/protections" }
        ],
        to: "/limit-plans"
      }
    ],
    collapsible: true,
    title: "Users & Limits"
  },
  {
    areas: [
      {
        description: "Configuration history, review and rollback",
        icon: "changes",
        label: "Changes",
        tabs: [
          { description: "Unpublished changes, problems and publishing", label: "Draft", to: "/changes" },
          { description: "Every revision and rollback", label: "History", to: "/configuration-revisions" },
          { description: "Compare any two revisions", label: "Compare", to: "/configuration-compare" },
          { description: "The whole draft document as JSON", label: "Edit as JSON", to: "/configuration" }
        ],
        to: "/changes"
      },
      { description: "Exact production policy resolver", icon: "simulator", label: "Simulator", to: "/route-simulator" },
      { description: "Bounded installation diagnostics", icon: "selftest", label: "Self-tests", to: "/self-tests" },
      { description: "Gateway liveness and readiness", icon: "health", label: "System Health", to: "/system-health" }
    ],
    collapsible: true,
    title: "Operate"
  }
];

/** Organization scope: the application and environment selection does not apply here. */
export const organizationNavigation: readonly NavGroup[] = [
  {
    areas: [
      {
        description: "Administrators, roles and automation credentials",
        icon: "team",
        label: "Team & Access",
        tabs: [
          { description: "People who can sign in, and their roles", label: "Members", to: "/administrators" },
          { description: "Your tokens for scripts and the CLI", label: "API tokens", to: "/api-tokens" },
          { description: "Console sign-ins, and signing them out", label: "Sessions", to: "/admin-sessions" },
          { description: "What each role can do", label: "Roles", to: "/roles" }
        ],
        to: "/administrators"
      },
      { description: "Redacted change history", icon: "audit", label: "Audit Log", to: "/audit" },
      {
        description: "Organization settings, applications and environments",
        icon: "settings",
        label: "Settings",
        tabs: [
          { description: "Organization, appearance, this server and data handling", label: "General", to: "/settings" },
          { description: "Applications and their environments", label: "Applications", to: "/applications" }
        ],
        to: "/settings"
      }
    ]
  }
];

const allAreas = [...environmentNavigation, ...organizationNavigation].flatMap((group) => group.areas);

/** The sidebar area that owns a path, if any. */
export function areaForPath(pathname: string): NavArea | undefined {
  return allAreas.find((area) => area.to === pathname || area.tabs?.some((tab) => tab.to === pathname));
}

/** Pages where the application and environment crumbs are not used, so the header dims them. */
export function isOrganizationPath(pathname: string): boolean {
  return organizationNavigation.some((group) => group.areas.some((area) => area.to === pathname || area.tabs?.some((tab) => tab.to === pathname)));
}

export interface Command {
  description: string;
  label: string;
  /** Where the destination lives, e.g. "Analytics". */
  section?: string;
  to: ConsoleRoute;
}

/** Every navigable destination, for the command palette. Commands only navigate; they never perform actions. */
/** Pages reached from the account menu rather than the sidebar. */
const accountCommands: readonly Command[] = [
  { description: "Your profile, password and console sessions", label: "Your account", to: "/account" }
];

export const commands: readonly Command[] = [
  ...allAreas.flatMap((area): Command[] =>
    area.tabs
      ? area.tabs.map((tab) => ({ description: tab.description, label: tab.label, section: area.label, to: tab.to }))
      : [{ description: area.description, label: area.label, to: area.to }]
  ),
  ...accountCommands
];

/** Paths kept only to redirect pre-redesign links to their new home. */
export const LEGACY_REDIRECT_PATHS: readonly string[] = ["/latency", "/errors", "/attestation-failures", "/access-policies", "/abuse-controls", "/environments"];

/**
 * The search a shell link carries to another page: only the workspace scope. Page selections such as a feature, a
 * tab or request filters belong to the page that set them and must not reopen something on the next page.
 */
export function scopeSearch(previous: Readonly<Record<string, unknown>>): { application?: string; environment?: string; organization?: string } {
  const pick = (key: "application" | "environment" | "organization") => (typeof previous[key] === "string" && previous[key] ? { [key]: previous[key] } : {});
  return { ...pick("organization"), ...pick("application"), ...pick("environment") };
}
