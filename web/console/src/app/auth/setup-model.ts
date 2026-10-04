import { acceptable, passwordStrength } from "./password-strength";

export interface SetupValues {
  bootstrap_token: string;
  display_name: string;
  email: string;
  organization_name: string;
  organization_slug: string;
  password: string;
}

/** Form order, so the first problem is the first field the operator reaches. */
export const SETUP_FIELDS = ["bootstrap_token", "organization_name", "organization_slug", "display_name", "email", "password"] as const;
export type SetupField = (typeof SETUP_FIELDS)[number];

export const SLUG_PATTERN = /^[a-z][a-z0-9_-]{0,62}$/;

/** A slug suggestion from a display name; the operator can still edit it. */
export function slugify(name: string): string {
  return name
    .normalize("NFKD")
    .replaceAll(/\p{M}/gu, "")
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/g, "-")
    .replace(/^[^a-z]+/, "")
    .replace(/-+$/, "")
    .slice(0, 63)
    .replace(/-+$/, "");
}

/** Every problem at once, keyed by field, mirroring the server's own limits. */
export function validateSetup(values: SetupValues): Partial<Record<SetupField, string>> {
  const problems: Partial<Record<SetupField, string>> = {};
  if (values.bootstrap_token.length < 32 || values.bootstrap_token.length > 2048) {
    problems.bootstrap_token = values.bootstrap_token ? "The token is 32 to 2048 characters. Copy it again from the server's environment." : "Paste the token from LATCHWAY_ADMIN_BOOTSTRAP_TOKEN.";
  }
  if (!values.organization_name.trim()) problems.organization_name = "Name your organization.";
  else if (values.organization_name.trim().length > 200) problems.organization_name = "Use 200 characters or fewer.";
  if (!SLUG_PATTERN.test(values.organization_slug)) {
    problems.organization_slug = values.organization_slug ? "Start with a letter; use lowercase letters, digits, hyphens and underscores, up to 63 characters." : "Choose a slug for URLs.";
  }
  if (!values.display_name.trim()) problems.display_name = "Enter your name.";
  else if (values.display_name.trim().length > 200) problems.display_name = "Use 200 characters or fewer.";
  const email = values.email.trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 320) problems.email = email ? "Enter a valid email address." : "Enter the email you'll sign in with.";
  const strength = passwordStrength(values.password);
  if (!acceptable(strength)) {
    problems.password = strength === "too-short" ? "Use at least 12 characters." : "Choose a stronger password: mix cases, numbers and symbols, or use a longer passphrase.";
  }
  return problems;
}

export type Platform = "compose" | "fly" | "ecs" | "cloud-run";

/** Display order of the platforms with token-removal steps. */
export const PLATFORMS: readonly Platform[] = ["compose", "fly", "ecs", "cloud-run"];

export const REMOVE_TOKEN_STEPS: Readonly<Record<Platform, { code: string; label: string; text: string }>> = {
  "cloud-run": {
    code: "gcloud run services update SERVICE --remove-env-vars LATCHWAY_ADMIN_BOOTSTRAP_TOKEN",
    label: "Cloud Run",
    text: "Remove the variable and deploy a new revision. If you mounted it from Secret Manager, use --remove-secrets instead."
  },
  compose: {
    code: "docker compose up -d",
    label: "Docker Compose",
    text: "Delete the LATCHWAY_ADMIN_BOOTSTRAP_TOKEN line from your Compose or .env file, then recreate the container."
  },
  ecs: {
    code: "aws ecs update-service --cluster CLUSTER --service SERVICE --task-definition FAMILY",
    label: "Amazon ECS",
    text: "Delete LATCHWAY_ADMIN_BOOTSTRAP_TOKEN from the task definition's environment or secrets, register the new revision, then roll the service onto it."
  },
  fly: {
    code: "fly secrets unset LATCHWAY_ADMIN_BOOTSTRAP_TOKEN",
    label: "Fly.io",
    text: "Unset the secret; Fly restarts the machines without it."
  }
};
