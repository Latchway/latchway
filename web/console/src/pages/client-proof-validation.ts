export type ConsoleEnvironmentKind = "development" | "staging" | "production";

const appleBundleIDPattern = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{1,253}[A-Za-z0-9])$/;
const appleBundleVersionPattern = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,126}[A-Za-z0-9])?$/;
const androidPackagePattern = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/;
const canonicalHostnameLabelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const maximumUint64 = 18_446_744_073_709_551_615n;

export function requireAppleBundleID(value: string | undefined): string {
  if (!value || value.length < 3 || value.length > 255 || !appleBundleIDPattern.test(value) ||
    value.includes("..") || value.includes(".-") || value.includes("-.")) {
    throw new Error("Bundle ID must be 3 through 255 canonical App Attest characters without empty or hyphen-adjacent labels.");
  }
  return value;
}

export function requireAppleBundleVersion(value: string | undefined): string {
  if (!value || value.length > 128 || !appleBundleVersionPattern.test(value) || value.includes("..")) {
    throw new Error("CFBundleVersion must be 1 through 128 canonical characters without empty labels.");
  }
  return value;
}

export function requireAndroidPackageName(value: string | undefined): string {
  if (!value || value.length < 3 || value.length > 255 || !androidPackagePattern.test(value)) {
    throw new Error("Android package name must be a canonical 3 through 255 character package identifier.");
  }
  return value;
}

export function requirePlayCertificateDigest(value: string | undefined): string {
  if (!value || !/^[A-Za-z0-9_-]{43}(?:=)?$/.test(value)) {
    throw new Error("Signing-certificate digest must be one canonical base64url-encoded SHA-256 value.");
  }
  try {
    const unpadded = value.endsWith("=") ? value.slice(0, -1) : value;
    const binary = atob(unpadded.replaceAll("-", "+").replaceAll("_", "/") + "=");
    const canonical = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    if (binary.length !== 32 || canonical !== unpadded || [...binary].every((character) => character.charCodeAt(0) === 0)) {
      throw new Error("invalid digest");
    }
  } catch {
    throw new Error("Signing-certificate digest must be a nonzero canonical base64url-encoded SHA-256 value.");
  }
  return value;
}

export function requireFirebaseProjectNumber(value: string | undefined): string {
  if (!value || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > maximumUint64) {
    throw new Error("Firebase project number must be a canonical unsigned 64-bit decimal value.");
  }
  return value;
}

export function requireCloudProjectNumber(value: number | undefined): number {
  if (value === undefined || !Number.isSafeInteger(value) || !/^[1-9][0-9]{5,18}$/.test(String(value))) {
    throw new Error("Cloud project number must contain 6 through 19 canonical decimal digits within the exact integer range.");
  }
  return value;
}

function canonicalHostname(hostname: string): boolean {
  if (hostname.startsWith("[") && hostname.endsWith("]")) return true;
  if (/^[0-9.]+$/u.test(hostname)) {
    const octets = hostname.split(".");
    return octets.length === 4 && octets.every((octet) =>
      /^(?:0|[1-9][0-9]{0,2})$/u.test(octet) && Number(octet) <= 255
    );
  }
  return hostname.length <= 253 && !hostname.endsWith(".") && !hostname.includes("..") &&
    hostname.split(".").every((label) => canonicalHostnameLabelPattern.test(label));
}

export function requireCanonicalBrowserOrigin(value: string | undefined, environmentKind: ConsoleEnvironmentKind): URL {
  if (!value || value.length > 2048 || [...value].some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x20 || code >= 0x7f || character === ",";
  })) {
    throw new Error("Enter an exact canonical browser origin.");
  }
  let origin: URL;
  try {
    origin = new URL(value);
  } catch {
    throw new Error("Enter an exact canonical browser origin.");
  }
  const loopback = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]).has(origin.hostname);
  const port = origin.port;
  const canonicalPort = port === "" || (/^[1-9][0-9]{0,4}$/u.test(port) && Number(port) <= 65_535);
  if (origin.origin !== value || origin.username || origin.password || origin.search || origin.hash ||
    !canonicalPort || !canonicalHostname(origin.hostname) ||
    (origin.protocol !== "https:" && !(environmentKind === "development" && origin.protocol === "http:" && loopback))) {
    throw new Error("Browser origin must be exact canonical HTTPS, or exact loopback HTTP in Development.");
  }
  return origin;
}

export function requireTurnstileHostname(hostname: string): string {
  if (hostname.length > 253 || !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/u.test(hostname) ||
    !canonicalHostname(hostname)) {
    throw new Error("Turnstile requires a canonical lowercase DNS hostname.");
  }
  return hostname;
}

export function requireGuidedUpstreamURL(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Upstream URL must be an absolute HTTPS URL.");
  }
  const path = parsed.pathname;
  const canonicalPath = path.length <= 2048 && !path.includes("//") && !path.includes("\\") && !path.includes("%") &&
    !path.split("/").some((segment) => segment === "." || segment === "..") &&
    [...path].every((character) => character.charCodeAt(0) >= 0x20 && character.charCodeAt(0) < 0x7f);
  const canonicalPort = parsed.port === "" || (/^[1-9][0-9]{0,4}$/u.test(parsed.port) && Number(parsed.port) <= 65_535);
  const canonicalValue = parsed.href.replace(/\/$/u, "");
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash ||
    value.includes("?") || value.includes("#") || !canonicalPath || !canonicalPort ||
    !canonicalHostname(parsed.hostname) || canonicalValue !== value) {
    throw new Error("Upstream URL must be exact canonical HTTPS without credentials, a query, a fragment, or a normalized path or host alias.");
  }
  return canonicalValue;
}
