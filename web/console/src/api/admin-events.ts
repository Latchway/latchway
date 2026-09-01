import { z } from "zod";

import { queryPath } from "./admin";

export const adminEventTopics = [
  "requests",
  "usage",
  "configuration",
  "audit",
  "self_tests",
  "health"
] as const;

export type AdminEventTopic = (typeof adminEventTopics)[number];
export type AdminEventStreamState = "connected" | "reconnecting" | "unavailable";

const AdminEventTopicSchema = z.enum(adminEventTopics);
const AdminEventReadySchema = z
  .object({
    stream_version: z.literal(1),
    topics: z.array(AdminEventTopicSchema).max(adminEventTopics.length)
  })
  .strict();
const AdminEventRefreshSchema = z
  .object({ topics: z.array(AdminEventTopicSchema).min(1).max(adminEventTopics.length) })
  .strict();
const AdminEventUnavailableSchema = z.object({ retry: z.literal(true) }).strict();
const AdminEventReconnectSchema = z.object({ reauthenticate: z.literal(true) }).strict();

export interface AdminEventSourceLike {
  addEventListener(type: string, listener: EventListener): void;
  close(): void;
  removeEventListener(type: string, listener: EventListener): void;
}

export type AdminEventSourceFactory = (url: string) => AdminEventSourceLike;

export interface OpenAdminEventStreamOptions {
  environmentID?: string;
  eventSourceFactory?: AdminEventSourceFactory;
  onState?: (state: AdminEventStreamState) => void;
  onTopics: (topics: readonly AdminEventTopic[]) => void;
}

export interface AdminEventStreamConnection {
  close(): void;
}

function parseEvent<T>(event: Event, schema: z.ZodType<T>): T | undefined {
  if (!(event instanceof MessageEvent) || typeof event.data !== "string" || event.data.length > 4096) {
    return undefined;
  }
  try {
    return schema.parse(JSON.parse(event.data));
  } catch {
    return undefined;
  }
}

export function openAdminEventStream(options: OpenAdminEventStreamOptions): AdminEventStreamConnection {
  const sourceFactory = options.eventSourceFactory ?? ((url) => new EventSource(url));
  const source = sourceFactory(queryPath("/admin/v1/events", {
    environment_id: options.environmentID
  }));

  const ready: EventListener = (event) => {
    const document = parseEvent(event, AdminEventReadySchema);
    if (!document) return;
    options.onState?.("connected");
    options.onTopics(document.topics);
  };
  const refresh: EventListener = (event) => {
    const document = parseEvent(event, AdminEventRefreshSchema);
    if (document) options.onTopics(document.topics);
  };
  const unavailable: EventListener = (event) => {
    if (parseEvent(event, AdminEventUnavailableSchema)) options.onState?.("unavailable");
  };
  const reconnect: EventListener = (event) => {
    if (parseEvent(event, AdminEventReconnectSchema)) options.onState?.("reconnecting");
  };
  const error: EventListener = () => options.onState?.("reconnecting");

  source.addEventListener("ready", ready);
  source.addEventListener("refresh", refresh);
  source.addEventListener("unavailable", unavailable);
  source.addEventListener("reconnect", reconnect);
  source.addEventListener("error", error);

  return {
    close() {
      source.removeEventListener("ready", ready);
      source.removeEventListener("refresh", refresh);
      source.removeEventListener("unavailable", unavailable);
      source.removeEventListener("reconnect", reconnect);
      source.removeEventListener("error", error);
      source.close();
    }
  };
}

export function startAdminEventFallback(
  onTopics: (topics: readonly AdminEventTopic[]) => void,
  intervalMilliseconds = 15_000
): AdminEventStreamConnection {
  if (!Number.isSafeInteger(intervalMilliseconds) || intervalMilliseconds < 5_000) {
    throw new Error("The administrative refresh interval must be at least five seconds.");
  }
  const interval = window.setInterval(() => {
    if (document.visibilityState === "visible") onTopics(adminEventTopics);
  }, intervalMilliseconds);
  return { close: () => window.clearInterval(interval) };
}

export const adminRefreshEventName = "latchway:admin-refresh";

export function dispatchAdminRefresh(topics: readonly AdminEventTopic[]): void {
  window.dispatchEvent(new CustomEvent<readonly AdminEventTopic[]>(adminRefreshEventName, { detail: topics }));
}

export function subscribeAdminRefreshTopic(topic: AdminEventTopic, listener: () => void): () => void {
  const receive = (event: Event): void => {
    if (event instanceof CustomEvent && Array.isArray(event.detail) && event.detail.includes(topic)) listener();
  };
  window.addEventListener(adminRefreshEventName, receive);
  return () => window.removeEventListener(adminRefreshEventName, receive);
}
