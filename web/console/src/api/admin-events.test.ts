import { describe, expect, it, vi } from "vitest";

import {
  adminRefreshEventName,
  dispatchAdminRefresh,
  openAdminEventStream,
  startAdminEventFallback,
  subscribeAdminRefreshTopic,
  type AdminEventSourceLike
} from "./admin-events";

class FakeEventSource implements AdminEventSourceLike {
  readonly listeners = new Map<string, Set<EventListener>>();
  closed = false;

  addEventListener(type: string, listener: EventListener): void {
    const listeners = this.listeners.get(type) ?? new Set<EventListener>();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  close(): void {
    this.closed = true;
  }

  emit(type: string, data: unknown): void {
    const event = new MessageEvent(type, { data: typeof data === "string" ? data : JSON.stringify(data) });
    this.listeners.get(type)?.forEach((listener) => listener(event));
  }

  removeEventListener(type: string, listener: EventListener): void {
    this.listeners.get(type)?.delete(listener);
  }
}

describe("administrative live refresh", () => {
  it("opens an environment-scoped stream and accepts only the closed event contract", () => {
    const source = new FakeEventSource();
    const topics = vi.fn();
    const states = vi.fn();
    let requestedURL = "";
    const connection = openAdminEventStream({
      environmentID: "env_0123456789ABCDEFGHJKMNPQRS",
      eventSourceFactory: (url) => { requestedURL = url; return source; },
      onState: states,
      onTopics: topics
    });

    expect(requestedURL).toBe("/admin/v1/events?environment_id=env_0123456789ABCDEFGHJKMNPQRS");
    source.emit("ready", { stream_version: 1, topics: ["requests", "health"] });
    source.emit("refresh", { topics: ["requests", "usage"] });
    source.emit("refresh", { topics: ["requests"], credential: "must-be-rejected" });
    source.emit("refresh", { topics: ["unknown"] });
    source.emit("unavailable", { retry: true });
    source.emit("reconnect", { reauthenticate: true });
    source.emit("error", "");

    expect(topics.mock.calls).toEqual([[["requests", "health"]], [["requests", "usage"]]]);
    expect(states.mock.calls).toEqual([["connected"], ["unavailable"], ["reconnecting"], ["reconnecting"]]);

    connection.close();
    expect(source.closed).toBe(true);
    source.emit("refresh", { topics: ["audit"] });
    expect(topics).toHaveBeenCalledTimes(2);
  });

  it("dispatches only matching local refresh topics", () => {
    const requests = vi.fn();
    const usage = vi.fn();
    const unsubscribeRequests = subscribeAdminRefreshTopic("requests", requests);
    const unsubscribeUsage = subscribeAdminRefreshTopic("usage", usage);

    dispatchAdminRefresh(["requests", "health"]);
    expect(requests).toHaveBeenCalledTimes(1);
    expect(usage).not.toHaveBeenCalled();

    window.dispatchEvent(new CustomEvent(adminRefreshEventName, { detail: ["unknown"] }));
    expect(requests).toHaveBeenCalledTimes(1);
    unsubscribeRequests();
    unsubscribeUsage();
  });

  it("uses a bounded visible-page fallback and rejects aggressive polling", () => {
    vi.useFakeTimers();
    const topics = vi.fn();
    const connection = startAdminEventFallback(topics, 5_000);
    vi.advanceTimersByTime(5_000);
    expect(topics).toHaveBeenCalledWith(["requests", "usage", "configuration", "audit", "self_tests", "health"]);
    connection.close();
    vi.advanceTimersByTime(5_000);
    expect(topics).toHaveBeenCalledTimes(1);
    expect(() => startAdminEventFallback(topics, 1_000)).toThrow(/at least five seconds/);
    vi.useRealTimers();
  });
});
