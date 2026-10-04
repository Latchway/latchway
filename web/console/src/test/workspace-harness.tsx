import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";

import { type HarnessOptions, WorkspaceHarness } from "./workspace-harness-provider";

export { ids, instant } from "./workspace-fixtures";
export type { HarnessOptions } from "./workspace-harness-provider";

/** Renders a page inside a fresh query client and a stateful workspace whose URL updates apply immediately. */
export function renderWithWorkspace(page: ReactNode, options: HarnessOptions = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const result = render(<QueryClientProvider client={queryClient}><WorkspaceHarness options={options}>{page}</WorkspaceHarness></QueryClientProvider>);
  return { ...result, queryClient, rerenderPage: (next: ReactNode) => result.rerender(<QueryClientProvider client={queryClient}><WorkspaceHarness options={options}>{next}</WorkspaceHarness></QueryClientProvider>) };
}

type Options = { bearerToken?: string; body?: unknown; etag?: string; method?: string } | undefined;

/** The mutating calls a mock received, as "METHOD path". */
export function mutationsOf(mock: { mock: { calls: unknown[][] } }): string[] {
  return mock.mock.calls.filter(([, , options]) => (options as Options)?.method).map(([path, , options]) => `${(options as Options)?.method} ${String(path)}`);
}
