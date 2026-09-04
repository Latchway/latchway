import { createContext, useContext } from "react";

import type { SystemStatus } from "../api/admin";
import type { ConsoleCompatibility } from "../api/console-compatibility";

export interface ConsoleCompatibilityState {
  compatibility?: ConsoleCompatibility;
  error: unknown;
  isFetching: boolean;
  mutationAllowed: boolean;
  refresh: () => Promise<SystemStatus | undefined>;
  status?: SystemStatus;
}

const absentCompatibilityState: ConsoleCompatibilityState = {
  error: undefined,
  isFetching: false,
  mutationAllowed: false,
  refresh: async () => undefined
};

export const ConsoleCompatibilityContext = createContext<ConsoleCompatibilityState>(absentCompatibilityState);

export function useConsoleCompatibility(): ConsoleCompatibilityState {
  return useContext(ConsoleCompatibilityContext);
}
