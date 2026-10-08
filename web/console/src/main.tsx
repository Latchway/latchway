import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { createAppRouter } from "./app/router";
import { applyStoredTheme } from "./app/theme";
// Fonts are bundled (OFL-1.1) and served same-origin: the console's CSP allows only 'self'.
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./ui/tokens.css";
import "./ui/base.css";
import "./ui/ui.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: true
    }
  }
});
applyStoredTheme();
const router = createAppRouter();
const container = document.querySelector<HTMLDivElement>("#root");

if (!container) {
  throw new Error("Latchway console root element is missing.");
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>
);
