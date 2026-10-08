import { Link } from "@tanstack/react-router";

import { buttonClass, EmptyState } from "../ui";

export function NotFoundPage() {
  return (
    <div className="lw-page-notice">
      <EmptyState
        action={<Link className={buttonClass({ variant: "primary" })} to="/">Go to Overview</Link>}
        icon="search"
        title="This console page doesn't exist."
        titleAs="h1"
      >
        The address may be from an older console. Use the sidebar or search to find the page you need.
      </EmptyState>
    </div>
  );
}
