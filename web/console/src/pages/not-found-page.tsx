import { Link } from "@tanstack/react-router";

export function NotFoundPage() {
  return (
    <section className="empty-state">
      <p className="eyebrow">404</p>
      <h1>This console route does not exist.</h1>
      <p>Return to the gateway overview or inspect the system health endpoints.</p>
      <Link className="primary-action" to="/">
        Return to overview
        <span aria-hidden="true">→</span>
      </Link>
    </section>
  );
}
