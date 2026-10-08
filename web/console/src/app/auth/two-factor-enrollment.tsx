import { useQueryClient } from "@tanstack/react-query";

import type { AdminSession } from "../../api/auth";
import { consoleSessionQueryOptions } from "../../api/session";
import { Button } from "../../ui";
import { AuthLayout } from "./auth-layout";
import { TotpSetup } from "./totp-setup";

/**
 * Shown instead of the console when the organization requires a second factor this administrator hasn't set up: the
 * server allows nothing else until they do.
 */
export function TwoFactorEnrollmentScreen({ onSignOut, session }: { onSignOut: () => void; session: AdminSession }) {
  const queryClient = useQueryClient();
  return (
    <AuthLayout description={`Your organization requires two-factor sign-in for ${session.administrator.email}. Set up an authenticator app to continue.`} title="Set up two-factor sign-in">
      <TotpSetup onDone={() => void queryClient.invalidateQueries({ exact: true, queryKey: consoleSessionQueryOptions.queryKey })} />
      <Button className="lw-auth__link" onClick={onSignOut} size="sm" variant="ghost">Sign out</Button>
    </AuthLayout>
  );
}
