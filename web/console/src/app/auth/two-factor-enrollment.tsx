import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { type AdminSession, adminSignInInfoQueryOptions } from "../../api/auth";
import { consoleSessionQueryOptions } from "../../api/session";
import { passkeysAvailable } from "../../api/webauthn";
import { Button } from "../../ui";
import { AuthLayout } from "./auth-layout";
import { AddPasskeyDialog } from "./passkey-setup";
import { TotpSetup } from "./totp-setup";

/**
 * Shown instead of the console when the organization requires a second factor this administrator hasn't set up: the
 * server allows nothing else until they do. A passkey is offered when the server and this browser can use one.
 */
export function TwoFactorEnrollmentScreen({ onSignOut, session }: { onSignOut: () => void; session: AdminSession }) {
  const queryClient = useQueryClient();
  const info = useQuery(adminSignInInfoQueryOptions);
  const [addingPasskey, setAddingPasskey] = useState(false);
  const passkeys = (info.data?.sign_in_methods.includes("passkey") ?? false) && passkeysAvailable();
  const done = () => void queryClient.invalidateQueries({ exact: true, queryKey: consoleSessionQueryOptions.queryKey });
  return (
    <AuthLayout description={`Your organization requires two-factor sign-in for ${session.administrator.email}. Set up ${passkeys ? "a passkey or an authenticator app" : "an authenticator app"} to continue.`} title="Set up two-factor sign-in">
      {passkeys ? <Button className="lw-auth__submit" icon="key" onClick={() => setAddingPasskey(true)} variant="primary">Add a Passkey</Button> : null}
      <TotpSetup onDone={done} />
      {addingPasskey ? <AddPasskeyDialog onCancel={() => setAddingPasskey(false)} onDone={() => { setAddingPasskey(false); done(); }} suggestedName="Passkey 1" /> : null}
      <Button className="lw-auth__link" onClick={onSignOut} size="sm" variant="ghost">Sign out</Button>
    </AuthLayout>
  );
}
