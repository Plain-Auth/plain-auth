import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { customSessionClient } from "better-auth/client/plugins";
import { customSession } from "better-auth/plugins";

// A new public plugin option requires its own behavioral coverage.
const checkedOptions: Record<keyof NonNullable<Parameters<typeof customSession>[2]>, true> = {
  shouldMutateListDeviceSessionsEndpoint: true,
};
void checkedOptions;

const auth = betterAuth({
  plugins: [customSession(async ({ user }) => ({ viewer: user.email }))],
});
const browser = createAuthClient({ plugins: [customSessionClient<typeof auth>()] });

function acceptsViewer(value: { viewer: string }) {
  return value.viewer;
}
async function readViewer() {
  const result = await browser.getSession();
  if (!result.data) return null;
  // The configured projection is visible to the public client's type system.
  acceptsViewer(result.data);
  // @ts-expect-error The application projection omits the underlying credential.
  result.data.session.token;
  return result.data.viewer;
}
void readViewer;
