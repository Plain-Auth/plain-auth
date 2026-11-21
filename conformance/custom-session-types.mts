import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { customSessionClient, inferAdditionalFields } from "better-auth/client/plugins";
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


// The published client can merge application projection fields with inferred fields.
const extended = betterAuth({
  user: { additionalFields: { department: { type: "string", required: false } } },
  plugins: [customSession(async ({user}) => ({user:{initial:user.name.slice(0,1)},visible:true}))],
});
const combined = createAuthClient({plugins:[customSessionClient<typeof extended>(), inferAdditionalFields<typeof extended>()]});
type Combined = typeof combined.$Infer.Session;
const acceptsCombined = (session:Combined):[string,string | null | undefined,boolean] =>
  [session.user.initial,session.user.department,session.visible];
void acceptsCombined;
