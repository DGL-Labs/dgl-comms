export type EmailKind = "verify" | "login" | "invite";

export interface EmailMessage {
  to: string;
  kind: EmailKind;
  token: string;
}

export interface EmailSender {
  send(message: EmailMessage): Promise<void>;
}

const SUBJECTS: Record<EmailKind, string> = {
  verify: "Verify your Pingzo account",
  login: "Your Pingzo sign-in link",
  invite: "You have been invited to Pingzo",
};

// The email text is fixed: only the token varies. An invitation carries no
// workspace name and no user text. A real provider (later) renders this and
// sends it.
export function renderEmail(
  kind: EmailKind,
  token: string,
): { subject: string; text: string } {
  const subject = SUBJECTS[kind];
  const lifetime = kind === "invite" ? "7 days" : "15 minutes";
  const text =
    `Your Pingzo ${kind} token: ${token}\n` +
    `It works once and expires in ${lifetime}.\n` +
    "If you did not ask for this, ignore this email.\n";
  return { subject, text };
}

// The only EmailSender in C-1b: records messages in memory for tests.
export class TestSink implements EmailSender {
  readonly messages: EmailMessage[] = [];

  send(message: EmailMessage): Promise<void> {
    this.messages.push(message);
    return Promise.resolve();
  }

  lastTo(email: string): EmailMessage | undefined {
    return this.messages.filter((m) => m.to === email).at(-1);
  }
}
