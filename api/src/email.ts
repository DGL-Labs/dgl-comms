export type EmailKind = "verify" | "login";

export interface EmailMessage {
  to: string;
  kind: EmailKind;
  token: string;
}

export interface EmailSender {
  send(message: EmailMessage): Promise<void>;
}

// The email text is fixed: only the token varies. A real provider (later)
// renders this and sends it.
export function renderEmail(
  kind: EmailKind,
  token: string,
): { subject: string; text: string } {
  const subject =
    kind === "verify"
      ? "Verify your Pingzo account"
      : "Your Pingzo sign-in link";
  const text =
    `Your Pingzo ${kind} token: ${token}\n` +
    "It works once and expires in 15 minutes.\n" +
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
