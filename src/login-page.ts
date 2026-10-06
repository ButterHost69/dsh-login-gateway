/**
 * Server-rendered login pages.
 *
 * The pages are plain HTML with inline CSS and no scripts or external
 * resources, so the gateway can serve them under a restrictive
 * `Content-Security-Policy` and needs no client bundle of its own.
 *
 * @module dsh-login-gateway/login-page
 */

/** Inputs for the login form. */
export interface LoginPageOptions {
  /** Product name shown in the title and heading. */
  readonly issuer: string
  /** Form action path. */
  readonly loginPath: string
  /** Post-login path preserved across the form, when it is a safe local path. */
  readonly next?: string | undefined
  /** Value to prefill in the username field. */
  readonly username?: string | undefined
  /** Error banner text. */
  readonly error?: string | undefined
  /** Informational banner text. */
  readonly notice?: string | undefined
  /** Expected OTP length. */
  readonly digits: number
}

/** Inputs for a standalone notice page. */
export interface NoticePageOptions {
  /** Product name shown in the title and heading. */
  readonly issuer: string
  /** Page heading. */
  readonly title: string
  /** Page body text. */
  readonly message: string
  /** Optional link back to the login form. */
  readonly loginPath?: string | undefined
  /** Optional HTTP status the caller is about to send, used for the heading tone. */
  readonly tone?: 'info' | 'error' | undefined
}

/** Inputs for the first-run setup form. */
export interface SetupPageOptions {
  /** Product name shown in the title and heading. */
  readonly issuer: string
  /** Form action path. */
  readonly loginPath: string
  /** Error banner text. */
  readonly error?: string | undefined
  /** Value to prefill in the username field. */
  readonly username?: string | undefined
  /** Minimum accepted password length, stated on the form. */
  readonly minPasswordLength: number
}

/** Inputs for the enrollment page shown once, right after setup. */
export interface EnrollmentPageOptions {
  /** Product name shown in the title and heading. */
  readonly issuer: string
  /** Sign-in path the user continues to. */
  readonly loginPath: string
  /** The account that was just created. */
  readonly username: string
  /** Base32 TOTP secret to enter in the authenticator app. */
  readonly secret: string
  /** `otpauth://` enrollment URI. */
  readonly uri: string
}

/** Inputs for the refusal shown on every other path while no account exists. */
export interface UnconfiguredPageOptions {
  /** Product name shown in the title and heading. */
  readonly issuer: string
  /** Path that serves the setup form. */
  readonly loginPath: string
}

/**
 * Escape text for an HTML text or quoted-attribute position.
 * @param value - untrusted text.
 * @returns the escaped text.
 */
export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll('\'', '&#39;')
}

const STYLE = `
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#ffffff; --fg:#14161a; --muted:#5b6472;
  --line:#dfe3e8; --accent:#4d6bfe; --accent-fg:#ffffff; --danger:#b42318; --danger-bg:#fef3f2; }
@media (prefers-color-scheme: dark) { :root { --bg:#0e1013; --card:#171a1f; --fg:#eceff3; --muted:#9aa4b2;
  --line:#2a2f37; --danger:#f97066; --danger-bg:#2a1512; } }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px;
  background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { width:100%; max-width:380px; background:var(--card); border:1px solid var(--line); border-radius:14px;
  padding:28px; box-shadow:0 12px 32px rgb(0 0 0 / 8%); }
h1 { margin:0 0 4px; font-size:19px; }
p.sub { margin:0 0 20px; color:var(--muted); font-size:13px; }
label { display:block; margin:0 0 6px; font-size:13px; font-weight:600; }
input { width:100%; margin:0 0 16px; padding:10px 12px; border:1px solid var(--line); border-radius:9px;
  background:transparent; color:inherit; font:inherit; }
input:focus { outline:2px solid var(--accent); outline-offset:1px; border-color:transparent; }
button { width:100%; padding:11px 12px; border:0; border-radius:9px; background:var(--accent);
  color:var(--accent-fg); font:inherit; font-weight:600; cursor:pointer; }
button:hover { filter:brightness(1.06); }
.banner { margin:0 0 16px; padding:10px 12px; border-radius:9px; font-size:13px; }
.banner.error { background:var(--danger-bg); color:var(--danger); }
.banner.notice { background:transparent; border:1px solid var(--line); color:var(--muted); }
footer { margin-top:18px; color:var(--muted); font-size:12px; text-align:center; }
`.trim()

function documentShell(options: {
  issuer: string
  title: string
  body: string
}): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(options.title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
${options.body}
</main>
</body>
</html>
`
}

/**
 * Render the login form.
 * @param options - branding, form target, prefills, and banners.
 * @returns the complete HTML document.
 */
export function renderLoginPage(options: LoginPageOptions): string {
  const banner = options.error !== undefined
    ? `<p class="banner error" role="alert">${escapeHtml(options.error)}</p>`
    : options.notice !== undefined
      ? `<p class="banner notice" role="status">${escapeHtml(options.notice)}</p>`
      : ''
  const next = options.next === undefined
    ? ''
    : `<input type="hidden" name="next" value="${escapeHtml(options.next)}">`
  const username = options.username === undefined ? '' : escapeHtml(options.username)
  return documentShell({
    issuer: options.issuer,
    title: `Sign in - ${options.issuer}`,
    body: `<h1>Sign in</h1>
<p class="sub">${escapeHtml(options.issuer)}</p>
${banner}<form method="post" action="${escapeHtml(options.loginPath)}" autocomplete="on">
${next}<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none"
 spellcheck="false" required autofocus value="${username}">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<label for="otp">Authenticator code</label>
<input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code"
 pattern="[0-9]*" maxlength="${options.digits}" minlength="${options.digits}" required>
<button type="submit">Sign in</button>
</form>
<footer>Protected by a one-time code from your authenticator app.</footer>`,
  })
}

/**
 * Render a standalone message page for refusals such as a lockout.
 * @param options - branding, heading, and message.
 * @returns the complete HTML document.
 */
export function renderNoticePage(options: NoticePageOptions): string {
  const link = options.loginPath === undefined
    ? ''
    : `<p class="sub"><a href="${escapeHtml(options.loginPath)}">Back to sign in</a></p>`
  return documentShell({
    issuer: options.issuer,
    title: `${options.title} - ${options.issuer}`,
    body: `<h1>${escapeHtml(options.title)}</h1>
<p class="banner ${options.tone === 'error' ? 'error' : 'notice'}" role="alert">${escapeHtml(options.message)}</p>
${link}`,
  })
}

/**
 * Render the first-run setup form, shown while no account exists.
 * @param options - branding, form target, and banners.
 * @returns the complete HTML document.
 */
export function renderSetupPage(options: SetupPageOptions): string {
  const banner = options.error === undefined
    ? ''
    : `<p class="banner error" role="alert">${escapeHtml(options.error)}</p>`
  const username = options.username === undefined ? '' : escapeHtml(options.username)
  return documentShell({
    issuer: options.issuer,
    title: `Set up ${options.issuer}`,
    body: `<h1>Create the first account</h1>
<p class="sub">No account exists yet, so this deployment is not serving the harness. Create one to continue; it is stored in the harness credential store.</p>
${banner}<form method="post" action="${escapeHtml(options.loginPath)}" autocomplete="on">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none"
 spellcheck="false" required autofocus value="${username}" pattern="[a-z][a-z0-9-]{1,31}">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="new-password"
 minlength="${options.minPasswordLength}" required>
<label for="confirm">Confirm password</label>
<input id="confirm" name="confirm" type="password" autocomplete="new-password"
 minlength="${options.minPasswordLength}" required>
<button type="submit">Create account</button>
</form>
<footer>Lowercase letters, digits, and hyphens; at least ${options.minPasswordLength} characters.</footer>`,
  })
}

/**
 * Render the one-time enrollment page: the secret to enter in an authenticator
 * app, shown immediately after setup creates the account.
 * @param options - the account, its secret, and its enrollment URI.
 * @returns the complete HTML document.
 */
export function renderEnrollmentPage(options: EnrollmentPageOptions): string {
  const grouped = options.secret.replace(/(.{4})/gu, '$1 ').trim()
  return documentShell({
    issuer: options.issuer,
    title: `Enroll ${options.username} - ${options.issuer}`,
    body: `<h1>Add the authenticator</h1>
<p class="sub">Enter this secret in your authenticator app now. It is shown once and cannot be recovered from the server.</p>
<label for="secret">Secret</label>
<input id="secret" type="text" value="${escapeHtml(grouped)}" readonly onfocus="this.select()">
<label for="uri">Enrollment URI</label>
<input id="uri" type="text" value="${escapeHtml(options.uri)}" readonly onfocus="this.select()">
<p class="banner notice">Account <strong>${escapeHtml(options.username)}</strong> created. Sign in with a code from the app to confirm enrollment.</p>
<p class="sub"><a href="${escapeHtml(options.loginPath)}">Continue to sign in</a></p>`,
  })
}

/**
 * Render the refusal shown on every path except the setup form while no
 * account exists.
 * @param options - branding and the setup path.
 * @returns the complete HTML document.
 */
export function renderUnconfiguredPage(options: UnconfiguredPageOptions): string {
  return documentShell({
    issuer: options.issuer,
    title: `Not configured - ${options.issuer}`,
    body: `<h1>Not configured</h1>
<p class="banner notice" role="alert">This deployment has no account yet, so it is not serving the harness. Create the first account at <code>${escapeHtml(options.loginPath)}</code> to continue.</p>
<p class="sub"><a href="${escapeHtml(options.loginPath)}">Set up the first account</a></p>`,
  })
}
