/**
 * Server-rendered login pages.
 *
 * The pages are plain HTML with inline CSS and no scripts or external
 * resources, so the gateway can serve them under a restrictive
 * `Content-Security-Policy` and needs no client bundle of its own. The visual
 * language follows the harness settings dialogs: a centered surface, a quiet
 * header, and one clear primary action.
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

const LOCK_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
 stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<rect x="5" y="10" width="14" height="10" rx="2.5"></rect>
<path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"></path>
</svg>`

const STYLE = `
:root {
  color-scheme: light dark;
  --page: #f3f5f8;
  --glow: rgb(65 118 230 / 10%);
  --card: #ffffff;
  --fg: #0f1115;
  --muted: #61666d;
  --tertiary: #81858c;
  --line: rgb(0 0 0 / 10%);
  --line-strong: rgb(0 0 0 / 16%);
  --field: #ffffff;
  --field-hover: rgb(38 49 72 / 4%);
  --button: #0f1115;
  --button-hover: #43454a;
  --button-fg: #ffffff;
  --error: #b42318;
  --error-bg: #fef3f2;
  --notice-bg: #f9fafb;
  --brand: #4176e6;
  --brand-bg: rgb(65 118 230 / 10%);
  --focus: rgb(65 118 230 / 32%);
  --shadow: 0 24px 64px rgb(15 17 21 / 12%), 0 2px 8px rgb(15 17 21 / 4%);
  --radius: 28px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --page: #151517;
    --glow: rgb(86 134 254 / 10%);
    --card: #2c2c2e;
    --fg: #f2f3f5;
    --muted: #a2a6ad;
    --tertiary: #8f939a;
    --line: rgb(255 255 255 / 12%);
    --line-strong: rgb(255 255 255 / 16%);
    --field: #232325;
    --field-hover: rgb(255 255 255 / 5%);
    --button: #f2f3f5;
    --button-hover: #d9dadd;
    --button-fg: #0f1115;
    --error: #ff8a80;
    --error-bg: rgb(242 90 90 / 12%);
    --notice-bg: rgb(255 255 255 / 4%);
    --brand: #7aaaff;
    --brand-bg: rgb(122 170 255 / 12%);
    --focus: rgb(122 170 255 / 38%);
    --shadow: 0 24px 64px rgb(0 0 0 / 36%), 0 2px 8px rgb(0 0 0 / 20%);
  }
}
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  padding: 32px 20px;
  background: var(--page);
  color: var(--fg);
  font: 14px/22px -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
    "Hiragino Sans GB", "Microsoft YaHei", "Helvetica Neue", Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    radial-gradient(720px 420px at 50% -10%, var(--glow), transparent 70%),
    radial-gradient(560px 420px at 100% 110%, var(--glow), transparent 72%);
}
main {
  position: relative;
  z-index: 1;
  width: min(400px, 100%);
  margin: auto;
  padding: 28px;
  border: 0.5px solid var(--line-strong);
  border-radius: var(--radius);
  background: var(--card);
  box-shadow: var(--shadow);
  animation: card-in 180ms cubic-bezier(0.4, 0, 0.2, 1);
}
@keyframes card-in {
  from { opacity: 0; transform: translateY(4px) scale(0.995); }
  to { opacity: 1; transform: none; }
}
@media (prefers-reduced-motion: reduce) {
  main { animation: none; }
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 22px;
  color: var(--muted);
  font-size: 13px;
  line-height: 18px;
  font-weight: 500;
}
.brand-mark {
  display: inline-flex;
  flex: none;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 10px;
  background: var(--brand-bg);
  color: var(--brand);
}
.brand-mark svg { width: 17px; height: 17px; }
.brand-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
h1 {
  margin: 0;
  font-size: 20px;
  line-height: 28px;
  font-weight: 500;
  letter-spacing: -0.01em;
}
p { margin: 0; }
.sub {
  margin: 6px 0 22px;
  color: var(--muted);
  font-size: 14px;
  line-height: 22px;
}
.banner {
  margin: 0 0 18px;
  padding: 11px 13px;
  border-radius: 12px;
  font-size: 13px;
  line-height: 19px;
  overflow-wrap: anywhere;
}
h1 + .banner { margin-top: 20px; }
.banner.error {
  background: var(--error-bg);
  color: var(--error);
}
.banner.notice {
  border: 0.5px solid var(--line);
  background: var(--notice-bg);
  color: var(--muted);
}
form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
label {
  color: var(--fg);
  font-size: 13px;
  line-height: 18px;
  font-weight: 500;
}
input {
  width: 100%;
  height: 40px;
  padding: 0 12px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--field);
  color: var(--fg);
  font: inherit;
  transition: border-color 120ms ease, box-shadow 120ms ease, background-color 120ms ease;
}
input:hover { background: var(--field-hover); }
input:focus {
  outline: none;
  border-color: var(--brand);
  box-shadow: 0 0 0 3px var(--focus);
}
input[readonly] {
  cursor: text;
  text-overflow: ellipsis;
  color: var(--muted);
  font-family: "SF Mono", "JetBrains Mono", "Fira Code", Consolas, "Liberation Mono",
    Menlo, Courier, monospace;
  font-size: 12px;
}
.field-hint {
  color: var(--tertiary);
  font-size: 12px;
  line-height: 18px;
}
button, .button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 40px;
  padding: 0 16px;
  border: 0;
  border-radius: 12px;
  background: var(--button);
  color: var(--button-fg);
  font: inherit;
  font-size: 14px;
  line-height: 22px;
  font-weight: 500;
  text-decoration: none;
  cursor: pointer;
  transition: background-color 120ms ease, opacity 120ms ease;
}
button:hover, .button:hover { background: var(--button-hover); }
button:focus-visible, .button:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}
.button.secondary {
  border: 0.5px solid var(--line-strong);
  background: transparent;
  color: var(--fg);
}
.button.secondary:hover { background: var(--field-hover); }
.hint {
  margin-top: 18px;
  color: var(--tertiary);
  font-size: 12px;
  line-height: 18px;
  text-align: center;
}
a { color: var(--brand); text-underline-offset: 3px; }
a:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
  border-radius: 4px;
}
code {
  padding: 1px 5px;
  border-radius: 5px;
  background: var(--notice-bg);
  font-family: "SF Mono", "JetBrains Mono", "Fira Code", Consolas, "Liberation Mono",
    Menlo, Courier, monospace;
  font-size: 0.92em;
}
@media (max-width: 480px) {
  body { padding: 16px; }
  main { padding: 22px; border-radius: 22px; }
}
`.trim()

function brand(issuer: string): string {
  return `<div class="brand">
<span class="brand-mark">${LOCK_ICON}</span>
<span class="brand-name">${escapeHtml(issuer)}</span>
</div>`
}

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
<main aria-labelledby="page-title">
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
    body: `${brand(options.issuer)}
<h1 id="page-title">Sign in</h1>
<p class="sub">Use your account and a one-time code from your authenticator app to continue.</p>
${banner}<form method="post" action="${escapeHtml(options.loginPath)}" autocomplete="on">
${next}<div class="field">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none"
 spellcheck="false" required autofocus value="${username}">
</div>
<div class="field">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
</div>
<div class="field">
<label for="otp">Authenticator code</label>
<input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code"
 pattern="[0-9]*" maxlength="${options.digits}" minlength="${options.digits}" required>
<span class="field-hint">Open your authenticator app for a ${options.digits}-digit code.</span>
</div>
<button type="submit">Sign in</button>
</form>
<p class="hint">Protected by a one-time code from your authenticator app.</p>`,
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
    : `<a class="button secondary" href="${escapeHtml(options.loginPath)}">Back to sign in</a>`
  return documentShell({
    issuer: options.issuer,
    title: `${options.title} - ${options.issuer}`,
    body: `${brand(options.issuer)}
<h1 id="page-title">${escapeHtml(options.title)}</h1>
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
    body: `${brand(options.issuer)}
<h1 id="page-title">Create the first account</h1>
<p class="sub">No account exists yet, so this deployment is not serving the harness. Create one to continue. It is stored in the harness credential store.</p>
${banner}<form method="post" action="${escapeHtml(options.loginPath)}" autocomplete="on">
<div class="field">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none"
 spellcheck="false" required autofocus value="${username}" pattern="[a-z][a-z0-9-]{1,31}">
<span class="field-hint">Lowercase letters, digits, and hyphens; start with a letter.</span>
</div>
<div class="field">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="new-password"
 minlength="${options.minPasswordLength}" required>
<span class="field-hint">Use at least ${options.minPasswordLength} characters.</span>
</div>
<div class="field">
<label for="confirm">Confirm password</label>
<input id="confirm" name="confirm" type="password" autocomplete="new-password"
 minlength="${options.minPasswordLength}" required>
</div>
<button type="submit">Create account</button>
</form>
<p class="hint">Next you will add the account to an authenticator app.</p>`,
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
    body: `${brand(options.issuer)}
<h1 id="page-title">Add the authenticator</h1>
<p class="sub">Enter this secret in your authenticator app now. It is shown once and cannot be recovered from the server.</p>
<div class="field">
<label for="secret">Secret</label>
<input id="secret" type="text" value="${escapeHtml(grouped)}" readonly>
</div>
<div class="field">
<label for="uri">Enrollment URI</label>
<input id="uri" type="text" value="${escapeHtml(options.uri)}" readonly>
</div>
<p class="banner notice">Account <strong>${escapeHtml(options.username)}</strong> created. Sign in with a code from the app to confirm enrollment.</p>
<a class="button" href="${escapeHtml(options.loginPath)}">Continue to sign in</a>`,
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
    body: `${brand(options.issuer)}
<h1 id="page-title">Not configured</h1>
<p class="banner notice" role="alert">This deployment has no account yet, so it is not serving the harness. Create the first account at <code>${escapeHtml(options.loginPath)}</code> to continue.</p>
<a class="button" href="${escapeHtml(options.loginPath)}">Set up the first account</a>`,
  })
}
