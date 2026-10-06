import { describe, expect, it } from 'vitest'
import { escapeHtml, renderEnrollmentPage, renderLoginPage, renderNoticePage, renderSetupPage, renderUnconfiguredPage } from '../src/login-page.ts'

describe('escapeHtml', () => {
  it('escapes every markup-significant character', () => {
    expect(escapeHtml('<script>"x" & \'y\'</script>'))
      .toBe('&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;')
  })
})

describe('renderLoginPage', () => {
  it('renders the three credential fields and the form target', () => {
    const html = renderLoginPage({ issuer: 'Harness', loginPath: '/login', digits: 6 })
    expect(html).toContain('action="/login"')
    expect(html).toContain('name="username"')
    expect(html).toContain('name="password"')
    expect(html).toContain('name="otp"')
    expect(html).toContain('autocomplete="one-time-code"')
    expect(html).toContain('maxlength="6"')
    expect(html).toContain('Sign in')
  })

  it('escapes untrusted values and keeps the next path hidden', () => {
    const html = renderLoginPage({
      issuer: 'Harness',
      loginPath: '/login',
      digits: 8,
      username: '"><script>alert(1)</script>',
      error: '<b>bad</b>',
      next: '/api/sessions?x=1&y=2',
    })
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).not.toContain('<b>bad</b>')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
    expect(html).toContain('value="/api/sessions?x=1&amp;y=2"')
    expect(html).toContain('maxlength="8"')
  })

  it('omits the hidden next field and the banner when unset', () => {
    const html = renderLoginPage({ issuer: 'Harness', loginPath: '/login', digits: 6 })
    expect(html).not.toContain('name="next"')
    expect(html).not.toContain('class="banner')
  })

  it('renders a notice instead of an error when asked', () => {
    const html = renderLoginPage({
      issuer: 'Harness',
      loginPath: '/login',
      digits: 6,
      notice: 'Signed out.',
    })
    expect(html).toContain('banner notice')
    expect(html).toContain('Signed out.')
  })
})

describe('renderNoticePage', () => {
  it('links back to the login form and escapes its message', () => {
    const html = renderNoticePage({
      issuer: 'Harness',
      title: 'Too many attempts',
      message: 'Try again in 30 seconds. <b>',
      loginPath: '/login',
      tone: 'error',
    })
    expect(html).toContain('Too many attempts')
    expect(html).toContain('href="/login"')
    expect(html).toContain('&lt;b&gt;')
    expect(html).toContain('banner error')
  })

  it('renders without a link when no login path is given', () => {
    const html = renderNoticePage({ issuer: 'Harness', title: 'No', message: 'Nope' })
    expect(html).not.toContain('<a href=')
  })
})

describe('renderSetupPage', () => {
  it('renders the three setup fields with the stated minimum', () => {
    const html = renderSetupPage({ issuer: 'Harness', loginPath: '/login', minPasswordLength: 12 })
    expect(html).toContain('action="/login"')
    expect(html).toContain('name="username"')
    expect(html).toContain('name="password"')
    expect(html).toContain('name="confirm"')
    expect(html).toContain('minlength="12"')
    expect(html).toContain('pattern="[a-z][a-z0-9-]{1,31}"')
    expect(html).toContain('at least 12 characters')
  })

  it('escapes the error and the prefilled username', () => {
    const html = renderSetupPage({
      issuer: 'Harness',
      loginPath: '/login',
      minPasswordLength: 12,
      username: '"><script>alert(1)</script>',
      error: '<b>nope</b>',
    })
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).not.toContain('<b>nope</b>')
    expect(html).toContain('banner error')
  })
})

describe('renderEnrollmentPage', () => {
  it('shows the grouped secret, the URI, and the account', () => {
    const html = renderEnrollmentPage({
      issuer: 'Harness',
      loginPath: '/login',
      username: 'alice',
      secret: 'ABCDEFGHIJKLMNOP',
      uri: 'otpauth://totp/Harness:alice?secret=ABCDEFGHIJKLMNOP&issuer=Harness',
    })
    expect(html).toContain('value="ABCD EFGH IJKL MNOP"')
    expect(html).toContain('otpauth://totp/Harness:alice?secret=ABCDEFGHIJKLMNOP&amp;issuer=Harness')
    expect(html).toContain('alice')
    expect(html).toContain('href="/login"')
  })

  it('escapes a hostile username', () => {
    const html = renderEnrollmentPage({
      issuer: 'Harness',
      loginPath: '/login',
      username: '<script>x</script>',
      secret: 'ABCD',
      uri: 'otpauth://totp/x',
    })
    expect(html).not.toContain('<script>x</script>')
  })
})

describe('renderUnconfiguredPage', () => {
  it('points at the setup path', () => {
    const html = renderUnconfiguredPage({ issuer: 'Harness', loginPath: '/login' })
    expect(html).toContain('Not configured')
    expect(html).toContain('href="/login"')
  })
})
