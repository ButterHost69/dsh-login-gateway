#!/usr/bin/env node
/**
 * Print a ready-to-paste user block for `cordis.patch.yml`.
 *
 * Usage:
 *   npm run build
 *   node scripts/enroll.mjs --username alice
 *
 * The password is read from a hidden prompt on a terminal, or from the first
 * line of stdin when piped; `DSH_LOGIN_PASSWORD` overrides both. The generated
 * block carries an scrypt hash and a fresh base32 TOTP secret, plus the
 * `otpauth://` URI to scan with an authenticator app.
 */

import { randomInt } from 'node:crypto'

const HELP = `Usage: node scripts/enroll.mjs --username <name> [options]

Options:
  --username <name>   Login name (required)
  --issuer <name>     Issuer shown in the authenticator app (default: DeepSeek Harness)
  --account <name>    Account label in the authenticator app (default: the username)
  --random            Generate a random password instead of prompting
  --help              Show this message
`

const PASSWORD_ALPHABET = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'

function parseArgs(argv) {
  const options = { issuer: 'DeepSeek Harness', random: false }
  for (let at = 0; at < argv.length; at += 1) {
    const flag = argv[at]
    if (flag === '--help' || flag === '-h') return { help: true }
    if (flag === '--random') {
      options.random = true
      continue
    }
    if (flag === '--username' || flag === '--issuer' || flag === '--account') {
      const value = argv[at + 1]
      if (value === undefined) throw new Error(`missing value for ${flag}`)
      options[flag.slice(2)] = value
      at += 1
      continue
    }
    throw new Error(`unknown option ${flag}`)
  }
  return options
}

/**
 * Read one line without echoing it. A piped stdin is read as its first line.
 * @param {string} label - prompt written to stdout on a terminal.
 * @returns {Promise<string>} the entered text.
 */
async function readHidden(label) {
  const stdin = process.stdin
  if (!stdin.isTTY) {
    const chunks = []
    for await (const chunk of stdin) chunks.push(chunk)
    return Buffer.concat(chunks).toString('utf8').split('\n')[0] ?? ''
  }
  return await new Promise((resolve) => {
    const bytes = []
    process.stdout.write(label)
    stdin.setRawMode(true)
    stdin.resume()
    const finish = () => {
      stdin.setRawMode(false)
      stdin.pause()
      stdin.off('data', onData)
      process.stdout.write('\n')
      resolve(Buffer.from(bytes).toString('utf8'))
    }
    const onData = (data) => {
      for (const byte of data) {
        if (byte === 0x0d || byte === 0x0a) {
          finish()
          return
        }
        if (byte === 0x03) {
          process.stdout.write('\n')
          process.exit(130)
        }
        if (byte === 0x7f || byte === 0x08) {
          bytes.pop()
          continue
        }
        if (byte >= 0x20) bytes.push(byte)
      }
    }
    stdin.on('data', onData)
  })
}

async function main() {
  let options
  try {
    options = parseArgs(process.argv.slice(2))
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}`)
    process.exitCode = 1
    return
  }
  if (options.help) {
    process.stdout.write(HELP)
    return
  }
  if (options.username === undefined || options.username.trim() === '') {
    process.stderr.write(`--username is required\n\n${HELP}`)
    process.exitCode = 1
    return
  }

  let hashPassword
  let generateTotpSecret
  let totpUri
  try {
    ({ hashPassword } = await import('../lib/password.js'))
    ;({ generateTotpSecret, totpUri } = await import('../lib/totp.js'))
  } catch {
    process.stderr.write('This script imports the built plugin. Run `npm run build` first.\n')
    process.exitCode = 1
    return
  }

  const username = options.username.trim()
  const password = options.random
    ? Array.from({ length: 24 }, () => PASSWORD_ALPHABET[randomInt(PASSWORD_ALPHABET.length)]).join('')
    : process.env.DSH_LOGIN_PASSWORD ?? await readHidden('Password: ')
  if (password === '') {
    process.stderr.write('Password must not be empty.\n')
    process.exitCode = 1
    return
  }

  const passwordHash = await hashPassword(password)
  const totpSecret = generateTotpSecret()
  const uri = totpUri({
    secret: totpSecret,
    account: options.account ?? username,
    issuer: options.issuer,
  })

  process.stdout.write('\nAdd this user under the login-gateway row\'s config in cordis.patch.yml:\n\n')
  process.stdout.write('        users:\n')
  process.stdout.write(`          - username: ${username}\n`)
  process.stdout.write(`            passwordHash: '${passwordHash}'\n`)
  process.stdout.write(`            totpSecret: '${totpSecret}'\n`)
  process.stdout.write('\nAuthenticator enrollment URI (add a new account by QR or manual entry):\n\n')
  process.stdout.write(`${uri}\n`)
  if (options.random) {
    process.stdout.write(`\nGenerated password: ${password}\nStore it now; it is not recoverable from the hash.\n`)
  }
  process.stdout.write('\n')
}

await main()
