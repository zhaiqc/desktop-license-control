import { createPrivateKey, sign, verify, createPublicKey } from 'node:crypto'
import fs from 'node:fs'
import { pathToFileURL } from 'node:url'

const PREFIX = 'vmos-edge-license:v1\n'
export function issueLicense(control, privateKey, previous = null, now = Date.now()) {
  if (
    control?.productId !== 'vmos-edge-pools' ||
    typeof control.deploymentId !== 'string' ||
    !control.deploymentId
  )
    throw Error('Invalid deployment configuration')
  if (typeof control.enabled !== 'boolean') throw Error('Enabled must be a boolean')
  if (
    control.expiresAt !== null &&
    (!Number.isSafeInteger(control.expiresAt) || control.expiresAt <= 0)
  )
    throw Error('Invalid entitlement expiry')
  if (typeof control.reason !== 'string' || control.reason.length > 180)
    throw Error('Invalid license reason')
  const key = createPrivateKey(privateKey)
  if (key.asymmetricKeyType !== 'ed25519') throw Error('An Ed25519 signing key is required')
  let revision = 0
  if (previous) {
    if (
      !verify(
        null,
        Buffer.from(PREFIX + previous.payload),
        createPublicKey(key),
        Buffer.from(previous.signature, 'base64url')
      )
    )
      throw Error('Previous authorization signature is invalid')
    const policy = JSON.parse(Buffer.from(previous.payload, 'base64url').toString('utf8'))
    if (policy.deploymentId !== control.deploymentId || policy.productId !== control.productId)
      throw Error('Previous authorization belongs to a different deployment')
    revision = policy.revision
    if (!Number.isSafeInteger(revision) || revision < 1) throw Error('Invalid previous revision')
  }
  const policy = {
    schemaVersion: 1,
    productId: control.productId,
    deploymentId: control.deploymentId,
    revision: Math.max(now, revision + 1),
    enabled: control.enabled,
    issuedAt: now,
    validUntil: now + 6 * 60 * 60 * 1000,
    expiresAt: control.expiresAt,
    reason: control.reason
  }
  const payload = Buffer.from(JSON.stringify(policy)).toString('base64url')
  return {
    payload,
    signature: sign(null, Buffer.from(PREFIX + payload), key).toString('base64url')
  }
}

export function updateControl(control, action, expiry = '', reason = '') {
  const next = { ...control }
  if (!['renew', 'enable', 'disable'].includes(action)) throw Error('Unknown license action')
  if (action !== 'renew') {
    next.enabled = action === 'enable'
    next.reason = reason.trim() || (next.enabled ? '' : '软件使用授权已暂停，请联系提供方')
  }
  if (expiry.trim()) {
    if (expiry.trim().toLowerCase() === 'never') next.expiresAt = null
    else {
      if (!/T.*(?:Z|[+-]\d{2}:\d{2})$/.test(expiry.trim()))
        throw Error('Expiry must include a timezone, for example 2026-11-23T23:59:59+08:00')
      const value = Date.parse(expiry)
      if (!Number.isSafeInteger(value)) throw Error('Invalid expiry date')
      next.expiresAt = value
    }
  }
  return next
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const control = updateControl(
      JSON.parse(fs.readFileSync('control.json', 'utf8')),
      process.env.LICENSE_ACTION || 'renew',
      process.env.LICENSE_EXPIRES_AT || '',
      process.env.LICENSE_REASON || ''
    )
    const previous = fs.existsSync('license.json')
      ? JSON.parse(fs.readFileSync('license.json', 'utf8'))
      : null
    const envelope = issueLicense(control, process.env.LICENSE_SIGNING_KEY, previous)
    fs.writeFileSync('control.json', JSON.stringify(control, null, 2) + '\n')
    fs.writeFileSync('license.json', JSON.stringify(envelope, null, 2) + '\n')
    console.log(`Authorization published: ${control.enabled ? 'enabled' : 'disabled'}`)
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
