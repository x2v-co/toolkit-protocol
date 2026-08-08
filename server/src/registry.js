import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { mcpToolName } from './mcp_names.js';

const devArtifactKeyPair = crypto.generateKeyPairSync('ed25519');
const devRootKeyPair = crypto.generateKeyPairSync('ed25519');
const devReleaseRootKeyPair = crypto.generateKeyPairSync('ed25519');

function envValue(name, fallback = '') {
  return process.env[name] || fallback;
}

function registryIssuer() {
  return envValue('REGISTRY_ISSUER', 'toolkit.fun');
}

function registryKeysetVersion() {
  return Number(envValue('REGISTRY_KEYSET_VERSION', '1'));
}

function registryPreviousKeysetDigest() {
  return envValue('REGISTRY_PREVIOUS_KEYSET_DIGEST');
}

function registryPreviousCheckpointDigest() {
  return envValue('REGISTRY_PREVIOUS_CHECKPOINT_DIGEST');
}

function registryPreviousStatusHeadDigest() {
  return envValue('REGISTRY_PREVIOUS_STATUS_HEAD_DIGEST');
}

function registryArtifactPrivateKeyPem() {
  return envValue('REGISTRY_ED25519_PRIVATE_KEY');
}

function registryRootPrivateKeyPem() {
  return envValue('REGISTRY_ROOT_ED25519_PRIVATE_KEY') || registryArtifactPrivateKeyPem();
}

function registryKeyId() {
  return envValue('REGISTRY_KEY_ID', process.env.NODE_ENV === 'production' ? 'production' : 'dev-local');
}

function registryRootKeyId() {
  return envValue('REGISTRY_ROOT_KEY_ID', process.env.NODE_ENV === 'production' ? 'production-root' : 'dev-root');
}

function sandboxRuntime() {
  const runtime = envValue('SANDBOX_RUNTIME', 'node_vm').trim().toLowerCase();
  return runtime === 'microvm' ? 'microvm' : 'node_vm';
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function isSemverLike(value) {
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(String(value || ''));
}

function wildcardMatch(pattern, value) {
  const escaped = String(pattern || '').replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(String(value || ''));
}

const PUBLIC_TOOL_LICENSE_ALLOWLIST = Object.freeze([
  'Apache-2.0',
  'MIT',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  'MPL-2.0',
]);

function normalizePem(value) {
  return String(value || '').trim().replace(/\\n/g, '\n');
}

function keyObjectFromEnv(value, kind) {
  const raw = normalizePem(value);
  if (!raw) return null;
  if (raw.includes('-----BEGIN')) {
    return kind === 'private' ? crypto.createPrivateKey(raw) : crypto.createPublicKey(raw);
  }
  const der = Buffer.from(raw, 'base64');
  return kind === 'private'
    ? crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
    : crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function artifactPrivateKey() {
  return keyObjectFromEnv(registryArtifactPrivateKeyPem(), 'private') || devArtifactKeyPair.privateKey;
}

function rootPrivateKey() {
  return keyObjectFromEnv(registryRootPrivateKeyPem(), 'private') || devRootKeyPair.privateKey;
}

function publicJwk(publicKey, kid) {
  return {
    ...publicKey.export({ format: 'jwk' }),
    kid,
    use: 'sig',
    alg: 'EdDSA',
  };
}

function publicJwkFingerprint(jwk) {
  return digestObject({
    kty: jwk?.kty || '',
    crv: jwk?.crv || '',
    x: jwk?.x || '',
  });
}

function signingKeyId() {
  return registryKeyId();
}

function rootKeyId() {
  return registryRootKeyId();
}

function releaseRootKeyId() {
  return `${registryIssuer()}-release-root-dev`;
}

function signPayloadDigest(digest, privateKey, { keyId = signingKeyId(), createdAt = new Date() } = {}) {
  const signature = crypto.sign(null, Buffer.from(String(digest)), privateKey).toString('base64url');
  return {
    alg: 'EdDSA',
    keyId,
    createdAt: createdAt.toISOString(),
    payloadDigest: String(digest),
    value: `ed25519:${signature}`,
  };
}

export function publicKeyFromJwk(jwk) {
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

export function verifyDigestSignature(digest, signature, publicKey) {
  const raw = String(signature?.value || '').replace(/^ed25519:/, '');
  if (signature?.alg !== 'EdDSA' || signature?.payloadDigest !== String(digest) || !raw) return false;
  return crypto.verify(null, Buffer.from(String(digest)), publicKey, Buffer.from(raw, 'base64url'));
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalValue(value) {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'string') return value.normalize('NFC');
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error('canonical JSON only supports finite non-negative-zero numbers');
    if (!Number.isSafeInteger(value)) throw new Error('canonical JSON number must be a safe integer; encode decimals or large integers as strings');
    return value;
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
    throw new Error('canonical JSON does not support undefined, function, symbol, or bigint values');
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!value || typeof value !== 'object') return value;
  if (value.constructor !== Object) throw new Error('canonical JSON only supports plain objects, arrays, dates, and JSON primitives');
  return Object.keys(value).sort().reduce((acc, key) => {
    acc[key] = canonicalValue(value[key]);
    return acc;
  }, {});
}

export function digestObject(value) {
  return `sha256:${sha256(canonicalJson(value))}`;
}

export function digestSource(source) {
  return `sha256:${sha256(String(source || ''))}`;
}

function digestBody(body) {
  return digestSource(body);
}

export function signDigest(digest) {
  return signPayloadDigest(digest, artifactPrivateKey(), { keyId: signingKeyId() });
}

export function signedEnvelope(payload) {
  const digest = digestObject(payload);
  return { ...payload, digest, signature: signDigest(digest) };
}

function withoutEnvelopeFields(envelope) {
  const { digest: _digest, signature: _signature, ...payload } = envelope || {};
  return payload;
}

export function registryTrustKeyset({ now = new Date() } = {}) {
  const artifactPrivate = artifactPrivateKey();
  const rootPrivate = rootPrivateKey();
  const artifactPublic = crypto.createPublicKey(artifactPrivate);
  const rootPublic = crypto.createPublicKey(rootPrivate);
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const payload = {
    schemaVersion: 'toolkit.registry.keyset.v1',
    registryId: registryIssuer(),
    keysetVersion: Number(registryKeysetVersion() || 1),
    previousKeysetDigest: registryPreviousKeysetDigest() || '',
    issuedAt,
    expiresAt,
    keys: [{ ...publicJwk(artifactPublic, signingKeyId()), purposes: ['artifact', 'status'] }],
    revokedKeys: [],
    root: {
      kid: rootKeyId(),
      publicKey: publicJwk(rootPublic, rootKeyId()),
    },
  };
  const digest = digestObject(payload);
  return {
    ...payload,
    digest,
    signature: signPayloadDigest(digest, rootPrivate, { keyId: rootKeyId(), createdAt: now }),
  };
}

export function registryTrustCheckpoint({ now = new Date(), statusHead = null } = {}) {
  const keyset = registryTrustKeyset({ now });
  const payload = {
    schemaVersion: 'toolkit.registry.checkpoint.v1',
    registryId: registryIssuer(),
    checkpointVersion: keyset.keysetVersion,
    checkpointType: 'current',
    issuedAt: keyset.issuedAt,
    keysetDigest: keyset.digest,
    keysetVersion: keyset.keysetVersion,
    previousCheckpointDigest: registryPreviousCheckpointDigest() || '',
    statusHead: statusHead ? {
      digest: statusHead.digest,
      sequence: statusHead.sequence,
      logSize: statusHead.logSize,
      eventLogRoot: statusHead.eventLogRoot,
      stateMapRoot: statusHead.stateMapRoot,
      previousHeadDigest: statusHead.previousHeadDigest,
      issuedAt: statusHead.issuedAt,
      expiresAt: statusHead.expiresAt,
    } : {
      sequence: 0,
      logSize: 0,
      eventLogRoot: '',
      stateMapRoot: '',
      previousHeadDigest: '',
    },
  };
  const digest = digestObject(payload);
  return {
    ...payload,
    digest,
    signature: signPayloadDigest(digest, rootPrivateKey(), { keyId: rootKeyId(), createdAt: now }),
  };
}

function checkpointStatusHead(statusHead) {
  return statusHead ? {
    digest: statusHead.digest,
    sequence: statusHead.sequence,
    logSize: statusHead.logSize,
    eventLogRoot: statusHead.eventLogRoot,
    stateMapRoot: statusHead.stateMapRoot,
    previousHeadDigest: statusHead.previousHeadDigest,
    issuedAt: statusHead.issuedAt,
    expiresAt: statusHead.expiresAt,
  } : {
    sequence: 0,
    logSize: 0,
    eventLogRoot: '',
    stateMapRoot: '',
    previousHeadDigest: '',
  };
}

function keysetHistoryEntry(keyset) {
  return {
    keysetVersion: keyset.keysetVersion,
    digest: keyset.digest,
    previousKeysetDigest: keyset.previousKeysetDigest || '',
    issuedAt: keyset.issuedAt,
    expiresAt: keyset.expiresAt,
    keys: (keyset.keys || []).map((key) => ({
      kid: key.kid,
      alg: key.alg,
      purposes: key.purposes || [],
    })),
    revokedKeys: keyset.revokedKeys || [],
  };
}

export function registryTrustFinalCheckpoint({
  now = new Date(),
  statusHead = null,
  keysets = [],
  archiveIndexDigest = '',
  finalIndexDigest = '',
  manifestSetDigest = '',
  tombstoneIndexDigest = '',
} = {}) {
  const currentKeyset = registryTrustKeyset({ now });
  const keyHistory = (keysets.length ? keysets : [currentKeyset]).map(keysetHistoryEntry);
  const payload = {
    schemaVersion: 'toolkit.registry.checkpoint.v1',
    registryId: registryIssuer(),
    checkpointVersion: currentKeyset.keysetVersion,
    checkpointType: 'final',
    registryStatus: 'retired',
    finalizedAt: now.toISOString(),
    keysetDigest: currentKeyset.digest,
    keysetVersion: currentKeyset.keysetVersion,
    previousCheckpointDigest: registryPreviousCheckpointDigest() || '',
    keyHistory,
    keyHistoryDigest: digestObject({
      schemaVersion: 'toolkit.registry.key-history.v1',
      registryId: registryIssuer(),
      keyHistory,
    }),
    revokedKeys: keyHistory.flatMap((entry) => entry.revokedKeys || []),
    statusHead: checkpointStatusHead(statusHead),
    finalIndexDigest,
    manifestSetDigest,
    archiveIndexDigest,
    tombstoneIndexDigest,
    historicalValidation: {
      result: 'historically-valid',
      statusAsOf: now.toISOString(),
      currentlyTrusted: false,
      reason: 'registry_retired_final_checkpoint_no_fresh_revocation_service',
    },
  };
  const digest = digestObject(payload);
  return {
    ...payload,
    digest,
    signature: signPayloadDigest(digest, rootPrivateKey(), { keyId: rootKeyId(), createdAt: now }),
  };
}

export function registryCheckpointTrustResult(checkpoint, { now = new Date() } = {}) {
  if (!checkpoint || checkpoint.schemaVersion !== 'toolkit.registry.checkpoint.v1') {
    throw new Error('registry checkpoint schema mismatch');
  }
  if (checkpoint.checkpointType === 'final') {
    if (checkpoint.registryStatus !== 'retired') throw new Error('final registry checkpoint must be retired');
    if (!checkpoint.finalizedAt) throw new Error('final registry checkpoint finalizedAt is required');
    if (Object.hasOwn(checkpoint, 'expiresAt')) throw new Error('final registry checkpoint must not use expiresAt');
    return {
      result: 'historically-valid',
      historicallyValid: true,
      currentlyTrusted: false,
      statusAsOf: checkpoint.finalizedAt,
      reason: 'registry_retired_final_checkpoint_no_fresh_revocation_service',
    };
  }
  const expiresAt = checkpoint.statusHead?.expiresAt ? Date.parse(checkpoint.statusHead.expiresAt) : null;
  const fresh = expiresAt ? now.getTime() <= expiresAt : true;
  return {
    result: fresh ? 'currently-trusted' : 'historically-valid',
    historicallyValid: true,
    currentlyTrusted: Boolean(fresh),
    statusAsOf: checkpoint.statusHead?.issuedAt || checkpoint.issuedAt || '',
    reason: fresh ? 'registry_current_checkpoint_fresh' : 'registry_current_checkpoint_status_expired',
  };
}

export function packageReleaseTrustPolicy({
  now = new Date(),
  policyVersion = 1,
  rootVersion = policyVersion,
  releaseRootPrivateKey = devReleaseRootKeyPair.privateKey,
  releaseRootKid = releaseRootKeyId(),
  allowed = {},
  registryTrustBundleDigest = '',
} = {}) {
  const releasePrivate = releaseRootPrivateKey;
  const releasePublic = crypto.createPublicKey(releasePrivate);
  const payload = {
    schemaVersion: 'toolkit.package.release-policy.v1',
    trustDomain: 'package-release',
    policyVersion,
    issuedAt: now.toISOString(),
    releaseRoot: {
      kid: releaseRootKid,
      rootVersion: Number(rootVersion || policyVersion),
      publicKey: publicJwk(releasePublic, releaseRootKid),
      threshold: 1,
      keyUsage: ['package-release-policy', 'package-attestation', 'package-release-checkpoint', 'package-release-transition'],
    },
    allowed: {
      oidcIssuer: allowed.oidcIssuer || 'https://token.actions.githubusercontent.com',
      repository: allowed.repository || 'toolkit/public-community',
      workflowIdentity: allowed.workflowIdentity || '.github/workflows/release.yml@refs/tags/*',
      builder: allowed.builder || 'github-actions',
      packageRegistry: allowed.packageRegistry || 'npm',
    },
    registryTrustBundleDigest,
  };
  const digest = digestObject(payload);
  return {
    ...payload,
    digest,
    signature: signPayloadDigest(digest, releasePrivate, { keyId: releaseRootKid, createdAt: now }),
  };
}

function verifyPackageReleasePolicy(policy) {
  if (!policy || policy.schemaVersion !== 'toolkit.package.release-policy.v1') throw new Error('package release policy schema mismatch');
  const releasePublic = publicKeyFromJwk(policy.releaseRoot.publicKey);
  const policyDigest = digestObject(withoutEnvelopeFields(policy));
  if (policy.digest !== policyDigest) throw new Error('package release policy digest mismatch');
  if (!verifyDigestSignature(policy.digest, policy.signature, releasePublic)) throw new Error('package release policy signature invalid');
  for (const usage of ['package-release-policy', 'package-attestation', 'package-release-checkpoint', 'package-release-transition']) {
    if (!(policy.releaseRoot.keyUsage || []).includes(usage)) throw new Error(`package release policy key usage missing: ${usage}`);
  }
  if (!Number.isSafeInteger(Number(policy.releaseRoot.rootVersion)) || Number(policy.releaseRoot.rootVersion) <= 0) {
    throw new Error('package release root version invalid');
  }
  return {
    publicKey: releasePublic,
    rootFingerprint: publicJwkFingerprint(policy.releaseRoot.publicKey),
    rootVersion: Number(policy.releaseRoot.rootVersion),
  };
}

export function packageReleaseRootTransition({
  now = new Date(),
  fromPolicy,
  toPolicy,
  fromRootPrivateKey = devReleaseRootKeyPair.privateKey,
  toRootPrivateKey,
  reason = 'scheduled_rotation',
} = {}) {
  const from = verifyPackageReleasePolicy(fromPolicy);
  const to = verifyPackageReleasePolicy(toPolicy);
  if (!toRootPrivateKey) throw new Error('package release transition requires new root private key');
  if (to.rootVersion <= from.rootVersion) throw new Error('package release transition root version must increase');
  if (to.rootFingerprint === from.rootFingerprint) throw new Error('package release transition must rotate root material');
  if (Number(toPolicy.policyVersion) <= Number(fromPolicy.policyVersion)) {
    throw new Error('package release transition policy version must increase');
  }
  const payload = {
    schemaVersion: 'toolkit.package.release-root-transition.v1',
    trustDomain: 'package-release',
    issuedAt: now.toISOString(),
    reason: String(reason || 'scheduled_rotation'),
    from: {
      policyDigest: fromPolicy.digest,
      policyVersion: Number(fromPolicy.policyVersion),
      rootKid: fromPolicy.releaseRoot.kid,
      rootVersion: from.rootVersion,
      rootFingerprint: from.rootFingerprint,
    },
    to: {
      policyDigest: toPolicy.digest,
      policyVersion: Number(toPolicy.policyVersion),
      rootKid: toPolicy.releaseRoot.kid,
      rootVersion: to.rootVersion,
      rootFingerprint: to.rootFingerprint,
    },
  };
  const digest = digestObject(payload);
  return {
    ...payload,
    digest,
    signatures: [
      signPayloadDigest(digest, fromRootPrivateKey, { keyId: fromPolicy.releaseRoot.kid, createdAt: now }),
      signPayloadDigest(digest, toRootPrivateKey, { keyId: toPolicy.releaseRoot.kid, createdAt: now }),
    ],
  };
}

export function verifyPackageReleaseRootTransition(transition, fromPolicy, toPolicy, {
  persistedRootVersion = 0,
} = {}) {
  if (!transition || transition.schemaVersion !== 'toolkit.package.release-root-transition.v1') throw new Error('package release transition schema mismatch');
  const from = verifyPackageReleasePolicy(fromPolicy);
  const to = verifyPackageReleasePolicy(toPolicy);
  const { digest: _digest, signatures: _signatures, ...payload } = transition;
  const digest = digestObject(payload);
  if (transition.digest !== digest) throw new Error('package release transition digest mismatch');
  if (transition.from?.policyDigest !== fromPolicy.digest || transition.to?.policyDigest !== toPolicy.digest) {
    throw new Error('package release transition policy digest mismatch');
  }
  if (transition.from.rootFingerprint !== from.rootFingerprint || transition.to.rootFingerprint !== to.rootFingerprint) {
    throw new Error('package release transition root fingerprint mismatch');
  }
  if (to.rootVersion <= from.rootVersion || Number(toPolicy.policyVersion) <= Number(fromPolicy.policyVersion)) {
    throw new Error('package release transition version rollback');
  }
  if (Number(persistedRootVersion || 0) >= to.rootVersion) {
    throw new Error('package release transition root version rollback');
  }
  const signatures = transition.signatures || [];
  const oldSignature = signatures.find((sig) => sig.keyId === fromPolicy.releaseRoot.kid);
  const newSignature = signatures.find((sig) => sig.keyId === toPolicy.releaseRoot.kid);
  if (!oldSignature || !newSignature) throw new Error('package release transition threshold signatures missing');
  if (!verifyDigestSignature(transition.digest, oldSignature, from.publicKey)) throw new Error('package release transition old root signature invalid');
  if (!verifyDigestSignature(transition.digest, newSignature, to.publicKey)) throw new Error('package release transition new root signature invalid');
  return {
    ok: true,
    trustDomain: 'package-release',
    fromRootVersion: from.rootVersion,
    toRootVersion: to.rootVersion,
    toPolicyDigest: toPolicy.digest,
  };
}

export function packageReleaseAttestation({
  now = new Date(),
  policy,
  packageName,
  version,
  packageDigest,
  tarballDigest = packageDigest,
  sourceRepository = '',
  sourceCommit = '',
  workflowIdentity = '',
  oidcIssuer = '',
  builder = '',
  sbomDigest = '',
  builtinManifestSetDigest = '',
  registryTrustBundleDigest = '',
  lockfileDigest = '',
} = {}) {
  if (!policy || policy.schemaVersion !== 'toolkit.package.release-policy.v1') throw new Error('package release policy is required');
  const payload = {
    schemaVersion: 'toolkit.package.release-attestation.v1',
    trustDomain: 'package-release',
    policyDigest: policy.digest,
    issuedAt: now.toISOString(),
    package: {
      name: String(packageName || ''),
      version: String(version || ''),
      registry: policy.allowed.packageRegistry,
      digest: packageDigest,
      tarballDigest,
    },
    provenance: {
      oidcIssuer: oidcIssuer || policy.allowed.oidcIssuer,
      repository: sourceRepository || policy.allowed.repository,
      sourceCommit,
      workflowIdentity: workflowIdentity || policy.allowed.workflowIdentity,
      builder: builder || policy.allowed.builder,
    },
    sbomDigest,
    builtinManifestSetDigest,
    registryTrustBundleDigest: registryTrustBundleDigest || policy.registryTrustBundleDigest,
    lockfileDigest,
  };
  for (const [label, digest] of Object.entries({
    packageDigest: payload.package.digest,
    tarballDigest: payload.package.tarballDigest,
    sbomDigest,
    builtinManifestSetDigest,
    registryTrustBundleDigest: payload.registryTrustBundleDigest,
    lockfileDigest,
  })) {
    if (digest) digestHex(digest, label);
  }
  if (!payload.package.name || !payload.package.version || !payload.package.digest || !payload.provenance.sourceCommit) {
    throw new Error('package release attestation requires package name, version, digest and source commit');
  }
  if (!isSemverLike(payload.package.version)) throw new Error('package release version must be semver');
  if (!isFullCommitHash(payload.provenance.sourceCommit)) throw new Error('package release source commit must be a full commit hash');
  const digest = digestObject(payload);
  return {
    ...payload,
    digest,
    signature: signPayloadDigest(digest, devReleaseRootKeyPair.privateKey, { keyId: releaseRootKeyId(), createdAt: now }),
  };
}

export function verifyPackageReleaseAttestation(attestation, policy, {
  statusProof = null,
  now = new Date(),
  requireCurrentlyTrusted = true,
  registryStatusPublicKey = null,
} = {}) {
  if (!attestation || attestation.schemaVersion !== 'toolkit.package.release-attestation.v1') throw new Error('package release attestation schema mismatch');
  const { publicKey: releasePublic } = verifyPackageReleasePolicy(policy);
  const attestationDigest = digestObject(withoutEnvelopeFields(attestation));
  if (attestation.digest !== attestationDigest) throw new Error('package release attestation digest mismatch');
  if (attestation.policyDigest !== policy.digest) throw new Error('package release attestation policy digest mismatch');
  if (!verifyDigestSignature(attestation.digest, attestation.signature, releasePublic)) throw new Error('package release attestation signature invalid');
  if (attestation.trustDomain !== 'package-release') throw new Error('package release attestation trustDomain mismatch');
  if (attestation.provenance.oidcIssuer !== policy.allowed.oidcIssuer) throw new Error('package release oidc issuer mismatch');
  if (attestation.provenance.repository !== policy.allowed.repository) throw new Error('package release repository mismatch');
  if (!wildcardMatch(policy.allowed.workflowIdentity, attestation.provenance.workflowIdentity)) throw new Error('package release workflow identity mismatch');
  if (attestation.provenance.builder !== policy.allowed.builder) throw new Error('package release builder mismatch');
  if (attestation.package.registry !== policy.allowed.packageRegistry) throw new Error('package release registry mismatch');
  if (!isSemverLike(attestation.package.version)) throw new Error('package release version must be semver');
  if (!isFullCommitHash(attestation.provenance.sourceCommit)) throw new Error('package release source commit must be a full commit hash');
  if (policy.registryTrustBundleDigest && attestation.registryTrustBundleDigest !== policy.registryTrustBundleDigest) {
    throw new Error('package release registry trust bundle digest mismatch');
  }
  if (attestation.package.digest !== attestation.package.tarballDigest) throw new Error('package release tarball digest mismatch');
  if (statusProof) {
    const result = verifyRegistryStatusProof(statusProof, {
      now,
      requireCurrentlyTrusted,
      publicKey: registryStatusPublicKey,
    });
    const packageSubject = (statusProof.proofs || []).find((proof) => proof.subject?.type === 'package' && proof.subject?.digest === attestation.package.digest);
    if (!packageSubject) throw new Error('package release status proof missing package subject');
    if (requireCurrentlyTrusted && packageSubject.status !== 'active') throw new Error('package release package status is not active');
    return {
      ok: true,
      packageDigest: attestation.package.digest,
      packageStatus: packageSubject.status,
      statusAsOf: result.statusAsOf,
      trustDomain: 'package-release',
    };
  }
  if (requireCurrentlyTrusted) throw new Error('package release status proof is required');
  return {
    ok: true,
    packageDigest: attestation.package.digest,
    packageStatus: 'unchecked',
    statusAsOf: '',
    trustDomain: 'package-release',
  };
}

export function packageReleaseSigningRequest({
  now = new Date(),
  attestation,
  policy,
  finalTarballDigest = '',
  transparencyLogDigest = '',
  independentVerifier = {},
} = {}) {
  if (!attestation || attestation.schemaVersion !== 'toolkit.package.release-attestation.v1') throw new Error('package release signing request requires attestation');
  if (!policy || policy.schemaVersion !== 'toolkit.package.release-policy.v1') throw new Error('package release signing request requires policy');
  const tarballDigest = finalTarballDigest || attestation.package.tarballDigest;
  digestHex(tarballDigest, 'finalTarballDigest');
  if (tarballDigest !== attestation.package.tarballDigest) throw new Error('package release final tarball digest mismatch');
  const payload = {
    schemaVersion: 'toolkit.package.release-signing-request.v1',
    trustDomain: 'package-release',
    requestedAt: now.toISOString(),
    policyDigest: policy.digest,
    attestationDigest: attestation.digest,
    packageDigest: attestation.package.digest,
    finalTarballDigest: tarballDigest,
    sbomDigest: attestation.sbomDigest,
    builtinManifestSetDigest: attestation.builtinManifestSetDigest,
    registryTrustBundleDigest: attestation.registryTrustBundleDigest,
    transparencyLogDigest,
    independentVerifier: {
      identity: independentVerifier.identity || 'independent-ci',
      source: independentVerifier.source || 'final-registry-tarball-download',
      verifiedAt: independentVerifier.verifiedAt || now.toISOString(),
    },
  };
  if (payload.transparencyLogDigest) digestHex(payload.transparencyLogDigest, 'transparencyLogDigest');
  if (!payload.transparencyLogDigest) throw new Error('package release transparency log digest is required');
  if (!payload.independentVerifier.identity) throw new Error('package release independent verifier identity is required');
  if (payload.independentVerifier.source !== 'final-registry-tarball-download') {
    throw new Error('package release independent verifier must use final registry tarball download');
  }
  const digest = digestObject(payload);
  return { ...payload, digest };
}

export function packageReleaseCheckpoint({
  now = new Date(),
  signingRequest,
  policy,
  broker = {},
} = {}) {
  if (!signingRequest || signingRequest.schemaVersion !== 'toolkit.package.release-signing-request.v1') {
    throw new Error('package release checkpoint requires signing request');
  }
  if (!policy || policy.schemaVersion !== 'toolkit.package.release-policy.v1') throw new Error('package release checkpoint requires policy');
  if (signingRequest.policyDigest !== policy.digest) throw new Error('package release checkpoint policy digest mismatch');
  const payload = {
    schemaVersion: 'toolkit.package.release-checkpoint.v1',
    trustDomain: 'package-release',
    checkpointType: 'release',
    issuedAt: now.toISOString(),
    releaseRootKid: policy.releaseRoot.kid,
    policyDigest: policy.digest,
    signingRequestDigest: signingRequest.digest,
    packageDigest: signingRequest.packageDigest,
    finalTarballDigest: signingRequest.finalTarballDigest,
    registryTrustBundleDigest: signingRequest.registryTrustBundleDigest,
    transparencyLogDigest: signingRequest.transparencyLogDigest,
    broker: {
      identity: broker.identity || 'isolated-release-signer-broker',
      approvalId: broker.approvalId || '',
      signerPurpose: 'release-checkpoint',
      offlineRootAccessibleToCi: false,
    },
  };
  const digest = digestObject(payload);
  return {
    ...payload,
    digest,
    signature: signPayloadDigest(digest, devReleaseRootKeyPair.privateKey, { keyId: releaseRootKeyId(), createdAt: now }),
  };
}

export function verifyPackageReleaseCheckpoint(checkpoint, signingRequest, policy) {
  if (!checkpoint || checkpoint.schemaVersion !== 'toolkit.package.release-checkpoint.v1') throw new Error('package release checkpoint schema mismatch');
  if (!signingRequest || signingRequest.schemaVersion !== 'toolkit.package.release-signing-request.v1') throw new Error('package release signing request schema mismatch');
  if (!policy || policy.schemaVersion !== 'toolkit.package.release-policy.v1') throw new Error('package release policy schema mismatch');
  const releasePublic = publicKeyFromJwk(policy.releaseRoot.publicKey);
  const requestDigest = digestObject(withoutEnvelopeFields(signingRequest));
  if (signingRequest.digest !== requestDigest) throw new Error('package release signing request digest mismatch');
  const checkpointDigest = digestObject(withoutEnvelopeFields(checkpoint));
  if (checkpoint.digest !== checkpointDigest) throw new Error('package release checkpoint digest mismatch');
  if (!verifyDigestSignature(checkpoint.digest, checkpoint.signature, releasePublic)) throw new Error('package release checkpoint signature invalid');
  if (checkpoint.policyDigest !== policy.digest || signingRequest.policyDigest !== policy.digest) throw new Error('package release checkpoint policy digest mismatch');
  if (checkpoint.signingRequestDigest !== signingRequest.digest) throw new Error('package release checkpoint signing request digest mismatch');
  if (checkpoint.packageDigest !== signingRequest.packageDigest) throw new Error('package release checkpoint package digest mismatch');
  if (checkpoint.finalTarballDigest !== signingRequest.finalTarballDigest) throw new Error('package release checkpoint tarball digest mismatch');
  if (checkpoint.registryTrustBundleDigest !== signingRequest.registryTrustBundleDigest) throw new Error('package release checkpoint registry trust bundle digest mismatch');
  if (checkpoint.transparencyLogDigest !== signingRequest.transparencyLogDigest) throw new Error('package release checkpoint transparency log digest mismatch');
  if (checkpoint.broker?.offlineRootAccessibleToCi !== false) throw new Error('package release checkpoint broker boundary mismatch');
  return {
    ok: true,
    packageDigest: checkpoint.packageDigest,
    finalTarballDigest: checkpoint.finalTarballDigest,
    trustDomain: 'package-release',
  };
}

export const PACKAGE_RELEASE_PRODUCTION_EVIDENCE_SCHEMA = 'toolkit.package.release-production-evidence.v1';
export const PACKAGE_RELEASE_EVIDENCE_MAX_AGE_HOURS = 72;
export const PACKAGE_RELEASE_EVIDENCE_CLOCK_SKEW_MS = 60_000;

function pushReleaseBlocker(blockers, code, details = {}) {
  blockers.push({ code, ...details });
}

function hasSensitiveEvidenceField(value) {
  if (!value || typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value)) {
    if (/secret|token|password|cookie|private.*key|credential|api.*key/i.test(key)) return true;
    if (hasSensitiveEvidenceField(child)) return true;
  }
  return false;
}

function evidenceDigestOrEmpty(value) {
  const digest = String(value || '').trim();
  if (!digest) return '';
  try {
    digestHex(digest);
    return digest;
  } catch {
    return '';
  }
}

function isEvidenceDigest(value) {
  return evidenceDigestOrEmpty(value) === String(value || '').trim();
}

function isStrictEvidenceDigest(value) {
  return /^sha256:[0-9a-f]{64}$/.test(String(value || '').trim());
}

function releaseEvidenceTimestamp(section = {}) {
  return section.checkedAt || section.verifiedAt || section.generatedAt || section.issuedAt || section.observedAt || '';
}

function checkReleaseEvidenceFreshness(blockers, section, field, generatedAtIso, {
  maxAgeHours = PACKAGE_RELEASE_EVIDENCE_MAX_AGE_HOURS,
} = {}) {
  if (!section || typeof section !== 'object' || !Object.keys(section).length) return;
  const timestamp = releaseEvidenceTimestamp(section);
  const valueMs = Date.parse(timestamp || '');
  const generatedAtMs = Date.parse(generatedAtIso || '');
  if (!Number.isFinite(valueMs) || !Number.isFinite(generatedAtMs)) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_EVIDENCE_TIMESTAMP_MISSING', { field });
    return;
  }
  if (valueMs > generatedAtMs + PACKAGE_RELEASE_EVIDENCE_CLOCK_SKEW_MS) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_EVIDENCE_FROM_FUTURE', { field, value: String(timestamp || '') });
    return;
  }
  if (generatedAtMs - valueMs > Number(maxAgeHours || PACKAGE_RELEASE_EVIDENCE_MAX_AGE_HOURS) * 3600_000) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_EVIDENCE_STALE', {
      field,
      value: String(timestamp || ''),
      maxAgeHours: Number(maxAgeHours || PACKAGE_RELEASE_EVIDENCE_MAX_AGE_HOURS),
    });
  }
}

function compactPackageReleaseEvidenceRefs(evidence = {}) {
  const trustedPublishing = evidence.npmTrustedPublishing || {};
  const sigstore = evidence.sigstore || {};
  const workflow = evidence.releaseWorkflow || {};
  const provenance = evidence.provenance || {};
  const finalTarball = evidence.finalTarball || {};
  const sbom = evidence.sbom || {};
  const checkpointEvidence = evidence.checkpoint || {};
  const packageStatus = evidence.packageStatus || {};
  return {
    npmTrustedPublishing: {
      enabled: trustedPublishing.enabled === true,
      oidcIssuer: String(trustedPublishing.oidcIssuer || ''),
      repository: String(trustedPublishing.repository || ''),
      workflowIdentity: String(trustedPublishing.workflowIdentity || ''),
      packageName: String(trustedPublishing.packageName || ''),
      registry: String(trustedPublishing.registry || ''),
      attestationDigest: String(trustedPublishing.attestationDigest || ''),
      observedAt: releaseEvidenceTimestamp(trustedPublishing),
    },
    sigstore: {
      bundleDigest: String(sigstore.bundleDigest || ''),
      transparencyLogDigest: String(sigstore.transparencyLogDigest || ''),
      inclusionProofDigest: String(sigstore.inclusionProofDigest || ''),
      inclusionVerified: sigstore.inclusionVerified === true,
      identity: {
        oidcIssuer: String(sigstore.identity?.oidcIssuer || ''),
        repository: String(sigstore.identity?.repository || ''),
        workflowIdentity: String(sigstore.identity?.workflowIdentity || ''),
      },
      observedAt: releaseEvidenceTimestamp(sigstore),
    },
    releaseWorkflow: {
      protected: workflow.protected === true,
      repository: String(workflow.repository || ''),
      workflowIdentity: String(workflow.workflowIdentity || ''),
      sourceCommit: String(workflow.sourceCommit || ''),
      thirdPartyActionsPinned: workflow.thirdPartyActionsPinned === true,
      environmentProtected: workflow.environmentProtected === true,
      runAttemptDigest: String(workflow.runAttemptDigest || ''),
      observedAt: releaseEvidenceTimestamp(workflow),
    },
    provenance: {
      sourceCommit: String(provenance.sourceCommit || ''),
      builder: String(provenance.builder || ''),
      packageDigest: String(provenance.packageDigest || ''),
      tarballDigest: String(provenance.tarballDigest || ''),
      slsaPredicateType: String(provenance.slsaPredicateType || ''),
      transparencyLogDigest: String(provenance.transparencyLogDigest || ''),
      statementDigest: String(provenance.statementDigest || ''),
      observedAt: releaseEvidenceTimestamp(provenance),
    },
    finalTarball: {
      digest: String(finalTarball.digest || ''),
      source: String(finalTarball.source || ''),
      recomputedDigest: finalTarball.recomputedDigest === true,
      independentVerifierIdentity: String(finalTarball.independentVerifierIdentity || ''),
      downloadEvidenceDigest: String(finalTarball.downloadEvidenceDigest || ''),
      observedAt: releaseEvidenceTimestamp(finalTarball),
    },
    sbom: {
      digest: String(sbom.digest || ''),
      format: String(sbom.format || ''),
      dependencyLicenseAuditPassed: sbom.dependencyLicenseAuditPassed === true,
      attachedToPackageDigest: String(sbom.attachedToPackageDigest || ''),
      licenseAuditDigest: String(sbom.licenseAuditDigest || ''),
      observedAt: releaseEvidenceTimestamp(sbom),
    },
    registryTrustBundleDigest: String(evidence.registryTrustBundleDigest || ''),
    checkpoint: {
      digest: String(checkpointEvidence.digest || ''),
      brokerIdentity: String(checkpointEvidence.brokerIdentity || ''),
      approvalId: String(checkpointEvidence.approvalId || ''),
      approvalDigest: String(checkpointEvidence.approvalDigest || ''),
      brokerRunDigest: String(checkpointEvidence.brokerRunDigest || ''),
      offlineRootAccessibleToCi: typeof checkpointEvidence.offlineRootAccessibleToCi === 'boolean'
        ? checkpointEvidence.offlineRootAccessibleToCi
        : null,
      releaseRootVersion: Number(checkpointEvidence.releaseRootVersion || 0),
      observedAt: releaseEvidenceTimestamp(checkpointEvidence),
    },
    packageStatus: {
      subjectType: String(packageStatus.subjectType || ''),
      digest: String(packageStatus.digest || ''),
      status: String(packageStatus.status || ''),
      statusHeadDigest: String(packageStatus.statusHeadDigest || ''),
      proofDigest: String(packageStatus.proofDigest || ''),
      observedAt: releaseEvidenceTimestamp(packageStatus),
    },
  };
}

function stripPackageReleaseBindingDigest(value) {
  if (Array.isArray(value)) return value.map(stripPackageReleaseBindingDigest);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([key]) => key !== 'evidenceBindingDigest')
      .map(([key, child]) => [key, stripPackageReleaseBindingDigest(child)]));
  }
  return value;
}

export function packageReleaseEvidenceBindingDigest(evidence = {}) {
  return digestObject({
    schemaVersion: 'toolkit.package.release-evidence-binding.v1',
    package: stripPackageReleaseBindingDigest(evidence.package || {}),
    policyDigest: String(evidence.policyDigest || ''),
    attestationDigest: String(evidence.attestationDigest || ''),
    signingRequestDigest: String(evidence.signingRequestDigest || ''),
    checkpointDigest: String(evidence.checkpointDigest || ''),
    registryTrustBundleDigest: String(evidence.registryTrustBundleDigest || ''),
    evidencePolicy: stripPackageReleaseBindingDigest(evidence.evidencePolicy || {}),
    evidenceRefs: stripPackageReleaseBindingDigest(evidence.evidenceRefs || {}),
  });
}

function normalizeRegistryStatusPublicKey(publicKey) {
  if (!publicKey) return null;
  if (publicKey.type && publicKey.asymmetricKeyType) return publicKey;
  if (publicKey.kty) return publicKeyFromJwk(publicKey);
  return publicKey;
}

export function packageReleaseStatusProofDigest(statusProof, packageDigest) {
  const subject = (statusProof?.proofs || []).find((proof) => (
    proof?.subject?.type === 'package'
    && proof.subject.digest === packageDigest
  ));
  if (!subject) return '';
  return digestObject({
    schemaVersion: 'toolkit.package.release-status-proof-binding.v1',
    statusHeadDigest: statusProof?.head?.digest || '',
    subject: subject.subject,
    status: subject.status,
    event: subject.event || null,
    stateMapProof: subject.stateMapProof || null,
    sparseStateMapProof: subject.sparseStateMapProof || null,
    eventInclusionProof: subject.eventInclusionProof || null,
  });
}

function verifiedPackageStatusSubject(statusProof, packageDigest) {
  const subject = (statusProof?.proofs || []).find((proof) => (
    proof?.subject?.type === 'package'
    && proof.subject.digest === packageDigest
  ));
  if (!subject) return null;
  return {
    subjectType: 'package',
    digest: subject.subject.digest,
    status: subject.status,
    sequence: subject.event?.sequence || subject.stateMapProof?.latestEventSequence || subject.sparseStateMapProof?.stateEntry?.sequence || 0,
    statusHeadDigest: statusProof?.head?.digest || '',
    proofDigest: packageReleaseStatusProofDigest(statusProof, packageDigest),
  };
}

export function packageReleaseProductionEvidence({
  now = new Date(),
  generatedBy = '',
  policy,
  evidencePolicy = {},
  attestation,
  signingRequest,
  checkpoint,
  statusProof = null,
  registryStatusPublicKey = null,
  evidence = {},
} = {}) {
  const blockers = [];
  let attestationResult = null;
  let checkpointResult = null;
  let policyRoot = null;
  let packageStatusResult = null;
  const generatedAt = now.toISOString();
  const maxEvidenceAgeHours = Math.max(1, Number(evidencePolicy.maxEvidenceAgeHours || PACKAGE_RELEASE_EVIDENCE_MAX_AGE_HOURS));

  try {
    policyRoot = verifyPackageReleasePolicy(policy);
  } catch (e) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_POLICY_INVALID', { reason: e.message || 'invalid policy' });
  }

  const normalizedRegistryStatusPublicKey = normalizeRegistryStatusPublicKey(registryStatusPublicKey);

  try {
    attestationResult = verifyPackageReleaseAttestation(attestation, policy, {
      statusProof,
      now,
      registryStatusPublicKey: normalizedRegistryStatusPublicKey,
      requireCurrentlyTrusted: true,
    });
  } catch (e) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_ATTESTATION_INVALID', { reason: e.message || 'invalid attestation' });
  }

  try {
    checkpointResult = verifyPackageReleaseCheckpoint(checkpoint, signingRequest, policy);
  } catch (e) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_CHECKPOINT_INVALID', { reason: e.message || 'invalid checkpoint' });
  }

  if (hasSensitiveEvidenceField(evidence)) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_EVIDENCE_CONTAINS_SECRET_FIELD');
  }

  const trustedPublishing = evidence.npmTrustedPublishing || {};
  const sigstore = evidence.sigstore || {};
  checkReleaseEvidenceFreshness(blockers, trustedPublishing, 'npmTrustedPublishing', generatedAt, { maxAgeHours: maxEvidenceAgeHours });
  checkReleaseEvidenceFreshness(blockers, sigstore, 'sigstore', generatedAt, { maxAgeHours: maxEvidenceAgeHours });
  const trustedPublishingOk = trustedPublishing.enabled === true
    && trustedPublishing.oidcIssuer === attestation?.provenance?.oidcIssuer
    && trustedPublishing.repository === attestation?.provenance?.repository
    && wildcardMatch(policy?.allowed?.workflowIdentity || '', trustedPublishing.workflowIdentity || '')
    && trustedPublishing.packageName === attestation?.package?.name
    && trustedPublishing.registry === attestation?.package?.registry
    && isEvidenceDigest(trustedPublishing.attestationDigest);
  const sigstoreOk = Boolean(sigstore.bundleDigest)
    && evidenceDigestOrEmpty(sigstore.bundleDigest) === sigstore.bundleDigest
    && sigstore.transparencyLogDigest === signingRequest?.transparencyLogDigest
    && isEvidenceDigest(sigstore.inclusionProofDigest)
    && sigstore.inclusionVerified === true
    && sigstore.identity?.oidcIssuer === attestation?.provenance?.oidcIssuer
    && sigstore.identity?.repository === attestation?.provenance?.repository
    && wildcardMatch(policy?.allowed?.workflowIdentity || '', sigstore.identity?.workflowIdentity || '');
  if (!trustedPublishingOk && !sigstoreOk) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_TRUSTED_PUBLISHING_OR_SIGSTORE_MISSING');
  }

  const workflow = evidence.releaseWorkflow || {};
  checkReleaseEvidenceFreshness(blockers, workflow, 'releaseWorkflow', generatedAt, { maxAgeHours: maxEvidenceAgeHours });
  if (workflow.protected !== true
    || workflow.repository !== attestation?.provenance?.repository
    || !wildcardMatch(policy?.allowed?.workflowIdentity || '', workflow.workflowIdentity || '')
    || workflow.sourceCommit !== attestation?.provenance?.sourceCommit
    || workflow.thirdPartyActionsPinned !== true
    || workflow.environmentProtected !== true
    || !isEvidenceDigest(workflow.runAttemptDigest)) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_PROTECTED_WORKFLOW_EVIDENCE_MISSING');
  }

  const provenance = evidence.provenance || {};
  checkReleaseEvidenceFreshness(blockers, provenance, 'provenance', generatedAt, { maxAgeHours: maxEvidenceAgeHours });
  if (provenance.sourceCommit !== attestation?.provenance?.sourceCommit
    || provenance.builder !== attestation?.provenance?.builder
    || provenance.packageDigest !== attestation?.package?.digest
    || provenance.tarballDigest !== attestation?.package?.tarballDigest
    || provenance.slsaPredicateType !== 'https://slsa.dev/provenance/v1'
    || provenance.transparencyLogDigest !== signingRequest?.transparencyLogDigest
    || !isEvidenceDigest(provenance.statementDigest)) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_PROVENANCE_EVIDENCE_MISMATCH');
  }

  const finalTarball = evidence.finalTarball || {};
  checkReleaseEvidenceFreshness(blockers, finalTarball, 'finalTarball', generatedAt, { maxAgeHours: maxEvidenceAgeHours });
  if (finalTarball.digest !== signingRequest?.finalTarballDigest
    || finalTarball.source !== 'final-registry-tarball-download'
    || finalTarball.recomputedDigest !== true
    || finalTarball.independentVerifierIdentity !== signingRequest?.independentVerifier?.identity
    || !isEvidenceDigest(finalTarball.downloadEvidenceDigest)) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_FINAL_TARBALL_VERIFICATION_MISSING');
  }

  const sbom = evidence.sbom || {};
  checkReleaseEvidenceFreshness(blockers, sbom, 'sbom', generatedAt, { maxAgeHours: maxEvidenceAgeHours });
  if (sbom.digest !== attestation?.sbomDigest
    || sbom.format !== 'spdx-json'
    || sbom.dependencyLicenseAuditPassed !== true
    || sbom.attachedToPackageDigest !== attestation?.package?.digest
    || !isEvidenceDigest(sbom.licenseAuditDigest)) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_SBOM_EVIDENCE_MISSING');
  }

  if (evidence.registryTrustBundleDigest !== attestation?.registryTrustBundleDigest
    || evidence.registryTrustBundleDigest !== signingRequest?.registryTrustBundleDigest) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_REGISTRY_TRUST_BUNDLE_MISMATCH');
  }

  const checkpointEvidence = evidence.checkpoint || {};
  checkReleaseEvidenceFreshness(blockers, checkpointEvidence, 'checkpoint', generatedAt, { maxAgeHours: maxEvidenceAgeHours });
  if (checkpointEvidence.digest !== checkpoint?.digest
    || checkpointEvidence.brokerIdentity !== checkpoint?.broker?.identity
    || !checkpointEvidence.approvalId
    || !isEvidenceDigest(checkpointEvidence.approvalDigest)
    || !isEvidenceDigest(checkpointEvidence.brokerRunDigest)
    || checkpointEvidence.offlineRootAccessibleToCi !== false
    || Number(checkpointEvidence.releaseRootVersion || 0) < Number(policyRoot?.rootVersion || policy?.releaseRoot?.rootVersion || 0)) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_CHECKPOINT_EVIDENCE_MISSING');
  }

  const packageStatus = evidence.packageStatus || {};
  checkReleaseEvidenceFreshness(blockers, packageStatus, 'packageStatus', generatedAt, { maxAgeHours: maxEvidenceAgeHours });
  packageStatusResult = verifiedPackageStatusSubject(statusProof, attestation?.package?.digest);
  if (!packageStatusResult
    || packageStatus.subjectType !== 'package'
    || packageStatus.digest !== packageStatusResult.digest
    || packageStatus.status !== 'active'
    || packageStatusResult.status !== 'active'
    || packageStatus.statusHeadDigest !== packageStatusResult.statusHeadDigest
    || packageStatus.proofDigest !== packageStatusResult.proofDigest
    || !isStrictEvidenceDigest(packageStatus.statusHeadDigest)
    || !isStrictEvidenceDigest(packageStatus.proofDigest)) {
    pushReleaseBlocker(blockers, 'PACKAGE_RELEASE_STATUS_EVIDENCE_MISSING');
  }

  const normalized = {
    schemaVersion: PACKAGE_RELEASE_PRODUCTION_EVIDENCE_SCHEMA,
    generatedAt,
    generatedBy: String(generatedBy || ''),
    package: {
      name: attestation?.package?.name || '',
      version: attestation?.package?.version || '',
      registry: attestation?.package?.registry || '',
      digest: attestation?.package?.digest || '',
      finalTarballDigest: signingRequest?.finalTarballDigest || attestation?.package?.tarballDigest || '',
    },
    policyDigest: policy?.digest || '',
    attestationDigest: attestation?.digest || '',
    signingRequestDigest: signingRequest?.digest || '',
    checkpointDigest: checkpoint?.digest || '',
    releaseRootVersion: Number(policyRoot?.rootVersion || policy?.releaseRoot?.rootVersion || 0),
    registryTrustBundleDigest: attestation?.registryTrustBundleDigest || '',
    evidencePolicy: {
      maxEvidenceAgeHours,
    },
    evidenceRefs: compactPackageReleaseEvidenceRefs(evidence),
    verification: {
      attestation: attestationResult,
      checkpoint: checkpointResult,
      packageStatus: packageStatusResult,
      npmTrustedPublishing: trustedPublishingOk,
      sigstore: sigstoreOk,
    },
    evidenceSummary: {
      protectedWorkflow: workflow.protected === true,
      provenance: Boolean(provenance.slsaPredicateType),
      finalTarball: Boolean(finalTarball.digest),
      sbom: Boolean(sbom.digest),
      packageStatus: packageStatus.status || '',
      checkpointApproval: checkpointEvidence.approvalId || '',
    },
    readiness: {
      ready: blockers.length === 0,
      blockers,
    },
  };
  normalized.evidenceBindingDigest = packageReleaseEvidenceBindingDigest(normalized);
  return {
    ...normalized,
    evidenceDigest: digestObject(normalized),
  };
}

export function toolManifest(tool, { baseUrl }) {
  const version = tool.currentVersion?.v || 1;
  const source = tool.currentVersion?.source || '';
  const artifactDigest = digestSource(source);
  const slug = tool.slug;
  const metadata = registryArtifactMetadata(tool, { baseUrl, artifactDigest });
  return {
    schemaVersion: 'toolkit.registry.tool.v1',
    kind: 'toolkit.tool',
    issuer: registryIssuer(),
    id: String(tool._id),
    slug,
    name: tool.name,
    version,
    status: tool.status,
    category: tool.category || '其他',
    description: tool.i18n?.zh?.description || tool.description || '',
    updatedAt: tool.updatedAt || tool.createdAt || null,
    artifact: {
      type: 'javascript-source',
      digest: artifactDigest,
      sourceHash: artifactDigest.slice('sha256:'.length),
      byteLength: Buffer.byteLength(source, 'utf8'),
      sourceUrl: `${baseUrl}/api/v1/registry/tools/${encodeURIComponent(slug)}/source`,
      contentAddressedUrl: `${baseUrl}/api/v1/registry/artifacts/sha256/${artifactDigest.slice('sha256:'.length)}`,
    },
    license: metadata.license,
    copyright: metadata.copyright,
    provenance: metadata.provenance,
    thirdParty: metadata.thirdParty,
    runtime: {
      engine: sandboxRuntime(),
      sandbox: tool.currentVersion?.sandbox || { timeoutMs: 2000, memMb: 128, net: false, ai: false },
    },
    inputSchema: inputSchemaForTool(tool),
    endpoints: {
      rest: `${baseUrl}/api/v1/t/${encodeURIComponent(slug)}`,
      mcp: `${baseUrl}/api/mcp`,
      manifest: `${baseUrl}/api/v1/registry/tools/${encodeURIComponent(slug)}/manifest`,
      lockfile: `${baseUrl}/api/v1/registry/lockfile?tools=${encodeURIComponent(slug)}`,
    },
  };
}

export function registryAttachmentArtifacts(tool, { baseUrl }) {
  const source = tool.currentVersion?.source || '';
  const artifactDigest = digestSource(source);
  return registryArtifactMetadata(tool, { baseUrl, artifactDigest }).attachments;
}

function registryArtifactMetadata(tool, { baseUrl, artifactDigest }) {
  const version = tool.currentVersion?.v || 1;
  const publishedAt = timestamp(tool.publishedAt || tool.reviewedAt || tool.updatedAt || tool.createdAt);
  const licenseExpression = tool.type === 'builtin'
    ? 'Apache-2.0'
    : 'LicenseRef-Toolkit-Publisher-Attested-Preview';
  const licenseText = licenseTextForTool(tool, licenseExpression);
  const noticeText = noticeTextForTool(tool);
  const sbomPayload = sbomForTool(tool, { artifactDigest, publishedAt });
  const sbomBody = canonicalJson(sbomPayload);
  const licenseDigest = digestBody(licenseText);
  const noticeDigest = digestBody(noticeText);
  const sbomDigest = digestBody(sbomBody);
  const licenseUrl = `${baseUrl}/api/v1/registry/attachments/sha256/${licenseDigest.slice('sha256:'.length)}`;
  const noticeUrl = `${baseUrl}/api/v1/registry/attachments/sha256/${noticeDigest.slice('sha256:'.length)}`;
  const sbomUrl = `${baseUrl}/api/v1/registry/attachments/sha256/${sbomDigest.slice('sha256:'.length)}`;
  const rightsAttestation = {
    statementVersion: 'toolkit.publisher-rights.v1',
    attested: true,
    attestedBy: publisherForTool(tool),
    attestedAt: publishedAt,
    acceptedAt: publishedAt,
    scope: tool.type === 'builtin' ? 'official-builtin-preview' : 'publisher-reviewed-tool-preview',
    statementDigest: digestObject({
      schemaVersion: 'toolkit.publisher-rights.statement-digest.v1',
      publisher: publisherForTool(tool),
      licenseExpression,
      artifactDigest,
      publishedAt,
    }),
    note: 'Preview attestation records publisher responsibility; it is not an open-source license grant.',
  };
  const provenance = {
    schemaVersion: 'toolkit.registry.provenance.v1',
    type: provenanceType(tool),
    publisher: publisherForTool(tool),
    publishedAt,
    rightsAttestation,
    revision: provenanceRevision(tool, { artifactDigest, publishedAt }),
  };
  return {
    license: {
      expression: licenseExpression,
      text: { digest: licenseDigest, url: licenseUrl, mediaType: 'text/plain; charset=utf-8' },
    },
    copyright: copyrightForTool(tool, publishedAt),
    provenance,
    thirdParty: {
      notice: { digest: noticeDigest, url: noticeUrl, mediaType: 'text/plain; charset=utf-8' },
      sbom: { digest: sbomDigest, url: sbomUrl, mediaType: 'application/spdx+json; charset=utf-8' },
    },
    attachments: [
      { kind: 'license', role: 'license-text', digest: licenseDigest, mediaType: 'text/plain; charset=utf-8', body: licenseText },
      { kind: 'notice', role: 'third-party-notice', digest: noticeDigest, mediaType: 'text/plain; charset=utf-8', body: noticeText },
      { kind: 'sbom', role: 'spdx-sbom', digest: sbomDigest, mediaType: 'application/spdx+json; charset=utf-8', body: sbomBody },
    ],
  };
}

function timestamp(value) {
  if (!value) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function publisherForTool(tool) {
  if (tool.type === 'builtin') return { type: 'organization', name: 'Toolkit', id: registryIssuer() };
  return {
    type: 'user',
    id: tool.ownerId ? String(tool.ownerId) : '',
    name: tool.authorName || 'Publisher',
  };
}

function copyrightForTool(tool, publishedAt) {
  const year = (publishedAt || new Date().toISOString()).slice(0, 4);
  if (tool.type === 'builtin') return [`Copyright ${year} Toolkit`];
  const holder = tool.authorName || (tool.ownerId ? `Toolkit Publisher ${String(tool.ownerId)}` : 'Toolkit Publisher');
  return [`Copyright ${year} ${holder}`];
}

function provenanceType(tool) {
  if (tool.flags?.includes('agent-generated')) return 'generated';
  if (tool.type === 'builtin') return 'git';
  if (tool.flags?.includes('imported') || tool.flags?.includes('legacy-import')) return 'imported';
  return 'toolkit-studio';
}

function provenanceRevision(tool, { artifactDigest, publishedAt }) {
  const version = tool.currentVersion?.v || 1;
  const common = {
    artifactDigest,
    toolId: String(tool._id),
    toolVersion: version,
  };
  if (tool.flags?.includes('agent-generated')) {
    return {
      ...common,
      generationRecordDigest: digestObject({
        schemaVersion: 'toolkit.registry.generation-record.v1',
        toolId: String(tool._id),
        toolVersion: version,
        artifactDigest,
        provider: tool.agent?.provider || 'unknown',
        generatedAt: timestamp(tool.agent?.generatedAt) || publishedAt,
      }),
      generator: tool.agent?.provider || 'unknown',
      generatedAt: timestamp(tool.agent?.generatedAt) || publishedAt,
      humanReviewed: ['published', 'market'].includes(tool.status),
      editAuditDigest: digestObject({
        schemaVersion: 'toolkit.registry.generated-edit-audit.v1',
        toolId: String(tool._id),
        toolVersion: version,
        artifactDigest,
        reviewedAt: timestamp(tool.reviewedAt || tool.updatedAt || tool.createdAt) || publishedAt,
      }),
    };
  }
  if (tool.type === 'builtin') {
    return {
      ...common,
      repository: 'private://toolkit_new',
      commit: process.env.RELEASE_VERSION || process.env.GITHUB_SHA || 'local-preview',
      path: `scripts/builtin_tools.js#${tool.slug}`,
    };
  }
  if (tool.flags?.includes('imported') || tool.flags?.includes('legacy-import')) {
    return {
      ...common,
      importedFrom: tool.legacy?.source || 'legacy-toolkit',
      originalArtifactDigest: tool.legacy?.originalArtifactDigest || tool.legacy?.artifactDigest || artifactDigest,
      originalManifestDigest: tool.legacy?.originalManifestDigest || tool.legacy?.manifestDigest || '',
      upstreamProvenanceDigest: tool.legacy?.upstreamProvenanceDigest || '',
      importRecordDigest: digestObject({
        schemaVersion: 'toolkit.registry.import-record.v1',
        toolId: String(tool._id),
        toolVersion: version,
        artifactDigest,
        importedFrom: tool.legacy?.source || 'legacy-toolkit',
        originalArtifactDigest: tool.legacy?.originalArtifactDigest || tool.legacy?.artifactDigest || artifactDigest,
        originalManifestDigest: tool.legacy?.originalManifestDigest || tool.legacy?.manifestDigest || '',
      }),
    };
  }
  return {
    ...common,
    toolVersionId: `${String(tool._id)}:${version}`,
    snapshotDigest: digestObject({
      schemaVersion: 'toolkit.registry.tool-snapshot.v1',
      toolId: String(tool._id),
      toolVersion: version,
      slug: tool.slug,
      name: tool.name,
      artifactDigest,
      sandbox: tool.currentVersion?.sandbox || {},
    }),
    editAuditDigest: digestObject({
      schemaVersion: 'toolkit.registry.edit-audit.v1',
      toolId: String(tool._id),
      toolVersion: version,
      authorId: tool.ownerId ? String(tool.ownerId) : '',
      updatedAt: timestamp(tool.updatedAt || tool.createdAt),
    }),
  };
}

function isSha256Digest(value) {
  return /^sha256:[0-9a-f]{64}$/.test(String(value || ''));
}

function isFullCommitHash(value) {
  return /^[0-9a-f]{40,64}$/i.test(String(value || ''));
}

function isPreviewGitRevision(revision) {
  return String(revision?.commit || revision?.sourceRevision || '') === 'local-preview'
    && String(revision?.repository || revision?.sourceRepository || '').startsWith('private://');
}

function assertPublicManifest(condition, message) {
  if (!condition) throw new Error(`public tool manifest not publishable: ${message}`);
}

function containsSensitiveGeneratedField(value, path = []) {
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some((item, index) => containsSensitiveGeneratedField(item, [...path, String(index)]));
  const sensitiveKeys = new Set([
    'prompt',
    'request',
    'input',
    'output',
    'secret',
    'token',
    'password',
    'credential',
    'cookie',
    'personalData',
    'privatePrompt',
  ]);
  return Object.entries(value).some(([key, child]) => sensitiveKeys.has(key) || containsSensitiveGeneratedField(child, [...path, key]));
}

export function validatePublicToolManifestPublishability(manifest, {
  allowedLicenses = PUBLIC_TOOL_LICENSE_ALLOWLIST,
  allowPreviewLicenseRefs = false,
} = {}) {
  assertPublicManifest(manifest?.schemaVersion === 'toolkit.registry.tool.v1', 'schema mismatch');
  assertPublicManifest(manifest.kind === 'toolkit.tool', 'kind mismatch');
  assertPublicManifest(isSha256Digest(manifest.artifact?.digest), 'artifact digest missing');
  assertPublicManifest(Number.isSafeInteger(manifest.artifact?.byteLength) && manifest.artifact.byteLength > 0, 'artifact byteLength missing');

  const licenseExpression = String(manifest.license?.expression || '');
  assertPublicManifest(licenseExpression, 'license expression missing');
  assertPublicManifest(
    allowedLicenses.includes(licenseExpression) || (allowPreviewLicenseRefs && licenseExpression.startsWith('LicenseRef-')),
    `license expression is not allowed: ${licenseExpression}`,
  );
  assertPublicManifest(isSha256Digest(manifest.license?.text?.digest), 'license text digest missing');
  assertPublicManifest(String(manifest.license?.text?.url || '').includes('/sha256/'), 'license text content-addressed URL missing');
  assertPublicManifest(Array.isArray(manifest.copyright) && manifest.copyright.length > 0, 'copyright missing');
  assertPublicManifest(manifest.copyright.every((entry) => /^Copyright \d{4} .+/.test(String(entry || ''))), 'copyright entries must include year and holder');

  const provenance = manifest.provenance || {};
  const revision = provenance.revision || {};
  const rights = provenance.rightsAttestation || {};
  assertPublicManifest(provenance.schemaVersion === 'toolkit.registry.provenance.v1', 'provenance schema mismatch');
  assertPublicManifest(['git', 'toolkit-studio', 'generated', 'imported'].includes(provenance.type), 'unknown provenance type');
  assertPublicManifest(provenance.publisher?.type && (provenance.publisher?.id || provenance.publisher?.name), 'publisher missing');
  assertPublicManifest(Number.isFinite(Date.parse(provenance.publishedAt)), 'publishedAt missing');
  assertPublicManifest(rights.statementVersion === 'toolkit.publisher-rights.v1', 'rights attestation statementVersion missing');
  assertPublicManifest(rights.attested === true, 'rights attestation missing');
  assertPublicManifest(Number.isFinite(Date.parse(rights.acceptedAt || rights.attestedAt)), 'rights attestation timestamp missing');
  assertPublicManifest(isSha256Digest(rights.statementDigest), 'rights statement digest missing');
  assertPublicManifest(revision.artifactDigest === manifest.artifact.digest, 'provenance artifact digest mismatch');

  if (provenance.type === 'git') {
    assertPublicManifest(revision.repository || revision.sourceRepository, 'git source repository missing');
    assertPublicManifest(
      isFullCommitHash(revision.commit || revision.sourceRevision) || (allowPreviewLicenseRefs && isPreviewGitRevision(revision)),
      'git source revision must be a full commit hash',
    );
  } else if (provenance.type === 'toolkit-studio') {
    assertPublicManifest(revision.toolVersionId, 'Studio toolVersionId missing');
    assertPublicManifest(isSha256Digest(revision.snapshotDigest), 'Studio snapshot digest missing');
    assertPublicManifest(isSha256Digest(revision.editAuditDigest), 'Studio edit audit digest missing');
  } else if (provenance.type === 'generated') {
    assertPublicManifest(isSha256Digest(revision.generationRecordDigest), 'generation record digest missing');
    assertPublicManifest(revision.generator && revision.generator !== 'unknown', 'generator identity missing');
    assertPublicManifest(revision.humanReviewed === true, 'generated tool must be human reviewed');
    assertPublicManifest(isSha256Digest(revision.editAuditDigest), 'generated edit audit digest missing');
    assertPublicManifest(!containsSensitiveGeneratedField(provenance), 'generated provenance contains sensitive generation fields');
  } else if (provenance.type === 'imported') {
    assertPublicManifest(revision.importedFrom, 'import source missing');
    assertPublicManifest(isSha256Digest(revision.originalArtifactDigest), 'original artifact digest missing');
    assertPublicManifest(isSha256Digest(revision.originalManifestDigest), 'original manifest digest missing');
    assertPublicManifest(isSha256Digest(revision.importRecordDigest), 'import record digest missing');
  }

  assertPublicManifest(isSha256Digest(manifest.thirdParty?.notice?.digest), 'NOTICE digest missing');
  assertPublicManifest(String(manifest.thirdParty?.notice?.url || '').includes('/sha256/'), 'NOTICE content-addressed URL missing');
  assertPublicManifest(isSha256Digest(manifest.thirdParty?.sbom?.digest), 'SBOM digest missing');
  assertPublicManifest(String(manifest.thirdParty?.sbom?.url || '').includes('/sha256/'), 'SBOM content-addressed URL missing');

  return {
    ok: true,
    licenseExpression,
    provenanceType: provenance.type,
    artifactDigest: manifest.artifact.digest,
  };
}

function licenseTextForTool(tool, expression) {
  if (tool.type === 'builtin') {
    return [
      expression,
      '',
      'Toolkit official built-in tool license.',
      'Official built-in tool artifacts are intended to be published with the toolkit-builtins public package.',
      'This artifact is licensed under Apache License 2.0 when distributed from the public toolkit-builtins package or a Registry manifest that declares Apache-2.0.',
      '',
    ].join('\n');
  }
  return [
    expression,
    '',
    'Toolkit publisher-attested preview license.',
    'The publisher attests they have the rights required to submit this tool for Toolkit registry distribution.',
    'This artifact is visible for audit and may be executed through Toolkit-compatible runtimes according to product terms.',
    'No open-source, redistribution, sublicensing, or standalone reuse rights are granted by this preview license.',
    '',
  ].join('\n');
}

function noticeTextForTool(tool) {
  const deps = tool.currentVersion?.dependencies || tool.dependencies || [];
  if (!deps.length) return 'No third-party runtime dependencies declared for this tool artifact.\n';
  return [
    'Third-party notices declared by publisher:',
    '',
    ...deps.map((dep) => `- ${dep.name || dep.package || 'unknown'} ${dep.version || ''} ${dep.license || ''}`.trim()),
    '',
  ].join('\n');
}

function sbomForTool(tool, { artifactDigest, publishedAt }) {
  const deps = tool.currentVersion?.dependencies || tool.dependencies || [];
  const documentNamespace = `https://${registryIssuer()}/registry/sbom/${artifactDigest.slice('sha256:'.length)}`;
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `toolkit-${tool.slug}-${tool.currentVersion?.v || 1}`,
    documentNamespace,
    creationInfo: {
      created: publishedAt || new Date(0).toISOString(),
      creators: ['Tool: toolkit-registry-preview'],
    },
    packages: [
      {
        name: tool.slug,
        SPDXID: 'SPDXRef-Tool',
        versionInfo: String(tool.currentVersion?.v || 1),
        filesAnalyzed: false,
        downloadLocation: 'NOASSERTION',
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: tool.type === 'builtin'
          ? 'Apache-2.0'
          : 'LicenseRef-Toolkit-Publisher-Attested-Preview',
        checksums: [{ algorithm: 'SHA256', checksumValue: artifactDigest.slice('sha256:'.length) }],
        externalRefs: [],
      },
      ...deps.map((dep, index) => ({
        name: dep.name || dep.package || `dependency-${index + 1}`,
        SPDXID: `SPDXRef-Dependency-${index + 1}`,
        versionInfo: dep.version || 'NOASSERTION',
        filesAnalyzed: false,
        downloadLocation: dep.url || 'NOASSERTION',
        licenseConcluded: dep.license || 'NOASSERTION',
        licenseDeclared: dep.license || 'NOASSERTION',
      })),
    ],
  };
}

export function toolManifestEnvelope(tool, opts) {
  return signedEnvelope(toolManifest(tool, opts));
}

export function registryIndex(tools, { baseUrl }) {
  return signedEnvelope({
    schemaVersion: 'toolkit.registry.index.v1',
    kind: 'toolkit.registry.index',
    issuer: registryIssuer(),
    registry: `${baseUrl}/api/v1/registry`,
    tools: tools.map((tool) => {
      const envelope = toolManifestEnvelope(tool, { baseUrl });
      return {
        slug: tool.slug,
        name: tool.name,
        version: tool.currentVersion?.v || 1,
        digest: envelope.digest,
        signature: envelope.signature,
        manifestUrl: `${baseUrl}/api/v1/registry/tools/${encodeURIComponent(tool.slug)}/manifest`,
      };
    }),
  });
}

function sortedLockfileTools(tools = []) {
  return [...tools].sort((a, b) => String(a.slug || '').localeCompare(String(b.slug || '')));
}

export function registryLockfileResolutionCore(tools, { baseUrl, now = new Date() }) {
  const keyset = registryTrustKeyset({ now });
  const checkpoint = registryTrustCheckpoint({ now });
  return signedEnvelope({
    schemaVersion: 'toolkit.lock.resolution.v1',
    kind: 'toolkit.lock.resolution',
    registryId: registryIssuer(),
    registry: `${baseUrl}/api/v1/registry`,
    keyset: {
      version: keyset.keysetVersion,
      digest: keyset.digest,
    },
    checkpoint: {
      version: checkpoint.checkpointVersion,
      digest: checkpoint.digest,
    },
    statusPolicy: {
      manifestStatus: 'active',
      artifactStatus: 'active',
      executionProofMaxAgeSeconds: 300,
    },
    tools: sortedLockfileTools(tools).map((tool) => {
      const envelope = toolManifestEnvelope(tool, { baseUrl });
      return {
        name: `toolkit-${tool.slug}`,
        slug: tool.slug,
        id: String(tool._id),
        version: tool.currentVersion?.v || 1,
        manifest: {
          digest: envelope.digest,
          mediaType: 'application/json; charset=utf-8',
          signature: envelope.signature,
          byteLength: Buffer.byteLength(JSON.stringify(envelope), 'utf8'),
        },
        artifact: {
          type: envelope.artifact.type,
          digest: envelope.artifact.digest,
          sourceHash: envelope.artifact.sourceHash,
          mediaType: 'text/javascript; charset=utf-8',
          byteLength: envelope.artifact.byteLength,
        },
        attachments: {
          license: envelope.license?.text?.digest || '',
          notice: envelope.thirdParty?.notice?.digest || '',
          sbom: envelope.thirdParty?.sbom?.digest || '',
        },
        runtime: envelope.runtime,
        inputSchemaDigest: digestObject(envelope.inputSchema || {}),
        mcpTool: mcpToolName(tool),
      };
    }),
  });
}

export function registryLockfileTransportOverlay(resolutionCore, tools, { baseUrl }) {
  const toolBySlug = new Map((tools || []).map((tool) => [String(tool.slug || ''), tool]));
  return {
    schemaVersion: 'toolkit.lock.transport.v1',
    resolutionDigest: resolutionCore.digest,
    primaryBaseUrl: baseUrl,
    mirrors: [],
    localContentStores: [],
    tools: (resolutionCore.tools || []).map((entry) => {
      const tool = toolBySlug.get(entry.slug) || { slug: entry.slug };
      return {
        slug: entry.slug,
        manifestUrl: `${baseUrl}/api/v1/registry/tools/${encodeURIComponent(entry.slug)}/manifest`,
        manifestContentAddressedUrl: `${baseUrl}/api/v1/registry/manifests/sha256/${entry.manifest.digest.slice('sha256:'.length)}`,
        artifactUrl: `${baseUrl}/api/v1/registry/artifacts/sha256/${entry.artifact.digest.slice('sha256:'.length)}`,
        endpoint: `${baseUrl}/api/v1/t/${encodeURIComponent(tool.slug || entry.slug)}`,
        mcpEndpoint: `${baseUrl}/api/mcp`,
      };
    }),
  };
}

function digestHex(digest, label = 'digest') {
  const value = String(digest || '').trim().toLowerCase();
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new Error(`${label} must be a sha256 digest`);
  return value.slice('sha256:'.length);
}

function registryContentAddressedPath(kind, digest) {
  const hex = digestHex(digest, `${kind} digest`);
  if (kind === 'manifest') return `manifests/sha256/${hex}`;
  if (kind === 'artifact') return `artifacts/sha256/${hex}`;
  if (kind === 'attachment') return `attachments/sha256/${hex}`;
  throw new Error(`unsupported registry content kind: ${kind}`);
}

function registryApiContentAddressedPath(kind, digest) {
  return `/api/v1/registry/${registryContentAddressedPath(kind, digest)}`;
}

function joinTransportBaseUrl(baseUrl, apiPath) {
  const base = String(baseUrl || '').replace(/\/+$/, '');
  if (!base) throw new Error('transport baseUrl is required');
  return `${base}${apiPath}`;
}

function assertTransportUrl(value, label) {
  const url = new URL(String(value || ''));
  if (!['http:', 'https:', 'file:'].includes(url.protocol)) throw new Error(`${label} uses unsupported transport protocol`);
  if (url.username || url.password) throw new Error(`${label} must not include credentials`);
  return url.toString();
}

const DEFAULT_LOCKFILE_TRANSPORT_POLICY = Object.freeze({
  maxAttempts: 1,
  timeoutMs: 15000,
  retryBackoffMs: 0,
  retryStatuses: [408, 425, 429, 500, 502, 503, 504],
});

export function registryLockfileTransportPolicy(policy = {}) {
  const maxAttempts = Number.isInteger(policy.maxAttempts) ? policy.maxAttempts : DEFAULT_LOCKFILE_TRANSPORT_POLICY.maxAttempts;
  const timeoutMs = Number.isInteger(policy.timeoutMs) ? policy.timeoutMs : DEFAULT_LOCKFILE_TRANSPORT_POLICY.timeoutMs;
  const retryBackoffMs = Number.isInteger(policy.retryBackoffMs) ? policy.retryBackoffMs : DEFAULT_LOCKFILE_TRANSPORT_POLICY.retryBackoffMs;
  const retryStatuses = Array.isArray(policy.retryStatuses) ? policy.retryStatuses : DEFAULT_LOCKFILE_TRANSPORT_POLICY.retryStatuses;
  if (maxAttempts < 1 || maxAttempts > 5) throw new Error('lockfile transport maxAttempts must be between 1 and 5');
  if (timeoutMs < 0 || timeoutMs > 120000) throw new Error('lockfile transport timeoutMs must be between 0 and 120000');
  if (retryBackoffMs < 0 || retryBackoffMs > 60000) throw new Error('lockfile transport retryBackoffMs must be between 0 and 60000');
  const normalizedStatuses = retryStatuses.map((status) => Number(status));
  if (normalizedStatuses.some((status) => !Number.isInteger(status) || status < 400 || status > 599)) {
    throw new Error('lockfile transport retryStatuses must be HTTP 4xx/5xx integers');
  }
  return {
    maxAttempts,
    timeoutMs,
    retryBackoffMs,
    retryStatuses: [...new Set(normalizedStatuses)],
  };
}

export function validateRegistryLockfileTransportOverlay(resolutionCore, overlay) {
  if (!resolutionCore || resolutionCore.schemaVersion !== 'toolkit.lock.resolution.v1') {
    throw new Error('lockfile resolution core is required');
  }
  if (!overlay || overlay.schemaVersion !== 'toolkit.lock.transport.v1') {
    throw new Error('lockfile transport overlay schema mismatch');
  }
  if (overlay.resolutionDigest !== resolutionCore.digest) {
    throw new Error('lockfile transport overlay resolutionDigest mismatch');
  }
  for (const forbidden of ['digest', 'signature', 'toolsDigest', 'checkpoint', 'keyset', 'statusPolicy', 'runtime', 'manifest', 'artifact', 'attachments']) {
    if (Object.hasOwn(overlay, forbidden)) throw new Error(`lockfile transport overlay cannot override ${forbidden}`);
  }
  const allowedOverlayKeys = new Set([
    'schemaVersion',
    'resolutionDigest',
    'primaryBaseUrl',
    'mirrors',
    'localContentStores',
    'tools',
    'authRefs',
    'proxyRef',
  ]);
  for (const key of Object.keys(overlay)) {
    if (!allowedOverlayKeys.has(key)) throw new Error(`lockfile transport overlay contains unsupported field: ${key}`);
  }
  if (overlay.primaryBaseUrl) assertTransportUrl(overlay.primaryBaseUrl, 'overlay primaryBaseUrl');
  if (!Array.isArray(overlay.mirrors || [])) throw new Error('lockfile transport overlay mirrors must be an array');
  for (const [index, mirror] of (overlay.mirrors || []).entries()) {
    if (!mirror || typeof mirror !== 'object') throw new Error(`lockfile transport overlay mirror ${index} must be an object`);
    const allowedMirrorKeys = new Set(['type', 'baseUrl', 'authRef', 'priority']);
    for (const key of Object.keys(mirror)) {
      if (!allowedMirrorKeys.has(key)) throw new Error(`lockfile transport overlay mirror cannot include ${key}`);
    }
    assertTransportUrl(mirror.baseUrl, `overlay mirror ${index} baseUrl`);
  }
  if (!Array.isArray(overlay.localContentStores || [])) throw new Error('lockfile transport overlay localContentStores must be an array');
  for (const [index, store] of (overlay.localContentStores || []).entries()) {
    if (!store || typeof store !== 'object') throw new Error(`lockfile transport overlay localContentStore ${index} must be an object`);
    const allowedStoreKeys = new Set(['type', 'path', 'priority']);
    for (const key of Object.keys(store)) {
      if (!allowedStoreKeys.has(key)) throw new Error(`lockfile transport overlay localContentStore cannot include ${key}`);
    }
    if (String(store.type || 'filesystem') !== 'filesystem') throw new Error('lockfile transport overlay localContentStore type must be filesystem');
    if (!String(store.path || '').trim()) throw new Error('lockfile transport overlay localContentStore path is required');
  }
  const coreTools = new Map((resolutionCore.tools || []).map((tool) => [tool.slug, tool]));
  const overlayTools = overlay.tools || [];
  if (!Array.isArray(overlayTools)) throw new Error('lockfile transport overlay tools must be an array');
  const seen = new Set();
  for (const entry of overlayTools) {
    const slug = String(entry?.slug || '');
    if (!slug || seen.has(slug)) throw new Error('lockfile transport overlay contains duplicate or empty slug');
    seen.add(slug);
    const coreTool = coreTools.get(slug);
    if (!coreTool) throw new Error(`lockfile transport overlay references unknown tool: ${slug}`);
    for (const forbidden of ['digest', 'signature', 'manifestDigest', 'sourceHash', 'runtime', 'inputSchemaDigest', 'statusPolicy']) {
      if (Object.hasOwn(entry, forbidden)) throw new Error(`lockfile transport overlay tool cannot override ${forbidden}`);
    }
    const manifestPath = `/api/v1/registry/manifests/sha256/${coreTool.manifest.digest.slice('sha256:'.length)}`;
    const artifactPath = `/api/v1/registry/artifacts/sha256/${coreTool.artifact.digest.slice('sha256:'.length)}`;
    const manifestUrl = assertTransportUrl(entry.manifestContentAddressedUrl, `overlay ${slug} manifestContentAddressedUrl`);
    const artifactUrl = assertTransportUrl(entry.artifactUrl, `overlay ${slug} artifactUrl`);
    if (!manifestUrl.endsWith(manifestPath)) throw new Error(`lockfile transport overlay manifest URL must bind core digest for ${slug}`);
    if (!artifactUrl.endsWith(artifactPath)) throw new Error(`lockfile transport overlay artifact URL must bind core digest for ${slug}`);
  }
  if (seen.size !== coreTools.size) throw new Error('lockfile transport overlay must include every resolved tool');
  return {
    ok: true,
    resolutionDigest: resolutionCore.digest,
    tools: overlayTools.map((entry) => ({
      slug: entry.slug,
      manifestContentAddressedUrl: entry.manifestContentAddressedUrl,
      artifactUrl: entry.artifactUrl,
    })),
  };
}

function lockfileCoreTool(resolutionCore, slug) {
  const tool = (resolutionCore.tools || []).find((entry) => entry.slug === slug);
  if (!tool) throw new Error(`lockfile resolution core does not contain tool: ${slug}`);
  return tool;
}

function lockfileToolTransportOverlay(overlay, slug) {
  const entry = (overlay.tools || []).find((tool) => tool.slug === slug);
  if (!entry) throw new Error(`lockfile transport overlay does not contain tool: ${slug}`);
  return entry;
}

function localContentPath(root, kind, digest) {
  return `${String(root || '').replace(/\/+$/, '')}/${registryContentAddressedPath(kind, digest)}`;
}

export function resolveRegistryLockfileTransportCandidates(resolutionCore, overlay, { slug, kind = 'artifact' } = {}) {
  validateRegistryLockfileTransportOverlay(resolutionCore, overlay);
  const coreTool = lockfileCoreTool(resolutionCore, String(slug || ''));
  const transport = lockfileToolTransportOverlay(overlay, coreTool.slug);
  const target = kind === 'manifest' ? coreTool.manifest : coreTool.artifact;
  if (!target) throw new Error(`lockfile resolution core tool does not have ${kind}`);
  const digest = target.digest;
  const apiPath = registryApiContentAddressedPath(kind, digest);
  const explicitUrl = kind === 'manifest' ? transport.manifestContentAddressedUrl : transport.artifactUrl;
  const candidates = [];
  const seen = new Set();
  function pushUrl(source, url, extra = {}) {
    const normalizedUrl = assertTransportUrl(url, `${source} ${kind} url`);
    if (!normalizedUrl.endsWith(apiPath)) throw new Error(`${source} ${kind} url must bind core digest`);
    const key = `url:${normalizedUrl}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({
      transport: 'url',
      source,
      url: normalizedUrl,
      digest,
      mediaType: target.mediaType,
      byteLength: target.byteLength,
      ...extra,
    });
  }
  function pushFile(source, rootPath, extra = {}) {
    const filePath = localContentPath(rootPath, kind, digest);
    const key = `file:${filePath}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({
      transport: 'filesystem',
      source,
      path: filePath,
      digest,
      mediaType: target.mediaType,
      byteLength: target.byteLength,
      ...extra,
    });
  }
  pushUrl('tool-overlay', explicitUrl);
  if (overlay.primaryBaseUrl) pushUrl('primary', joinTransportBaseUrl(overlay.primaryBaseUrl, apiPath));
  for (const mirror of overlay.mirrors || []) {
    pushUrl('mirror', joinTransportBaseUrl(mirror.baseUrl, apiPath), {
      authRef: mirror.authRef || '',
      priority: mirror.priority ?? null,
    });
  }
  for (const store of overlay.localContentStores || []) {
    pushFile('local-content-store', store.path, { priority: store.priority ?? null });
  }
  return {
    schemaVersion: 'toolkit.lock.transport-candidates.v1',
    resolutionDigest: resolutionCore.digest,
    slug: coreTool.slug,
    kind,
    digest,
    candidates,
  };
}

function bufferFromContent(content) {
  if (Buffer.isBuffer(content)) return content;
  if (content instanceof ArrayBuffer) return Buffer.from(content);
  if (ArrayBuffer.isView(content)) return Buffer.from(content.buffer, content.byteOffset, content.byteLength);
  return Buffer.from(String(content || ''), 'utf8');
}

function bodyString(content) {
  return bufferFromContent(content).toString('utf8');
}

function verifyManifestEnvelopeBytes(bytes, expectedDigest) {
  let envelope;
  try {
    envelope = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('registry manifest candidate is not valid JSON');
  }
  if (envelope.digest !== expectedDigest) throw new Error('registry manifest candidate digest field mismatch');
  const payloadDigest = digestObject(withoutEnvelopeFields(envelope));
  if (payloadDigest !== expectedDigest) throw new Error('registry manifest candidate payload digest mismatch');
  if (envelope.signature?.payloadDigest !== expectedDigest) throw new Error('registry manifest candidate signature payloadDigest mismatch');
  return envelope;
}

export function verifyRegistryLockfileCandidateBytes({ kind, expectedDigest, expectedByteLength = null, bytes }) {
  const buf = bufferFromContent(bytes);
  if (Number.isSafeInteger(expectedByteLength) && expectedByteLength >= 0 && buf.byteLength !== expectedByteLength) {
    throw new Error(`registry ${kind} candidate byteLength mismatch`);
  }
  const digest = String(expectedDigest || '');
  if (kind === 'manifest') {
    const envelope = verifyManifestEnvelopeBytes(buf, digest);
    return { ok: true, kind, digest, byteLength: buf.byteLength, envelope };
  }
  const actualDigest = `sha256:${sha256(buf)}`;
  if (actualDigest !== digest) throw new Error(`registry ${kind} candidate digest mismatch`);
  return { ok: true, kind, digest, byteLength: buf.byteLength };
}

function publicTransportCandidate(candidate) {
  const { authRef, ...rest } = candidate;
  return authRef ? { ...rest, authRef } : rest;
}

function sanitizeTransportLocation(location) {
  const raw = String(location || '');
  try {
    const url = new URL(raw);
    url.username = '';
    url.password = '';
    for (const key of [...url.searchParams.keys()]) {
      if (/token|secret|password|credential|signature|key/i.test(key)) {
        url.searchParams.set(key, '[redacted]');
      }
    }
    return url.toString();
  } catch {
    return raw.replace(/(token|secret|password|credential|signature|key)=([^&\s]+)/gi, '$1=[redacted]');
  }
}

function sanitizeTransportError(message) {
  return String(message || '')
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [redacted]')
    .replace(/(token|secret|password|credential|signature|key)=([^&\s]+)/gi, '$1=[redacted]')
    .slice(0, 300);
}

function transportDelay(ms, sleepImpl) {
  if (!ms) return Promise.resolve();
  if (typeof sleepImpl === 'function') return Promise.resolve(sleepImpl(ms));
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withTransportTimeout(promise, { timeoutMs, onTimeout }) {
  if (!timeoutMs) return promise;
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          if (typeof onTimeout === 'function') onTimeout();
          reject(new Error(`registry candidate fetch timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function authOptionsForCandidate(candidate, { authResolver }) {
  if (!candidate.authRef) return {};
  if (typeof authResolver !== 'function') return {};
  const resolved = await authResolver({
    authRef: candidate.authRef,
    candidate: publicTransportCandidate(candidate),
  });
  if (!resolved) return {};
  if (!resolved || typeof resolved !== 'object' || Array.isArray(resolved)) {
    throw new Error('registry transport authResolver must return an object');
  }
  const allowedKeys = new Set(['headers']);
  for (const key of Object.keys(resolved)) {
    if (!allowedKeys.has(key)) throw new Error(`registry transport authResolver cannot return ${key}`);
  }
  if (resolved.headers && (typeof resolved.headers !== 'object' || Array.isArray(resolved.headers))) {
    throw new Error('registry transport authResolver headers must be an object');
  }
  return resolved.headers ? { headers: { ...resolved.headers } } : {};
}

async function fetchCandidateBytes(candidate, { fetchImpl, authResolver, transportPolicy, sleepImpl }) {
  const policy = registryLockfileTransportPolicy(transportPolicy);
  const authOptions = await authOptionsForCandidate(candidate, { authResolver });
  const retryStatuses = new Set(policy.retryStatuses);
  const attempts = [];
  for (let attempt = 1; attempt <= policy.maxAttempts; attempt += 1) {
    const controller = typeof AbortController === 'function' && policy.timeoutMs ? new AbortController() : null;
    try {
      const res = await withTransportTimeout(fetchImpl(candidate.url, {
        ...authOptions,
        signal: controller?.signal,
        toolkitCandidate: publicTransportCandidate(candidate),
      }), {
        timeoutMs: policy.timeoutMs,
        onTimeout: () => controller?.abort(),
      });
      const status = Number(res?.status || 0);
      if (status < 200 || status >= 300) {
        attempts.push({ attempt, status: status || 'no_response', retryable: retryStatuses.has(status) });
        if (attempt < policy.maxAttempts && retryStatuses.has(status)) {
          await transportDelay(policy.retryBackoffMs, sleepImpl);
          continue;
        }
        throw new Error(`registry candidate fetch failed: ${status || 'no_response'}`);
      }
      return bufferFromContent(await withTransportTimeout(res.arrayBuffer(), {
        timeoutMs: policy.timeoutMs,
        onTimeout: () => controller?.abort(),
      }));
    } catch (e) {
      const error = sanitizeTransportError(e.message || String(e));
      if (!attempts.some((entry) => entry.attempt === attempt)) attempts.push({ attempt, error, retryable: true });
      const currentAttempt = attempts.find((entry) => entry.attempt === attempt);
      if (attempt < policy.maxAttempts && currentAttempt?.retryable !== false) {
        await transportDelay(policy.retryBackoffMs, sleepImpl);
        continue;
      }
      const err = new Error(`registry candidate fetch failed after ${attempts.length} attempt(s)`);
      err.attempts = attempts;
      throw err;
    }
  }
  throw new Error('registry candidate fetch failed without attempts');
}

async function readCandidateBytes(candidate, { fetchImpl, readFileImpl, authResolver, transportPolicy, sleepImpl }) {
  if (candidate.transport === 'filesystem') {
    return bufferFromContent(await readFileImpl(candidate.path));
  }
  if (candidate.transport === 'url') {
    return fetchCandidateBytes(candidate, { fetchImpl, authResolver, transportPolicy, sleepImpl });
  }
  throw new Error(`unsupported registry transport: ${candidate.transport}`);
}

export async function resolveRegistryLockfileContent(resolutionCore, overlay, {
  slug,
  kind = 'artifact',
  fetchImpl = globalThis.fetch,
  readFileImpl = fs.readFile,
  authResolver,
  transportPolicy,
  sleepImpl,
} = {}) {
  const resolved = resolveRegistryLockfileTransportCandidates(resolutionCore, overlay, { slug, kind });
  if (typeof fetchImpl !== 'function') throw new Error('registry URL resolver requires fetch');
  if (typeof readFileImpl !== 'function') throw new Error('registry filesystem resolver requires readFile');
  const failures = [];
  for (const candidate of resolved.candidates) {
    try {
      const bytes = await readCandidateBytes(candidate, { fetchImpl, readFileImpl, authResolver, transportPolicy, sleepImpl });
      const verified = verifyRegistryLockfileCandidateBytes({
        kind,
        expectedDigest: resolved.digest,
        expectedByteLength: candidate.byteLength,
        bytes,
      });
      return {
        schemaVersion: 'toolkit.lock.resolved-content.v1',
        resolutionDigest: resolved.resolutionDigest,
        slug: resolved.slug,
        kind,
        digest: resolved.digest,
        candidate,
        bytes,
        verified,
      };
    } catch (e) {
      const failure = {
        source: candidate.source,
        transport: candidate.transport,
        location: sanitizeTransportLocation(candidate.url || candidate.path || ''),
        error: sanitizeTransportError(e.message || String(e)),
      };
      if (e.attempts) failure.attempts = e.attempts;
      failures.push(failure);
    }
  }
  const err = new Error(`registry ${kind} content could not be resolved for ${resolved.slug}`);
  err.failures = failures;
  throw err;
}

export function registryLockfileFileSet(lockfile) {
  const resolutionCore = lockfile?.resolutionCore;
  const transportOverlay = lockfile?.transportOverlay;
  validateRegistryLockfileTransportOverlay(resolutionCore, transportOverlay);
  const resolutionBody = canonicalJson(resolutionCore);
  const transportBody = canonicalJson(transportOverlay);
  return {
    schemaVersion: 'toolkit.lock.files.v1',
    resolutionDigest: resolutionCore.digest,
    files: [
      {
        role: 'signed-resolution-core',
        path: '.toolkit/lock.resolution.json',
        mediaType: 'application/json; charset=utf-8',
        digest: digestSource(resolutionBody),
        body: resolutionBody,
      },
      {
        role: 'transport-overlay',
        path: '.toolkit/transport.json',
        mediaType: 'application/json; charset=utf-8',
        digest: digestSource(transportBody),
        body: transportBody,
      },
    ],
  };
}

function parseJsonBody(body, label) {
  try {
    return JSON.parse(String(body || ''));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

export function parseRegistryLockfileFiles({ resolutionCoreBody, transportOverlayBody } = {}) {
  const resolutionCore = parseJsonBody(resolutionCoreBody, 'lockfile resolution core');
  const transportOverlay = parseJsonBody(transportOverlayBody, 'lockfile transport overlay');
  if (resolutionCore.schemaVersion !== 'toolkit.lock.resolution.v1') throw new Error('lockfile resolution core schema mismatch');
  const expectedDigest = digestObject(withoutEnvelopeFields(resolutionCore));
  if (resolutionCore.digest !== expectedDigest) throw new Error('lockfile resolution core digest mismatch');
  if (resolutionCore.signature?.payloadDigest !== resolutionCore.digest) throw new Error('lockfile resolution core signature payloadDigest mismatch');
  validateRegistryLockfileTransportOverlay(resolutionCore, transportOverlay);
  return {
    schemaVersion: 'toolkit.lock.files.parsed.v1',
    resolutionDigest: resolutionCore.digest,
    resolutionCore,
    transportOverlay,
  };
}

function assertOfflineExportPath(path) {
  const value = String(path || '').trim();
  if (!value || value.startsWith('/') || value.includes('\\') || value.split('/').some((part) => part === '..')) {
    throw new Error('registry offline export file path must be relative and safe');
  }
  return value;
}

function offlineContentPath(kind, digest) {
  if (kind === 'manifest') return `registry/${registryContentAddressedPath('manifest', digest)}`;
  if (kind === 'artifact' || kind === 'source') return `registry/${registryContentAddressedPath('artifact', digest)}`;
  if (kind === 'attachment' || kind === 'license' || kind === 'notice' || kind === 'sbom') {
    return `registry/${registryContentAddressedPath('attachment', digest)}`;
  }
  throw new Error(`unsupported registry offline content kind: ${kind}`);
}

export function registryOfflineExportContentFile({
  kind,
  role = '',
  path = '',
  mediaType = 'application/octet-stream',
  body,
  contentDigest = '',
} = {}) {
  const normalizedKind = String(kind || '').trim();
  const contentBody = bodyString(body);
  const bodyDigest = digestSource(contentBody);
  const effectiveContentDigest = contentDigest || bodyDigest;
  digestHex(effectiveContentDigest, 'offline export contentDigest');
  return {
    role: role || normalizedKind,
    kind: normalizedKind,
    path: assertOfflineExportPath(path || offlineContentPath(normalizedKind, effectiveContentDigest)),
    mediaType,
    contentDigest: effectiveContentDigest,
    bodyDigest,
    byteLength: Buffer.byteLength(contentBody, 'utf8'),
    body: contentBody,
  };
}

function offlineExportFile({ role, kind, path, mediaType, body, contentDigest = '' }) {
  const contentBody = bodyString(body);
  const bodyDigest = digestSource(contentBody);
  return {
    role,
    kind,
    path: assertOfflineExportPath(path),
    mediaType,
    contentDigest: contentDigest || bodyDigest,
    bodyDigest,
    byteLength: Buffer.byteLength(contentBody, 'utf8'),
    body: contentBody,
  };
}

function offlineArchiveIndex(files) {
  return {
    schemaVersion: 'toolkit.registry.offline-archive-index.v1',
    registryId: registryIssuer(),
    files: files.map(({ body: _body, ...entry }) => entry),
  };
}

export function registryOfflineExportBundle({
  lockfile,
  keyset,
  checkpoint,
  statusSnapshot = null,
  contentFiles = [],
  now = new Date(),
} = {}) {
  if (!lockfile) throw new Error('registry offline export requires lockfile');
  if (!keyset || keyset.schemaVersion !== 'toolkit.registry.keyset.v1') throw new Error('registry offline export requires keyset');
  if (!checkpoint || checkpoint.schemaVersion !== 'toolkit.registry.checkpoint.v1') throw new Error('registry offline export requires checkpoint');
  const lockfileFiles = registryLockfileFileSet(lockfile);
  const files = [
    offlineExportFile({
      role: 'signed-resolution-core',
      kind: 'lockfile-resolution',
      path: '.toolkit/lock.resolution.json',
      mediaType: 'application/json; charset=utf-8',
      contentDigest: lockfile.resolutionCore.digest,
      body: lockfileFiles.files.find((file) => file.role === 'signed-resolution-core')?.body,
    }),
    offlineExportFile({
      role: 'transport-overlay',
      kind: 'lockfile-transport',
      path: '.toolkit/transport.json',
      mediaType: 'application/json; charset=utf-8',
      body: lockfileFiles.files.find((file) => file.role === 'transport-overlay')?.body,
    }),
    offlineExportFile({
      role: 'registry-keyset',
      kind: 'keyset',
      path: `registry/keysets/${keyset.digest.slice('sha256:'.length)}.json`,
      mediaType: 'application/json; charset=utf-8',
      contentDigest: keyset.digest,
      body: canonicalJson(keyset),
    }),
    offlineExportFile({
      role: 'registry-checkpoint',
      kind: 'checkpoint',
      path: `registry/checkpoints/${checkpoint.digest.slice('sha256:'.length)}.json`,
      mediaType: 'application/json; charset=utf-8',
      contentDigest: checkpoint.digest,
      body: canonicalJson(checkpoint),
    }),
  ];
  if (statusSnapshot?.head) {
    files.push(offlineExportFile({
      role: 'registry-status-head',
      kind: 'status-head',
      path: 'registry/status/head.json',
      mediaType: 'application/json; charset=utf-8',
      contentDigest: statusSnapshot.head.digest,
      body: canonicalJson(statusSnapshot.head),
    }));
    files.push(offlineExportFile({
      role: 'registry-status-events',
      kind: 'status-events',
      path: 'registry/status/events.json',
      mediaType: 'application/json; charset=utf-8',
      body: canonicalJson(statusSnapshot.events || []),
    }));
  }
  for (const file of contentFiles || []) {
    files.push(registryOfflineExportContentFile(file));
  }
  files.sort((a, b) => a.path.localeCompare(b.path));
  const seenPaths = new Set();
  for (const file of files) {
    if (seenPaths.has(file.path)) throw new Error(`registry offline export duplicate file path: ${file.path}`);
    seenPaths.add(file.path);
  }
  const archiveIndex = offlineArchiveIndex(files);
  const archiveIndexDigest = digestObject(archiveIndex);
  return {
    schemaVersion: 'toolkit.registry.offline-export.v1',
    registryId: registryIssuer(),
    createdAt: now.toISOString(),
    lockfileResolutionDigest: lockfile.resolutionCore.digest,
    keysetDigest: keyset.digest,
    checkpointDigest: checkpoint.digest,
    statusHeadDigest: statusSnapshot?.head?.digest || checkpoint.statusHead?.digest || '',
    archiveIndexDigest,
    archiveIndex,
    files,
  };
}

function verifyOfflineEnvelope(file, label) {
  const parsed = parseJsonBody(file.body, label);
  const digest = digestObject(withoutEnvelopeFields(parsed));
  if (parsed.digest !== digest) throw new Error(`${label} digest mismatch`);
  if (file.contentDigest !== digest) throw new Error(`${label} contentDigest mismatch`);
  if (parsed.signature?.payloadDigest !== digest) throw new Error(`${label} signature payloadDigest mismatch`);
  return parsed;
}

export function verifyRegistryOfflineExportBundle(bundle) {
  if (!bundle || bundle.schemaVersion !== 'toolkit.registry.offline-export.v1') {
    throw new Error('registry offline export schema mismatch');
  }
  if (bundle.registryId !== registryIssuer()) throw new Error('registry offline export registryId mismatch');
  const files = bundle.files || [];
  if (!Array.isArray(files) || !files.length) throw new Error('registry offline export files are required');
  const seenPaths = new Set();
  for (const file of files) {
    assertOfflineExportPath(file.path);
    if (seenPaths.has(file.path)) throw new Error(`registry offline export duplicate file path: ${file.path}`);
    seenPaths.add(file.path);
    const body = bodyString(file.body);
    if (digestSource(body) !== file.bodyDigest) throw new Error(`registry offline export bodyDigest mismatch: ${file.path}`);
    if (Buffer.byteLength(body, 'utf8') !== file.byteLength) throw new Error(`registry offline export byteLength mismatch: ${file.path}`);
    if (file.kind === 'manifest') {
      verifyRegistryLockfileCandidateBytes({ kind: 'manifest', expectedDigest: file.contentDigest, expectedByteLength: file.byteLength, bytes: body });
    } else if (['artifact', 'source', 'attachment', 'license', 'notice', 'sbom'].includes(file.kind)) {
      if (digestSource(body) !== file.contentDigest) throw new Error(`registry offline export contentDigest mismatch: ${file.path}`);
    } else if (['keyset', 'checkpoint', 'status-head'].includes(file.kind)) {
      verifyOfflineEnvelope(file, `registry offline export ${file.kind}`);
    }
  }
  const resolution = files.find((file) => file.role === 'signed-resolution-core');
  const transport = files.find((file) => file.role === 'transport-overlay');
  if (!resolution || !transport) throw new Error('registry offline export missing lockfile files');
  const parsedLockfiles = parseRegistryLockfileFiles({
    resolutionCoreBody: resolution.body,
    transportOverlayBody: transport.body,
  });
  if (parsedLockfiles.resolutionDigest !== bundle.lockfileResolutionDigest) {
    throw new Error('registry offline export lockfileResolutionDigest mismatch');
  }
  const contentDigests = new Set(files.map((file) => file.contentDigest).filter(Boolean));
  for (const tool of parsedLockfiles.resolutionCore.tools || []) {
    const required = [
      tool.manifest?.digest,
      tool.artifact?.digest,
      tool.attachments?.license?.digest,
      tool.attachments?.notice?.digest,
      tool.attachments?.sbom?.digest,
    ].filter(Boolean);
    for (const digest of required) {
      if (!contentDigests.has(digest)) throw new Error(`registry offline export missing content digest: ${digest}`);
    }
  }
  if (!files.some((file) => file.kind === 'keyset' && file.contentDigest === bundle.keysetDigest)) {
    throw new Error('registry offline export missing keyset digest');
  }
  if (!files.some((file) => file.kind === 'checkpoint' && file.contentDigest === bundle.checkpointDigest)) {
    throw new Error('registry offline export missing checkpoint digest');
  }
  if (bundle.statusHeadDigest && !files.some((file) => file.kind === 'status-head' && file.contentDigest === bundle.statusHeadDigest)) {
    throw new Error('registry offline export missing status head digest');
  }
  const archiveIndex = offlineArchiveIndex(files);
  const archiveIndexDigest = digestObject(archiveIndex);
  if (archiveIndexDigest !== bundle.archiveIndexDigest) throw new Error('registry offline export archiveIndexDigest mismatch');
  if (canonicalJson(archiveIndex) !== canonicalJson(bundle.archiveIndex)) throw new Error('registry offline export archiveIndex mismatch');
  return {
    ok: true,
    registryId: bundle.registryId,
    archiveIndexDigest,
    fileCount: files.length,
    lockfileResolutionDigest: parsedLockfiles.resolutionDigest,
  };
}

export function registryLockfile(tools, { baseUrl, now = new Date() }) {
  const resolutionCore = registryLockfileResolutionCore(tools, { baseUrl, now });
  const transportOverlay = registryLockfileTransportOverlay(resolutionCore, tools, { baseUrl });
  validateRegistryLockfileTransportOverlay(resolutionCore, transportOverlay);
  return {
    schemaVersion: 'toolkit.registry.lockfile.v1',
    kind: 'toolkit.lockfile',
    issuer: registryIssuer(),
    registry: `${baseUrl}/api/v1/registry`,
    digest: resolutionCore.digest,
    signature: resolutionCore.signature,
    resolutionDigest: resolutionCore.digest,
    resolutionCore,
    transportOverlay,
    tools: resolutionCore.tools.map((entry) => {
      const transport = transportOverlay.tools.find((tool) => tool.slug === entry.slug) || {};
      return {
        name: entry.name,
        slug: entry.slug,
        id: entry.id,
        version: entry.version,
        digest: entry.manifest.digest,
        manifestDigest: entry.manifest.digest,
        sourceHash: entry.artifact.sourceHash,
        signature: entry.manifest.signature,
        manifestUrl: transport.manifestUrl,
        manifestContentAddressedUrl: transport.manifestContentAddressedUrl,
        artifactUrl: transport.artifactUrl,
        endpoint: transport.endpoint,
        mcpTool: entry.mcpTool,
      };
    }),
  };
}

function toolTimestamp(tool) {
  const value = tool.updatedAt || tool.createdAt || null;
  if (!value) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

export function registryStatusSubjectKey(subject) {
  return `${subject.type}:${subject.digest}`;
}

function statusEventDigest(event) {
  return digestObject(event);
}

function statusEventLogRoot(events) {
  return digestObject({
    schemaVersion: 'toolkit.registry.status-event-log-root.preview.v1',
    registryId: registryIssuer(),
    logSize: events.length,
    eventDigests: events.map((event) => event.eventDigest),
  });
}

function statusStateMapRoot(stateEntries) {
  return digestObject({
    schemaVersion: 'toolkit.registry.status-state-map-root.preview.v1',
    registryId: registryIssuer(),
    entries: stateEntries,
  });
}

const STATUS_SPARSE_MAP_DEPTH = 256;

function hexToBits(hex) {
  return String(hex || '').split('').flatMap((char) => {
    const value = Number.parseInt(char, 16);
    if (!Number.isFinite(value)) throw new Error('registry sparse map key digest invalid');
    return [3, 2, 1, 0].map((shift) => (value >> shift) & 1);
  });
}

function sparseSubjectPath(key, depth = STATUS_SPARSE_MAP_DEPTH) {
  const digest = crypto.createHash('sha256').update(String(key || ''), 'utf8').digest('hex');
  return hexToBits(digest).slice(0, depth).join('');
}

const sparseEmptyHashMemo = new Map();

function sparseEmptyHash(level, depth = STATUS_SPARSE_MAP_DEPTH) {
  const memoKey = `${depth}:${level}`;
  if (sparseEmptyHashMemo.has(memoKey)) return sparseEmptyHashMemo.get(memoKey);
  const value = level === depth
    ? digestObject({
        schemaVersion: 'toolkit.registry.status-sparse-empty-leaf.v1',
        registryId: registryIssuer(),
        depth,
      })
    : sparseParentHash({
        level,
        left: sparseEmptyHash(level + 1, depth),
        right: sparseEmptyHash(level + 1, depth),
      });
  sparseEmptyHashMemo.set(memoKey, value);
  return value;
}

function sparseLeafHash(entry) {
  return digestObject({
    schemaVersion: 'toolkit.registry.status-sparse-leaf.v1',
    registryId: registryIssuer(),
    key: entry.key,
    stateEntry: entry,
  });
}

function sparseParentHash({ level, left, right }) {
  return digestObject({
    schemaVersion: 'toolkit.registry.status-sparse-node.v1',
    registryId: registryIssuer(),
    level,
    left,
    right,
  });
}

function buildStatusSparseStateMap(stateEntries, { depth = STATUS_SPARSE_MAP_DEPTH } = {}) {
  const sorted = [...stateEntries].sort((a, b) => String(a.key).localeCompare(String(b.key)));
  const byKey = new Map();
  const leaves = new Map();
  for (const entry of sorted) {
    if (byKey.has(entry.key)) throw new Error('registry sparse map duplicate state key');
    const path = sparseSubjectPath(entry.key, depth);
    if (leaves.has(path)) throw new Error('registry sparse map path collision');
    byKey.set(entry.key, { entry, path, leafHash: sparseLeafHash(entry) });
    leaves.set(path, sparseLeafHash(entry));
  }

  const levels = new Map([[depth, leaves]]);
  for (let level = depth; level > 0; level -= 1) {
    const current = levels.get(level);
    const parents = new Map();
    const parentPrefixes = new Set([...current.keys()].map((path) => path.slice(0, level - 1)));
    for (const prefix of parentPrefixes) {
      const left = current.get(`${prefix}0`) || sparseEmptyHash(level);
      const right = current.get(`${prefix}1`) || sparseEmptyHash(level);
      parents.set(prefix, sparseParentHash({ level: level - 1, left, right }));
    }
    levels.set(level - 1, parents);
  }
  const root = levels.get(0).get('') || sparseEmptyHash(0);
  return { schemaVersion: 'toolkit.registry.status-sparse-state-map.preview.v1', depth, root, levels, byKey };
}

function statusSparseStateMapProof(sparseMap, key) {
  const depth = sparseMap.depth || STATUS_SPARSE_MAP_DEPTH;
  const path = sparseSubjectPath(key, depth);
  const known = sparseMap.byKey.get(key);
  const siblings = [];
  for (let level = depth; level > 0; level -= 1) {
    const prefix = path.slice(0, level);
    const bit = path[level - 1];
    const siblingPrefix = `${prefix.slice(0, -1)}${bit === '0' ? '1' : '0'}`;
    const siblingHash = sparseMap.levels.get(level).get(siblingPrefix) || sparseEmptyHash(level);
    siblings.push({ level, direction: bit === '0' ? 'left' : 'right', siblingHash });
  }
  const proof = {
    schemaVersion: 'toolkit.registry.status-sparse-state-proof.preview.v1',
    model: 'preview-sparse-merkle-state-map',
    key,
    keyPathHash: `sha256:${crypto.createHash('sha256').update(String(key || ''), 'utf8').digest('hex')}`,
    depth,
    root: sparseMap.root,
    stateEntry: known?.entry || null,
    leafHash: known?.leafHash || '',
    membership: !!known,
    siblings,
  };
  return { ...proof, proofDigest: digestObject(proof) };
}

function verifyStatusSparseStateMapProof(proof, { key, expectedRoot }) {
  if (!proof || proof.schemaVersion !== 'toolkit.registry.status-sparse-state-proof.preview.v1') {
    throw new Error('registry status proof sparse state proof missing');
  }
  if (proof.model !== 'preview-sparse-merkle-state-map') throw new Error('registry status proof sparse state model mismatch');
  if (proof.key !== key) throw new Error('registry status proof sparse state key mismatch');
  const { proofDigest: _proofDigest, ...proofPayload } = proof;
  if (proof.proofDigest !== digestObject(proofPayload)) throw new Error('registry status proof sparse state digest mismatch');
  const depth = proof.depth || STATUS_SPARSE_MAP_DEPTH;
  if (!Number.isSafeInteger(depth) || depth <= 0 || depth > STATUS_SPARSE_MAP_DEPTH) {
    throw new Error('registry status proof sparse state depth invalid');
  }
  const path = sparseSubjectPath(key, depth);
  const expectedKeyPathHash = `sha256:${crypto.createHash('sha256').update(String(key || ''), 'utf8').digest('hex')}`;
  if (proof.keyPathHash !== expectedKeyPathHash) throw new Error('registry status proof sparse state path mismatch');
  if (!Array.isArray(proof.siblings) || proof.siblings.length !== depth) {
    throw new Error('registry status proof sparse state sibling path invalid');
  }
  let current = proof.membership
    ? sparseLeafHash(proof.stateEntry)
    : sparseEmptyHash(depth);
  if (proof.membership && current !== proof.leafHash) throw new Error('registry status proof sparse state leaf mismatch');
  for (let level = depth; level > 0; level -= 1) {
    const sibling = proof.siblings[depth - level];
    if (!sibling || sibling.level !== level) throw new Error('registry status proof sparse state sibling level mismatch');
    const bit = path[level - 1];
    if (bit === '0') {
      if (sibling.direction !== 'left') throw new Error('registry status proof sparse state direction mismatch');
      current = sparseParentHash({ level: level - 1, left: current, right: sibling.siblingHash });
    } else {
      if (sibling.direction !== 'right') throw new Error('registry status proof sparse state direction mismatch');
      current = sparseParentHash({ level: level - 1, left: sibling.siblingHash, right: current });
    }
  }
  if (current !== expectedRoot || proof.root !== expectedRoot) {
    throw new Error('registry status proof sparse state root mismatch');
  }
  return { ok: true, membership: !!proof.membership, root: current };
}

function statusHeadSummary(head) {
  if (!head) return null;
  return {
    digest: head.digest,
    sequence: head.sequence,
    logSize: head.logSize,
    eventLogRoot: head.eventLogRoot,
    stateMapRoot: head.stateMapRoot,
    previousHeadDigest: head.previousHeadDigest || '',
    issuedAt: head.issuedAt,
    expiresAt: head.expiresAt,
  };
}

export function registryStatusHeadConsistencyProof({ previousHead = null, nextHead }) {
  if (!nextHead?.digest) throw new Error('registry status consistency proof requires next head');
  const previous = previousHead ? statusHeadSummary(previousHead) : null;
  const next = statusHeadSummary(nextHead);
  if (previous) {
    if (next.previousHeadDigest !== previous.digest) throw new Error('registry status head previous digest mismatch');
    if (Number(next.sequence) < Number(previous.sequence)) throw new Error('registry status head sequence regressed');
    if (Number(next.logSize) < Number(previous.logSize)) throw new Error('registry status head log size regressed');
  }
  const payload = {
    schemaVersion: 'toolkit.registry.status-head-consistency-proof.preview.v1',
    registryId: registryIssuer(),
    model: 'preview-linked-head-chain',
    previousHead: previous,
    nextHead: next,
    consistent: previous ? next.previousHeadDigest === previous.digest : !next.previousHeadDigest,
  };
  return { ...payload, proofDigest: digestObject(payload) };
}

export function verifyRegistryStatusHeadConsistencyProof(proof, { head, previousHead = null } = {}) {
  if (!proof || proof.schemaVersion !== 'toolkit.registry.status-head-consistency-proof.preview.v1') {
    throw new Error('registry status head consistency proof missing');
  }
  if (proof.registryId !== registryIssuer()) throw new Error('registry status head consistency registry mismatch');
  if (proof.model !== 'preview-linked-head-chain') throw new Error('registry status head consistency model mismatch');
  const { proofDigest: _proofDigest, ...proofPayload } = proof;
  const proofDigest = digestObject(proofPayload);
  if (proof.proofDigest !== proofDigest) throw new Error('registry status head consistency proof digest mismatch');
  const next = statusHeadSummary(head);
  if (canonicalJson(proof.nextHead) !== canonicalJson(next)) throw new Error('registry status head consistency next head mismatch');
  const previous = previousHead ? statusHeadSummary(previousHead) : proof.previousHead;
  if (previous) {
    if (canonicalJson(proof.previousHead) !== canonicalJson(previous)) throw new Error('registry status head consistency previous head mismatch');
    if (next.previousHeadDigest !== previous.digest || proof.consistent !== true) throw new Error('registry status head consistency mismatch');
    if (Number(next.sequence) < Number(previous.sequence) || Number(next.logSize) < Number(previous.logSize)) {
      throw new Error('registry status head consistency regression');
    }
  } else if (next.previousHeadDigest && proof.consistent !== true) {
    throw new Error('registry status head consistency proof required');
  }
  return { ok: true, previousHeadDigest: previous?.digest || '', nextHeadDigest: next.digest };
}

export function registryStatusWitnessStatement(head, { witnessId = 'preview-local-witness', observedAt = new Date(), splitViewId = '' } = {}) {
  if (!head?.digest) throw new Error('registry status witness statement requires head');
  const payload = {
    schemaVersion: 'toolkit.registry.status-witness-statement.preview.v1',
    registryId: registryIssuer(),
    witnessId: String(witnessId || ''),
    observedAt: new Date(observedAt).toISOString(),
    splitViewId: String(splitViewId || ''),
    head: statusHeadSummary(head),
  };
  return { ...payload, statementDigest: digestObject(payload) };
}

export function verifyRegistryStatusWitnessStatements(head, witnesses = []) {
  const seenByWitness = new Map();
  const current = statusHeadSummary(head);
  for (const statement of witnesses || []) {
    if (!statement || statement.schemaVersion !== 'toolkit.registry.status-witness-statement.preview.v1') {
      throw new Error('registry status witness statement schema mismatch');
    }
    if (statement.registryId !== registryIssuer()) throw new Error('registry status witness registry mismatch');
    const { statementDigest: _statementDigest, ...statementPayload } = statement;
    const expectedDigest = digestObject(statementPayload);
    if (statement.statementDigest !== expectedDigest) throw new Error('registry status witness digest mismatch');
    const observed = statement.head || {};
    if (Number(observed.sequence) === Number(current.sequence) && observed.digest !== current.digest) {
      throw new Error('registry status split-view detected');
    }
    const key = String(statement.witnessId || '');
    const previous = seenByWitness.get(key);
    if (previous && previous.head?.sequence === observed.sequence && previous.head?.digest !== observed.digest) {
      throw new Error('registry status witness equivocation detected');
    }
    seenByWitness.set(key, statement);
  }
  return { ok: true, witnessCount: (witnesses || []).length };
}

function statusEvent({ sequence, subject, status, reason, toolRefs, manifestDigest = '', artifactDigest = '', effectiveAt = null, statusOverride = null }) {
  const payload = {
    schemaVersion: 'toolkit.registry.status-event.v1',
    registryId: registryIssuer(),
    sequence,
    eventType: `status.${status}`,
    subject,
    status,
    reason,
    manifestDigest,
    artifactDigest,
    toolRefs,
    effectiveAt,
    statusOverride,
  };
  return { ...payload, eventDigest: statusEventDigest(payload) };
}

export function registryStatusSnapshot(tools, { baseUrl, now = new Date(), statusOverrides = {}, previousHead = null } = {}) {
  const manifestSubjects = [];
  const artifactSubjects = new Map();
  for (const tool of tools || []) {
    const manifest = toolManifestEnvelope(tool, { baseUrl });
    const ref = {
      id: String(tool._id),
      slug: tool.slug,
      version: tool.currentVersion?.v || 1,
      manifestDigest: manifest.digest,
    };
    manifestSubjects.push({
      subject: { type: 'manifest', digest: manifest.digest },
      status: 'active',
      reason: 'registry_preview_current_public_manifest',
      manifestDigest: manifest.digest,
      artifactDigest: manifest.artifact.digest,
      toolRefs: [ref],
      effectiveAt: toolTimestamp(tool),
    });
    const artifactKey = registryStatusSubjectKey({ type: 'artifact', digest: manifest.artifact.digest });
    const existing = artifactSubjects.get(artifactKey) || {
      subject: { type: 'artifact', digest: manifest.artifact.digest },
      status: 'active',
      reason: 'registry_preview_current_public_artifact',
      manifestDigest: '',
      artifactDigest: manifest.artifact.digest,
      toolRefs: [],
      effectiveAt: toolTimestamp(tool),
    };
    existing.toolRefs.push(ref);
    const updatedAt = toolTimestamp(tool);
    if (updatedAt && (!existing.effectiveAt || updatedAt > existing.effectiveAt)) existing.effectiveAt = updatedAt;
    artifactSubjects.set(artifactKey, existing);
  }

  const currentSubjects = [...manifestSubjects, ...artifactSubjects.values()];
  const knownKeys = new Set(currentSubjects.map((entry) => registryStatusSubjectKey(entry.subject)));
  const overrideOnlySubjects = Object.entries(statusOverrides)
    .filter(([key]) => !knownKeys.has(key))
    .map(([key, override]) => {
      const i = key.indexOf(':');
      const type = key.slice(0, i);
      const digest = key.slice(i + 1);
      return {
        subject: { type, digest },
        status: override.status || 'revoked',
        reason: override.reason || `registry_override_${override.status || 'revoked'}`,
        manifestDigest: type === 'manifest' ? digest : '',
        artifactDigest: type === 'artifact' ? digest : '',
        toolRefs: [],
        effectiveAt: timestamp(override.updatedAt) || null,
        statusOverride: {
          status: override.status || 'revoked',
          reason: override.reason || '',
          actorId: override.actorId || '',
          updatedAt: timestamp(override.updatedAt) || null,
        },
      };
    });

  const subjects = [...currentSubjects, ...overrideOnlySubjects]
    .map((entry) => ({
      ...entry,
      toolRefs: entry.toolRefs.sort((a, b) => `${a.slug}:${a.version}`.localeCompare(`${b.slug}:${b.version}`)),
    }))
    .map((entry) => {
      const override = statusOverrides[registryStatusSubjectKey(entry.subject)];
      if (!override) return entry;
      return {
        ...entry,
        status: override.status || entry.status,
        reason: override.reason || `registry_override_${override.status || entry.status}`,
        statusOverride: {
          status: override.status || entry.status,
          reason: override.reason || '',
          actorId: override.actorId || '',
          updatedAt: timestamp(override.updatedAt) || null,
        },
      };
    })
    .sort((a, b) => registryStatusSubjectKey(a.subject).localeCompare(registryStatusSubjectKey(b.subject)));
  const events = subjects.map((entry, index) => statusEvent({ ...entry, sequence: index + 1 }));
  const stateEntries = events.map((event) => ({
    key: registryStatusSubjectKey(event.subject),
    subject: event.subject,
    status: event.status,
    sequence: event.sequence,
    eventDigest: event.eventDigest,
  }));
  const eventLogRoot = statusEventLogRoot(events);
  const stateMapRoot = statusStateMapRoot(stateEntries);
  const sparseStateMap = buildStatusSparseStateMap(stateEntries);
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
  const payload = {
    schemaVersion: 'toolkit.registry.status-head.v1',
    registryId: registryIssuer(),
    sequence: events.length,
    logSize: events.length,
    eventLogRoot,
    stateMapRoot,
    sparseStateMapRoot: sparseStateMap.root,
    previousHeadDigest: previousHead?.digest || registryPreviousStatusHeadDigest() || '',
    issuedAt,
    expiresAt,
    executionProofMaxAgeSeconds: 300,
    proofModel: 'preview-sparse-merkle-state-map',
    stateMapRootModel: 'preview-sparse-merkle-state-map+legacy-full-state-map',
  };
  const digest = digestObject(payload);
  const head = {
    ...payload,
    digest,
    signature: signPayloadDigest(digest, artifactPrivateKey(), { keyId: signingKeyId(), createdAt: now }),
  };
  return { head, events, stateEntries, sparseStateMap };
}

export function registryStatusProof(tools, { baseUrl, subjects = [], now = new Date(), statusOverrides = {}, previousHead = null, witnesses = null } = {}) {
  const snapshot = registryStatusSnapshot(tools, { baseUrl, now, statusOverrides, previousHead });
  const byKey = new Map(snapshot.events.map((event) => [registryStatusSubjectKey(event.subject), event]));
  const stateEntryByKey = new Map(snapshot.stateEntries.map((entry) => [entry.key, entry]));
  const requested = subjects.map((subject) => ({ type: subject.type, digest: subject.digest }));
  const headConsistencyProof = registryStatusHeadConsistencyProof({ previousHead, nextHead: snapshot.head });
  const witnessStatements = witnesses || [
    registryStatusWitnessStatement(snapshot.head, { witnessId: `${registryIssuer()}:preview-local`, observedAt: now }),
  ];
  const proofs = requested.map((subject) => {
    const key = registryStatusSubjectKey(subject);
    const event = byKey.get(key);
    const stateEntry = stateEntryByKey.get(key);
    return {
      subject,
      status: event?.status || 'missing',
      statusAsOf: snapshot.head.issuedAt,
      stateMapProof: {
        model: 'preview-authenticated-full-state-map',
        key,
        stateMapRoot: snapshot.head.stateMapRoot,
        stateEntry: stateEntry || null,
        latestEventDigest: event?.eventDigest || '',
        latestEventSequence: event?.sequence || 0,
        membership: !!event,
        allStateEntries: snapshot.stateEntries,
      },
      sparseStateMapProof: statusSparseStateMapProof(snapshot.sparseStateMap, key),
      eventInclusionProof: {
        model: 'preview-full-event-log',
        eventLogRoot: snapshot.head.eventLogRoot,
        eventDigest: event?.eventDigest || '',
        sequence: event?.sequence || 0,
        logSize: snapshot.head.logSize,
        included: !!event,
        allEventDigests: snapshot.events.map((entry) => entry.eventDigest),
      },
      headConsistencyProof: {
        model: headConsistencyProof.model,
        proofDigest: headConsistencyProof.proofDigest,
        previousHeadDigest: headConsistencyProof.previousHead?.digest || '',
        nextHeadDigest: headConsistencyProof.nextHead.digest,
        consistent: headConsistencyProof.consistent,
      },
      event: event || null,
    };
  });
  return {
    schemaVersion: 'toolkit.registry.status-proof.v1',
    registryId: registryIssuer(),
    head: snapshot.head,
    headConsistencyProof,
    witnessStatements,
    proofs,
  };
}

export function verifyRegistryStatusProof(proof, {
  now = new Date(),
  requireCurrentlyTrusted = false,
  maxProofAgeSeconds = null,
  maxClockSkewSeconds = 60,
  publicKey = null,
} = {}) {
  if (!proof || proof.schemaVersion !== 'toolkit.registry.status-proof.v1') throw new Error('registry status proof schema mismatch');
  const head = proof.head;
  if (!head || head.schemaVersion !== 'toolkit.registry.status-head.v1') throw new Error('registry status proof head missing');
  const headDigest = digestObject(withoutEnvelopeFields(head));
  if (head.digest !== headDigest) throw new Error('registry status proof head digest mismatch');
  if (head.signature?.payloadDigest !== head.digest) throw new Error('registry status proof head signature payloadDigest mismatch');
  if (publicKey && !verifyDigestSignature(head.digest, head.signature, publicKey)) throw new Error('registry status proof head signature invalid');
  if (head.previousHeadDigest || proof.headConsistencyProof) {
    verifyRegistryStatusHeadConsistencyProof(proof.headConsistencyProof, { head });
  }
  verifyRegistryStatusWitnessStatements(head, proof.witnessStatements || []);
  const issuedAtMs = Date.parse(head.issuedAt || '');
  const expiresAtMs = Date.parse(head.expiresAt || '');
  if (!Number.isFinite(issuedAtMs)) throw new Error('registry status proof head issuedAt invalid');
  if (requireCurrentlyTrusted) {
    const maxClockSkewMs = Math.max(0, Number(maxClockSkewSeconds) || 0) * 1000;
    if (issuedAtMs - now.getTime() > maxClockSkewMs) {
      throw new Error('registry status proof head issuedAt exceeds clock skew');
    }
  }
  if (requireCurrentlyTrusted && (!Number.isFinite(expiresAtMs) || now.getTime() > expiresAtMs)) {
    throw new Error('registry status proof head expired');
  }
  if (requireCurrentlyTrusted) {
    const maxAge = Number.isFinite(maxProofAgeSeconds) ? maxProofAgeSeconds : head.executionProofMaxAgeSeconds;
    if (Number.isFinite(maxAge) && maxAge >= 0 && now.getTime() - issuedAtMs > maxAge * 1000) {
      throw new Error('registry status proof execution proof too old');
    }
  }
  for (const item of proof.proofs || []) {
    const key = registryStatusSubjectKey(item.subject);
    const sparseRoot = head.sparseStateMapRoot || head.stateMapRoot;
    const sparseResult = item.sparseStateMapProof
      ? verifyStatusSparseStateMapProof(item.sparseStateMapProof, { key, expectedRoot: sparseRoot })
      : null;
    const stateEntries = item.stateMapProof?.allStateEntries || [];
    const eventDigests = item.eventInclusionProof?.allEventDigests || [];
    let stateEntry = null;
    if (stateEntries.length || item.stateMapProof?.stateMapRoot) {
      const stateRoot = statusStateMapRoot(stateEntries);
      if (stateRoot !== head.stateMapRoot || stateRoot !== item.stateMapProof?.stateMapRoot) {
        throw new Error('registry status proof state map root mismatch');
      }
      stateEntry = stateEntries.find((entry) => entry.key === key) || null;
    } else if (sparseResult) {
      stateEntry = item.sparseStateMapProof.stateEntry || null;
    }
    const eventRoot = digestObject({
      schemaVersion: 'toolkit.registry.status-event-log-root.preview.v1',
      registryId: registryIssuer(),
      logSize: eventDigests.length,
      eventDigests,
    });
    if (eventRoot !== head.eventLogRoot || eventRoot !== item.eventInclusionProof?.eventLogRoot) {
      throw new Error('registry status proof event log root mismatch');
    }
    if (!stateEntry && item.status !== 'missing') throw new Error('registry status proof missing latest state');
    if (stateEntry && sparseResult && !sparseResult.membership) throw new Error('registry status proof sparse membership mismatch');
    if (!stateEntry && sparseResult?.membership) throw new Error('registry status proof sparse non-membership mismatch');
    if (stateEntry && item.stateMapProof && !item.stateMapProof.membership) throw new Error('registry status proof membership mismatch');
    if (!stateEntry && item.stateMapProof?.membership) throw new Error('registry status proof non-membership mismatch');
    if (stateEntry) {
      if (item.stateMapProof?.stateEntry && canonicalJson(stateEntry) !== canonicalJson(item.stateMapProof.stateEntry)) throw new Error('registry status proof state entry mismatch');
      if (item.sparseStateMapProof?.stateEntry && canonicalJson(stateEntry) !== canonicalJson(item.sparseStateMapProof.stateEntry)) throw new Error('registry status proof sparse state entry mismatch');
      const latestEventDigest = item.sparseStateMapProof?.stateEntry?.eventDigest || item.stateMapProof?.latestEventDigest;
      const latestEventSequence = item.sparseStateMapProof?.stateEntry?.sequence || item.stateMapProof?.latestEventSequence;
      if (stateEntry.eventDigest !== latestEventDigest) throw new Error('registry status proof latest event digest mismatch');
      if (stateEntry.sequence !== latestEventSequence) throw new Error('registry status proof latest event sequence mismatch');
      if (!eventDigests.includes(stateEntry.eventDigest)) throw new Error('registry status proof latest event not included');
      if (item.event?.eventDigest !== stateEntry.eventDigest) throw new Error('registry status proof event mismatch');
      if (item.event?.sequence !== stateEntry.sequence) throw new Error('registry status proof event sequence mismatch');
      if (item.eventInclusionProof?.eventDigest !== stateEntry.eventDigest || item.eventInclusionProof?.included !== true) {
        throw new Error('registry status proof event inclusion mismatch');
      }
      if (item.status !== stateEntry.status) throw new Error('registry status proof status mismatch');
      if (requireCurrentlyTrusted && item.status !== 'active') throw new Error('registry status proof subject is not active');
    } else if (requireCurrentlyTrusted) {
      throw new Error('registry status proof subject missing');
    }
  }
  return {
    ok: true,
    result: requireCurrentlyTrusted ? 'currently-trusted' : 'historically-valid',
    proofCount: (proof.proofs || []).length,
    statusAsOf: head.issuedAt,
    headDigest: head.digest,
  };
}

function inputSchemaForTool(tool) {
  const props = { input: { type: 'string', description: '工具输入' } };
  for (const p of tool.paramsSchema || []) {
    const prop = {
      type: 'string',
      description: p.label || p.key,
    };
    if (p.opts) prop.enum = String(p.opts).split(',').map((s) => s.trim()).filter(Boolean);
    props[p.key] = prop;
  }
  return { type: 'object', properties: props, required: ['input'] };
}
