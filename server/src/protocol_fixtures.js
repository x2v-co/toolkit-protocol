import crypto from 'node:crypto';
import {
  canonicalJson,
  digestObject,
  digestSource,
  registryLockfileResolutionCore,
  registryStatusProof,
  registryTrustKeyset,
  registryStatusSubjectKey,
  toolManifestEnvelope,
  verifyDigestSignature,
  verifyRegistryStatusProof,
} from './registry.js';
import {
  canonicalJson as protocolCanonicalJson,
  DEFAULT_AUTHORIZATION_RULES_DIGEST,
  mutationRequestDigest,
  resourceContextDigest,
} from './protocol_digests.js';

export const PROTOCOL_FIXTURE_SCHEMA = 'toolkit.protocol.conformance-fixtures.v1';
export const PROTOCOL_CROSS_LANGUAGE_VECTOR_SCHEMA = 'toolkit.protocol.cross-language-vectors.v1';
export const PROTOCOL_CONFORMANCE_BUNDLE_SCHEMA = 'toolkit.protocol.conformance-bundle.v1';

function publicKeyFromJwk(jwk) {
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

function sha256Text(value = '') {
  return `sha256:${crypto.createHash('sha256').update(String(value), 'utf8').digest('hex')}`;
}

function stripDigest(value = {}) {
  const { digest: _digest, ...rest } = value || {};
  return rest;
}

export function protocolFixtureTool() {
  const source = 'function transform(input, params) { return params.prefix + String(input).trim(); }';
  return {
    _id: '64f100000000000000000001',
    type: 'custom',
    slug: 'protocol-fixture-tool',
    name: 'Protocol Fixture Tool',
    status: 'published',
    category: '文本',
    description: 'A deterministic protocol conformance fixture tool.',
    createdAt: new Date('2026-07-21T00:00:00.000Z'),
    updatedAt: new Date('2026-07-21T01:00:00.000Z'),
    currentVersion: {
      v: 7,
      source,
      sandbox: { timeoutMs: 2000, memMb: 128, net: false, ai: false },
    },
    paramsSchema: [{ key: 'prefix', label: 'Prefix', opts: 'ok:,err:' }],
  };
}

export function protocolConformanceFixtures({
  baseUrl = 'https://toolkit.fun',
  now = new Date('2026-07-21T02:00:00.000Z'),
} = {}) {
  const canonicalInput = {
    z: 1,
    a: { c: 3, b: 2 },
    list: [{ y: 2, x: 1 }],
    text: 'e\u0301',
  };
  const canonicalBody = canonicalJson(canonicalInput);
  const tool = protocolFixtureTool();
  const manifest = toolManifestEnvelope(tool, { baseUrl });
  const lockfileResolutionCore = registryLockfileResolutionCore([tool], { baseUrl, now });
  const statusSubjects = [
    { type: 'manifest', digest: manifest.digest },
    { type: 'artifact', digest: manifest.artifact.digest },
  ];
  const statusProof = registryStatusProof([tool], { baseUrl, subjects: statusSubjects, now });
  const keyset = registryTrustKeyset({ now });
  const entitlementResourceContext = {
    action: 'user_settings.update',
    resourceType: 'user_settings',
    resourceId: 'user_123',
    resourceVersion: 7,
    ownerType: 'user',
    ownerId: 'user_123',
    workspaceId: '',
    contextSchema: 'toolkit.entitlement.resource-context.v1.empty',
    context: {},
  };
  const entitlementResourceContextBody = {
    schemaVersion: 'toolkit.entitlement.resource-context.v1',
    action: 'user_settings.update',
    context: {},
    contextSchema: 'toolkit.entitlement.resource-context.v1.empty',
    ownerId: 'user_123',
    ownerType: 'user',
    resourceId: 'user_123',
    resourceType: 'user_settings',
    resourceVersion: 7,
    workspaceId: '',
  };
  const entitlementRequestBody = {
    schemaVersion: 'toolkit.mutation-request.v1',
    action: 'user_settings.update',
    authorizationRulesDigest: DEFAULT_AUTHORIZATION_RULES_DIGEST,
    features: ['a', 'b'],
    payload: {
      count: 7,
      label: 'é',
      optional: null,
      ordered: ['first', 'second'],
      tags: ['a', 'z'],
    },
    payloadSchema: 'toolkit.digest-vector.v1',
    resourceContextDigest: resourceContextDigest({
      action: 'user_settings.update',
      resourceContext: entitlementResourceContext,
    }),
  };
  return {
    schemaVersion: PROTOCOL_FIXTURE_SCHEMA,
    baseUrl,
    issuedAt: now.toISOString(),
    canonicalJson: {
      input: canonicalInput,
      body: canonicalBody,
      digest: digestObject(canonicalInput),
      expectedBody: '{"a":{"b":2,"c":3},"list":[{"x":1,"y":2}],"text":"é","z":1}',
      negativeCases: [
        { name: 'undefined', input: { skip: undefined }, error: 'undefined' },
        { name: 'nan', input: { n: Number.NaN }, error: 'finite' },
        { name: 'negative-zero', input: { n: -0 }, error: 'non-negative-zero' },
        { name: 'unsafe-integer', input: { n: Number.MAX_SAFE_INTEGER + 1 }, error: 'safe integer' },
      ],
    },
    tool: {
      slug: tool.slug,
      sourceDigest: digestSource(tool.currentVersion.source),
      sourceByteLength: Buffer.byteLength(tool.currentVersion.source, 'utf8'),
    },
    manifest: {
      body: canonicalJson(manifest),
      digest: manifest.digest,
      signature: manifest.signature,
      artifactDigest: manifest.artifact.digest,
      manifestUrl: manifest.self,
      artifactUrl: manifest.artifact.contentAddressedUrl,
    },
    lockfileResolutionCore: {
      body: canonicalJson(lockfileResolutionCore),
      digest: lockfileResolutionCore.digest,
      signature: lockfileResolutionCore.signature,
      toolCount: lockfileResolutionCore.tools.length,
      statusPolicy: lockfileResolutionCore.statusPolicy,
    },
    statusProof: {
      body: canonicalJson(statusProof),
      headDigest: statusProof.head.digest,
      subjects: statusSubjects.map((subject) => ({
        ...subject,
        key: registryStatusSubjectKey(subject),
      })),
      proofCount: statusProof.proofs.length,
    },
    trust: {
      keysetDigest: keyset.digest,
      artifactPublicKey: keyset.keys[0],
    },
    entitlementDigests: {
      resourceContext: {
        input: entitlementResourceContext,
        body: protocolCanonicalJson(entitlementResourceContextBody),
        digest: resourceContextDigest({
          action: 'user_settings.update',
          resourceContext: entitlementResourceContext,
        }),
        expectedBody: '{"action":"user_settings.update","context":{},"contextSchema":"toolkit.entitlement.resource-context.v1.empty","ownerId":"user_123","ownerType":"user","resourceId":"user_123","resourceType":"user_settings","resourceVersion":7,"schemaVersion":"toolkit.entitlement.resource-context.v1","workspaceId":""}',
        expectedDigest: 'sha256:fd9ba960d0e39864ab3f53724bdf58ffbb891c1169348c0befa548bc354b6f4e',
      },
      mutationRequest: {
        input: {
          action: 'user_settings.update',
          resourceContext: entitlementResourceContext,
          authorizationRulesDigest: DEFAULT_AUTHORIZATION_RULES_DIGEST,
          features: ['b', 'a'],
          payloadSchema: 'toolkit.digest-vector.v1',
          payload: {
            label: 'e\u0301',
            optional: null,
            ordered: ['first', 'second'],
            tags: ['z', 'a'],
            count: 7,
          },
        },
        body: protocolCanonicalJson(entitlementRequestBody),
        digest: mutationRequestDigest({
          action: 'user_settings.update',
          resourceContext: entitlementResourceContext,
          authorizationRulesDigest: DEFAULT_AUTHORIZATION_RULES_DIGEST,
          features: ['b', 'a'],
          payloadSchema: 'toolkit.digest-vector.v1',
          payload: {
            label: 'e\u0301',
            optional: null,
            ordered: ['first', 'second'],
            tags: ['z', 'a'],
            count: 7,
          },
        }),
        expectedBody: '{"action":"user_settings.update","authorizationRulesDigest":"sha256:f5e8e0f5cbbf55302209b8f8aa312be6afde5420ae9e539575b5ba3f88e26a60","features":["a","b"],"payload":{"count":7,"label":"é","optional":null,"ordered":["first","second"],"tags":["a","z"]},"payloadSchema":"toolkit.digest-vector.v1","resourceContextDigest":"sha256:fd9ba960d0e39864ab3f53724bdf58ffbb891c1169348c0befa548bc354b6f4e","schemaVersion":"toolkit.mutation-request.v1"}',
        expectedDigest: 'sha256:b3a8be568dce11ce7a64271c203ffd7fcf984dfbaf53911c849e0c5fc389806d',
      },
    },
  };
}

export function validateProtocolConformanceFixtures(fixtures = protocolConformanceFixtures()) {
  if (fixtures.schemaVersion !== PROTOCOL_FIXTURE_SCHEMA) throw new Error('protocol fixture schema mismatch');
  if (fixtures.canonicalJson.body !== fixtures.canonicalJson.expectedBody) throw new Error('canonical JSON body mismatch');
  if (fixtures.canonicalJson.digest !== digestObject(fixtures.canonicalJson.input)) throw new Error('canonical JSON digest mismatch');
  for (const testCase of fixtures.canonicalJson.negativeCases || []) {
    let failed = false;
    try {
      canonicalJson(testCase.input);
    } catch (e) {
      failed = String(e.message || e).includes(testCase.error);
    }
    if (!failed) throw new Error(`canonical JSON negative case failed: ${testCase.name}`);
  }

  const artifactPublicKey = publicKeyFromJwk(fixtures.trust.artifactPublicKey);
  if (!verifyDigestSignature(fixtures.manifest.digest, fixtures.manifest.signature, artifactPublicKey)) {
    throw new Error('manifest signature invalid');
  }
  if (!verifyDigestSignature(fixtures.lockfileResolutionCore.digest, fixtures.lockfileResolutionCore.signature, artifactPublicKey)) {
    throw new Error('lockfile resolution core signature invalid');
  }
  const statusProof = JSON.parse(fixtures.statusProof.body);
  const statusResult = verifyRegistryStatusProof(statusProof, {
    now: new Date(fixtures.issuedAt),
    requireCurrentlyTrusted: true,
    publicKey: artifactPublicKey,
  });
  if (statusResult.proofCount !== fixtures.statusProof.proofCount) throw new Error('status proof count mismatch');
  if (fixtures.entitlementDigests?.resourceContext?.body !== fixtures.entitlementDigests?.resourceContext?.expectedBody) {
    throw new Error('resource context digest body mismatch');
  }
  if (fixtures.entitlementDigests?.resourceContext?.digest !== fixtures.entitlementDigests?.resourceContext?.expectedDigest) {
    throw new Error('resource context digest mismatch');
  }
  if (fixtures.entitlementDigests?.resourceContext?.digest !== resourceContextDigest({
    action: fixtures.entitlementDigests.resourceContext.input.action,
    resourceContext: fixtures.entitlementDigests.resourceContext.input,
  })) {
    throw new Error('resource context digest recompute mismatch');
  }
  if (fixtures.entitlementDigests?.mutationRequest?.body !== fixtures.entitlementDigests?.mutationRequest?.expectedBody) {
    throw new Error('mutation request digest body mismatch');
  }
  if (fixtures.entitlementDigests?.mutationRequest?.digest !== fixtures.entitlementDigests?.mutationRequest?.expectedDigest) {
    throw new Error('mutation request digest mismatch');
  }
  if (fixtures.entitlementDigests?.mutationRequest?.digest !== mutationRequestDigest(fixtures.entitlementDigests.mutationRequest.input)) {
    throw new Error('mutation request digest recompute mismatch');
  }
  return {
    ok: true,
    canonicalDigest: fixtures.canonicalJson.digest,
    manifestDigest: fixtures.manifest.digest,
    lockfileDigest: fixtures.lockfileResolutionCore.digest,
    statusHeadDigest: fixtures.statusProof.headDigest,
    resourceContextDigest: fixtures.entitlementDigests.resourceContext.digest,
    mutationRequestDigest: fixtures.entitlementDigests.mutationRequest.digest,
  };
}

export function protocolCrossLanguageVectorPack(fixtures = protocolConformanceFixtures()) {
  validateProtocolConformanceFixtures(fixtures);
  const canonical = fixtures.canonicalJson;
  const resourceContext = fixtures.entitlementDigests.resourceContext;
  const mutationRequest = fixtures.entitlementDigests.mutationRequest;
  const mutationAbsentOptionalInput = {
    ...mutationRequest.input,
    payload: {
      label: 'é',
      ordered: ['first', 'second'],
      tags: ['z', 'a'],
      count: 7,
    },
  };
  const mutationAbsentOptionalBody = {
    schemaVersion: 'toolkit.mutation-request.v1',
    action: 'user_settings.update',
    authorizationRulesDigest: DEFAULT_AUTHORIZATION_RULES_DIGEST,
    features: ['a', 'b'],
    payload: {
      count: 7,
      label: 'é',
      ordered: ['first', 'second'],
      tags: ['a', 'z'],
    },
    payloadSchema: 'toolkit.digest-vector.v1',
    resourceContextDigest: resourceContext.expectedDigest,
  };
  const mutationWithTransportFieldsInput = {
    ...mutationRequest.input,
    operationId: 'op_should_not_affect_digest',
    idempotencyKey: 'idem_should_not_affect_digest',
    traceId: 'trace_should_not_affect_digest',
    requestedAt: '2026-08-05T00:00:00.000Z',
  };
  return {
    schemaVersion: PROTOCOL_CROSS_LANGUAGE_VECTOR_SCHEMA,
    spec: {
      canonicalJson: 'RFC-8785-compatible-json-canonicalization-with-unicode-nfc',
      digest: 'sha256:<lowercase-hex-of-utf8-canonical-json>',
      resourceContextInputSchema: 'toolkit.entitlement.resource-context.v1',
      mutationRequestInputSchema: 'toolkit.mutation-request.v1',
      fieldPolicy: 'schema allowlist; unknown fields rejected; absent optional fields omitted; null accepted only when schema marks nullable',
      numberPolicy: 'finite safe integers only; -0 rejected; decimals and large integers must use schema strings',
      stringNormalization: 'Unicode NFC before digesting and before writing normalized values',
      safeIntegerOnly: true,
      negativeZeroRejected: true,
      setArrayOrdering: 'schema-marked sets sort by canonical item bytes and reject duplicates',
      transportFieldPolicy: 'operationId, idempotencyKey, traceId, requestedAt, and transport-layer fields are excluded from semantic request digest input',
    },
    targetLanguages: [
      { language: 'nodejs', minimumVersion: '22', packageHint: 'toolkit-protocol' },
      { language: 'python', minimumVersion: '3.11', packageHint: 'toolkit-protocol-python' },
      { language: 'go', minimumVersion: '1.22', packageHint: 'toolkit-protocol-go' },
    ],
    vectors: [
      {
        name: 'canonical-json-nfc-key-order',
        kind: 'canonical-json',
        input: canonical.input,
        expectedBody: canonical.expectedBody,
        expectedDigest: canonical.digest,
      },
      {
        name: 'entitlement-resource-context-v1',
        kind: 'resource-context-digest',
        input: resourceContext.input,
        expectedBody: resourceContext.expectedBody,
        expectedDigest: resourceContext.expectedDigest,
      },
      {
        name: 'mutation-request-v1',
        kind: 'mutation-request-digest',
        input: mutationRequest.input,
        expectedBody: mutationRequest.expectedBody,
        expectedDigest: mutationRequest.expectedDigest,
      },
      {
        name: 'mutation-request-optional-absent-v1',
        kind: 'mutation-request-digest',
        input: mutationAbsentOptionalInput,
        expectedBody: protocolCanonicalJson(mutationAbsentOptionalBody),
        expectedDigest: mutationRequestDigest(mutationAbsentOptionalInput),
        note: 'Absent nullable fields are omitted and must not be treated as JSON null.',
      },
      {
        name: 'mutation-request-transport-fields-ignored-v1',
        kind: 'mutation-request-digest',
        input: mutationWithTransportFieldsInput,
        expectedBody: mutationRequest.expectedBody,
        expectedDigest: mutationRequest.expectedDigest,
        ignoredFields: ['operationId', 'idempotencyKey', 'traceId', 'requestedAt'],
      },
    ],
    negativeVectors: [
      {
        name: 'canonical-json-undefined-not-representable',
        kind: 'canonical-json',
        inputEncoding: 'host-language-value',
        valueShape: { field: 'undefined' },
        expectedError: 'undefined',
      },
      {
        name: 'canonical-json-nan-rejected',
        kind: 'canonical-json',
        inputEncoding: 'host-language-value',
        valueShape: { n: 'NaN' },
        expectedError: 'finite',
      },
      {
        name: 'canonical-json-negative-zero-rejected',
        kind: 'canonical-json',
        inputEncoding: 'host-language-value',
        valueShape: { n: '-0' },
        expectedError: 'negative-zero',
      },
      {
        name: 'resource-context-null-workspace-rejected',
        kind: 'resource-context-digest',
        input: {
          ...resourceContext.input,
          workspaceId: null,
        },
        expectedError: 'must not be null',
      },
      {
        name: 'resource-context-unknown-field-rejected',
        kind: 'resource-context-digest',
        input: {
          ...resourceContext.input,
          transportTraceId: 'trace_should_not_be_hashed',
        },
        expectedError: 'not allowed',
      },
      {
        name: 'mutation-request-unknown-payload-field-rejected',
        kind: 'mutation-request-digest',
        input: {
          ...mutationRequest.input,
          payload: {
            ...mutationRequest.input.payload,
            unknown: true,
          },
        },
        expectedError: 'unknown is not allowed',
      },
      {
        name: 'mutation-request-unsafe-integer-rejected',
        kind: 'mutation-request-digest',
        input: {
          ...mutationRequest.input,
          payload: {
            ...mutationRequest.input.payload,
            count: Number.MAX_SAFE_INTEGER + 1,
          },
        },
        expectedError: 'safe integer',
      },
      {
        name: 'mutation-request-duplicate-set-rejected',
        kind: 'mutation-request-digest',
        input: {
          ...mutationRequest.input,
          payload: {
            ...mutationRequest.input.payload,
            tags: ['a', 'a'],
          },
        },
        expectedError: 'duplicate set items',
      },
    ],
  };
}

export function validateProtocolCrossLanguageVectorPack(pack = protocolCrossLanguageVectorPack()) {
  if (pack.schemaVersion !== PROTOCOL_CROSS_LANGUAGE_VECTOR_SCHEMA) throw new Error('protocol cross-language vector schema mismatch');
  const languages = new Set((pack.targetLanguages || []).map((item) => item.language));
  for (const language of ['nodejs', 'python', 'go']) {
    if (!languages.has(language)) throw new Error(`protocol vector target missing: ${language}`);
  }
  const requiredVectors = new Map((pack.vectors || []).map((vector) => [vector.name, vector]));
  for (const name of [
    'canonical-json-nfc-key-order',
    'entitlement-resource-context-v1',
    'mutation-request-v1',
    'mutation-request-optional-absent-v1',
    'mutation-request-transport-fields-ignored-v1',
  ]) {
    if (!requiredVectors.has(name)) throw new Error(`protocol vector missing: ${name}`);
  }
  const canonicalVector = requiredVectors.get('canonical-json-nfc-key-order');
  if (canonicalJson(canonicalVector.input) !== canonicalVector.expectedBody) throw new Error('cross-language canonical body mismatch');
  if (digestObject(canonicalVector.input) !== canonicalVector.expectedDigest) throw new Error('cross-language canonical digest mismatch');
  const resourceVector = requiredVectors.get('entitlement-resource-context-v1');
  if (resourceContextDigest({ action: resourceVector.input.action, resourceContext: resourceVector.input }) !== resourceVector.expectedDigest) {
    throw new Error('cross-language resource context digest mismatch');
  }
  const mutationVector = requiredVectors.get('mutation-request-v1');
  if (mutationRequestDigest(mutationVector.input) !== mutationVector.expectedDigest) {
    throw new Error('cross-language mutation request digest mismatch');
  }
  const absentOptionalVector = requiredVectors.get('mutation-request-optional-absent-v1');
  if (mutationRequestDigest(absentOptionalVector.input) !== absentOptionalVector.expectedDigest) {
    throw new Error('cross-language absent optional mutation request digest mismatch');
  }
  if (absentOptionalVector.expectedDigest === mutationVector.expectedDigest) {
    throw new Error('cross-language absent optional vector must differ from nullable null vector');
  }
  const transportVector = requiredVectors.get('mutation-request-transport-fields-ignored-v1');
  if (mutationRequestDigest(transportVector.input) !== mutationVector.expectedDigest
    || transportVector.expectedDigest !== mutationVector.expectedDigest) {
    throw new Error('cross-language transport fields must not affect mutation request digest');
  }
  for (const negative of pack.negativeVectors || []) {
    if (!negative.name || !negative.kind || !negative.expectedError) throw new Error('cross-language negative vector incomplete');
    let failed = false;
    try {
      if (negative.name === 'canonical-json-undefined-not-representable') canonicalJson({ field: undefined });
      else if (negative.name === 'canonical-json-nan-rejected') canonicalJson({ n: Number.NaN });
      else if (negative.name === 'canonical-json-negative-zero-rejected') canonicalJson({ n: -0 });
      else if (negative.kind === 'resource-context-digest') {
        resourceContextDigest({ action: negative.input.action, resourceContext: negative.input });
      } else if (negative.kind === 'mutation-request-digest') {
        mutationRequestDigest(negative.input);
      }
    } catch (e) {
      failed = String(e.message || e).includes(negative.expectedError);
    }
    if (!failed) throw new Error(`cross-language negative vector did not fail as expected: ${negative.name}`);
  }
  return {
    ok: true,
    targetLanguages: [...languages].sort(),
    vectorCount: (pack.vectors || []).length,
    negativeVectorCount: (pack.negativeVectors || []).length,
  };
}

export function protocolConformanceBundleManifest({
  files = {},
  vectorPack = protocolCrossLanguageVectorPack(),
  packageName = 'toolkit-protocol',
  bundleVersion = '0.1.0-preview',
} = {}) {
  validateProtocolCrossLanguageVectorPack(vectorPack);
  const vectorBody = files['fixtures/protocol/cross-language-vectors.v1.json']
    || `${JSON.stringify(vectorPack, null, 2)}\n`;
  const artifactSpecs = [
    {
      path: 'fixtures/protocol/cross-language-vectors.v1.json',
      role: 'cross-language-vectors',
      mediaType: 'application/json; charset=utf-8',
      schemaVersion: PROTOCOL_CROSS_LANGUAGE_VECTOR_SCHEMA,
      body: vectorBody,
    },
    {
      path: 'scripts/protocol_cross_language_node_selftest.mjs',
      role: 'nodejs-verifier',
      mediaType: 'text/javascript; charset=utf-8',
      body: files['scripts/protocol_cross_language_node_selftest.mjs'] || '',
    },
    {
      path: 'scripts/protocol_cross_language_python_selftest.py',
      role: 'python-verifier',
      mediaType: 'text/x-python; charset=utf-8',
      body: files['scripts/protocol_cross_language_python_selftest.py'] || '',
    },
    {
      path: 'scripts/protocol_cross_language_go_selftest.go',
      role: 'go-verifier',
      mediaType: 'text/x-go; charset=utf-8',
      body: files['scripts/protocol_cross_language_go_selftest.go'] || '',
    },
  ];
  const manifest = {
    schemaVersion: PROTOCOL_CONFORMANCE_BUNDLE_SCHEMA,
    packageName: String(packageName || 'toolkit-protocol'),
    bundleVersion: String(bundleVersion || '0.1.0-preview'),
    vectorSchemaVersion: vectorPack.schemaVersion,
    targetLanguages: vectorPack.targetLanguages.map((item) => item.language).sort(),
    vectorCount: vectorPack.vectors.length,
    negativeVectorCount: vectorPack.negativeVectors.length,
    artifacts: artifactSpecs.map(({ body, ...artifact }) => ({
      ...artifact,
      byteLength: Buffer.byteLength(String(body || ''), 'utf8'),
      digest: sha256Text(body),
    })),
    requiredCommands: [
      'npm run protocol:node:selftest',
      'npm run protocol:python:selftest',
      'npm run protocol:go:selftest',
      'npm run protocol:cross-language:selftest',
    ],
    publishContract: {
      registryTrust: 'disabled-for-developer-preview',
      networkEffect: 'none',
      privateImportsAllowed: false,
      canonicalJson: vectorPack.spec.canonicalJson,
      digest: vectorPack.spec.digest,
    },
  };
  return {
    ...manifest,
    digest: digestObject(manifest),
  };
}

export function validateProtocolConformanceBundleManifest({
  manifest,
  files = {},
  vectorPack = protocolCrossLanguageVectorPack(),
} = {}) {
  if (!manifest || manifest.schemaVersion !== PROTOCOL_CONFORMANCE_BUNDLE_SCHEMA) {
    throw new Error('protocol conformance bundle schema mismatch');
  }
  if (manifest.digest !== digestObject(stripDigest(manifest))) throw new Error('protocol conformance bundle digest mismatch');
  const vectorValidation = validateProtocolCrossLanguageVectorPack(vectorPack);
  if (vectorValidation.ok !== true) throw new Error('protocol conformance vector pack invalid');
  if (manifest.vectorSchemaVersion !== PROTOCOL_CROSS_LANGUAGE_VECTOR_SCHEMA) {
    throw new Error('protocol conformance bundle vector schema mismatch');
  }
  const roles = new Set((manifest.artifacts || []).map((artifact) => artifact.role));
  for (const role of ['cross-language-vectors', 'nodejs-verifier', 'python-verifier', 'go-verifier']) {
    if (!roles.has(role)) throw new Error(`protocol conformance bundle artifact missing: ${role}`);
  }
  for (const command of [
    'npm run protocol:node:selftest',
    'npm run protocol:python:selftest',
    'npm run protocol:go:selftest',
    'npm run protocol:cross-language:selftest',
  ]) {
    if (!(manifest.requiredCommands || []).includes(command)) {
      throw new Error(`protocol conformance bundle command missing: ${command}`);
    }
  }
  for (const artifact of manifest.artifacts || []) {
    const body = files[artifact.path];
    if (typeof body !== 'string') throw new Error(`protocol conformance bundle file missing: ${artifact.path}`);
    if (artifact.digest !== sha256Text(body)) throw new Error(`protocol conformance bundle artifact digest mismatch: ${artifact.path}`);
    if (artifact.byteLength !== Buffer.byteLength(body, 'utf8')) {
      throw new Error(`protocol conformance bundle artifact byteLength mismatch: ${artifact.path}`);
    }
    if (artifact.role === 'cross-language-vectors') {
      validateProtocolCrossLanguageVectorPack(JSON.parse(body));
    }
  }
  return {
    ok: true,
    digest: manifest.digest,
    artifactCount: manifest.artifacts.length,
    targetLanguages: [...manifest.targetLanguages].sort(),
  };
}
