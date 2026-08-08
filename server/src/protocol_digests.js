import crypto from 'node:crypto';

export const PROTOCOL_DIGEST_SCHEMA = 'toolkit.protocol-digests.v1';
export const RESOURCE_CONTEXT_SCHEMA = 'toolkit.entitlement.resource-context.v1';
export const RESOURCE_CONTEXT_EMPTY_SCHEMA = `${RESOURCE_CONTEXT_SCHEMA}.empty`;
export const RESOURCE_CONTEXT_KNOWN_SCHEMAS = Object.freeze([
  RESOURCE_CONTEXT_EMPTY_SCHEMA,
  'toolkit.scheduled-workflow-run.v1',
  'toolkit.workflow-webhook-run.v1',
  'toolkit.workflow-agent-step.v1',
]);
export const MUTATION_REQUEST_SCHEMA = 'toolkit.mutation-request.v1';
export const DEFAULT_AUTHORIZATION_RULES_DIGEST = 'sha256:f5e8e0f5cbbf55302209b8f8aa312be6afde5420ae9e539575b5ba3f88e26a60';

const RESOURCE_CONTEXT_FIELDS = Object.freeze({
  schemaVersion: { type: 'enum', values: [RESOURCE_CONTEXT_SCHEMA] },
  action: { type: 'string', required: true, nonEmpty: true },
  resourceType: { type: 'string', required: true, nonEmpty: true },
  resourceId: { type: 'string' },
  resourceVersion: { type: 'integer' },
  ownerType: { type: 'enum', required: true, values: ['user', 'workspace'] },
  ownerId: { type: 'string', required: true, nonEmpty: true },
  workspaceId: { type: 'string' },
  contextSchema: { type: 'string' },
  context: { type: 'jsonObject' },
});

const MUTATION_PAYLOAD_SCHEMAS = Object.freeze({
  'toolkit.user-settings-update.v1': {
    fields: {
      nickname: { type: 'string' },
      'settings.locale': { type: 'enum', values: ['zh', 'en'] },
      'settings.region': { type: 'enum', values: ['CN', 'GLOBAL'] },
      'settings.currency': { type: 'enum', values: ['CNY', 'USD'] },
      'settings.theme': { type: 'enum', values: ['light', 'dark'] },
      'settings.workbench': { type: 'jsonObject' },
    },
  },
  'toolkit.rules-selftest.v1': {
    fields: {
      ok: { type: 'boolean' },
    },
  },
  'toolkit.workflow-update.v1': {
    fields: {
      name: { type: 'string' },
      steps: { type: 'json' },
    },
  },
  'toolkit.workflow-delete.v1': {
    fields: {
      transition: { type: 'enum', required: true, values: ['delete'] },
      fromStatus: { type: 'string', required: true },
      toStatus: { type: 'enum', required: true, values: ['deleted'] },
      sharedTeamId: { type: 'string' },
    },
  },
  'toolkit.workflow-downgrade-retention.v1': {
    fields: {
      keepOnDowngrade: { type: 'boolean', required: true },
    },
  },
  'toolkit.workflow-restore.v1': {
    fields: {
      transition: { type: 'enum', required: true, values: ['restore'] },
      fromCloudRunStatus: { type: 'string', required: true },
      toCloudRunStatus: { type: 'enum', required: true, values: ['active'] },
    },
  },
  'toolkit.workflow-team-share.v1': {
    fields: {
      shared: { type: 'boolean', required: true },
    },
  },
  'toolkit.workflow-schedule.v1': {
    fields: {
      intervalMinutes: { type: 'integer', required: true },
      timezone: { type: 'string' },
    },
  },
  'toolkit.workflow-schedule-disable.v1': {
    fields: {
      previousStatus: { type: 'string', required: true },
    },
  },
  'toolkit.workflow-webhook.v1': {
    fields: {
      name: { type: 'string', required: true, nonEmpty: true },
    },
  },
  'toolkit.workflow-webhook-rotate-secret.v1': {
    fields: {
      endpointId: { type: 'string', required: true, nonEmpty: true },
    },
  },
  'toolkit.workflow-webhook-disable.v1': {
    fields: {
      previousStatus: { type: 'string', required: true },
    },
  },
  'toolkit.api-token-delete.v1': {
    fields: {
      transition: { type: 'enum', required: true, values: ['delete'] },
      fromStatus: { type: 'string', required: true },
      toStatus: { type: 'enum', required: true, values: ['deleted'] },
    },
  },
  'toolkit.api-token-downgrade-retention.v1': {
    fields: {
      keepOnDowngrade: { type: 'boolean', required: true },
    },
  },
  'toolkit.api-token-restore.v1': {
    fields: {
      transition: { type: 'enum', required: true, values: ['restore'] },
      fromStatus: { type: 'string', required: true },
      toStatus: { type: 'enum', required: true, values: ['active'] },
    },
  },
  'toolkit.team-member-remove.v1': {
    fields: {
      memberId: { type: 'string', required: true, nonEmpty: true },
      previousRole: { type: 'string' },
    },
  },
  'toolkit.custom-tool-update.v1': {
    fields: {
      name: { type: 'string' },
      category: { type: 'string' },
      sampleIn: { type: 'string' },
      description: { type: 'string' },
      doc: { type: 'string' },
      slug: { type: 'string' },
      io: { type: 'json' },
      paramsSchema: { type: 'json' },
      flags: { type: 'json' },
      source: { type: 'string' },
      sandbox: { type: 'json' },
      changelog: { type: 'string' },
    },
  },
  'toolkit.custom-tool-lifecycle.v1': {
    fields: {
      transition: { type: 'enum', required: true, values: ['submit', 'delist', 'delete'] },
      fromStatus: { type: 'string', required: true },
      toStatus: { type: 'string', required: true },
    },
  },
  'toolkit.custom-tool-team-share.v1': {
    fields: {
      shared: { type: 'boolean', required: true },
    },
  },
  'toolkit.digest-vector.v1': {
    fields: {
      label: { type: 'string', required: true },
      optional: { type: 'string', nullable: true },
      ordered: { type: 'array', items: { type: 'string' } },
      tags: { type: 'set', items: { type: 'string' } },
      count: { type: 'integer' },
    },
  },
  'toolkit.hosted-endpoint-domain.v1': {
    fields: {
      customDomain: { type: 'string', required: true, nonEmpty: true },
      verificationType: { type: 'enum', values: ['dns_txt'] },
    },
  },
  'toolkit.hosted-endpoint-update.v1': {
    fields: {
      name: { type: 'string' },
      enabled: { type: 'boolean' },
    },
  },
  'toolkit.hosted-endpoint-disable.v1': {
    fields: {
      previousEnabled: { type: 'boolean', required: true },
      enabled: { type: 'boolean', required: true },
    },
  },
  'toolkit.hosted-endpoint-domain-remove.v1': {
    fields: {
      previousCustomDomain: { type: 'string' },
    },
  },
  'toolkit.hosted-endpoint-delete.v1': {
    fields: {
      transition: { type: 'enum', required: true, values: ['delete'] },
      fromStatus: { type: 'string', required: true },
      toStatus: { type: 'enum', required: true, values: ['deleted'] },
    },
  },
});

function plainObject(value) {
  return value && typeof value === 'object' && value.constructor === Object;
}

function canonical(value) {
  if (typeof value === 'string') return value.normalize('NFC');
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error('canonical JSON only supports finite non-negative-zero numbers');
    if (!Number.isSafeInteger(value)) throw new Error('canonical JSON number must be a safe integer; use a schema string for decimals or large integers');
    return value;
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
    throw new Error('canonical JSON does not support undefined, function, symbol, or bigint values');
  }
  if (Array.isArray(value)) return value.map(canonical);
  if (plainObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function normalizeSchemaValue(value, spec = {}, path = 'value') {
  if (value === undefined) {
    if (spec.required) throw new Error(`${path} is required`);
    return undefined;
  }
  if (value === null) {
    if (spec.nullable) return null;
    throw new Error(`${path} must not be null`);
  }
  switch (spec.type) {
    case 'string': {
      if (typeof value !== 'string') throw new Error(`${path} must be a string`);
      const normalized = value.normalize('NFC');
      if (spec.nonEmpty && !normalized) throw new Error(`${path} must not be empty`);
      return normalized;
    }
    case 'enum': {
      if (typeof value !== 'string') throw new Error(`${path} must be a string enum`);
      const normalized = value.normalize('NFC');
      if (!spec.values.includes(normalized)) throw new Error(`${path} is not allowed`);
      return normalized;
    }
    case 'boolean':
      if (typeof value !== 'boolean') throw new Error(`${path} must be a boolean`);
      return value;
    case 'integer':
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error(`${path} must be a safe integer`);
      return value;
    case 'array': {
      if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
      return value.map((item, index) => normalizeSchemaValue(item, spec.items || { type: 'json' }, `${path}[${index}]`));
    }
    case 'set': {
      if (!Array.isArray(value)) throw new Error(`${path} must be a set array`);
      const normalizedItems = value.map((item, index) => normalizeSchemaValue(item, spec.items || { type: 'json' }, `${path}[${index}]`));
      const keyed = normalizedItems.map((item) => [canonicalJson(item), item]);
      const seen = new Set();
      for (const [key] of keyed) {
        if (seen.has(key)) throw new Error(`${path} must not contain duplicate set items`);
        seen.add(key);
      }
      return keyed.sort(([a], [b]) => a.localeCompare(b)).map(([, item]) => item);
    }
    case 'object':
      return normalizeObjectByFields(value, spec.fields || {}, path);
    case 'jsonObject':
      if (!plainObject(value)) throw new Error(`${path} must be an object`);
      return canonical(value);
    case 'json':
      return canonical(value);
    default:
      throw new Error(`${path} has unsupported schema type`);
  }
}

function normalizeObjectByFields(value, fields, path) {
  if (!plainObject(value)) throw new Error(`${path} must be an object`);
  const allowed = new Set(Object.keys(fields));
  const trie = { leaf: false, children: new Map() };
  for (const key of allowed) {
    let node = trie;
    for (const segment of key.split('.')) {
      if (!node.children.has(segment)) node.children.set(segment, { leaf: false, children: new Map() });
      node = node.children.get(segment);
    }
    node.leaf = true;
  }
  const validateUnknown = (obj, node, prefix) => {
    for (const key of Object.keys(obj)) {
      if (prefix === path && allowed.has(key)) continue;
      const child = node.children.get(key);
      const childPath = `${prefix}.${key}`;
      if (!child) throw new Error(`${childPath} is not allowed`);
      if (!child.leaf) {
        if (!plainObject(obj[key])) throw new Error(`${childPath} must be an object`);
        validateUnknown(obj[key], child, childPath);
      }
    }
  };
  const nestedValue = (obj, key) => {
    const segments = key.split('.');
    if (segments.length === 1) return { found: Object.hasOwn(obj, key), value: obj[key] };
    let current = obj;
    for (const segment of segments) {
      if (!plainObject(current) || !Object.hasOwn(current, segment)) return { found: false, value: undefined };
      current = current[segment];
    }
    return { found: true, value: current };
  };
  validateUnknown(value, trie, path);
  const normalized = {};
  for (const key of Object.keys(fields).sort()) {
    const literal = { found: Object.hasOwn(value, key), value: value[key] };
    const nested = nestedValue(value, key);
    if (literal.found && nested.found && canonicalJson(literal.value) !== canonicalJson(nested.value)) {
      throw new Error(`${path}.${key} is provided both as a literal key and nested path`);
    }
    const inputValue = literal.found ? literal.value : nested.value;
    const normalizedValue = normalizeSchemaValue(inputValue, fields[key], `${path}.${key}`);
    if (normalizedValue !== undefined) normalized[key] = normalizedValue;
  }
  return normalized;
}

function normalizeMutationPayload(payloadSchema, payload) {
  const schema = MUTATION_PAYLOAD_SCHEMAS[payloadSchema];
  if (!schema) throw new Error(`unknown mutation payload schema: ${payloadSchema}`);
  return normalizeObjectByFields(payload || {}, schema.fields || {}, 'payload');
}

export function normalizeResourceContext(resourceContext = {}, action = '') {
  const raw = {
    ...resourceContext,
    action: String(action || resourceContext.action || ''),
    ownerType: String(resourceContext.ownerType || 'user'),
  };
  const ctx = normalizeObjectByFields(raw, RESOURCE_CONTEXT_FIELDS, 'resourceContext');
  if (!ctx.action || !ctx.resourceType || !ctx.ownerId) throw new Error('resource context is incomplete');
  if (ctx.contextSchema && !RESOURCE_CONTEXT_KNOWN_SCHEMAS.includes(ctx.contextSchema)) {
    throw new Error('unknown resource context schema');
  }
  if (ctx.contextSchema && !ctx.context) ctx.context = {};
  return {
    schemaVersion: RESOURCE_CONTEXT_SCHEMA,
    ...ctx,
  };
}

export function canonicalJson(value) {
  return JSON.stringify(canonical(value));
}

export function sha256Digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

export function resourceContextDigest({ action, resourceContext } = {}) {
  return sha256Digest(normalizeResourceContext(resourceContext, action));
}

export function mutationRequestDigest({
  action,
  resourceContext,
  authorizationRulesDigest: rulesDigest,
  features = [],
  payloadSchema = 'toolkit.mutation-payload.v1',
  payload = {},
} = {}) {
  const normalizedFeatures = [...new Set((features || []).map((feature) => String(feature)).sort())];
  if (normalizedFeatures.length !== (features || []).length) throw new Error('mutation features must not contain duplicates');
  const normalizedPayloadSchema = String(payloadSchema || '');
  return sha256Digest({
    schemaVersion: MUTATION_REQUEST_SCHEMA,
    action: String(action || ''),
    resourceContextDigest: resourceContextDigest({ action, resourceContext }),
    authorizationRulesDigest: String(rulesDigest || ''),
    features: normalizedFeatures,
    payloadSchema: normalizedPayloadSchema,
    payload: normalizeMutationPayload(normalizedPayloadSchema, payload || {}),
  });
}
