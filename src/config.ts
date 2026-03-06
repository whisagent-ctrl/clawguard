import fs from 'fs';
import yaml from 'js-yaml';
import { Config } from './types';

function substituteEnvVars(str: string): string {
  return str.replace(/\$\{(\w+)\}/g, (match, varName) => {
    const val = process.env[varName];
    if (!val) {
      console.error(`❌ Required environment variable ${varName} is not set`);
      process.exit(1);
    }
    return val;
  });
}

function deepSubstitute(obj: unknown): unknown {
  if (typeof obj === 'string') {
    // Only substitute if the string contains ${...} pattern
    if (obj.includes('${')) {
      return substituteEnvVars(obj);
    }
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(deepSubstitute);
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = deepSubstitute(value);
    }
    return result;
  }
  return obj;
}

const DEFAULT_SECURITY = {
  allowedUpstreams: [],
  blockPrivateIPs: true,
  followRedirects: false,
  maxPayloadLogSize: 10240, // 10KB
};

const DEFAULT_ADMIN = {
  enabled: true,
  pin: '',
  allowedIPs: ['127.0.0.1', '::1', '::ffff:127.0.0.1', '172.16.0.0/12'],
};

const DEFAULT_AUDIT = {
  type: 'sqlite' as const,
  path: './clawguard.db',
  logPayload: false,
};

const DEFAULT_PROXY = {
  enabled: false,
  caDir: './data/ca',
  discovery: false,
  discoveryPolicy: 'block' as const,
};

const DEFAULT_TELEGRAM_PAIRING = {
  enabled: true,
  secret: '',
};

export function loadConfig(configPath: string): Config {
  if (!fs.existsSync(configPath)) {
    console.error(`❌ Config file not found: ${configPath}`);
    console.error(`   Create one from clawguard.yaml.example`);
    process.exit(1);
  }

  const raw = fs.readFileSync(configPath, 'utf-8');
  const parsed = yaml.load(raw) as Record<string, unknown>;
  const config = deepSubstitute(parsed) as Config;

  // ─── Validate required fields ──────────────────────────────

  if (!config.server?.port || !config.server?.agentKey) {
    console.error('❌ Missing server.port or server.agentKey in config');
    process.exit(1);
  }

  if (!config.services || Object.keys(config.services).length === 0) {
    console.error('❌ No services configured');
    process.exit(1);
  }

  if (!config.notifications?.telegram?.botToken) {
    console.error('❌ Missing notifications.telegram.botToken');
    process.exit(1);
  }

  if (!config.notifications.telegram.chatId) {
    console.error('❌ Missing notifications.telegram.chatId');
    process.exit(1);
  }

  // ─── Apply defaults ────────────────────────────────────────

  config.security = { ...DEFAULT_SECURITY, ...(config.security || {}) };
  config.admin = { ...DEFAULT_ADMIN, ...(config.admin || {}) };
  config.audit = { ...DEFAULT_AUDIT, ...(config.audit || {}) };
  config.proxy = { ...DEFAULT_PROXY, ...(config.proxy || {}) };

  if (!['block', 'silent_allow'].includes(config.proxy.discoveryPolicy)) {
    console.error('❌ Invalid proxy.discoveryPolicy. Allowed values: block, silent_allow');
    process.exit(1);
  }

  if (!config.notifications.telegram.pairing) {
    config.notifications.telegram.pairing = { ...DEFAULT_TELEGRAM_PAIRING };
  }

  // ─── Validate admin PIN ────────────────────────────────────

  if (config.admin.enabled && !config.admin.pin) {
    console.error('❌ Admin panel is enabled but no PIN is set.');
    console.error('   Set admin.pin in config or disable with admin.enabled: false');
    process.exit(1);
  }

  // ─── Validate Telegram pairing ─────────────────────────────

  if (config.notifications.telegram.pairing.enabled && !config.notifications.telegram.pairing.secret) {
    console.error('❌ Telegram pairing is enabled but no secret is set.');
    console.error('   Set notifications.telegram.pairing.secret in config');
    process.exit(1);
  }

  // ─── Validate dummyToken uniqueness per hostname ──────────

  const hostnameToServices = new Map<string, { name: string; dummyToken?: string }[]>();
  for (const [name, svc] of Object.entries(config.services)) {
    const hostnames: string[] = [...(svc.hostnames || [])];
    try {
      const upstreamHost = new URL(svc.upstream).hostname;
      if (!hostnames.includes(upstreamHost)) hostnames.push(upstreamHost);
    } catch { /* skip */ }

    for (const h of hostnames) {
      if (!hostnameToServices.has(h)) hostnameToServices.set(h, []);
      hostnameToServices.get(h)!.push({ name, dummyToken: svc.auth.dummyToken });
    }
  }

  for (const [hostname, svcs] of hostnameToServices.entries()) {
    if (svcs.length <= 1) continue;

    // Check for duplicate dummyToken values
    const tokens = svcs.filter(s => s.dummyToken).map(s => s.dummyToken!);
    const dupes = tokens.filter((t, i) => tokens.indexOf(t) !== i);
    if (dupes.length > 0) {
      console.error(`❌ Duplicate dummyToken "${dupes[0]}" for hostname "${hostname}": ${svcs.filter(s => s.dummyToken === dupes[0]).map(s => s.name).join(', ')}`);
      process.exit(1);
    }

    // Warn if some services lack dummyToken
    const missing = svcs.filter(s => !s.dummyToken);
    if (missing.length > 0 && missing.length < svcs.length) {
      console.warn(`⚠️  Hostname "${hostname}" has ${svcs.length} services but ${missing.map(s => s.name).join(', ')} lack dummyToken (will act as fallback)`);
    }
  }

  return config;
}

/**
 * Save config back to YAML (used by admin API for service updates).
 * Preserves env var references by re-reading the original file.
 */
export function saveConfig(configPath: string, config: Config): void {
  const yamlStr = yaml.dump(config, { indent: 2, lineWidth: 120, noRefs: true });
  fs.writeFileSync(configPath, yamlStr, 'utf-8');
}
