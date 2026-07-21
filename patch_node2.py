import re

with open('src/client.ts', 'r') as f:
    content = f.read()

content = content.replace(
    'opts: { body?: unknown; auth?: boolean; query?: Record<string, unknown>; signal?: AbortSignal } = {}',
    'opts: { body?: unknown; auth?: boolean; query?: Record<string, unknown>; signal?: AbortSignal; headers?: Record<string, string> } = {}'
)

content = content.replace(
    """    if (opts.auth !== false) {
      if (!this.accessToken) {
        throw new Error('No access token available. Call authenticate() first or provide it to the constructor.');
      }
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }""",
    """    if (opts.headers) {
      for (const [k, v] of Object.entries(opts.headers)) {
        headers[k] = v;
      }
    }
    if (opts.auth !== false) {
      if (!this.accessToken) {
        throw new Error('No access token available. Call authenticate() first or provide it to the constructor.');
      }
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }"""
)

with open('src/client.ts', 'w') as f:
    f.write(content)
