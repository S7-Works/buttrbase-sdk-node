import re

with open('src/client.ts', 'r') as f:
    content = f.read()

content = content.replace(
    'clientId: string;\n  clientSecret: string;',
    'clientId: string;\n  clientSecret?: string;'
)

content = content.replace(
    "if (!opts.clientSecret) throw new Error('clientSecret is required');",
    ""
)

content = content.replace(
    'this.clientSecret = opts.clientSecret;',
    "this.clientSecret = opts.clientSecret ?? '';"
)

# Fix sendOtpV1 to use auth: false, but send Basic Auth
content = content.replace(
    """  sendOtpV1(email: string, appUuid: string): Promise<void> {
    return this.request<void>('POST', '/api/v1/auth/otp/send', {
      body: { email, app_uuid: appUuid },
      auth: false,
    });
  }""",
    """  sendOtpV1(email: string, appUuid: string): Promise<void> {
    return this.request<void>('POST', '/api/v1/auth/otp/send', {
      body: { email, app_uuid: appUuid },
      auth: false,
      headers: {
        'Authorization': 'Basic ' + Buffer.from(this.clientId + ':' + this.clientSecret).toString('base64'),
      }
    });
  }"""
)

# Same for sendOtpEmail
content = content.replace(
    """  sendOtpEmail(email: string, appUuid: string): Promise<void> {
    return this.request<void>('POST', '/api/v1/auth/otp/send', {
      body: { email, app_uuid: appUuid },
      auth: false,
    });
  }""",
    """  sendOtpEmail(email: string, appUuid: string): Promise<void> {
    return this.request<void>('POST', '/api/v1/auth/otp/send', {
      body: { email, app_uuid: appUuid },
      auth: false,
      headers: {
        'Authorization': 'Basic ' + Buffer.from(this.clientId + ':' + this.clientSecret).toString('base64'),
      }
    });
  }"""
)

with open('src/client.ts', 'w') as f:
    f.write(content)
