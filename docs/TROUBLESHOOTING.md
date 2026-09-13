# Troubleshooting

- **Missing module:** activate the project virtual environment and install the required extra.
- **Missing credentials:** run `credentials status PROFILE`; set the matching Credential Manager entry or environment variables in the process that launches NERD.
- **Host key rejected:** independently verify the fingerprint, then use `devices host-key enroll DEVICE`.
- **SSH timeout:** verify routing, TCP/22, inventory host/port, platform, and device SSH settings.
- **OpenAI 401:** replace the API key in the current process.
- **OpenAI 429 or exhausted credits:** check API billing and usage, then retry.
- **MCP absent in a client:** use absolute paths, restart the client, and inspect its MCP logs. A stdio server normally shows no standalone prompt.
- **Write disabled:** add `--enable-writes` only after reviewing the plan. It cannot be enabled through an environment variable.
- **Stale plan:** create a new plan because device state changed after preflight.

Never paste secrets into issue reports. Include sanitized command, version, platform, and traceback.
