export const USAGE = `CHARADE — an open-source, telemetry-free secret platform.

Usage:
  charade init --home <dir> [--passphrase-file <file>] [--custody <backend>] [--dry-run]
  charade vault backup --home <dir>
  charade vault recovery-kit --home <dir> --out <file> [--passphrase-file <file>]
  charade vault drill --backup <file> --kit <file>
  charade policy init --home <dir> [--accept-defaults] [--dry-run] [--passphrase-file <file>]
  charade policy show --home <dir>
  charade broker serve --home <dir> [--passphrase-file <file>] [--socket <path>]
  charade broker status --home <dir> [--socket <path>] [--json]
  charade secret add --home <dir> --service <id> [--label <text>] [--passphrase-file <file>]
  charade secret list --home <dir> [--passphrase-file <file>]
  charade secret rotate --home <dir> --id <secret-id> [--overlap <seconds>] [--passphrase-file <file>]
  charade secret remove --home <dir> --id <secret-id> [--passphrase-file <file>]
  charade registry add-service --home <dir> --id <id> --name <name> --url <url> --auth <type>
                               [--auth-name <name>] [--auth-template <text>]
                               [--read <patterns>] [--write <patterns>] [--destructive <patterns>]
  charade registry add-consumer --home <dir> --id <id> --name <name> --services <ids>
  charade registry add-device --home <dir> --id <id> --consumer <id> --public-key <base64url>
  charade registry validate --home <dir>
  charade device enroll --home <dir> --consumer <id> --id <id> --out <file>
  charade grant create --home <dir> --consumer <id> --services <ids> --duration <preset>
                       [--device <id>] [--methods <list>] [--paths <list>] [--calls <n>]
                       [--accept] [--passphrase-file <file>]
  charade grant list --home <dir>
  charade grant revoke --home <dir> --id <grant> [--accept]
  charade call --home <dir> --service <id> --path <path> [--method <verb>]
               [--device <file>] [--data <file>] [--socket <path>]
  charade doctor --home <dir> [--json] [--socket <path>] [--passphrase-file <file>]
  charade receipts verify --home <dir>
  charade --version

Custody backends: macos-keychain, secret-service, systemd-creds.
The default is the passphrase slot plus a recovery key. The passphrase is never
accepted from an environment variable; use a file with mode 0600 or the prompt.
Secret values are read from stdin or a masked prompt, never from arguments.
`;
