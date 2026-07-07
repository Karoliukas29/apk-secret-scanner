# apk-scanner

Scans Android APKs for hardcoded secrets and sensitive strings. Works on `.apk`, `.xapk`, and `.aab` files — single file or a whole directory at once.

I use this during mobile pentests and bug bounty to quickly check if an app is leaking credentials before spending time on dynamic analysis.

## What it finds

- AWS keys, GCP service accounts
- Stripe, SendGrid, Mailgun, Mailchimp keys
- Firebase / Google API keys
- GitHub tokens, Slack tokens, OpenAI keys, Mapbox tokens
- Private key material (RSA, EC, PGP)
- Hardcoded passwords, bearer tokens, JWTs
- Facebook, Twitter, Twilio credentials

## Usage

```bash
python3 apk-scanner.py target.apk
python3 apk-scanner.py /path/to/apks/
python3 apk-scanner.py target.apk --min-severity HIGH
python3 apk-scanner.py target.apk --json
```

Output is a markdown report per APK with severity-ranked findings and the matched values. `--json` gives you the raw data if you want to pipe it into something else.

## Requirements

```bash
# No pip dependencies — stdlib only

# apktool for DEX/smali extraction (recommended)
# https://apktool.org/docs/install/
```

Works without apktool — falls back to scanning resources and assets directly from the ZIP. apktool gives better coverage by extracting string constants from compiled DEX.

## License

MIT
