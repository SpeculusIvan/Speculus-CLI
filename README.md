# Speculus CLI

An interactive terminal client for the [Speculus](https://speculus.co) IP threat intelligence API. Bulk-query IPs from a file, look up a single address, check API health, and watch your monthly quota — all from a colorful Bubble Tea TUI.

## Install

Requires Go 1.21 or newer.

```bash
git clone git@github.com:SpeculusIvan/Speculus-CLI.git
cd Speculus-CLI
go build -o speculus-cli
```

The resulting binary is self-contained and runs on macOS, Linux, and Windows (cross-compile with `GOOS=windows GOARCH=amd64 go build -o speculus-cli.exe`).

## Setup

You need a Speculus API token. Grab one from your dashboard, then pick one of:

- **Interactive setup** (recommended): `./speculus-cli --setup` — walks you through it and writes a `.env` for you.
- **Manual `.env`**: copy `.env.example` to `.env` and replace the placeholder.
- **Environment variable**: `export SPECULUS_TOKEN=spec_live_...`

`.env` is gitignored, so your key never leaves the machine.

## Usage

```bash
./speculus-cli                     # interactive menu
./speculus-cli ips.txt             # bulk-query, writes results_YYYY-MM-DD.csv
./speculus-cli ips.txt out.csv     # bulk-query with a custom output path
./speculus-cli --setup             # configure or rotate your API key
./speculus-cli --help              # show help
```

### Interactive mode

Run with no arguments to get the guided experience:

- **Query an IP list** — pick a file matching `ip*` in the current directory, or create a new `ips.txt` in the built-in editor.
- **Check a single IP** — type an address and see verdict, ASN, ISP, cloud, residential proxy, attribution, and threat flags.
- **Health check** — confirm the API is reachable.
- **View quota** — see used / remaining / grace and reset date.

### Bulk-fetch summary

After a bulk run finishes you get a breakdown:

- Top 3 countries and top 5 outlier countries
- Top 5 ASNs and top 5 outlier ASNs
- Tables of IPs flagged as **VPN / Proxy**, **Residential proxy**, **Risky IPs**, and (when present) **Malicious Activity** with activity and attribution
- Final line: `Wrote N records to <output>.csv`

## Input format

One IP per line. Comments and blank lines aren't supported yet — anything that isn't a parseable public IPv4 is silently skipped.

```
8.8.8.8
1.1.1.1
193.161.193.99
```

## License

(Add a license file when you're ready to publish more widely.)
