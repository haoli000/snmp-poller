# SNMP Poller

A simple SNMPv3 poller written in Go.

## Configuration

Configuration can be provided via environment variables or command-line flags. Command-line flags take precedence over environment variables.

### Using .env file

1. Copy the example file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your credentials:
   ```bash
   SNMP_TARGET=192.168.1.100
   SNMP_PORT=161
   SNMP_USERNAME=snmpuser
   SNMP_AUTH_PROTOCOL=SHA
   SNMP_AUTH_PASSPHRASE=your_auth_passphrase
   SNMP_PRIV_PROTOCOL=DES
   SNMP_PRIV_PASSPHRASE=your_priv_passphrase
   SNMP_OIDS=1.3.6.1.2.1.1.1.0,1.3.6.1.2.1.1.3.0
   ```

3. Run the application:
   ```bash
   go run main.go
   ```

### Using CLI flags

Override any configuration with command-line flags:

```bash
go run main.go \
  -target=192.168.1.1 \
  -port=161 \
  -username=myuser \
  -auth-protocol=SHA256 \
  -auth-passphrase=myauthpass \
  -priv-protocol=AES \
  -priv-passphrase=myprivpass \
  -oids="1.3.6.1.2.1.1.1.0,1.3.6.1.2.1.1.3.0"
```

### Available Options

- `-target`: SNMP target host (default: from env or "192.168.1.100")
- `-port`: SNMP port (default: from env or "161")
- `-username`: SNMPv3 username (default: from env or "snmpuser")
- `-auth-protocol`: Authentication protocol - MD5, SHA, SHA224, SHA256, SHA384, SHA512 (default: from env or "SHA")
- `-auth-passphrase`: Authentication passphrase (default: from env or "your_auth_passphrase")
- `-priv-protocol`: Privacy protocol - DES, AES, AES192, AES256, AES192C, AES256C (default: from env or "DES")
- `-priv-passphrase`: Privacy passphrase (default: from env or "your_priv_passphrase")
- `-oids`: Comma-separated list of OIDs to query (default: from env or a set of default OIDs)

## Build

```bash
go build -o snmp-poller main.go
```

## Run

```bash
./snmp-poller
```
