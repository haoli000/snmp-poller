package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/joho/godotenv"
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getAuthProtocol(proto string) gosnmp.SnmpV3AuthProtocol {
	switch proto {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.SHA
	}
}

func getPrivProtocol(proto string) gosnmp.SnmpV3PrivProtocol {
	switch proto {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	case "AES192C":
		return gosnmp.AES192C
	case "AES256C":
		return gosnmp.AES256C
	default:
		return gosnmp.DES
	}
}

func getMsgFlags(secLevel string) gosnmp.SnmpV3MsgFlags {
	switch strings.ToLower(secLevel) {
	case "authpriv":
		return gosnmp.AuthPriv
	case "authnopriv":
		return gosnmp.AuthNoPriv
	case "noauthnopriv":
		return gosnmp.NoAuthNoPriv
	default:
		return gosnmp.AuthNoPriv
	}
}

func main() {
	// Load .env file if it exists (ignore error if not found)
	_ = godotenv.Load()

	// Define CLI flags
	target := flag.String("target", getEnv("SNMP_TARGET", "192.168.1.100"), "SNMP target host")
	portStr := flag.String("port", getEnv("SNMP_PORT", "161"), "SNMP port")
	username := flag.String("username", getEnv("SNMP_USERNAME", "snmpuser"), "SNMPv3 username")
	authProto := flag.String("auth-protocol", getEnv("SNMP_AUTH_PROTOCOL", "SHA"), "Authentication protocol (MD5, SHA, SHA224, SHA256, SHA384, SHA512)")
	authPass := flag.String("auth-passphrase", getEnv("SNMP_AUTH_PASSPHRASE", "your_auth_passphrase"), "Authentication passphrase")
	privProto := flag.String("priv-protocol", getEnv("SNMP_PRIV_PROTOCOL", "DES"), "Privacy protocol (DES, AES, AES192, AES256, AES192C, AES256C)")
	privPass := flag.String("priv-passphrase", getEnv("SNMP_PRIV_PASSPHRASE", "your_priv_passphrase"), "Privacy passphrase")
	secLevel := flag.String("security-level", getEnv("SNMP_SECURITY_LEVEL", "AuthNoPriv"), "Security level (NoAuthNoPriv, AuthNoPriv, AuthPriv)")
	transport := flag.String("transport", getEnv("SNMP_TRANSPORT", "udp"), "Transport protocol (udp or tcp)")
	oidsStr := flag.String("oids", getEnv("SNMP_OIDS", "1.3.6.1.2.1.1.1.0,1.3.6.1.2.1.1.3.0"), "Comma-separated list of OIDs to query")

	flag.Parse()

	// Convert port to uint16
	port, err := strconv.ParseUint(*portStr, 10, 16)
	if err != nil {
		log.Fatalf("Invalid port: %v", err)
	}

	// SNMPv3 parameters
	gs := &gosnmp.GoSNMP{
		Target:        *target,
		Port:          uint16(port),
		Transport:     *transport,
		Version:       gosnmp.Version3,
		Timeout:       time.Duration(10) * time.Second,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      getMsgFlags(*secLevel),
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 *username,
			AuthenticationProtocol:   getAuthProtocol(*authProto),
			AuthenticationPassphrase: *authPass,
			PrivacyProtocol:          getPrivProtocol(*privProto),
			PrivacyPassphrase:        *privPass,
		},
	}

	err = gs.Connect()
	if err != nil {
		log.Fatalf("Connect error: %v", err)
	}
	defer gs.Conn.Close()

	// Parse OIDs from configuration
	oids := strings.Split(*oidsStr, ",")
	for i := range oids {
		oids[i] = strings.TrimSpace(oids[i])
	}

	fmt.Printf("Sending one single GETNEXT PDU with %d OIDs...\n", len(oids))

	// This sends ONE packet with all 10 varbinds
	result, err := gs.GetNext(oids)
	if err != nil {
		log.Fatalf("GetNext error: %v", err)
	}

	fmt.Printf("Received %d varbinds in one response:\n", len(result.Variables))
	for i, v := range result.Variables {
		fmt.Printf("%d: %s = %v\n", i+1, v.Name, v.Value)
	}
}
