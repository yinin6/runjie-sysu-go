package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const ethTypeEAPOL = 0x888e

const (
	eapCodeRequest = 1
	eapCodeSuccess = 3
	eapCodeFailure = 4
)

const (
	eapTypeIdentity = 1
	eapTypeMD5      = 4
)

var paeGroupAddr = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}

type Config struct {
	ConfigPath string `json:"-"`

	DeviceName        string `json:"device_name"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	Identity          string `json:"identity"`
	IdentitySuffixHex string `json:"identity_suffix_hex"`
	LocalMACStr       string `json:"local_mac"`

	StartDelayMs int  `json:"start_delay_ms"`
	RetryDelayMs int  `json:"retry_delay_ms"`
	KeepaliveSec int  `json:"keepalive_sec"`
	Debug        bool `json:"debug"`
	OnlyLogin    bool `json:"only_login"`
	LogoffOnly   bool `json:"-"`
	ListDevices  bool `json:"-"`
}

type ConfigPatch struct {
	DeviceName        *string `json:"device_name"`
	Username          *string `json:"username"`
	Password          *string `json:"password"`
	Identity          *string `json:"identity"`
	IdentitySuffixHex *string `json:"identity_suffix_hex"`
	LocalMACStr       *string `json:"local_mac"`
	StartDelayMs      *int    `json:"start_delay_ms"`
	RetryDelayMs      *int    `json:"retry_delay_ms"`
	KeepaliveSec      *int    `json:"keepalive_sec"`
	Debug             *bool   `json:"debug"`
	OnlyLogin         *bool   `json:"only_login"`
}

type Client struct {
	cfg Config

	handle   *pcap.Handle
	localMAC net.HardwareAddr
	dstMAC   net.HardwareAddr

	mu               sync.Mutex
	online           bool
	lastServerMAC    net.HardwareAddr
	lastIdentityReq  time.Time
	lastChallengeReq time.Time
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	if cfg.ListDevices {
		if err := listDevices(); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := validateConfig(cfg); err != nil {
		log.Fatal(err)
	}

	client, err := NewClient(cfg)
	if err != nil {
		log.Fatalf("init client failed: %v", err)
	}
	defer client.Close()

	log.Printf("device=%s", cfg.DeviceName)
	log.Printf("local mac=%s", client.localMAC)

	if cfg.LogoffOnly {
		if err := client.sendLogoff(); err != nil {
			log.Fatalf("send logoff failed: %v", err)
		}
		log.Println("sent EAPOL-Logoff")
		return
	}

	log.Printf("identity=%q", cfg.Identity)

	if cfg.StartDelayMs > 0 {
		time.Sleep(time.Duration(cfg.StartDelayMs) * time.Millisecond)
	}

	if err := client.sendStart(); err != nil {
		log.Fatalf("send start failed: %v", err)
	}
	log.Println("sent EAPOL-Start")

	if !cfg.OnlyLogin {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			log.Println("signal received, sending EAPOL-Logoff")
			_ = client.sendLogoff()
			os.Exit(0)
		}()
	}

	if err := client.loop(); err != nil {
		log.Fatal(err)
	}
}

func parseConfig(args []string) (Config, error) {
	cfgPath := detectConfigPath(args)

	cfg := defaultConfig()

	if cfgPath != "" {
		fileCfg, err := loadConfigFile(cfgPath)
		if err != nil {
			return Config{}, err
		}
		cfg = applyPatch(cfg, fileCfg)
		cfg.ConfigPath = cfgPath
	}

	cfg = applyPatch(cfg, configFromEnv())

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Configuration priority: flags > environment variables > config file.")
		fmt.Fprintln(fs.Output(), "Environment variables:")
		fmt.Fprintln(fs.Output(), "  RUNJIE_CONFIG")
		fmt.Fprintln(fs.Output(), "  RUNJIE_DEVICE_NAME")
		fmt.Fprintln(fs.Output(), "  RUNJIE_USERNAME")
		fmt.Fprintln(fs.Output(), "  RUNJIE_PASSWORD")
		fmt.Fprintln(fs.Output(), "  RUNJIE_IDENTITY")
		fmt.Fprintln(fs.Output(), "  RUNJIE_IDENTITY_SUFFIX_HEX")
		fmt.Fprintln(fs.Output(), "  RUNJIE_LOCAL_MAC")
		fmt.Fprintln(fs.Output(), "  RUNJIE_START_DELAY_MS")
		fmt.Fprintln(fs.Output(), "  RUNJIE_RETRY_DELAY_MS")
		fmt.Fprintln(fs.Output(), "  RUNJIE_KEEPALIVE_SEC")
		fmt.Fprintln(fs.Output(), "  RUNJIE_DEBUG")
		fmt.Fprintln(fs.Output(), "  RUNJIE_ONLY_LOGIN")
		fmt.Fprintln(fs.Output(), "")
		fs.PrintDefaults()
	}

	fs.StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "path to JSON config file")
	fs.StringVar(&cfg.DeviceName, "i", cfg.DeviceName, `pcap device name, e.g. \Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`)
	fs.StringVar(&cfg.Username, "u", cfg.Username, "username")
	fs.StringVar(&cfg.Password, "p", cfg.Password, "password")
	fs.StringVar(&cfg.Identity, "id", cfg.Identity, "raw EAP identity; default=username")
	fs.StringVar(&cfg.IdentitySuffixHex, "id-suffix-hex", cfg.IdentitySuffixHex, "append hex bytes to identity, e.g. 0000131100")
	fs.StringVar(&cfg.LocalMACStr, "m", cfg.LocalMACStr, "local adapter MAC, e.g. 12:34:56:78:9a:bc")
	fs.IntVar(&cfg.StartDelayMs, "start-delay-ms", cfg.StartDelayMs, "delay before first EAPOL-Start")
	fs.IntVar(&cfg.RetryDelayMs, "retry-delay-ms", cfg.RetryDelayMs, "retry delay after authentication failure")
	fs.IntVar(&cfg.KeepaliveSec, "keepalive-sec", cfg.KeepaliveSec, "periodic keepalive by resending EAPOL-Start after success")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable debug logs")
	fs.BoolVar(&cfg.ListDevices, "list", false, "list pcap devices")
	fs.BoolVar(&cfg.OnlyLogin, "l", cfg.OnlyLogin, "exit immediately after successful authentication")
	fs.BoolVar(&cfg.LogoffOnly, "logout", false, "send EAPOL-Logoff and exit")
	fs.BoolVar(&cfg.LogoffOnly, "logoff", false, "send EAPOL-Logoff and exit")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if cfg.Identity == "" {
		cfg.Identity = cfg.Username
	}

	return cfg, nil
}

func defaultConfig() Config {
	return Config{
		StartDelayMs: 0,
		RetryDelayMs: 2000,
		KeepaliveSec: 30,
		OnlyLogin:    true,
	}
}

func detectConfigPath(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-config" && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(arg, "-config="):
			return strings.TrimPrefix(arg, "-config=")
		}
	}
	return strings.TrimSpace(os.Getenv("RUNJIE_CONFIG"))
}

func loadConfigFile(path string) (ConfigPatch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ConfigPatch{}, fmt.Errorf("read config file %q: %w", path, err)
	}

	var cfg ConfigPatch
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ConfigPatch{}, fmt.Errorf("parse config file %q: %w", path, err)
	}

	return cfg, nil
}

func configFromEnv() ConfigPatch {
	cfg := ConfigPatch{}

	if v, ok := lookupStringEnv("RUNJIE_DEVICE_NAME"); ok {
		cfg.DeviceName = &v
	}
	if v, ok := lookupStringEnv("RUNJIE_USERNAME"); ok {
		cfg.Username = &v
	}
	if v, ok := lookupStringEnv("RUNJIE_PASSWORD"); ok {
		cfg.Password = &v
	}
	if v, ok := lookupStringEnv("RUNJIE_IDENTITY"); ok {
		cfg.Identity = &v
	}
	if v, ok := lookupStringEnv("RUNJIE_IDENTITY_SUFFIX_HEX"); ok {
		cfg.IdentitySuffixHex = &v
	}
	if v, ok := lookupStringEnv("RUNJIE_LOCAL_MAC"); ok {
		cfg.LocalMACStr = &v
	}
	if v, ok := lookupIntEnv("RUNJIE_START_DELAY_MS"); ok {
		cfg.StartDelayMs = &v
	}
	if v, ok := lookupIntEnv("RUNJIE_RETRY_DELAY_MS"); ok {
		cfg.RetryDelayMs = &v
	}
	if v, ok := lookupIntEnv("RUNJIE_KEEPALIVE_SEC"); ok {
		cfg.KeepaliveSec = &v
	}
	if v, ok := lookupBoolEnv("RUNJIE_DEBUG"); ok {
		cfg.Debug = &v
	}
	if v, ok := lookupBoolEnv("RUNJIE_ONLY_LOGIN"); ok {
		cfg.OnlyLogin = &v
	}

	return cfg
}

func applyPatch(base Config, patch ConfigPatch) Config {
	if patch.DeviceName != nil {
		base.DeviceName = *patch.DeviceName
	}
	if patch.Username != nil {
		base.Username = *patch.Username
	}
	if patch.Password != nil {
		base.Password = *patch.Password
	}
	if patch.Identity != nil {
		base.Identity = *patch.Identity
	}
	if patch.IdentitySuffixHex != nil {
		base.IdentitySuffixHex = *patch.IdentitySuffixHex
	}
	if patch.LocalMACStr != nil {
		base.LocalMACStr = *patch.LocalMACStr
	}
	if patch.StartDelayMs != nil {
		base.StartDelayMs = *patch.StartDelayMs
	}
	if patch.RetryDelayMs != nil {
		base.RetryDelayMs = *patch.RetryDelayMs
	}
	if patch.KeepaliveSec != nil {
		base.KeepaliveSec = *patch.KeepaliveSec
	}
	if patch.Debug != nil {
		base.Debug = *patch.Debug
	}
	if patch.OnlyLogin != nil {
		base.OnlyLogin = *patch.OnlyLogin
	}
	return base
}

func lookupStringEnv(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	return v, true
}

func lookupIntEnv(key string) (int, bool) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return 0, false
	}

	var out int
	if _, err := fmt.Sscanf(v, "%d", &out); err != nil {
		log.Fatalf("invalid integer in %s: %v", key, err)
	}
	return out, true
}

func lookupBoolEnv(key string) (bool, bool) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return false, false
	}

	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		log.Fatalf("invalid boolean in %s", key)
		return false, false
	}
}

func validateConfig(cfg Config) error {
	if cfg.DeviceName == "" || cfg.LocalMACStr == "" {
		return errors.New("missing required configuration: device_name, local_mac")
	}
	if !cfg.LogoffOnly && (cfg.Username == "" || cfg.Password == "") {
		return errors.New("missing required configuration for login: username, password")
	}
	if _, err := net.ParseMAC(cfg.LocalMACStr); err != nil {
		return fmt.Errorf("invalid local_mac: %w", err)
	}
	if cfg.IdentitySuffixHex != "" {
		if _, err := decodeHexString(cfg.IdentitySuffixHex); err != nil {
			return fmt.Errorf("invalid identity_suffix_hex: %w", err)
		}
	}
	if cfg.RetryDelayMs < 0 {
		return errors.New("retry_delay_ms must be >= 0")
	}
	if cfg.StartDelayMs < 0 {
		return errors.New("start_delay_ms must be >= 0")
	}
	if cfg.KeepaliveSec < 0 {
		return errors.New("keepalive_sec must be >= 0")
	}
	return nil
}

func listDevices() error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	for i, d := range devs {
		fmt.Printf("[%d] %s\n", i, d.Name)
		if d.Description != "" {
			fmt.Printf("    desc: %s\n", d.Description)
		}
		for _, a := range d.Addresses {
			if a.IP != nil {
				fmt.Printf("    ip: %s\n", a.IP)
			}
		}
	}
	return nil
}

func NewClient(cfg Config) (*Client, error) {
	localMAC, err := net.ParseMAC(cfg.LocalMACStr)
	if err != nil {
		return nil, fmt.Errorf("parse mac failed: %w", err)
	}
	if len(localMAC) != 6 {
		return nil, errors.New("invalid MAC length")
	}

	handle, err := pcap.OpenLive(cfg.DeviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open pcap device: %w", err)
	}

	if err := handle.SetBPFFilter("ether proto 0x888e"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set bpf filter: %w", err)
	}

	return &Client{
		cfg:      cfg,
		handle:   handle,
		localMAC: localMAC,
		dstMAC:   paeGroupAddr,
	}, nil
}

func (c *Client) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}

func (c *Client) loop() error {
	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packets := src.Packets()

	var keepaliveTicker *time.Ticker
	if c.cfg.KeepaliveSec > 0 {
		keepaliveTicker = time.NewTicker(time.Duration(c.cfg.KeepaliveSec) * time.Second)
		defer keepaliveTicker.Stop()
	}

	for {
		select {
		case pkt, ok := <-packets:
			if !ok {
				return errors.New("packet source closed")
			}
			if err := c.handlePacket(pkt); err != nil {
				log.Printf("handle packet error: %v", err)
			}
			if c.isOnline() && c.cfg.OnlyLogin {
				return nil
			}
		case <-tickerChan(keepaliveTicker):
			if c.isOnline() {
				log.Println("keepalive: re-send EAPOL-Start")
				if err := c.sendStart(); err != nil {
					log.Printf("keepalive failed: %v", err)
				}
			}
		}
	}
}

func tickerChan(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func (c *Client) isOnline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online
}

func (c *Client) setOnline(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.online = v
}

func (c *Client) handlePacket(pkt gopacket.Packet) error {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	eth := ethLayer.(*layers.Ethernet)

	eapolLayer := pkt.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return nil
	}
	eapol := eapolLayer.(*layers.EAPOL)

	if c.cfg.Debug {
		log.Printf("recv EAPOL src=%s dst=%s type=%d len=%d",
			eth.SrcMAC, eth.DstMAC, eapol.Type, eapol.Length)
	}

	if len(eth.SrcMAC) == 6 {
		c.dstMAC = cloneMAC(eth.SrcMAC)
		c.lastServerMAC = cloneMAC(eth.SrcMAC)
	}

	if eapol.Type != layers.EAPOLTypeEAP {
		return nil
	}

	eapLayer := pkt.Layer(layers.LayerTypeEAP)
	if eapLayer == nil {
		return nil
	}
	eap := eapLayer.(*layers.EAP)

	if c.cfg.Debug {
		log.Printf("recv EAP code=%d id=%d type=%d len=%d typedata=%s",
			eap.Code, eap.Id, eap.Type, eap.Length, hexDump(eap.TypeData))
	}

	switch uint8(eap.Code) {
	case eapCodeRequest:
		switch uint8(eap.Type) {
		case eapTypeIdentity:
			c.lastIdentityReq = time.Now()
			log.Printf("recv Request/Identity from %s", eth.SrcMAC)
			return c.sendIdentity(eap.Id)
		case eapTypeMD5:
			c.lastChallengeReq = time.Now()
			log.Printf("recv Request/MD5-Challenge from %s", eth.SrcMAC)
			return c.sendMD5Response(eap.Id, eap.TypeData)
		default:
			log.Printf("recv unsupported EAP request type=%d", uint8(eap.Type))
			return nil
		}

	case eapCodeSuccess:
		if !c.isOnline() {
			log.Println("authentication success")
		}
		c.setOnline(true)
		return nil

	case eapCodeFailure:
		c.setOnline(false)
		log.Println("authentication failure")
		go c.retryStartLater()
		return nil
	}

	return nil
}

func (c *Client) retryStartLater() {
	delay := time.Duration(c.cfg.RetryDelayMs) * time.Millisecond
	if delay <= 0 {
		delay = 2 * time.Second
	}
	time.Sleep(delay)
	if err := c.sendStart(); err != nil {
		log.Printf("retry start failed: %v", err)
	} else {
		log.Println("re-sent EAPOL-Start")
	}
}

func (c *Client) sendStart() error {
	if c.cfg.Debug {
		log.Printf("send EAPOL-Start src=%s dst=%s", c.localMAC, paeGroupAddr)
	}
	return c.writeEAPOLPacket(paeGroupAddr, 0x01, nil)
}

func (c *Client) sendLogoff() error {
	dst := c.dstMAC
	if len(dst) != 6 {
		dst = paeGroupAddr
	}

	if c.cfg.Debug {
		log.Printf("send EAPOL-Logoff src=%s dst=%s", c.localMAC, dst)
	}
	return c.writeEAPOLPacket(dst, 0x02, nil)
}

func (c *Client) buildIdentityBytes() ([]byte, error) {
	base := []byte(c.cfg.Identity)

	if c.cfg.IdentitySuffixHex == "" {
		return base, nil
	}

	suffix, err := decodeHexString(c.cfg.IdentitySuffixHex)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(base)+len(suffix))
	out = append(out, base...)
	out = append(out, suffix...)
	return out, nil
}

func (c *Client) sendIdentity(id uint8) error {
	identityBytes, err := c.buildIdentityBytes()
	if err != nil {
		return fmt.Errorf("build identity failed: %w", err)
	}

	eapLen := 5 + len(identityBytes)
	eap := make([]byte, eapLen)
	eap[0] = 0x02
	eap[1] = id
	eap[2] = byte(eapLen >> 8)
	eap[3] = byte(eapLen)
	eap[4] = 0x01
	copy(eap[5:], identityBytes)

	log.Printf("send Response/Identity: %q", c.cfg.Identity)
	if c.cfg.Debug {
		log.Printf("identity bytes hex: %s", hexDump(identityBytes))
	}

	return c.writeEAPOLPacket(c.dstMAC, 0x00, eap)
}

func (c *Client) sendMD5Response(id uint8, reqTypeData []byte) error {
	if len(reqTypeData) < 1 {
		return errors.New("md5 challenge payload too short")
	}

	challengeLen := int(reqTypeData[0])
	if len(reqTypeData) < 1+challengeLen {
		return errors.New("md5 challenge payload malformed")
	}

	challenge := reqTypeData[1 : 1+challengeLen]
	sum := md5.Sum(buildMD5Input(id, c.cfg.Password, challenge))

	typeData := make([]byte, 1+16+len(c.cfg.Username))
	typeData[0] = 16
	copy(typeData[1:17], sum[:])
	copy(typeData[17:], []byte(c.cfg.Username))

	eapLen := 5 + len(typeData)
	eap := make([]byte, eapLen)
	eap[0] = 0x02
	eap[1] = id
	eap[2] = byte(eapLen >> 8)
	eap[3] = byte(eapLen)
	eap[4] = 0x04
	copy(eap[5:], typeData)

	log.Println("send Response/MD5-Challenge")
	if c.cfg.Debug {
		log.Printf("challenge hex: %s", hexDump(challenge))
		log.Printf("md5 resp hex: %s", hexDump(typeData))
	}

	return c.writeEAPOLPacket(c.dstMAC, 0x00, eap)
}

func buildMD5Input(id uint8, password string, challenge []byte) []byte {
	buf := make([]byte, 1+len(password)+len(challenge))
	buf[0] = id
	copy(buf[1:], []byte(password))
	copy(buf[1+len(password):], challenge)
	return buf
}

func cloneMAC(in net.HardwareAddr) net.HardwareAddr {
	if len(in) == 0 {
		return nil
	}
	out := make(net.HardwareAddr, len(in))
	copy(out, in)
	return out
}

func decodeHexString(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s)%2 != 0 {
		return nil, errors.New("hex string length must be even")
	}
	return hex.DecodeString(s)
}

func hexDump(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func (c *Client) writeEthernetPayload(dstMAC net.HardwareAddr, payload []byte) error {
	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], c.localMAC)
	eth[12] = 0x88
	eth[13] = 0x8e

	frame := append(eth, payload...)

	if c.cfg.Debug {
		log.Printf("send raw hex: %s", hexDump(frame))
	}

	return c.handle.WritePacketData(frame)
}

func (c *Client) writeEAPOLPacket(dstMAC net.HardwareAddr, eapolType byte, eapPayload []byte) error {
	payload := make([]byte, 4+len(eapPayload))
	payload[0] = 0x01
	payload[1] = eapolType
	payload[2] = byte(len(eapPayload) >> 8)
	payload[3] = byte(len(eapPayload))

	copy(payload[4:], eapPayload)
	return c.writeEthernetPayload(dstMAC, payload)
}
