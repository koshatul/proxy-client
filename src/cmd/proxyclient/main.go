package main

import (
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/multierr"
)

var rootCmd = &cobra.Command{
	Use:   "proxyclient [--proto=tcp4|udp4|unix] <host:port> <proxysource:port> [proxyserver:port]",
	Short: "proxyclient sends fake PROXY headers for a TCP connection to assist in testing PROXY support in servers",
	Long:  "<host:port> is the PROXY server host and port, <proxysource:port> is the source and port to send as the source in the PROXY header, [proxyserver:port] is the optional proxy server and port to send in the PROXY header",
	Args:  cobra.MinimumNArgs(2),
	Run:   mainCommand,
}

func init() {
	cobra.OnInitialize(configInit)

	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Debug output. ")
	rootCmd.PersistentFlags().StringP("proto", "p", "tcp4", "PROXY header protocol definition")
	rootCmd.PersistentFlags().Int("proto-version", 2, "PROXY protocol version (default: 2)")

	err := multierr.Combine(
		viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug")),
		viper.BindEnv("debug", "DEBUG"),
		viper.BindPFlag("proto", rootCmd.PersistentFlags().Lookup("proto")),
		viper.BindEnv("proto", "PROXY_PROTOCOL"),
		viper.BindPFlag("proto-version", rootCmd.PersistentFlags().Lookup("proto-version")),
		viper.BindEnv("proto-version", "PROXY_VERSION"),
	)
	if err != nil {
		logrus.Fatal(err)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func mainCommand(cmd *cobra.Command, args []string) {
	testIP := net.ParseIP("::1")
	logrus.Infof("ParsedIP: %s", testIP.String())
	logrus.Infof("ParsedIP.To4(): %s", testIP.To4().String())

	var protocol proxyproto.AddressFamilyAndProtocol
	switch strings.ToUpper(viper.GetString("proto")) {
	case "TCP4", "TCP":
		protocol = proxyproto.TCPv4
	case "UDP4", "UDP":
		protocol = proxyproto.UDPv4
	case "TCP6":
		protocol = proxyproto.TCPv6
	case "UDP6":
		protocol = proxyproto.UDPv6
	default:
		protocol = proxyproto.UNSPEC
	}

	proxyHost, proxyPort, err := net.SplitHostPort(args[0])
	if err != nil {
		logrus.Fatal(err)
	}
	srcHost, srcPort, err := net.SplitHostPort(args[1])
	if err != nil {
		logrus.Fatal(err)
	}

	if len(args) >= 3 {
		proxyHost, proxyPort, err = net.SplitHostPort(args[2])
		if err != nil {
			logrus.Fatal(err)
		}
	}

	proxyIP := net.ParseIP(proxyHost)
	if proxyIP == nil {
		if strings.EqualFold("localhost", proxyHost) {
			proxyIP = net.ParseIP("127.0.0.1")
		} else {
			ipl, err := net.LookupIP(proxyHost)
			if err != nil {
				logrus.Fatal(err)
			}
			if len(ipl) >= 1 {
				proxyIP = ipl[0]
			}
		}
	}
	srcIP := net.ParseIP(srcHost)
	if srcIP == nil {
		if strings.EqualFold("localhost", srcHost) {
			srcIP = net.ParseIP("127.0.0.1")
		} else {
			ipl, err := net.LookupIP(srcHost)
			if err != nil {
				logrus.Fatal(err)
			}
			if len(ipl) >= 1 {
				srcIP = ipl[0]
			}
		}
	}

	switch protocol {
	case proxyproto.TCPv6, proxyproto.UDPv6:
		proxyIP = proxyIP.To16()
		srcIP = srcIP.To16()
	default:
		proxyIP = proxyIP.To4()
		srcIP = srcIP.To4()
	}

	proxyPortInt, err := strconv.ParseUint(proxyPort, 10, 16)
	if err != nil {
		logrus.Fatal(err)
	}
	srcPortInt, err := strconv.ParseUint(srcPort, 10, 16)
	if err != nil {
		logrus.Fatal(err)
	}

	header := &proxyproto.Header{
		Command:            proxyproto.PROXY,
		DestinationAddress: proxyIP,
		DestinationPort:    uint16(proxyPortInt),
		SourceAddress:      srcIP,
		SourcePort:         uint16(srcPortInt),
		TransportProtocol:  protocol,
		Version:            byte(viper.GetInt("proto-version")),
	}
	logrus.Infof("Header: %#v", header)

	logrus.Infof("Source Address: %s", header.SourceAddress.String())
	logrus.Infof("Source Port: %d", header.SourcePort)
	logrus.Infof("Destination Address: %s", header.DestinationAddress.String())
	logrus.Infof("Destination Port: %d", header.DestinationPort)

	// header := fmt.Sprintf(
	// 	"PROXY %s %s %s %s %s\r\n",
	// 	protocol,
	// 	srcHost,
	// 	proxyHost,
	// 	srcPort,
	// 	proxyPort,
	// )

	c, err := net.Dial("tcp", args[0])
	if err != nil {
		logrus.Fatal(err)
	}
	defer c.Close()

	n, err := header.WriteTo(c)
	// n, err := fmt.Fprint(c, header)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Debugf("Sent PROXY Header (%d bytes)", n)

	go func() {
		io.Copy(os.Stdout, c)
	}()

	io.Copy(c, os.Stdin)
}
