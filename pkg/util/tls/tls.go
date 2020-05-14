package tls

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	tlsCertNotAfterTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "cortex",
		Name:      "tls_cert_not_after_timestamp",
		Help:      "Timestamp of expiry for the TLS certificate",
	}, []string{"filename"})
)

// ClientConfig is the config for client TLS.
type ClientConfig struct {
	CertPath string `yaml:"tls_cert_path"`
	KeyPath  string `yaml:"tls_key_path"`
	CAPath   string `yaml:"tls_ca_path"`
}

// RegisterFlagsWithPrefix registers flags with prefix.
func (cfg *ClientConfig) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.StringVar(&cfg.CertPath, prefix+".tls-cert-path", "", "TLS cert path for the client")
	f.StringVar(&cfg.KeyPath, prefix+".tls-key-path", "", "TLS key path for the client")
	f.StringVar(&cfg.CAPath, prefix+".tls-ca-path", "", "TLS CA path for the client")
}

// GetTLSConfig initialises tls.Config from config options
func (cfg *ClientConfig) GetTLSConfig() (*tls.Config, error) {
	if cfg.CertPath != "" && cfg.KeyPath != "" && cfg.CAPath != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load TLS certificate %s,%s", cfg.CertPath, cfg.KeyPath)
		}

		var caCertPool *x509.CertPool
		caCert, err := ioutil.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, errors.Wrapf(err, "error loading ca cert: %s", cfg.CAPath)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		if len(clientCert.Certificate) > 0 && caCertPool != nil {
			prometheus.MustRegister(tlsCertNotAfterTimestamp)
			var x509Cert *x509.Certificate
			var err error
			if x509Cert, err = x509.ParseCertificate(clientCert.Certificate[0]); err != nil {
				return nil, errors.Wrap(err, "error parsing TLS certificate")
			}
			tlsCertNotAfterTimestamp.WithLabelValues(cfg.CertPath).Set(float64(x509Cert.NotAfter.Unix()))
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{clientCert},
				RootCAs:            caCertPool,
			}, nil
		}
	}
	return nil, nil
}

// GetGRPCDialOptions creates GRPC DialOptions for TLS
func (cfg *ClientConfig) GetGRPCDialOptions() ([]grpc.DialOption, error) {
	if tlsConfig, err := cfg.GetTLSConfig(); err != nil {
		return nil, errors.Wrap(err, "error creating grpc dial options")
	} else if tlsConfig != nil {
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
	}
	return []grpc.DialOption{grpc.WithInsecure()}, nil
}
