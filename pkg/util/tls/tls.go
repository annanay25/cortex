package tls

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/cortexproject/cortex/pkg/util"
)

var (
	tlsCertNotAfterTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "cortex",
		Name:      "tls_cert_not_after_timestamp",
		Help:      "Timestamp of when the tls certificate expires",
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
			level.Error(util.Logger).Log("msg", "error loading certs", "error", err)
			return nil, err
		}

		var caCertPool *x509.CertPool
		caCert, err := ioutil.ReadFile(cfg.CAPath)
		if err != nil {
			level.Error(util.Logger).Log("msg", "error loading ca cert", "error", err)
			return nil, err
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		if len(clientCert.Certificate) > 0 && caCertPool != nil {
			prometheus.MustRegister(tlsCertNotAfterTimestamp)
			expiry, err := getCertExpiry(&clientCert)
			if err != nil {
				level.Error(util.Logger).Log("error parsing TLS certificate: %v", err)
			}
			tlsCertNotAfterTimestamp.WithLabelValues(cfg.CertPath).Set(float64(expiry.Unix()))
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
	var opts []grpc.DialOption
	if tlsConfig, err := cfg.GetTLSConfig(); err != nil {
		return nil, err
	} else if tlsConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	return opts, nil
}

func getCertExpiry(cert *tls.Certificate) (time.Time, error) {
	// LoadX509KeyPair sets cert.Leaf to nil, because parsed form of certificate
	// is not retained
	var x509Cert *x509.Certificate
	var err error
	if x509Cert, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return time.Now(), err
	}
	return x509Cert.NotAfter, nil
}
