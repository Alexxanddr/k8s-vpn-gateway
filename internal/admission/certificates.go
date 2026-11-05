package admission

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	core "k8s.io/api/core/v1"
)

func secretRequest(method, namespace, name string, body []byte) (core.Secret, error) {
	var secret core.Secret
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return secret, err
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return secret, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return secret, fmt.Errorf("invalid API CA")
	}
	client := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	req, err := http.NewRequest(method, "https://"+os.Getenv("KUBERNETES_SERVICE_HOST")+":"+os.Getenv("KUBERNETES_SERVICE_PORT")+"/api/v1/namespaces/"+namespace+"/secrets/"+name, bytes.NewReader(body))
	if err != nil {
		return secret, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return secret, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return secret, fmt.Errorf("Secret API returned %d", res.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&secret)
	return secret, err
}

func syncCertificates(namespace, name string, namespaces []string) {
	for {
		source, err := secretRequest("GET", namespace, "vpn-overlay-client", nil)
		if err == nil && len(source.Data["tls.key"]) > 0 && len(source.Data["tls.crt"]) > 0 && len(source.Data["ca.crt"]) > 0 {
			for _, ns := range namespaces {
				if ns == "" {
					continue
				}
				target, e := secretRequest("GET", ns, name, nil)
				if e == nil && !reflect.DeepEqual(source.Data, target.Data) {
					target.Data = source.Data
					var b []byte
					b, e = json.Marshal(target)
					if e == nil {
						_, e = secretRequest("PUT", ns, name, b)
					}
				}
				if e != nil {
					log.Printf("transport certificate sync failed namespace=%s: %v", ns, e)
				}
			}
		} else {
			log.Print("transport certificates not yet available")
		}
		time.Sleep(30 * time.Second)
	}
}
