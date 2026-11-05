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
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type apiStatus int

func (s apiStatus) Error() string { return fmt.Sprintf("Kubernetes API returned %d", s) }

func apiRequest(method, path string, body []byte, result any) error {
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return err
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("invalid API CA")
	}
	client := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	req, err := http.NewRequest(method, "https://"+os.Getenv("KUBERNETES_SERVICE_HOST")+":"+os.Getenv("KUBERNETES_SERVICE_PORT")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	if _, ok := result.(*meta.PartialObjectMetadataList); ok {
		req.Header.Set("Accept", "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1")
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return apiStatus(res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(result)
}

func secretRequest(method, namespace, name string, body []byte) (core.Secret, error) {
	var secret core.Secret
	err := apiRequest(method, "/api/v1/namespaces/"+namespace+"/secrets/"+name, body, &secret)
	return secret, err
}

const managedSecret = "vpn-gateway.io/transport-owner"

func (c Config) clientNamespaces() (map[string]bool, error) {
	namespaces := map[string]bool{}
	for _, namespace := range c.Namespaces {
		if namespace != "" {
			namespaces[namespace] = true
		}
	}
	if !c.AutoEnroll {
		return namespaces, nil
	}
	query := url.Values{"labelSelector": {Injected + "=v1"}, "limit": {"5"}}
	for {
		var pods meta.PartialObjectMetadataList
		if err := apiRequest("GET", "/api/v1/pods?"+query.Encode(), nil, &pods); err != nil {
			return namespaces, err
		}
		for _, pod := range pods.Items {
			enabled, err := selected(pod.Annotations)
			if err == nil && enabled && pod.Annotations[Injected] == "v1" && pod.DeletionTimestamp == nil && c.autoNamespace(pod.Namespace) {
				namespaces[pod.Namespace] = true
			}
		}
		if pods.Continue == "" {
			return namespaces, nil
		}
		query.Set("continue", pods.Continue)
	}
}

func (c Config) syncSecret(namespace string, data map[string][]byte) error {
	target, err := secretRequest("GET", namespace, c.ClientSecret, nil)
	if err == apiStatus(http.StatusNotFound) && c.autoNamespace(namespace) {
		target = core.Secret{
			ObjectMeta: meta.ObjectMeta{Name: c.ClientSecret, Namespace: namespace, Labels: map[string]string{managedSecret: c.GatewayNamespace}},
			Type:       core.SecretTypeOpaque,
			Data:       data,
		}
		body, err := json.Marshal(target)
		if err != nil {
			return err
		}
		return apiRequest("POST", "/api/v1/namespaces/"+namespace+"/secrets", body, &target)
	}
	if err != nil {
		return err
	}
	if !slices.Contains(c.Namespaces, namespace) && target.Labels[managedSecret] != c.GatewayNamespace {
		return fmt.Errorf("transport Secret already exists and is not managed by this gateway")
	}
	if reflect.DeepEqual(data, target.Data) {
		return nil
	}
	target.Data = data
	body, err := json.Marshal(target)
	if err != nil {
		return err
	}
	_, err = secretRequest("PUT", namespace, c.ClientSecret, body)
	return err
}

func (c Config) syncCertificates() {
	interval := 30 * time.Second
	if c.AutoEnroll {
		interval = 3 * time.Second
	}
	for {
		source, err := secretRequest("GET", c.GatewayNamespace, "vpn-overlay-client", nil)
		if err == nil && len(source.Data["tls.key"]) > 0 && len(source.Data["tls.crt"]) > 0 && len(source.Data["ca.crt"]) > 0 {
			namespaces, err := c.clientNamespaces()
			if err != nil {
				log.Printf("automatic client discovery failed: %v", err)
			}
			for namespace := range namespaces {
				if err := c.syncSecret(namespace, source.Data); err != nil {
					log.Printf("transport certificate sync failed namespace=%s: %v", namespace, err)
				}
			}
		} else {
			log.Print("transport certificates not yet available")
		}
		time.Sleep(interval)
	}
}
