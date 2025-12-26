package kubectl

import (
	"fmt"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps Kubernetes client
type Client struct {
	clientset     *kubernetes.Clientset
	dynamicClient dynamic.Interface
}

// NewClient creates a K8s client using default kubeconfig loading rules
// Respects KUBECONFIG env var and ~/.kube/config
func NewClient() (*Client, error) {
	// Use default loading rules (same as kubectl)
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	// Create standard clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	// Create dynamic client for CRDs
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &Client{
		clientset:     clientset,
		dynamicClient: dynamicClient,
	}, nil
}

// GetCurrentContext returns the current kubectl context name
func (c *Client) GetCurrentContext() (string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	config := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	)

	rawConfig, err := config.RawConfig()
	if err != nil {
		return "", err
	}

	return rawConfig.CurrentContext, nil
}

// DynamicClient returns the dynamic client for CRD queries
func (c *Client) DynamicClient() dynamic.Interface {
	return c.dynamicClient
}

// Clientset returns the kubernetes clientset
func (c *Client) Clientset() *kubernetes.Clientset {
	return c.clientset
}
