package trivy

import (
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/davealtena/trix/internal/tools/kubectl"
)

// Client wraps kubectl.Client for Trivy-specific operations
type Client struct {
	k8sClient     *kubectl.Client
	dynamicClient dynamic.Interface
	clientset     *kubernetes.Clientset
}

// NewClient creates a Trivy client from a kubectl client
func NewClient(k8sClient *kubectl.Client) *Client {
	return &Client{
		k8sClient:     k8sClient,
		dynamicClient: k8sClient.DynamicClient(),
		clientset:     k8sClient.Clientset(),
	}
}

// K8sClient returns the underlying kubectl client
func (c *Client) K8sClient() *kubectl.Client {
	return c.k8sClient
}
