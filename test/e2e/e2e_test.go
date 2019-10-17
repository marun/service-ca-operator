package e2e

import (
	"bytes"
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	pkgruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
)

const (
	serviceCAOperatorNamespace   = operatorclient.OperatorNamespace
	serviceCAOperatorPodPrefix   = operatorclient.OperatorName
	serviceCAControllerNamespace = operatorclient.TargetNamespace
	apiInjectorPodPrefix         = api.APIServiceInjectorDeploymentName
	configMapInjectorPodPrefix   = api.ConfigMapInjectorDeploymentName
	caControllerPodPrefix        = api.SignerControllerDeploymentName
	signingKeySecretName         = api.SignerControllerSecretName

	pollInterval = time.Second
	pollTimeout  = 10 * time.Second
)

func hasPodWithPrefixName(client *kubernetes.Clientset, name, namespace string) bool {
	if client == nil || len(name) == 0 || len(namespace) == 0 {
		return false
	}
	pods, err := client.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	if err != nil {
		return false
	}
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.GetName(), name) {
			return true
		}
	}
	return false
}

func createTestNamespace(client *kubernetes.Clientset, namespaceName string) (*v1.Namespace, error) {
	ns, err := client.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	})
	return ns, err
}

// on success returns serviceName, secretName, nil
func createServingCertAnnotatedService(client *kubernetes.Clientset, secretName, serviceName, namespace string) error {
	_, err := client.CoreV1().Services(namespace).Create(&v1.Service{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Annotations: map[string]string{
				api.ServingCertSecretAnnotation: secretName,
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name: "tests",
					Port: 8443,
				},
			},
		},
	})
	return err
}

func createAnnotatedCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	_, err := client.CoreV1().ConfigMaps(namespace).Create(&v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
			Annotations: map[string]string{
				api.InjectCABundleAnnotationName: "true",
			},
		},
	})
	return err
}

func pollForServiceServingSecret(client *kubernetes.Clientset, secretName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func pollForCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func editServiceServingSecretData(client *kubernetes.Clientset, secretName, namespace, edit string) error {
	sss, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	scopy := sss.DeepCopy()
	switch edit {
	case "badCert":
		scopy.Data[v1.TLSCertKey] = []byte("blah")
	case "extraData":
		scopy.Data["foo"] = []byte("blah")
	}
	_, err = client.CoreV1().Secrets(namespace).Update(scopy)
	if err != nil {
		return err
	}
	time.Sleep(10 * time.Second)
	return nil
}

func editConfigMapCABundleInjectionData(client *kubernetes.Clientset, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	cmcopy := cm.DeepCopy()
	if len(cmcopy.Data) != 1 {
		return fmt.Errorf("ca bundle injection configmap missing data")
	}
	cmcopy.Data["foo"] = "blah"
	_, err = client.CoreV1().ConfigMaps(namespace).Update(cmcopy)
	if err != nil {
		return err
	}
	time.Sleep(10 * time.Second)
	return nil
}

func checkServiceServingCertSecretData(client *kubernetes.Clientset, secretName, namespace string) ([]byte, bool, error) {
	sss, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return nil, false, err
	}
	if len(sss.Data) != 2 {
		return nil, false, fmt.Errorf("unexpected service serving secret data map length: %v", len(sss.Data))
	}
	ok := true
	_, ok = sss.Data[v1.TLSCertKey]
	_, ok = sss.Data[v1.TLSPrivateKeyKey]
	if !ok {
		return nil, false, fmt.Errorf("unexpected service serving secret data: %v", sss.Data)
	}
	block, _ := pem.Decode([]byte(sss.Data[v1.TLSCertKey]))
	if block == nil {
		return nil, false, fmt.Errorf("unable to decode TLSCertKey bytes")
	}
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return sss.Data[v1.TLSCertKey], false, nil
	}
	return sss.Data[v1.TLSCertKey], true, nil
}

func checkConfigMapCABundleInjectionData(client *kubernetes.Clientset, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if len(cm.Data) != 1 {
		return fmt.Errorf("unexpected ca bundle injection configmap data map length: %v", len(cm.Data))
	}
	ok := true
	_, ok = cm.Data[api.InjectionDataKey]
	if !ok {
		return fmt.Errorf("unexpected ca bundle injection configmap data: %v", cm.Data)
	}
	return nil
}

func pollForServiceServingSecretWithReturn(client *kubernetes.Clientset, secretName, namespace string) (*v1.Secret, error) {
	var secret *v1.Secret
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		s, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		secret = s
		return true, nil
	})
	return secret, err
}

func pollForCABundleInjectionConfigMapWithReturn(client *kubernetes.Clientset, configMapName, namespace string) (*v1.ConfigMap, error) {
	var configmap *v1.ConfigMap
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		configmap = cm
		return true, nil
	})
	return configmap, err
}

func pollForSecretChange(client *kubernetes.Clientset, secret *v1.Secret) error {
	return wait.PollImmediate(time.Second, 2*time.Minute, func() (bool, error) {
		s, err := client.CoreV1().Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !bytes.Equal(s.Data[v1.TLSCertKey], secret.Data[v1.TLSCertKey]) &&
			!bytes.Equal(s.Data[v1.TLSPrivateKeyKey], secret.Data[v1.TLSPrivateKeyKey]) {
			return true, nil
		}
		return false, nil
	})
}

func pollForConfigMapChange(client *kubernetes.Clientset, compareConfigMap *v1.ConfigMap) error {
	return wait.PollImmediate(time.Second, 2*time.Minute, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(compareConfigMap.Namespace).Get(compareConfigMap.Name, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, nil
		}
		if cm.Data[api.InjectionDataKey] != compareConfigMap.Data[api.InjectionDataKey] {
			// the change happened
			return true, nil
		}
		return false, nil
	})
}

func cleanupServiceSignerTestObjects(client *kubernetes.Clientset, secretName, serviceName, namespace string) {
	client.CoreV1().Secrets(namespace).Delete(secretName, &metav1.DeleteOptions{})
	client.CoreV1().Services(namespace).Delete(serviceName, &metav1.DeleteOptions{})
	client.CoreV1().Namespaces().Delete(namespace, &metav1.DeleteOptions{})
	// TODO this should just delete the namespace and wait for it to be gone
	// it should probably fail the test if the namespace gets stuck
}

func cleanupConfigMapCABundleInjectionTestObjects(client *kubernetes.Clientset, cmName, namespace string) {
	client.CoreV1().ConfigMaps(namespace).Delete(cmName, &metav1.DeleteOptions{})
	client.CoreV1().Namespaces().Delete(namespace, &metav1.DeleteOptions{})
	// TODO this should just delete the namespace and wait for it to be gone
	// it should probably fail the test if the namespace gets stuck
}

func TestE2E(t *testing.T) {
	// use /tmp/admin.conf (placed by ci-operator) or KUBECONFIG env
	confPath := "/tmp/admin.conf"
	if conf := os.Getenv("KUBECONFIG"); conf != "" {
		confPath = conf
	}

	// load client
	client, err := clientcmd.LoadFromFile(confPath)
	if err != nil {
		t.Fatalf("error loading config: %v", err)
	}
	adminConfig, err := clientcmd.NewDefaultClientConfig(*client, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("error loading admin config: %v", err)
	}
	adminClient, err := kubernetes.NewForConfig(adminConfig)
	if err != nil {
		t.Fatalf("error getting admin client: %v", err)
	}

	// the service-serving-cert-operator and controllers should be running as a stock OpenShift component. our first test is to
	// verify that all of the components are running.
	if !hasPodWithPrefixName(adminClient, serviceCAOperatorPodPrefix, serviceCAOperatorNamespace) {
		t.Fatalf("%s not running in %s namespace", serviceCAOperatorPodPrefix, serviceCAOperatorNamespace)
	}
	if !hasPodWithPrefixName(adminClient, apiInjectorPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", apiInjectorPodPrefix, serviceCAControllerNamespace)
	}
	if !hasPodWithPrefixName(adminClient, configMapInjectorPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", configMapInjectorPodPrefix, serviceCAControllerNamespace)
	}
	if !hasPodWithPrefixName(adminClient, caControllerPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", caControllerPodPrefix, serviceCAControllerNamespace)
	}

	// test the main feature. annotate service -> created secret
	t.Run("serving-cert-annotation", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}

		err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}

		_, is509, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}
		if !is509 {
			t.Fatalf("TLSCertKey not valid pem bytes")
		}
	})

	// test modified data in serving-cert-secret will regenerated
	t.Run("serving-cert-secret-modify-bad-tlsCert", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)
		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}
		err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		originalBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}

		err = editServiceServingSecretData(adminClient, testSecretName, ns.Name, "badCert")
		if err != nil {
			t.Fatalf("error editing serving cert secret: %v", err)
		}
		updatedBytes, is509, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}
		if bytes.Equal(originalBytes, updatedBytes) {
			t.Fatalf("expected TLSCertKey to be replaced with valid pem bytes")
		}
		if !is509 {
			t.Fatalf("TLSCertKey not valid pem bytes")
		}
	})

	// test extra data in serving-cert-secret will be removed
	t.Run("serving-cert-secret-add-data", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)
		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}
		err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		originalBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}

		err = editServiceServingSecretData(adminClient, testSecretName, ns.Name, "extraData")
		if err != nil {
			t.Fatalf("error editing serving cert secret: %v", err)
		}
		updatedBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}
		if !bytes.Equal(originalBytes, updatedBytes) {
			t.Fatalf("did not expect TLSCertKey to be replaced with a new cert")
		}
	})

	// test ca bundle injection configmap
	t.Run("ca-bundle-injection-configmap", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupConfigMapCABundleInjectionTestObjects(adminClient, testConfigMapName, ns.Name)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		err = pollForCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}

		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}
	})

	// test updated data in ca bundle injection configmap will be stomped on
	t.Run("ca-bundle-injection-configmap-update", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupConfigMapCABundleInjectionTestObjects(adminClient, testConfigMapName, ns.Name)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		err = pollForCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}

		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}

		err = editConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error editing ca bundle injection configmap: %v", err)
		}

		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}
	})

	t.Run("refresh-CA", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}

		// create secret
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}

		secret, err := pollForServiceServingSecretWithReturn(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		secretCopy := secret.DeepCopy()

		// create configmap
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupConfigMapCABundleInjectionTestObjects(adminClient, testConfigMapName, ns.Name)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		configmap, err := pollForCABundleInjectionConfigMapWithReturn(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}
		configmapCopy := configmap.DeepCopy()
		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}

		// delete ca secret
		err = adminClient.CoreV1().Secrets(serviceCAControllerNamespace).Delete(signingKeySecretName, nil)
		if err != nil {
			t.Fatalf("error deleting signing key: %v", err)
		}

		// make sure it's recreated
		err = pollForServiceServingSecret(adminClient, signingKeySecretName, serviceCAControllerNamespace)
		if err != nil {
			t.Fatalf("signing key was not recreated: %v", err)
		}

		err = pollForConfigMapChange(adminClient, configmapCopy)
		if err != nil {
			t.Fatalf("configmap bundle did not change: %v", err)
		}

		err = pollForSecretChange(adminClient, secretCopy)
		if err != nil {
			t.Fatalf("secret cert did not change: %v", err)
		}
	})

	t.Run("rotate-CA", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}

		// Prompt the creation of a service cert secret
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}

		// Prompt the injection of the ca bundle into a configmap
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupConfigMapCABundleInjectionTestObjects(adminClient, testConfigMapName, ns.Name)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		// Retrieve the pre-rotation service cert
		oldCertPEM, oldKeyPEM, err := pollForServiceCert(t, adminClient, ns.Name, testSecretName, nil, nil)
		if err != nil {
			t.Fatalf("failed to retrieve service cert: %v", err)
		}

		// Retrieve the pre-rotation ca bundle
		oldBundlePEM, err := pollForCABundle(t, adminClient, ns.Name, testConfigMapName, nil)
		if err != nil {
			t.Fatalf("failed to retrieve ca bundle: %v", err)
		}

		// Prompt CA rotation
		applyRotatableCert(t, adminClient)

		// Retrieve the post-rotation service cert
		newCertPEM, newKeyPEM, err := pollForServiceCert(t, adminClient, ns.Name, testSecretName, oldCertPEM, oldKeyPEM)
		if err != nil {
			t.Fatalf("failed to retrieve service cert: %v", err)
		}

		// Retrieve the post-rotation ca bundle
		newBundlePEM, err := pollForCABundle(t, adminClient, ns.Name, testConfigMapName, oldBundlePEM)
		if err != nil {
			t.Fatalf("failed to retrieve ca bundle: %v", err)
		}

		// Validate all the permutations of server and client cert state
		testCases := map[string]struct {
			certPEM   []byte
			keyPEM    []byte
			bundlePEM []byte
		}{
			"Pre-rotation": {
				certPEM:   oldCertPEM,
				keyPEM:    oldKeyPEM,
				bundlePEM: oldBundlePEM,
			},
			"Server rotated": {
				certPEM:   newCertPEM,
				keyPEM:    newKeyPEM,
				bundlePEM: oldBundlePEM,
			},
			"Client refreshed": {
				certPEM:   oldCertPEM,
				keyPEM:    oldKeyPEM,
				bundlePEM: newBundlePEM,
			},
			"Server rotated and client refreshed": {
				certPEM:   newCertPEM,
				keyPEM:    newKeyPEM,
				bundlePEM: newBundlePEM,
			},
		}
		for testName, tc := range testCases {
			t.Run(testName, func(t *testing.T) {
				checkClientTrust(t, tc.certPEM, tc.keyPEM, tc.bundlePEM)
			})
		}
	})

	// TODO: additional tests
	// - API service CA bundle injection
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var characters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

// TODO drop this and just use generate name
// used for random suffix
func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = characters[rand.Intn(len(characters))]
	}
	return string(b)
}

// applyRotatableCert replaces current CA cert with one that has passed its halfway-expired point.
func applyRotatableCert(t *testing.T, client *kubernetes.Clientset) {
	template := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "test"},
		SignatureAlgorithm: x509.SHA256WithRSA,
		// A 4 hour cert that has 3 of those hours elapsed, more than halfway to expiration.
		NotBefore:             time.Now().Add(-3 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		SerialNumber:          big.NewInt(1),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	priv, err := rsa.GenerateKey(rand2.Reader, 2048)
	if err != nil {
		t.Fatalf("error creating test CA key: %v", err)
	}
	caDer, err := x509.CreateCertificate(rand2.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("error creating test CA: %v", err)
	}
	certBuf := bytes.Buffer{}
	err = pem.Encode(&certBuf, &pem.Block{Type: cert.CertificateBlockType, Bytes: caDer})
	if err != nil {
		t.Fatalf("error encoding test CA pem: %v", err)
	}
	keyBuf := bytes.Buffer{}
	err = pem.Encode(&keyBuf, &pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		t.Fatalf("error encoding test CA key: %v", err)
	}
	secret := &v1.Secret{
		Data: map[string][]byte{
			v1.TLSCertKey:       certBuf.Bytes(),
			v1.TLSPrivateKeyKey: keyBuf.Bytes(),
		},
	}
	_, _, err = resourceapply.ApplySecret(client.CoreV1(), events.NewInMemoryRecorder("test"), secret)
	if err != nil {
		t.Fatalf("error updating secret with test CA: %v", err)
	}
}

func pollForServiceCert(t *testing.T, client *kubernetes.Clientset, namespace, name string, oldCertValue, oldKeyValue []byte) ([]byte, []byte, error) {
	resourceID := fmt.Sprintf("Secret \"%s/%s\"", namespace, name)
	expectedDataSize := 2
	obj, err := pollForResource(t, resourceID, func() (pkgruntime.Object, error) {
		secret, err := client.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if len(secret.Data) != expectedDataSize {
			return nil, fmt.Errorf("expected data size %d, got %d", expectedDataSize, len(secret.Data))
		}
		certValue, ok := secret.Data[v1.TLSCertKey]
		if !ok {
			return nil, fmt.Errorf("key %q is missing", v1.TLSCertKey)
		}
		if bytes.Equal(certValue, oldCertValue) {
			return nil, fmt.Errorf("value for key %q has not changed", v1.TLSCertKey)
		}
		keyValue, ok := secret.Data[v1.TLSPrivateKeyKey]
		if !ok {
			return nil, fmt.Errorf("key %q is missing", v1.TLSPrivateKeyKey)
		}
		if bytes.Equal(keyValue, oldKeyValue) {
			return nil, fmt.Errorf("value for key %q has not changed", v1.TLSPrivateKeyKey)
		}
		return secret, nil
	})
	if err != nil {
		return nil, nil, err
	}
	secret := obj.(*v1.Secret)
	return secret.Data[v1.TLSCertKey], secret.Data[v1.TLSPrivateKeyKey], nil

}

func pollForCABundle(t *testing.T, client *kubernetes.Clientset, namespace, name string, oldValue []byte) ([]byte, error) {
	resourceID := fmt.Sprintf("ConfigMap \"%s/%s\"", namespace, name)
	expectedDataSize := 1
	obj, err := pollForResource(t, resourceID, func() (pkgruntime.Object, error) {
		configMap, err := client.CoreV1().ConfigMaps(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if len(configMap.Data) != expectedDataSize {
			return nil, fmt.Errorf("expected data size %d, got %d", expectedDataSize, len(configMap.Data))
		}
		value, ok := configMap.Data[api.InjectionDataKey]
		if !ok {
			return nil, fmt.Errorf("key %q is missing", api.InjectionDataKey)
		}
		if value == string(oldValue) {
			return nil, fmt.Errorf("value for key %q has not changed", api.InjectionDataKey)
		}
		return configMap, nil
	})
	if err != nil {
		return nil, err
	}
	configMap := obj.(*v1.ConfigMap)
	return []byte(configMap.Data[api.InjectionDataKey]), nil
}

func pollForResource(t *testing.T, resourceID string, accessor func() (pkgruntime.Object, error)) (pkgruntime.Object, error) {
	var obj pkgruntime.Object
	err := wait.PollImmediate(pollInterval, pollTimeout, func() (bool, error) {
		o, err := accessor()
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			t.Logf("an error occurred while polling for %s: %v", resourceID, err)
			return false, nil
		}
		obj = o
		return true, nil
	})
	return obj, err
}

func checkClientTrust(t *testing.T, certPEM, keyPEM, bundlePEM []byte) {
	// Emulate how a service will consume the serving cert by writing
	// the cert and key to disk.
	certFile, err := ioutil.TempFile("", v1.TLSCertKey)
	if err != nil {
		t.Fatalf("error creating tmpfile for cert: %v", err)

	}
	defer os.Remove(certFile.Name())
	certFile.Write(certPEM)

	keyFile, err := ioutil.TempFile("", v1.TLSPrivateKeyKey)
	if err != nil {
		t.Fatalf("error creating tmpfile for key: %v", err)

	}
	defer os.Remove(keyFile.Name())
	keyFile.Write(keyPEM)

	// The need to listen on a random port precludes the use of
	// ListenAndServeTLS since that method provides no way to
	// determine the port that the server ends up listenting
	// on. Creating a listener and using ServeTLS instead ensures a
	// random port will be allocated (by specifying ':0') and that the
	// resulting port is discoverable via the listener's Addr()
	// method.
	listenerAddress := "127.0.0.1:0"
	ln, err := net.Listen("tcp", listenerAddress)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	serverAddress := ln.Addr().String()

	srv := http.Server{}
	// Start a server configured with the cert and key
	go func() {
		if err := srv.ServeTLS(ln, certFile.Name(), keyFile.Name()); err != nil && err != http.ErrServerClosed {
			t.Fatalf("ServeTLS failed: %v", err)
		}
	}()
	defer func() {
		err = srv.Close()
		if err != nil {
			t.Fatalf("tls server close failed: %v", err)
		}
	}()

	// Make a client connection configured with the provided bundle.
	// A client is expected to consume PEM content from a file, but
	// there would be little value in writing the bundle to disk ad
	// reading it back.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(bundlePEM)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}
	clientAddress := fmt.Sprintf("https://%s", serverAddress)
	_, err = client.Get(clientAddress)
	if err != nil {
		t.Fatalf("Failed to receive output: %v", err)
	}
	// No error indicates that validation was successful
}

// func serverCertFromSecret(secret *v1.Secret) (*crypto.TLSCertificateConfig, error) {
// 	// Create certificates from the cert PEM
// 	certPEM, ok := secret.Data[v1.TLSCertKey]
// 	if !ok {
// 		return nil, fmt.Errorf("%q not found", v1.TLSCertKey)
// 	}
// 	certASN1, err := pemToASN1(certPEM)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to convert cert: %v", err)
// 	}
// 	certs, err := x509.ParseCertificates(certASN1)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse certificates: %v", err)
// 	}

// 	// Create private key from key PEM
// 	keyPEM, ok := secret.Data[v1.TLSPrivateKeyKey]
// 	if !ok {
// 		return nil, fmt.Errorf("%q not found", v1.TLSPrivateKeyKey)
// 	}
// 	// At most one key is expected
// 	keyBlock, rest := pem.Decode(keyPEM)
// 	if keyBlock == nil {
// 		return nil, fmt.Errorf("key PEM not parsed")
// 	}
// 	if len(rest) > 0 {
// 		return nil, fmt.Errorf("key PEM has trailing data")
// 	}
// 	key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse key: %v", err)
// 	}

// 	return &crypto.TLSCertificateConfig{
// 		Certs: certs,
// 		Key:   key,
// 	}, nil
// }

// func pemToASN1(pemData []byte) ([]byte, error) {
// 	asn1Data := []byte{}
// 	rest := pemData
// 	for {
// 		var block *pem.Block
// 		block, rest = pem.Decode(rest)
// 		if block == nil {
// 			return nil, fmt.Errorf("PEM not parsed")
// 		}
// 		asn1Data = append(asn1Data, block.Bytes...)
// 		if len(rest) == 0 {
// 			break
// 		}
// 	}
// 	return asn1Data, nil
// }

/*
	namePrefix := "e2e-rotate-CA-"

	// Create test namespace
	ns, err := client.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: namePrefix,
		},
	})
	if err != nil {
		t.Fatalf("failed to create test namespace: %v", err)
	}
	namespace := ns.Namespace

	// Create annotated service to prompt creation of a cert secret
	service, err := client.CoreV1().Services(namespace).Create(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: namePrefix,
		},
	})
	if err != nil {
		t.Fatalf("failed to create configmap service: %v", err)
	}
	secretName := service.Name
	service.ObjectMeta.Annotations = map[string]string{
		api.ServingCertSecretAnnotation: secretName,
	}
	_, err := client.CoreV1().Services(namespace).Update(service)
	if err != nil {
		t.Fatalf("failed to update service with annotation: %v", err)
	}

	// Create annotated configmap to prompt injection of the ca bundle.
	configMap, err := client.CoreV1().Configmaps(namespace).Create(&v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: namePrefix,
		},
	})
	if err != nil {
		t.Fatalf("failed to create configmap service: %v", err)
	}
	configmMapName := configMap.Name
	configMap.ObjectMeta.Annotations = map[string]string{
		api.InjectCABundleAnnotationName: "true",
	}
	_, err := client.CoreV1().ConfigMaps(namespace).Update(configMap)
	if err != nil {
		t.Fatalf("failed to update configmap with annotation: %v", err)
	}
*/
