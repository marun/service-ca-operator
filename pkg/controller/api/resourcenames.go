package api

// Common controller/operator resource names
const (
	// Config instance
	OperatorConfigInstanceName = "cluster"

	// ConfigMaps
	SignerControllerConfigMapName = "service-serving-cert-signer-config"
	CABundleInjectorConfigMapName = "cabundle-injector-config"
	SigningCABundleConfigMapName  = "signing-cabundle"

	// SAs
	SignerControllerSAName = "service-serving-cert-signer-sa"
	CABundleInjectorSAName = "cabundle-injector-sa"

	// Services
	SignerControllerServiceName = "service-serving-cert-signer"

	// Deployments
	SignerControllerDeploymentName = "service-serving-cert-signer"
	CABundleInjectorDeploymentName = "cabundle-injector"

	// Secrets
	SignerControllerSecretName = "signing-key"
)
