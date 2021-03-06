package v1

import (
	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WebConsoleConfiguration holds the necessary configuration options for serving the web console
type WebConsoleConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// ServingInfo is the HTTP serving information for these assets
	ServingInfo configv1.HTTPServingInfo `json:"servingInfo"`

	// ClusterInfo holds information the web console needs to talk to the cluster such as master public URL
	// and metrics public URL
	ClusterInfo ClusterInfo `json:"clusterInfo"`

	// Features define various feature gates for the web console
	Features FeaturesConfiguration `json:"features"`

	// Extensions define custom scripts, stylesheets, and properties used for web console customization
	Extensions ExtensionsConfiguration `json:"extensions"`
}

// ClusterInfo holds information the web console needs to talk to the cluster such as master public URL and
// metrics public URL
type ClusterInfo struct {
	// ConsolePublicURL is where you can find the web console server (TODO do we really need this?)
	ConsolePublicURL string `json:"consolePublicURL"`

	// MasterPublicURL is how the web console can access the OpenShift v1 server
	MasterPublicURL string `json:"masterPublicURL"`

	// LoggingPublicURL is the public endpoint for logging (optional)
	LoggingPublicURL string `json:"loggingPublicURL"`

	// MetricsPublicURL is the public endpoint for metrics (optional)
	MetricsPublicURL string `json:"metricsPublicURL"`

	// LogoutPublicURL is an optional, absolute URL to redirect web browsers to after logging out of the web
	// console. If not specified, the built-in logout page is shown.
	LogoutPublicURL string `json:"logoutPublicURL"`

	// AdminConsolePublicURL is an optional, public URL of the OpenShift admin console. If specified, the web
	// console will add a link to the admin console in a context selector in its masthead.
	AdminConsolePublicURL string `json:"adminConsolePublicURL"`
}

// FeaturesConfiguration defines various feature gates for the web console
type FeaturesConfiguration struct {
	// InactivityTimeoutMinutes is the number of minutes of inactivity before you are automatically logged out of
	// the web console (optional). If set to 0, inactivity timeout is disabled.
	InactivityTimeoutMinutes int64 `json:"inactivityTimeoutMinutes"`

	// ClusterResourceOverridesEnabled indicates that the cluster is configured for overcommit. When set to
	// true, the web console will hide the CPU request, CPU limit, and memory request fields in its editors
	// and skip validation on those fields. The memory limit field will still be displayed.
	ClusterResourceOverridesEnabled bool `json:"clusterResourceOverridesEnabled"`
}

// ExtensionsConfiguration holds custom script, stylesheets, and properties used for web console customization
type ExtensionsConfiguration struct {
	// ScriptURLs are URLs to load as scripts when the Web Console loads. The URLs must be accessible from
	// the browser.
	ScriptURLs []string `json:"scriptURLs"`
	// StylesheetURLs are URLs to load as stylesheets when the Web Console loads. The URLs must be accessible
	// from the browser.
	StylesheetURLs []string `json:"stylesheetURLs"`
	// Properties are key(string) and value(string) pairs that will be injected into the console under the
	// global variable OPENSHIFT_EXTENSION_PROPERTIES
	Properties map[string]string `json:"properties"`
}
