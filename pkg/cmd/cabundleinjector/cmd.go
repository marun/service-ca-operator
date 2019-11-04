package cabundleinjector

import (
	"github.com/spf13/cobra"

	"github.com/openshift/library-go/pkg/controller/controllercmd"

	"github.com/openshift/service-ca-operator/pkg/controller/cabundleinjector"
	"github.com/openshift/service-ca-operator/pkg/version"
)

const (
	componentName      = "cabundle-injector"
	componentNamespace = "openshift-service-ca"
)

func NewController() *cobra.Command {
	cmd := controllercmd.
		NewControllerCommandConfig(componentName, version.Get(), cabundleinjector.StartCABundleInjector).
		NewCommand()
	cmd.Use = "cabundle-injector"
	cmd.Short = "Start the CA Bundle Injection controller"
	return cmd
}
