package cabundleinjector

import (
	"fmt"
	"io/ioutil"
	"time"

	"monis.app/go/openshift/controller"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type caBundleInjectorConfig struct {
	config        *rest.Config
	defaultResync time.Duration
	caBundle      []byte
	kubeClient    *kubernetes.Clientset
	kubeInformers kubeinformers.SharedInformerFactory
}

type startInformersFunc func(stopChan <-chan struct{})

type controllerConfig struct {
	name           string
	keySyncer      controller.KeySyncer
	informerGetter controller.InformerGetter
	startInformers startInformersFunc
}

type configBuilderFunc func(config *caBundleInjectorConfig) controllerConfig

func StartCABundleInjector(ctx *controllercmd.ControllerContext) error {
	// TODO(marun) Detect and respond to changes in this path rather than
	// depending on the operator for redeployment
	caBundleFile := "/var/run/configmaps/signing-cabundle/ca-bundle.crt"

	caBundleContent, err := ioutil.ReadFile(caBundleFile)
	if err != nil {
		return err
	}

	client := kubernetes.NewForConfigOrDie(ctx.ProtoKubeConfig)
	defaultResync := 20 * time.Minute
	informers := kubeinformers.NewSharedInformerFactory(client, defaultResync)
	injectorConfig := &caBundleInjectorConfig{
		config:        ctx.ProtoKubeConfig,
		defaultResync: defaultResync,
		caBundle:      caBundleContent,
		kubeClient:    client,
		kubeInformers: informers,
	}

	configConstructors := []configBuilderFunc{
		newAPIServiceInjectorConfig,
		newConfigMapInjectorConfig,
	}
	controllerRunners := []controller.Runner{}
	for _, configConstructor := range configConstructors {
		ctlConfig := configConstructor(injectorConfig)
		controllerRunner := controller.New(ctlConfig.name, ctlConfig.keySyncer,
			controller.WithInformer(ctlConfig.informerGetter, controller.FilterFuncs{
				AddFunc:    api.HasInjectCABundleAnnotation,
				UpdateFunc: api.HasInjectCABundleAnnotationUpdate,
			}),
		)
		controllerRunners = append(controllerRunners, controllerRunner)

		// Start non-core informers
		if ctlConfig.startInformers != nil {
			ctlConfig.startInformers(ctx.Done())
		}
	}

	// Start core informers
	informers.Start(ctx.Done())

	// Start injector controllers once all informers have started
	for _, controllerRunner := range controllerRunners {
		go controllerRunner.Run(5, ctx.Done())
	}

	<-ctx.Done()

	return fmt.Errorf("stopped")
}
