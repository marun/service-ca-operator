package cabundleinjector

import (
	"fmt"
	"io/ioutil"
	"time"

	"monis.app/go/openshift/controller"

	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	scsv1alpha1 "github.com/openshift/api/servicecertsigner/v1alpha1"
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
	config := &scsv1alpha1.CABundleInjectorConfig{}
	if ctx.ComponentConfig != nil {
		// make a copy we can mutate
		configCopy := ctx.ComponentConfig.DeepCopy()
		// force the config to our version to read it
		configCopy.SetGroupVersionKind(scsv1alpha1.GroupVersion.WithKind("CABundleInjectorConfig"))
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(configCopy.Object, config); err != nil {
			return err
		}
	}

	if len(config.CABundleFile) == 0 {
		return fmt.Errorf("no CA bundle provided")
	}

	caBundleContent, err := ioutil.ReadFile(config.CABundleFile)
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
