/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package huaweicloud

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/hashicorp/golang-lru"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/cloud-provider"
	"k8s.io/klog"

	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/cloudprovider/huaweicloud/wrapper"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/config"
)

// Cloud provider name: PaaS Web Services.
const (
	ProviderName      = "huaweicloud"
	providerNamespace = "huawei-cloud-provider"

	ElbClass           = "kubernetes.io/elb.class"
	ElbID              = "kubernetes.io/elb.id"
	ElbConnectionLimit = "kubernetes.io/elb.connection-limit"

	ElbSubnetID          = "kubernetes.io/elb.subnet-id"
	ElbEipID             = "kubernetes.io/elb.eip-id"
	ELBKeepEip           = "kubernetes.io/elb.keep-eip"
	AutoCreateEipOptions = "kubernetes.io/elb.eip-auto-create-options"

	ElbAlgorithm             = "kubernetes.io/elb.lb-algorithm"
	ElbSessionAffinityMode   = "kubernetes.io/elb.session-affinity-mode"
	ElbSessionAffinityOption = "kubernetes.io/elb.session-affinity-options"

	ElbHealthCheck        = "kubernetes.io/elb.health-check-flag"
	ElbHealthCheckOptions = "kubernetes.io/elb.health-check-options"

	ElbXForwardedFor = "kubernetes.io/elb.x-forwarded-for"

	NodeSubnetIDLabelKey = "node.kubernetes.io/subnetid"
	ELBMarkAnnotation    = "kubernetes.io/elb.mark"

	MaxRetry   = 3
	HealthzCCE = "cce-healthz"
	// Attention is a warning message that intended to set to auto-created instance, such as ELB listener.
	Attention = "It is auto-generated by cloud-provider-huaweicloud, do not modify!"

	ELBSessionNone      = ""
	ELBSessionSourceIP  = "SOURCE_IP"
	ELBPersistenTimeout = "persistence_timeout"

	ELBSessionSourceIPDefaultTimeout = 60
	ELBSessionSourceIPMinTimeout     = 1
	ELBSessionSourceIPMaxTimeout     = 60
)

type ELBProtocol string
type ELBAlgorithm string

type LBConfig struct {
	// Deprecated: no longer in use
	Apiserver    string       `json:"apiserver"`
	SecretName   string       `json:"secretName"`
	SignerType   string       `json:"signerType"`
	ELBAlgorithm ELBAlgorithm `json:"elbAlgorithm"`
	TenantId     string       `json:"tenantId"` // nolint:golint // struct field `TenantId` should be `TenantID` (golint)
	Region       string       `json:"region"`
	VPCId        string       `json:"vpcId"`
	SubnetId     string       `json:"subnetId"` // nolint:golint //struct field `SubnetId` should be `SubnetID` (golint)
	// Deprecated: We are going to move this ECSEndpoint to CloudConfig.Auth.
	// During the transition, you need to specify the same ECS endpoint both here and CloudConfig.Auth.ECSEndpoint.
	ECSEndpoint      string `json:"ecsEndpoint"`
	ELBEndpoint      string `json:"elbEndpoint"`
	ALBEndpoint      string `json:"albEndpoint"`
	GLBEndpoint      string `json:"plbEndpoint"`
	NATEndpoint      string `json:"natEndpoint"`
	VPCEndpoint      string `json:"vpcEndpoint"`
	EnterpriseEnable string `json:"enterpriseEnable"`
}

/*
type Secret struct {
	Data struct {
		Credential string `json:"security.credential"`
	} `json:"data"`
}
*/

// Secret is a temporary solution for both support 'Permanent Security Credentials' and 'Temporary Security Credentials'.
// TODO(RainbowMango): Refactor later by a graceful way.
type Secret struct {
	Credential    string `json:"security.credential,omitempty"`
	AccessKey     string `json:"access,omitempty"`
	SecretKey     string `json:"secret,omitempty"`
	base64Decoded bool   `json:"-"`
}

// DecodeBase64 will decode all necessary fields with base64.
// TODO(RainbowMango): If decode partially success means some fields has been decoded and overwritten.
// Just limit this issue here and deal with it later with refactor actions.
func (s *Secret) DecodeBase64() error {
	if s.base64Decoded {
		panic("secret can not be decod twice")
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(s.Credential)
	if err != nil {
		klog.Errorf("Decode credential failed. error: %v", err)
		return fmt.Errorf("secret access key format is unexpected, %v", err)
	}
	s.Credential = string(decodedBytes)

	decodedBytes, err = base64.StdEncoding.DecodeString(s.AccessKey)
	if err != nil {
		klog.Errorf("Decode access key failed. error: %v", err)
		return fmt.Errorf("secret credential format is unexpected, %v", err)
	}
	s.AccessKey = string(decodedBytes)

	decodedBytes, err = base64.StdEncoding.DecodeString(s.SecretKey)
	if err != nil {
		klog.Errorf("Decode secret key failed. error: %v", err)
		return fmt.Errorf("secret secret key format is unexpected, %v", err)
	}
	s.SecretKey = string(decodedBytes)

	s.base64Decoded = true

	return nil
}

// SecurityCredential represents 'Temporary Security Credentials'.
type SecurityCredential struct {
	AccessKey     string    `json:"access"`
	SecretKey     string    `json:"secret"`
	SecurityToken string    `json:"securitytoken"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Basic struct {
	cloudConfig        *config.CloudConfig
	loadBalancerConfig *config.LoadbalancerConfig //nolint: unused

	loadbalancerOpts *config.LoadBalancerOptions
	networkingOpts   *config.NetworkingOptions
	metadataOpts     *config.MetadataOptions

	sharedELBClient *wrapper.SharedLoadBalanceClient
	eipClient       *wrapper.EIpClient
	ecsClient       *wrapper.EcsClient

	kubeClient    *corev1.CoreV1Client
	eventRecorder record.EventRecorder
}

func (b Basic) listPodsBySelector(ctx context.Context, namespace string, selectors map[string]string) (*v1.PodList, error) {
	labelSelector := labels.SelectorFromSet(selectors)
	opts := metav1.ListOptions{LabelSelector: labelSelector.String()}
	return b.kubeClient.Pods(namespace).List(ctx, opts)
}

type CloudProvider struct {
	Basic
	providers map[LoadBalanceVersion]cloudprovider.LoadBalancer
}

type LoadBalanceVersion int

const (
	VersionNotNeedLB LoadBalanceVersion = iota // if the service type is not LoadBalancer
	VersionELB                                 // classic load balancer
	VersionShared                              // enhanced load balancer(performance share)
	VersionPLB                                 // enhanced load balancer(performance guarantee)
	VersionNAT                                 // network address translation
)

func init() {
	cloudprovider.RegisterCloudProvider(ProviderName, func(config io.Reader) (cloudprovider.Interface, error) {
		hwsCloud, err := NewHWSCloud(config)
		if err != nil {
			return nil, err
		}
		return hwsCloud, nil
	})
}

func parseOlderCloudConfig(globalConfig *config.CloudConfig) *CloudConfig {
	gConfig := &CloudConfig{
		Auth: AuthOpts{
			SecretName:  "",
			AccessKey:   globalConfig.AuthOpts.AccessKey,
			SecretKey:   globalConfig.AuthOpts.SecretKey,
			IAMEndpoint: fmt.Sprintf("https://iam.%s:443/v3", globalConfig.AuthOpts.Cloud),
			ECSEndpoint: fmt.Sprintf("https://ecs.%s.%s", globalConfig.AuthOpts.Region, globalConfig.AuthOpts.Cloud),
			ProjectID:   globalConfig.AuthOpts.ProjectID,
			Region:      globalConfig.AuthOpts.Region,
			Cloud:       globalConfig.AuthOpts.Cloud,
			DomainID:    "",
		},
		LoadBalancer: LBConfig{
			Apiserver:        "",
			SecretName:       "huaweicloud-auth-credentials",
			SignerType:       "ec2",
			ELBAlgorithm:     "ROUND_ROBIN",
			TenantId:         globalConfig.AuthOpts.ProjectID,
			Region:           globalConfig.AuthOpts.Region,
			VPCId:            globalConfig.VpcOpts.ID,
			SubnetId:         globalConfig.VpcOpts.SubnetID,
			ECSEndpoint:      fmt.Sprintf("https://ecs.%s.%s", globalConfig.AuthOpts.Region, globalConfig.AuthOpts.Cloud),
			ELBEndpoint:      fmt.Sprintf("https://elb.%s.%s", globalConfig.AuthOpts.Region, globalConfig.AuthOpts.Cloud),
			ALBEndpoint:      fmt.Sprintf("https://elb.%s.%s", globalConfig.AuthOpts.Region, globalConfig.AuthOpts.Cloud),
			GLBEndpoint:      "",
			NATEndpoint:      fmt.Sprintf("https://nat.%s.%s", globalConfig.AuthOpts.Region, globalConfig.AuthOpts.Cloud),
			VPCEndpoint:      fmt.Sprintf("https://vpc.%s.%s", globalConfig.AuthOpts.Region, globalConfig.AuthOpts.Cloud),
			EnterpriseEnable: "",
		},
	}

	return gConfig
}

func NewHWSCloud(cfg io.Reader) (*CloudProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("huaweicloud provider config is nil")
	}

	cloudConfig, err := config.ReadConfig(cfg)
	if err != nil {
		klog.Fatalf("failed to read AuthOpts CloudConfig: %v", err)
		return nil, err
	}

	elbCfg, err := config.LoadElbConfigFromCM()
	if err != nil {
		klog.Errorf("failed to read loadbalancer config: %v", err)
	}

	klog.Infof("get loadbalancer config: %#v", elbCfg)
	if elbCfg == nil {
		elbCfg = config.NewDefaultELBConfig()
	}

	kubeClient, err := newKubeClient()
	if err != nil {
		return nil, err
	}

	gConfig := parseOlderCloudConfig(cloudConfig)
	LogConf(gConfig)

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&corev1.EventSinkImpl{Interface: corev1.New(kubeClient.RESTClient()).Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "hws-cloudprovider"})
	lrucache, err := lru.New(200)
	if err != nil {
		return nil, err
	}

	secretInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return kubeClient.Secrets(metav1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return kubeClient.Secrets(metav1.NamespaceAll).Watch(context.TODO(), options)
			},
		},
		&v1.Secret{},
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	secretInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			kubeSecret := obj.(*v1.Secret)
			if kubeSecret.Name == gConfig.LoadBalancer.SecretName {
				key := kubeSecret.Namespace + "/" + kubeSecret.Name
				lrucache.Add(key, kubeSecret)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldSecret := oldObj.(*v1.Secret)
			newSecret := newObj.(*v1.Secret)
			if newSecret.Name == gConfig.LoadBalancer.SecretName {
				if reflect.DeepEqual(oldSecret.Data, newSecret.Data) {
					return
				}
				key := newSecret.Namespace + "/" + newSecret.Name
				lrucache.Add(key, newSecret)
			}
		},
		DeleteFunc: func(obj interface{}) {
			deleteSecret(obj, lrucache, gConfig.LoadBalancer.SecretName)
		},
	}, 30*time.Second)

	go secretInformer.Run(nil)

	if !cache.WaitForCacheSync(nil, secretInformer.HasSynced) {
		klog.Errorf("failed to wait for CloudProvider to be synced")
	}

	basic := Basic{
		cloudConfig: cloudConfig,

		loadbalancerOpts: &elbCfg.LoadBalancerOpts,
		networkingOpts:   &elbCfg.NetworkingOpts,
		metadataOpts:     &elbCfg.MetadataOpts,

		sharedELBClient: &wrapper.SharedLoadBalanceClient{AuthOpts: &cloudConfig.AuthOpts},
		eipClient:       &wrapper.EIpClient{AuthOpts: &cloudConfig.AuthOpts},
		ecsClient:       &wrapper.EcsClient{AuthOpts: &cloudConfig.AuthOpts},

		kubeClient:    kubeClient,
		eventRecorder: recorder,
	}

	hws := &CloudProvider{
		Basic:     basic,
		providers: map[LoadBalanceVersion]cloudprovider.LoadBalancer{},
	}

	hws.providers[VersionELB] = &ELBCloud{Basic: basic, lrucache: lrucache, config: &gConfig.LoadBalancer}
	hws.providers[VersionShared] = &SharedLoadBalancer{Basic: basic}
	// TODO(RainbowMango): Support PLB later.
	// hws.providers[VersionPLB] = &PLBCloud{lrucache: lrucache, config: &gConfig.LoadBalancer, kubeClient: kubeClient, clientPool: deprecateddynamic.NewDynamicClientPool(clientConfig), eventRecorder: recorder, subnetMap: map[string]string{}}
	hws.providers[VersionNAT] = &NATCloud{Basic: basic, lrucache: lrucache, config: &gConfig.LoadBalancer}

	return hws, nil
}

func newKubeClient() (*corev1.CoreV1Client, error) {
	clusterCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("initial cluster configuration failed with error: %v", err)
	}

	kubeClient, err := corev1.NewForConfig(clusterCfg)
	if err != nil {
		return nil, fmt.Errorf("create kubeClient failed with error: %v", err)
	}
	return kubeClient, nil
}

func (h *CloudProvider) GetLoadBalancer(ctx context.Context, clusterName string, service *v1.Service) (status *v1.LoadBalancerStatus, exists bool, err error) {
	LBVersion, err := getLoadBalancerVersion(service)
	if err != nil {
		return nil, false, err
	}

	provider, exist := h.providers[LBVersion]
	if !exist {
		return nil, false, nil
	}

	return provider.GetLoadBalancer(ctx, clusterName, service)
}

func (h *CloudProvider) GetLoadBalancerName(ctx context.Context, clusterName string, service *v1.Service) string {
	LBVersion, err := getLoadBalancerVersion(service)
	if err != nil {
		return ""
	}

	provider, exist := h.providers[LBVersion]
	if !exist {
		return ""
	}

	return provider.GetLoadBalancerName(ctx, clusterName, service)
}

func (h *CloudProvider) EnsureLoadBalancer(ctx context.Context, clusterName string, service *v1.Service, nodes []*v1.Node) (*v1.LoadBalancerStatus, error) {
	LBVersion, err := getLoadBalancerVersion(service)
	if err != nil {
		return nil, err
	}

	provider, exist := h.providers[LBVersion]
	if !exist {
		return nil, nil
	}

	return provider.EnsureLoadBalancer(ctx, clusterName, service, nodes)
}

func (h *CloudProvider) UpdateLoadBalancer(ctx context.Context, clusterName string, service *v1.Service, nodes []*v1.Node) error {
	LBVersion, err := getLoadBalancerVersion(service)
	if err != nil {
		return err
	}

	provider, exist := h.providers[LBVersion]
	if !exist {
		return nil
	}

	return provider.UpdateLoadBalancer(ctx, clusterName, service, nodes)
}

func (h *CloudProvider) EnsureLoadBalancerDeleted(ctx context.Context, clusterName string, service *v1.Service) error {
	LBVersion, err := getLoadBalancerVersion(service)
	if err != nil {
		return err
	}

	provider, exist := h.providers[LBVersion]
	if !exist {
		return nil
	}

	return provider.EnsureLoadBalancerDeleted(ctx, clusterName, service)
}

func getLoadBalancerVersion(service *v1.Service) (LoadBalanceVersion, error) {
	class := service.Annotations[ElbClass]

	switch class {
	case "elasticity":
		klog.Infof("Load balancer Version I for service %v", service.Name)
		return VersionELB, nil
	case "union", "":
		klog.Infof("Load balancer Version II for service %v", service.Name)
		return VersionShared, nil
	case "performance":
		klog.Infof("Load balancer Version III for service %v", service.Name)
		return VersionPLB, nil
	case "dnat":
		klog.Infof("DNAT for service %v", service.Name)
		return VersionNAT, nil
	default:
		return 0, fmt.Errorf("Load balancer version unknown")
	}
}

// type Instances interface {}

// ExternalID returns the cloud provider ID of the specified instance (deprecated).
func (h *CloudProvider) ExternalID(ctx context.Context, instance types.NodeName) (string, error) {
	return "", cloudprovider.NotImplemented
}

// type Routes interface {}

// ListRoutes is an implementation of Routes.ListRoutes
func (h *CloudProvider) ListRoutes(ctx context.Context, clusterName string) ([]*cloudprovider.Route, error) {
	return nil, nil
}

// CreateRoute is an implementation of Routes.CreateRoute
func (h *CloudProvider) CreateRoute(ctx context.Context, clusterName string, nameHint string, route *cloudprovider.Route) error {
	return nil
}

// DeleteRoute is an implementation of Routes.DeleteRoute
func (h *CloudProvider) DeleteRoute(ctx context.Context, clusterName string, route *cloudprovider.Route) error {
	return nil
}

// type Zones interface {}

// GetZone is an implementation of Zones.GetZone
func (h *CloudProvider) GetZone(ctx context.Context) (cloudprovider.Zone, error) {
	return cloudprovider.Zone{}, nil
}

// GetZoneByProviderID returns the Zone containing the current zone and locality region of the node specified by providerId
// This method is particularly used in the context of external cloud providers where node initialization must be down
// outside the kubelets.
func (h *CloudProvider) GetZoneByProviderID(ctx context.Context, providerID string) (cloudprovider.Zone, error) {
	return cloudprovider.Zone{}, nil
}

// GetZoneByNodeName returns the Zone containing the current zone and locality region of the node specified by node name
// This method is particularly used in the context of external cloud providers where node initialization must be down
// outside the kubelets.
func (h *CloudProvider) GetZoneByNodeName(ctx context.Context, nodeName types.NodeName) (cloudprovider.Zone, error) {
	return cloudprovider.Zone{}, nil
}

// HasClusterID returns true if the cluster has a clusterID
func (h *CloudProvider) HasClusterID() bool {
	return true
}

// Initialize provides the cloud with a kubernetes client builder and may spawn goroutines
// to perform housekeeping activities within the cloud provider.
func (h *CloudProvider) Initialize(clientBuilder cloudprovider.ControllerClientBuilder, stop <-chan struct{}) {
}

// TCPLoadBalancer returns an implementation of TCPLoadBalancer for Huawei Web Services.
func (h *CloudProvider) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return h, true
}

// Instances returns an instances interface. Also returns true if the interface is supported, false otherwise.
func (h *CloudProvider) Instances() (cloudprovider.Instances, bool) {
	instance := &Instances{
		Basic: h.Basic,
	}

	return instance, true
}

// Zones returns an implementation of Zones for Huawei Web Services.
func (h *CloudProvider) Zones() (cloudprovider.Zones, bool) {
	return h, true
}

// Clusters returns an implementation of Clusters for Huawei Web Services.
func (h *CloudProvider) Clusters() (cloudprovider.Clusters, bool) {
	return h, true
}

// Routes returns an implementation of Routes for Huawei Web Services.
func (h *CloudProvider) Routes() (cloudprovider.Routes, bool) {
	return h, true
}

// ProviderName returns the cloud provider ID.
func (h *CloudProvider) ProviderName() string {
	return ProviderName
}

// InstancesV2 is an implementation for instances and should only be implemented by external cloud providers.
// Don't support this feature for now.
func (h *CloudProvider) InstancesV2() (cloudprovider.InstancesV2, bool) {
	instance := &Instances{
		Basic: h.Basic,
	}

	return instance, true
}

// ListClusters is an implementation of Clusters.ListClusters
func (h *CloudProvider) ListClusters(ctx context.Context) ([]string, error) {
	return nil, nil
}

// Master is an implementation of Clusters.Master
func (h *CloudProvider) Master(ctx context.Context, clusterName string) (string, error) {
	return "", nil
}

//util functions

func deleteSecret(obj interface{}, lrucache *lru.Cache, secretName string) {
	kubeSecret, ok := obj.(*v1.Secret)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %#v", obj)
			return
		}
		kubeSecret, ok = tombstone.Obj.(*v1.Secret)
		if !ok {
			klog.Errorf("Tombstone contained object that is not a secret %#v", obj)
			return
		}
	}

	if kubeSecret.Name == secretName {
		key := kubeSecret.Namespace + "/" + kubeSecret.Name
		lrucache.Add(key, kubeSecret)
	}
}

func IsPodActive(p v1.Pod) bool {
	if v1.PodSucceeded != p.Status.Phase &&
		v1.PodFailed != p.Status.Phase &&
		p.DeletionTimestamp == nil {
		for _, c := range p.Status.Conditions {
			if c.Type == v1.PodReady && c.Status == v1.ConditionTrue {
				return true
			}
		}
	}
	return false
}

func sendEvent(eventRecorder record.EventRecorder, title, msg string, service *v1.Service) {
	klog.Errorf("[%s/%s]%s", service.Namespace, service.Name, msg)
	eventRecorder.Event(service, v1.EventTypeWarning, title, fmt.Sprintf("Details: %s", msg))
}
