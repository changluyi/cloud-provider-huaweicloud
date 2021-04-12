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

// nolint:golint // stop check lint issues as this file will be refactored
package huaweicloud

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
)

// ALBList represents a list of ALB.
type ALBList struct {
	Loadbalancers []ALB `json:"loadbalancers"`
}

// MemberList represents a list of ALBMember.
type MemberList struct {
	Members []ALBMember `json:"members"`
}

// ListenerList represents a list of ALBListener.
type ListenerList struct {
	Listeners []ALBListener `json:"listeners"`
}

// PoolList represents a list of ALBPool.
type PoolList struct {
	Pools []ALBPool `json:"pools"`
}

// HealthMonitorList represents a list of ALBHealthMonitor.
type HealthMonitorList struct {
	HealthMonitors []ALBHealthMonitor `json:"healthmonitors"`
}

// SubnetList represents a list of SubnetItem.
type SubnetList struct {
	Subnets []SubnetItem `json:"subnets"`
}

// ALBArr defines json style for compatibility with ALB API.
type ALBArr struct {
	Loadbalancer ALB `json:"loadbalancer"`
}

// MemberArr defines json style for ALBMember.
type MemberArr struct {
	Member ALBMember `json:"member"`
}

// ListenerArr defines json style for ALBListener.
type ListenerArr struct {
	Listener ALBListener `json:"listener"`
}

// PoolArr defines json style for ALBPool.
type PoolArr struct {
	Pool ALBPool `json:"pool"`
}

// HealthMonitorArr defines json style for ALBHealthMonitor.
type HealthMonitorArr struct {
	HealthMonitor ALBHealthMonitor `json:"healthmonitor"`
}

// ALB load balancer
type ALB struct {
	Id                  string             `json:"id,omitempty"`
	TenantId            string             `json:"tenant_id,omitempty"`
	Name                string             `json:"name,omitempty"`
	Description         string             `json:"description,omitempty"`
	VipSubnetId         string             `json:"vip_subnet_id,omitempty"`
	VipPortDd           string             `json:"vip_port_id,omitempty"`
	Provider            string             `json:"provider,omitempty"`    // support "vlb" only
	VipAddress          string             `json:"vip_address,omitempty"` // i.e. EIP/loadBalanceIP
	Listeners           []UUID             `json:"listeners,omitempty"`
	ProvisioningStatus  ELBProvisionStatus `json:"provisioning_status,omitempty"`
	OperatingStatus     ELBOperatingStatus `json:"operating_status,omitempty"`
	AdminStateUp        bool               `json:"admin_state_up,omitempty"`
	FlavorId            string             `json:"flavor_id,omitempty"`
	EnterpriseProjectId string             `json:"enterprise_project_id,omitempty"`
}

// ALBListener represents the listerner.
type ALBListener struct {
	Id                     string      `json:"id,omitempty"`
	TenantId               string      `json:"tenant_id,omitempty"`
	Name                   string      `json:"name,omitempty"`
	Description            string      `json:"description,omitempty"`
	Protocol               ELBProtocol `json:"protocol,omitempty"`
	ProtocolPort           int32       `json:"protocol_port,omitempty"`
	LoadbalancerId         string      `json:"loadbalancer_id,omitempty"`
	Loadbalancers          []UUID      `json:"loadbalancers,omitempty"`
	ConnectionLimit        int         `json:"connection_limit,omitempty"`
	AdminStateUp           bool        `json:"admin_state_up,omitempty"`
	DefaultPoolId          string      `json:"default_pool_id,omitempty"`
	DefaultTlsContainerRef string      `json:"default_tls_container_ref,omitempty"`
	SniContainerRefs       []string    `json:"sni_container_refs,omitempty"`
}

// ALBHealthMonitor implements the health monitor for ALB.
type ALBHealthMonitor struct {
	Id            string      `json:"id,omitempty"`
	TenantId      string      `json:"tenant_id,omitempty"`
	Name          string      `json:"name,omitempty"`
	Delay         int         `json:"delay,omitempty"`
	MaxRetries    int         `json:"max_retries,omitempty"` // [1, 10]
	Pools         []UUID      `json:"pools,omitempty"`
	PoolId        string      `json:"pool_id,omitempty"`
	AdminStateUp  bool        `json:"admin_state_up,omitempty"`
	Timeout       int         `json:"timeout,omitempty"`
	Type          ELBProtocol `json:"type,omitempty"` // TCP/HTTP
	ExpectedCodes string      `json:"expected_codes,omitempty"`
	UrlPath       string      `json:"url_path,omitempty"`
	HttpMethod    HTTPMethod  `json:"http_method,omitempty"`
	MonitorPort   *int        `json:"monitor_port"`
}

// ALBMember represents the backend host member
type ALBMember struct {
	Id              string       `json:"id,omitempty"`
	TenantId        string       `json:"tenant_id,omitempty"`
	Name            string       `json:"name,omitempty"`
	Address         string       `json:"address,omitempty"`       // IP address,e.g.192.168.3.11
	ProtocolPort    int32        `json:"protocol_port,omitempty"` // [1,65535]
	SubnetId        string       `json:"subnet_id,omitempty"`
	AdminStateUp    bool         `json:"admin_state_up,omitempty"` // has to be true
	Weight          int          `json:"weight,omitempty"`         // [0,256]
	OperatingStatus MemberStatus `json:"operating_status,omitempty"`
}

// ALBPool is an union of: loadbalance algorithm, load balancers, session_persistence, listeners, members, backend protocol and health monitor
// it only stores the id(s) of each object: load balancers, listeners, members and health monitor
type ALBPool struct {
	Id                 string                `json:"id,omitempty"`
	TenantId           string                `json:"tenant_id,omitempty"`
	Name               string                `json:"name,omitempty"`
	Description        string                `json:"description,omitempty"`
	Protocol           ELBProtocol           `json:"protocol,omitempty"`
	LbAlgorithm        ELBAlgorithm          `json:"lb_algorithm,omitempty"`
	Members            []UUID                `json:"members,omitempty"`
	HealthMonitorId    string                `json:"healthmonitor_id,omitempty"`
	AdminStateUp       bool                  `json:"admin_state_up,omitempty"`
	ListenerId         string                `json:"listener_id,omitempty"` // only used in creation
	Listeners          []UUID                `json:"listeners,omitempty"`   // multi-listeners not suggested
	SessionPersistence ELBSessionPersistence `json:"session_persistence"`
}

// ALBClient has two parts:
// ecsClient connect EcsEndpoint
// albClient connect albClient
type ALBClient struct {
	albClient *ServiceClient
	vpcClient *ServiceClient
	throttler *Throttler
	enableEPS string
}

// NewALBClient builds a new ALBClient.
func NewALBClient(albEndpoint, vpcEndpoint, id, accessKey, secretKey, securityToken, region, serviceType, enableEPS string) *ALBClient {
	access := &AccessInfo{
		AccessKey:     accessKey,
		SecretKey:     secretKey,
		SecurityToken: securityToken,
		Region:        region,
		ServiceType:   serviceType,
	}
	albClient := &ServiceClient{
		Client:   httpClient,
		Endpoint: albEndpoint,
		Access:   access,
		TenantId: id,
	}
	vpcClient := &ServiceClient{
		Client:   httpClient,
		Endpoint: vpcEndpoint,
		Access:   access,
		TenantId: id,
	}

	return &ALBClient{
		albClient: albClient,
		vpcClient: vpcClient,
		throttler: throttler,
		enableEPS: enableEPS,
	}
}

/*
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 *               ALB implement of functions regrding load balancers
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 */

// CreateLoadBalancer creates loadbalancer by conf.
func (a *ALBClient) CreateLoadBalancer(albConf *ALB) (*ALB, error) {
	var alb ALBArr
	alb.Loadbalancer = *albConf
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/loadbalancers"
	req := NewRequest(http.MethodPost, url, nil, &alb)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_INSTANCE_CREATE), req)
	if err != nil {
		return nil, err
	}

	var albResp ALBArr
	err = DecodeBody(resp, &albResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to CreateLoadalancer : %v", err)
	}
	return &(albResp.Loadbalancer), nil
}

// DeleteLoadBalancer deletes loadbalancer by ID.
func (a *ALBClient) DeleteLoadBalancer(loadbalancerID string) (int, error) {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/loadbalancers/" + loadbalancerID
	req := NewRequest(http.MethodDelete, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_INSTANCE_DELETE), req)
	if err != nil {
		return resp.StatusCode, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		resBody, _ := ioutil.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("Failed to DeleteLoadBalancer : %s, status code: %d", string(resBody), resp.StatusCode)
	}

	return resp.StatusCode, nil
}

// GetLoadBalancer gets loadbalancer by ID.
func (a *ALBClient) GetLoadBalancer(loadbalancerID string) (*ALB, error) {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/loadbalancers/" + loadbalancerID
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_INSTANCE_GET), req)
	if err != nil {
		return nil, err
	}

	var albResp ALBArr
	err = DecodeBody(resp, &albResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to GetLoadBalancer : %v", err)
	}

	return &(albResp.Loadbalancer), nil
}

// ListLoadBalancers list the loadbalancers by params.
func (a *ALBClient) ListLoadBalancers(params map[string]string) (*ALBList, error) {
	var query string

	if len(params) != 0 {
		query += "?"

		for key, value := range params {
			query += fmt.Sprintf("%s=%s&", key, value)
		}

		query = query[0 : len(query)-1]
	}

	url := fmt.Sprintf("%s/loadbalancers%s", generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId), query)
	klog.Infof("list LoadBalancer(%s)...", a.albClient.Endpoint+url)
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_INSTANCE_LIST), req)
	if err != nil {
		return nil, err
	}

	var albList ALBList
	err = DecodeBody(resp, &albList)
	if err != nil {
		return nil, fmt.Errorf("Failed to get ALBList : %v", err)
	}

	return &albList, nil
}

// CreateListener creates listeners via configuration.
// l connection_limit is allowed to be set by admin only
// 3 protocol TCP, HTTP and TERMINATED_HTTPS are supported
// 4 admin_state_up has to be true
// !!!!!MUST SET IN CREATION: protocol_port, protocol, loadbalancer_id!!!!!
func (a *ALBClient) CreateListener(listenerConf *ALBListener) (*ALBListener, error) {
	var ls ListenerArr
	ls.Listener = *listenerConf

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/listeners"
	req := NewRequest(http.MethodPost, url, nil, &ls)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_LISTENER_CREATE), req)
	if err != nil {
		return nil, err
	}

	var lsResp ListenerArr
	err = DecodeBody(resp, &lsResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to CreateListener : %v", err)
	}
	return &(lsResp.Listener), nil
}

// DeleteListener deletes listener by referencing ID.
// before deleting a listener, we have to remove all related pools in advance
func (a *ALBClient) DeleteListener(listenerID string) error {
	pool, err := a.findPoolOfListener(listenerID)
	if err != nil {
		return err
	}
	if pool != nil {
		return fmt.Errorf("Failed to delete listener %s: pool %s still exists", listenerID, pool.Id)
	}

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/listeners/" + listenerID
	req := NewRequest(http.MethodDelete, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_LISTENER_DELETE), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		resBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Failed to DeleteListener : %s, status code: %d", string(resBody), resp.StatusCode)
	}

	return nil
}

// GetListener gets the listener instance by listener ID
func (a *ALBClient) GetListener(listenerID string) (*ALBListener, error) {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/listeners/" + listenerID
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_LISTENER_GET), req)
	if err != nil {
		return nil, err
	}

	var lsResp ListenerArr
	err = DecodeBody(resp, &lsResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to GetListener : %v", err)
	}

	return &(lsResp.Listener), nil
}

// ListListeners lists listeners by params.
func (a *ALBClient) ListListeners(params map[string]string) (*ListenerList, error) {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/listeners"
	var query string
	if len(params) != 0 {
		query += "?"

		for key, value := range params {
			query += fmt.Sprintf("%s=%s&", key, value)
		}

		query = query[0 : len(query)-1]
	}

	url += query
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_LISTENER_LIST), req)
	if err != nil {
		return nil, err
	}

	var listenerList ListenerList
	err = DecodeBody(resp, &listenerList)
	if err != nil {
		return nil, fmt.Errorf("Failed to Get ListenersList : %v", err)
	}

	return &listenerList, nil
}

// UpdateListener updates listener.
// l connection_limit is allowed to be set by admin only
// 2 default_pool_id is supportted in the following ways:
//        (1) from specific default_pool_id to nil
//        (2) from nil to specific default_pool_id
// 3 default_pool_id cannot be a pool used by another listener
// !!!!! ONLY SUPPORT UPDATE: name, connection_limit, description, default_pool_id, default_tls_container_id !!!!!
func (a *ALBClient) UpdateListener(listenerMod *ALBListener, listenerID string) (*ALBListener, error) {
	var ls ListenerArr
	ls.Listener = *listenerMod

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/listeners/" + listenerID
	req := NewRequest(http.MethodPut, url, nil, &ls)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_LISTENER_UPDATE), req)
	if err != nil {
		return nil, err
	}

	var lsResp ListenerArr
	err = DecodeBody(resp, &lsResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to ModifyListener : %v", err)
	}

	return &(lsResp.Listener), nil
}

/*
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 *               ALB implement of functions regrding HealthMonitor
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 */

// CreateHealthMonitor creates health monitor.
// 1 100.125.0.0/16 should be open whtin safe group
// 2 admin_state_up has to be true
// !!!!! MUST SET IN CREATION: type, delay, timeout, max_retries, pool_id !!!!!
func (a *ALBClient) CreateHealthMonitor(healthConf *ALBHealthMonitor) (*ALBHealthMonitor, error) {
	var hm HealthMonitorArr
	hm.HealthMonitor = *healthConf

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/healthmonitors"
	req := NewRequest(http.MethodPost, url, nil, &hm)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_HEALTHZ_CREATE), req)
	if err != nil {
		return nil, err
	}

	var hmResp HealthMonitorArr
	err = DecodeBody(resp, &hmResp)
	if err != nil {
		return nil, fmt.Errorf("failed to CreateHealthMonitor : %v", err)
	}

	return &(hmResp.HealthMonitor), nil
}

// DeleteHealthMonitor deletes health monitor by ID.
func (a *ALBClient) DeleteHealthMonitor(healthMonitorID string) error {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/healthmonitors/" + healthMonitorID
	req := NewRequest(http.MethodDelete, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_HEALTHZ_DELETE), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		resBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete HealthMonitor : %s, status code: %d", string(resBody), resp.StatusCode)
	}

	return nil
}

// GetHealthMonitor gets health monitor by ID.
func (a *ALBClient) GetHealthMonitor(healthMonitorID string) (*ALBHealthMonitor, error) {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/healthmonitors/" + healthMonitorID
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_HEALTHZ_GET), req)
	if err != nil {
		return nil, err
	}

	var hmResp HealthMonitorArr
	err = DecodeBody(resp, &hmResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to GetHealthMonitor : %v", err)
	}

	return &(hmResp.HealthMonitor), nil
}

// UpdateHealthMonitor updates health monitor.
// !!!!! ONLY SUPPORT UPDATE: delay, max_retries, name, timeout, http_method, expected_codes, url_path !!!!!
func (a *ALBClient) UpdateHealthMonitor(healthMod *ALBHealthMonitor, healthMonitorID string) (*ALBHealthMonitor, error) {
	var hm HealthMonitorArr
	hm.HealthMonitor = *healthMod

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/healthmonitors/" + healthMonitorID
	req := NewRequest(http.MethodPut, url, nil, &hm)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_HEALTHZ_UPDATE), req)
	if err != nil {
		return nil, err
	}

	var hmResp HealthMonitorArr
	err = DecodeBody(resp, &hmResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to ModifyHealthMonitor : %v", err)
	}

	return &(hmResp.HealthMonitor), nil
}

/*
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 *               ALB implement of functions regrding Pools
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 */

// CreatePool creates pool by conf.
// 1 TCP & HTTP are supported only
// 2 admin_state_up has to be true
// !!!!! MUST SET IN CREATION: lb_algorithm, protocol, listener_id !!!!!
func (a *ALBClient) CreatePool(poolConf *ALBPool) (*ALBPool, error) {
	var pl PoolArr
	pl.Pool = *poolConf

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/pools"
	req := NewRequest(http.MethodPost, url, nil, &pl)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_POOL_CREATE), req)
	if err != nil {
		return nil, err
	}

	var plResp PoolArr
	err = DecodeBody(resp, &plResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to Create Pool : %v", err)
	}

	return &(plResp.Pool), nil
}

// DeletePool deletes a pool by ID.
// before deleting a pool, we have to remove all related members & healthmonitor in advance
func (a *ALBClient) DeletePool(poolID string) error {
	listMembers, err := a.ListMembers(poolID)
	if err != nil {
		return err
	}
	if len(listMembers.Members) != 0 {
		return fmt.Errorf("Failed to delete pool %s: members still exist", poolID)
	}

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/pools/" + poolID
	req := NewRequest(http.MethodDelete, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_POOL_DELETE), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		resBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Failed to delete pool : %s, status code: %d", string(resBody), resp.StatusCode)
	}

	return nil
}

// GetPool get pool by ID.
func (a *ALBClient) GetPool(poolID string) (*ALBPool, error) {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/pools/" + poolID
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_POOL_GET), req)
	if err != nil {
		return nil, err
	}

	var plResp PoolArr
	err = DecodeBody(resp, &plResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to GetPool : %v", err)
	}

	return &(plResp.Pool), nil
}

// UpdatePool updates pool.
// !!!!! ONLY SUPPORT UPDATE: lb_algorithm, session_persistence, name, description !!!!!
func (a *ALBClient) UpdatePool(poolMod *ALBPool, poolID string) (*ALBPool, error) {
	var pl PoolArr
	pl.Pool = *poolMod

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/pools/" + poolID
	req := NewRequest(http.MethodPut, url, nil, &pl)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_POOL_UPDATE), req)
	if err != nil {
		return nil, err
	}

	var plResp PoolArr
	err = DecodeBody(resp, &plResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to UpdatePool : %v", err)
	}

	return &(plResp.Pool), nil
}

func (a *ALBClient) listPools() (*PoolList, error) {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/pools"
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_POOL_LIST), req)
	if err != nil {
		return nil, err
	}

	var poolList PoolList
	err = DecodeBody(resp, &poolList)
	if err != nil {
		return nil, fmt.Errorf("Failed to Get listPools : %v", err)
	}

	return &poolList, nil
}

/*
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 *               ALB implement of functions regrding members
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 */

// AddMember adds a member.
// 1 differs from elb, which register a host to a listener directly
//         (see.RegisterInstancesWithListener() in file elb.go)
//         alb add a host to a pool, rather than to a listener
// 2 each pool belongs to a specific listener
// 3 in a 4-level load balancer, one listener has one  pool only
// 4 only one host is allowed to be added in each request
// 5 admin_state_up has to be true
// 6 the subset of the member should be same as the ELB
// !!!!! MUST SET IN CREATION: address, protocol_port, subnet_id !!!!!
func (a *ALBClient) AddMember(poolID string, memberConf *ALBMember) (*ALBMember, error) {
	var mem MemberArr
	mem.Member = *memberConf

	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/pools/" + poolID + "/members"
	req := NewRequest(http.MethodPost, url, nil, &mem)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_MEMBER_CREATE), req)
	if err != nil {
		klog.Warningf("Add member to pool failed. pool: %s, member: %s, error: %v", poolID, memberConf.Name, err)
		return nil, err
	}

	var memResp MemberArr
	err = DecodeBody(resp, &memResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to AddMembers : %v", err)
	}

	return &(memResp.Member), nil
}

// DeleteMember deletes a member.
func (a *ALBClient) DeleteMember(poolId string, memberID string) error {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/pools/" + poolId + "/members/" + memberID
	req := NewRequest(http.MethodDelete, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_MEMBER_DELETE), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		resBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Failed to delete member : %s, status code: %d", string(resBody), resp.StatusCode)
	}

	return nil
}

// ListMembers lists members.
func (a *ALBClient) ListMembers(poolID string) (*MemberList, error) {
	url := generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId) + "/pools/" + poolID + "/members"
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_MEMBER_LIST), req)
	if err != nil {
		return nil, err
	}

	var memberList MemberList
	err = DecodeBody(resp, &memberList)
	if err != nil {
		return nil, fmt.Errorf("failed to ListMembers : %v", err)
	}

	return &memberList, nil
}

// GetMember gets member.
func (a *ALBClient) GetMember(poolID, memberID string) (*MemberArr, error) {
	url := fmt.Sprintf("%s/pools/%s/members/%s", generateELBRoutePrefix(a.enableEPS, a.albClient.TenantId), poolID, memberID)
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.albClient, a.throttler.GetThrottleByKey(ELB_MEMBER_GET), req)
	if err != nil {
		return nil, err
	}

	var member MemberArr
	err = DecodeBody(resp, &member)
	if err != nil {
		return nil, fmt.Errorf("Failed to GetMember : %v", err)
	}

	return &member, nil
}

// DeleteMembers deletes members.
func (a *ALBClient) DeleteMembers(poolId string) error {
	memberList, err := a.ListMembers(poolId)
	if err != nil {
		return err
	}
	if len(memberList.Members) == 0 {
		return nil
	}

	for _, member := range memberList.Members {
		err := a.DeleteMember(poolId, member.Id)
		if err != nil {
			return err
		}
	}

	return nil
}

// WaitMemberComplete waits member complete.
func (a *ALBClient) WaitMemberComplete(poolID, memberID string) error {
	err := wait.Poll(time.Second*2, time.Minute*3, func() (bool, error) {
		m, err := a.GetMember(poolID, memberID)
		if err != nil {
			klog.Errorf("Get member(%s/%s) status error: %v", poolID, memberID, err)
			return false, nil
		}

		switch m.Member.OperatingStatus {
		case MemberStatusONLINE, MemberStatusNOMONITOR:
			return true, nil
		default:
			klog.Infof("Member is handling(%s)...(%s/%s)", m.Member.OperatingStatus, m.Member.Id, m.Member.Address)
			return false, nil
		}
	})

	return err
}

/*
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 *               Util function
 *    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 */
func (a *ALBClient) findListenerOfService(service *v1.Service) (map[string]ALBListener, error) {
	listeners := make(map[string]ALBListener)
	params := make(map[string]string)
	listenerList, err := a.ListListeners(params)
	if err != nil {
		return nil, err
	}

	clusterID := os.Getenv(ClusterID)
	lsName := GetListenerName(service)

	for _, listener := range listenerList.Listeners {
		if listener.Description != "" {
			var desc ELBListenerDescription
			err := json.Unmarshal([]byte(listener.Description), &desc)
			if err == nil {
				if desc.ClusterID == clusterID &&
					desc.ServiceID == string(service.UID) {
					listeners[listener.Id] = listener
					continue
				}
			}
		}

		if listener.Name == lsName {
			listeners[listener.Id] = listener
		}
	}
	if len(listeners) == 0 {
		return nil, nil
	}
	return listeners, nil
}

func (a *ALBClient) findPoolOfListener(listenerID string) (*ALBPool, error) {
	poolList, err := a.listPools()
	if err != nil {
		return nil, err
	}

	poolCnt := 0
	var resultPool ALBPool
	for _, pool := range poolList.Pools {
		if len(pool.Listeners) == 1 {
			if pool.Listeners[0].Id == listenerID {
				poolCnt++
				resultPool = pool
			}
		}
	}

	if poolCnt == 0 {
		return nil, nil
	}
	if poolCnt > 1 {
		return nil, fmt.Errorf("More than one pools found (%c pool)for listenerid %s", poolCnt, listenerID)
	}
	return &resultPool, nil
}

// CreateEip creates an EIP.
func (a *ALBClient) CreateEip(publicip *PublicIp) (*PublicIp, error) {

	url := "/v1/" + a.vpcClient.TenantId + "/publicips"
	req := NewRequest(http.MethodPost, url, nil, &publicip)

	resp, err := DoRequest(a.vpcClient, a.throttler.GetThrottleByKey(EIP_CREATE), req)
	if err != nil {
		return nil, err
	}

	var eipResp PublicIp
	err = DecodeBody(resp, &eipResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to Create Loadalancer : %v", err)
	}
	return &eipResp, nil
}

// DeleteEip deletes a EIP.
func (a *ALBClient) DeleteEip(ID string) (int, error) {
	url := "/v1/" + a.vpcClient.TenantId + "/publicips/" + ID
	req := NewRequest(http.MethodDelete, url, nil, nil)

	resp, err := DoRequest(a.vpcClient, a.throttler.GetThrottleByKey(EIP_DELETE), req)
	if err != nil {
		return resp.StatusCode, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		resBody, _ := ioutil.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("Failed to Delete EIP : %s, status code: %d", string(resBody), resp.StatusCode)
	}

	return resp.StatusCode, nil
}

// BindEip binds EIP
func (a *ALBClient) BindEip(publicIP *PublicIp, publicipID string) (*PublicIp, error) {
	url := "/v1/" + a.vpcClient.TenantId + "/publicips/" + publicipID
	req := NewRequest(http.MethodPut, url, nil, &publicIP)

	resp, err := DoRequest(a.vpcClient, a.throttler.GetThrottleByKey(EIP_BIND), req)
	if err != nil {
		return nil, err
	}

	var eipResp PublicIp
	err = DecodeBody(resp, &eipResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to Bind EIP : %v", err)
	}
	return &eipResp, nil
}

// ListEips lists EIPs
func (a *ALBClient) ListEips(params map[string]string) (*PublicIps, error) {
	url := "/v1/" + a.vpcClient.TenantId + "/publicips"
	var query string
	if len(params) != 0 {
		query += "?"

		for key, value := range params {
			query += fmt.Sprintf("%s=%s&", key, value)
		}

		query = query[0 : len(query)-1]
	}

	url += query

	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.vpcClient, a.throttler.GetThrottleByKey(EIP_LIST), req)
	if err != nil {
		return nil, err
	}

	var eipList PublicIps
	err = DecodeBody(resp, &eipList)
	if err != nil {
		return nil, fmt.Errorf("Failed to ListEips : %v", err)
	}

	return &eipList, nil
}

// GetSubnet get subnet by ID.
func (a *ALBClient) GetSubnet(subnetID string) (*SubnetItem, error) {
	url := "/v1/" + a.vpcClient.TenantId + "/subnets/" + subnetID
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.vpcClient, a.throttler.GetThrottleByKey(SUBNET_GET), req)
	if err != nil {
		return nil, err
	}

	var subnetResp SubnetArr
	err = DecodeBody(resp, &subnetResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to get Subnet : %v", err)
	}

	return &subnetResp.Subnet, nil
}

// ListSubnets lists subnets.
func (a *ALBClient) ListSubnets(params map[string]string) (*SubnetList, error) {
	var query string

	if len(params) != 0 {
		query += "?"
		for key, value := range params {
			query += fmt.Sprintf("%s=%s&", key, value)
		}
		query = query[0 : len(query)-1]
	}

	url := fmt.Sprintf("/v1/%s/subnets/%s", a.vpcClient.TenantId, query)
	req := NewRequest(http.MethodGet, url, nil, nil)

	resp, err := DoRequest(a.vpcClient, a.throttler.GetThrottleByKey(SUBNET_LIST), req)
	if err != nil {
		return nil, err
	}

	var subnetResp SubnetList
	err = DecodeBody(resp, &subnetResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to SubnetList : %v", err)
	}

	return &subnetResp, nil
}

func generateELBRoutePrefix(enableEnterpriseProject string, projectID string) string {
	if enableEnterpriseProject == "true" {
		return "/v2/" + projectID + "/elb"
	}
	return "/v2.0/lbaas"
}
