# Usage Guide

This page provides some examples and Service Annotations descriptions.

Before running the examples below,
make sure you have installed the `huawei-cloud-controller-manager` in your Kubernetes cluster,
refer to [Running on an Existing Cluster on Huawei Cloud](./getting-started.md).

If the annotation in the service is empty,
the [Loadbalancer Configuration](./huawei-cloud-controller-manager-configuration.md#loadbalancer-configuration)
will be used, otherwise use the set value.

## Service Annotations

* `kubernetes.io/elb.class` Required. Specifies the type of ELB service to use. Values are:

  **shared**: Use the shared load balancer service.

  **dedicated**: Use the dedicated load balancer service.

* `kubernetes.io/elb.availability-zones` Optional. Specifies AZs where the load balancer needs to be created, AZs should seperated by a semi-colon(;).
  This annotation works with dedicated load balancers (`kubernetes.io/elb.class: dedicated`),
  and it is required when creating a dedicated load balancer service.

* `kubernetes.io/elb.id` Optional. Specifies use of an existing ELB service.
  If empty, a new ELB service will be created automatically.

* `kubernetes.io/elb.connection-limit` Optional. Specifies the maximum number of connections for the listener.
  This option works with the Shared ELB service, the value ranges from `-1` to `2147483647`.
  The default value is `-1`, indicating that there is no restriction on the maximum number of connections.

* `kubernetes.io/elb.subnet-id` Optional. Specifies the IPv4 subnet ID where the load balancer works.
  If the value is empty, the `subnet-id` in `cloud-config` secret will be used.
  If both are empty, query the subnet where the node is located.
  Only IPv4 subnets are supported.

* `kubernetes.io/elb.eip-id` Optional. Specifies use the specified EIP for ELB service.
   This field has no effect when using an existing ELB service.

* `kubernetes.io/elb.keep-eip` Optional. Specifies whether to retain the EIP when deleting a ELB service
  Valid values are `'true'` and `'false'`, defaults to `'false'`.

* `kubernetes.io/elb.eip-auto-create-option` Optional. Specifies whether to automatically create an EIP for the ELB
  service.
  This is a JSON string, such as `{"ip_type": "5_bgp", "bandwidth_size": 5, "share_type": "PER"}`.

  For details:

  * `share_type` Required. Specifies the bandwidth type. Valid values:

    **PER**: Dedicated bandwidth.
    **WHOLE**: Shared bandwidth.

    If this parameter is set to **WHOLE**, the `share_id` must be specified.

  * `ip_type` Optional. Specifies the EIP type. The value can be `5_bgp` (dynamic BGP) or `5_sbgp` (static BGP).
    It is required when `share_type` is `PER`.

    For the `ip_type` supported by each region, please
    see [Assigning an EIP](https://support.huaweicloud.com/intl/en-us/api-eip/eip_api_0001.html) "Table 4 Description of
    the publicIP field".

  * `bandwidth_size` Optional. Specifies the bandwidth size. It is required when `share_type` is `PER`.

  * `charge_mode` Optional. Specifies whether the bandwidth is billed by traffic or by bandwidth size.

    It is required when `share_type` is `PER`. Defaults is `traffic`, valid values:

    **bandwidth**: billed by bandwidth size.

    **traffic**: billed by traffic.

  * `share_id` Optional. Specifies the bandwidth ID. You can specify an existing shared bandwidth when assigning an EIP.

    It is required when `share_type` is `WHOLE`.

* `kubernetes.io/elb.lb-algorithm` Optional. Specifies the load balancing algorithm of the backend server group.
  The value range varies depending on the protocol of the backend server group:

  **ROUND_ROBIN**: indicates the weighted round-robin algorithm.

  **LEAST_CONNECTIONS**: indicates the weighted least connections algorithm.

  **SOURCE_IP**: indicates the source IP hash algorithm.
  When the value is **SOURCE_IP**, the weights of backend servers in the server group are invalid.

* `kubernetes.io/elb.session-affinity-flag` Optional. Specifies whether to enable session affinity.
  Valid values are `'on'` and `'off'`, defaults to `'off'`.

* `kubernetes.io/elb.session-affinity-option` Specifies the sticky session timeout duration in minutes.
  This parameter is mandatory when the `kubernetes.io/elb.session-affinity-flag` is `'on'` or
  global `session-affinity-flag` is `on`.
  This is a json string, such as `{"type": "SOURCE_IP", "persistence_timeout": 15}`.
  For details:

  * `type` Required. Specifies the sticky session type.
    The value range varies depending on the protocol of the backend server group:

    **SOURCE_IP**: Requests are distributed based on the client's IP address.
    Requests from the same IP address are sent to the same backend server.

    **HTTP_COOKIE**: When the client sends a request for the first time, the load balancer automatically generates
    a cookie and inserts the cookie into the response message. Subsequent requests are sent to the backend server
    that processes the first request.

    **APP_COOKIE**: When the client sends a request for the first time, the backend server that receives the request
    generates a cookie and inserts the cookie into the response message.
    Subsequent requests are sent to this backend server.
    When the protocol of the backend server group is `TCP`, only **SOURCE_IP** takes effect.
    When the protocol of the backend server group is `HTTP`, only **HTTP_COOKIE** or **APP_COOKIE** takes effect.

  * `cookie_name` Optional. Specifies the cookie name.
    This parameter is mandatory when the sticky session type is **APP_COOKIE**.

  * `persistence_timeout` Optional. Specifies the sticky session timeout duration in minutes.
    This parameter is invalid when `type` is set to **APP_COOKIE**.
    The value range varies depending on the protocol of the backend server group:
    When the protocol of the backend server group is `TCP` or `UDP`, the value ranges from `1` to `60`.
    When the protocol of the backend server group is `HTTP` or `HTTPS`, the value ranges from `1` to `1440`.

* `kubernetes.io/elb.health-check-flag` Optional. Specifies whether to enable health check for a backend server group.
  Valid values are `on` and `off`, defaults to `on`.

  > When health check is enabled, CCM will add a new inbound rule to one of the security groups of the backend service,
  allowing traffic from `100.125.0.0/16`.
  This rule will be removed when all LoadBalance services are removed.
  >
  > `100.125.0.0/16` are internal IP addresses used by ELB to check the health of backend servers.

* `kubernetes.io/elb.health-check-option` Optional. Specifies the health check.
  This parameter is mandatory when the `health-check` is `on`.
  This is a json string, such as `{"delay": 3, "timeout": 15, "max_retries": 3}`.
  For details:

  * `delay` Required. Specifies the maximum time between health checks in the unit of second.
    The value ranges from `1` to `50`. Defaults to `5`.

  * `max_retries` Required. Specifies the maximum number of retries.
    The value ranges from `1` to `10`. Defaults to `3`.

  * `timeout` Required. Specifies the health check timeout duration in the unit of second.
    The value ranges from `1` to `50`. Defaults to `3`.

* `kubernetes.io/elb.enable-transparent-client-ip` Optional. Specifies whether to pass source IP addresses of the clients to backend servers.
  Valid values are `'true'` and `'false'`.

  TCP or UDP listeners of shared load balancers: 
  The value can be **true** or **false**, and the default value is **false** if this annotation is not passed.

  HTTP or HTTPS listeners of shared load balancers: 
  The value can only be **true**, and the default value is **true** if this annotation is not passed.

  All listeners of dedicated load balancers: 
  The value can only be **true**, and the default value is **true** if this annotation is not passed.

  > Note:
  > 
  > If this function is enabled, the load balancer communicates with backend servers using their real IP addresses. 
  > Ensure that security group rules and access control policies are correctly configured.
  > 
  > If this function is enabled, a server cannot serve as both a backend server and a client.
  > 
  > If this function is enabled, backend server specifications cannot be changed.

* `kubernetes.io/elb.x-forwarded-host` Optional. Specifies whether to rewrite the `X-Forwarded-Host` header.
  If this function is enabled, `X-Forwarded-Host` is rewritten based on Host in the request and sent to backend servers.

  Valid values are `'true'` and `'false'`, defaults to `'false'`.

* `kubernetes.io/elb.default-tls-container-ref` Optional. Specifies the ID of the server certificate used by the
  listener.
  When this option is set then the cloud provider will create a Listener of type `TERMINATED_HTTPS` for a TLS Terminated
  loadbalancer.

* `kubernetes.io/elb.idle-timeout` Optional. Specifies the idle timeout for the listener. Value range: `0` to `4000`.
  Unit: second.

* `kubernetes.io/elb.request-timeout` Optional. Specifies the request timeout for the listener. Value range: `1`
  to `300`.
  Unit: second. This parameter is valid when protocol is set to *HTTP* or *HTTPS*.

* `kubernetes.io/elb.response-timeout` Optional. Specifies the response timeout for the listener. Value range: `1`
  to `300`.
  Unit: second. This parameter is valid when protocol is set to *HTTP* or *HTTPS*.

* `kubernetes.io/elb.enable-cross-vpc` Optional. Specifies whether to enable cross-VPC backend.
  The value can be `true` (enable cross-VPC backend) or `false` (disable cross-VPC backend).
  The value can only be updated to `true`.
  Only dedicated load balancer service (`kubernetes.io/elb.class: dedicated`) will use this annotation.

* `kubernetes.io/elb.l4-flavor-id` Optional. Specifies the ID of a flavor at Layer 4.
  If neither `kubernetes.io/elb.l4-flavor-id` nor `kubernetes.io/elb.l7-flavor-id` is specified,
  the default flavor is used.
  Only dedicated load balancer service (`kubernetes.io/elb.class: dedicated`) will use this annotation.

* `kubernetes.io/elb.l7-flavor-id` Optional. Specifies the ID of a flavor at Layer 7.
  If neither `kubernetes.io/elb.l4-flavor-id` nor `kubernetes.io/elb.l7-flavor-id` is specified,
  the default flavor is used.
  Only dedicated load balancer service (`kubernetes.io/elb.class: dedicated`) will use this annotation.

## Creating a Service of LoadBalancer type

Below are some examples of using shared ELB services.
First, we should create a deployment for the bellow examples.

```shell
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: default
  name: deployment-ccm-test
spec:
  selector:
    matchLabels:
      app: nginx
  replicas: 1
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.23
          ports:
            - containerPort: 80
EOF
````

### Example 1: Use an existing shared ELB service

```shell
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  annotations:
    kubernetes.io/elb.class: shared
    kubernetes.io/elb.id: xx  # Please replace xx with your ELB instance ID.
    kubernetes.io/elb.lb-algorithm: ROUND_ROBIN
  labels:
    app: nginx
  name: loadbalancer-service-demo-01
  namespace: default
spec:
  ports:
    - port: 80
      protocol: TCP
      targetPort: 80
  selector:
    app: nginx
  type: LoadBalancer
EOF
```

Check the state the status of the LoadBalancer type Service until the `EXTERNAL-IP` status is no longer pending.

```shell
$ kubectl get service loadbalancer-service-demo-01
NAME                          TYPE           CLUSTER-IP     EXTERNAL-IP     PORT(S)        AGE
loadbalancer-service-demo-01  LoadBalancer   10.1.130.216   192.168.0.113   80:30993/TCP   3m10s
```

Once we can see that our service is active and has been assigned an external IP address,
test our application via `curl` from any internet accessible machine.

```shell
$ curl 192.168.0.113
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```

### Example 2: Automatically create a new shared ELB service

```shell
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  annotations:
    kubernetes.io/elb.class: shared
    kubernetes.io/elb.lb-algorithm: ROUND_ROBIN
    kubernetes.io/elb.enable-transparent-client-ip: 'true'  # Preserve client IP to backend servers.
  labels:
    app: nginx
  name: loadbalancer-service-demo-02
  namespace: default
spec:
  ports:
    - port: 80
      protocol: TCP
      targetPort: 80
  selector:
    app: nginx
  type: LoadBalancer
EOF
```

Check the state the status of the LoadBalancer type Service until the `EXTERNAL-IP` status is no longer pending.

```shell
$ kubectl get service loadbalancer-service-demo-02
NAME                           TYPE           CLUSTER-IP     EXTERNAL-IP     PORT(S)        AGE
loadbalancer-service-demo-02   LoadBalancer   10.1.130.216   192.168.0.80   80:30993/TCP   3m10s
```

Once we can see that our service is active and has been assigned an external IP address,
test our application via `curl` from any internet accessible machine.

```shell
$ curl 192.168.0.80
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```

### Example 3: Automatically create a new shared ELB service and create an EIP

```shell
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  annotations:
    kubernetes.io/elb.class: shared
    kubernetes.io/elb.lb-algorithm: ROUND_ROBIN
    kubernetes.io/elb.keep-eip: "false"
    kubernetes.io/elb.eip-auto-create-option: >-
      {"ip_type": "5_bgp", "bandwidth_size": 5, "share_type": "PER"}
  labels:
    app: nginx
  name: loadbalancer-service-demo-03
  namespace: default
spec:
  ports:
    - port: 80
      protocol: TCP
      targetPort: 80
  selector:
    app: nginx
  type: LoadBalancer
EOF
```

Check the state the status of the LoadBalancer type Service until the `EXTERNAL-IP` status is no longer pending.

```shell
$ kubectl get service loadbalancer-service-demo-03
NAME                           TYPE           CLUSTER-IP     EXTERNAL-IP     PORT(S)        AGE
loadbalancer-service-demo-03   LoadBalancer   10.1.35.151   159.138.37.76   80:30080/TCP   41s
```

Once we can see that our service is active and has been assigned an external IP address,
test our application via `curl` from any internet accessible machine.

```shell
$ curl 159.138.37.76
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```

### Example 4: Enable session affinity for shared ELB service listeners

```shell
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  annotations:
    kubernetes.io/elb.class: shared
    kubernetes.io/elb.lb-algorithm: ROUND_ROBIN
    kubernetes.io/elb.session-affinity-flag: 'on'
    kubernetes.io/elb.session-affinity-option: >-
      {"type": "SOURCE_IP", "persistence_timeout": 15}
  labels:
    app: nginx
  name: loadbalancer-service-demo-04
  namespace: default
spec:
  ports:
    - port: 80
      protocol: TCP
      targetPort: 80
  selector:
    app: nginx
  type: LoadBalancer
EOF
```

Check the state the status of the LoadBalancer type Service until the `EXTERNAL-IP` status is no longer pending.

```shell
$ kubectl get service loadbalancer-service-demo-04
NAME                           TYPE           CLUSTER-IP     EXTERNAL-IP     PORT(S)        AGE
loadbalancer-service-demo-04   LoadBalancer   10.1.130.216   192.168.0.113   80:30993/TCP   3m10s
```

Once we can see that our service is active and has been assigned an external IP address,
test our application via `curl` from any internet accessible machine.

```shell
$ curl 192.168.0.113
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```
