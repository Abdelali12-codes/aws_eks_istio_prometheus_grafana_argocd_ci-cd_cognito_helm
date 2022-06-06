# EKS with istio, prometheus, grafana

## eksctl create command

```
eksctl create nodegroup
eksctl create fargateprofile
eksctl create iamserviceaccount
eksctl create iamidentitymapping
```

## eksctl get command


```
eksctl get clusters/cluster
eksctl get nodegroup
eksctl get labels
```

## eksctl delete command

```
eksctl delete cluster
eksctl delete nodegroup
eksctl delete fargateprofile
eksctl delete iamserviceaccount
eksctl delete iamidentitymapping

```


## eksctl upgrade command

```
eksctl upgrade cluster
eksctl upgrade nodegroup
```


## eksctl unset/set commands

```
eksctl set labels
eksctl unset labels
```


## eksctl scale command 

```
eksctl scale nodegroup
```

## eksctl drain command

```
eksctl drain nodegroup
```


## eksctl enable command

```
eksctl enable profile
eksctl enable repo
```

## manage nodegroups

```
eksctl create nodegroup --config-file=<path> --include='ng-prod-*-??' --exclude='ng-test-1-ml-a,ng-test-2-?'
```

# Istio


## create eks cluster

```
export IAA_EKS_CLUSTER=IAA-EKS-CLUSTER
export IAA_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
export IAA_AWS_REGION=us-west-2 #<-- Change this to match your region
export AWS_REGION=us-west-2 #<-- Change this to match your region
export IAA_AMP_WORKSPACE_NAME=istio-amp-workshop

```

```
cat << EOF > eks-cluster-config.yaml
---
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: $IAA_EKS_CLUSTER
  region: $IAA_AWS_REGION
  version: '1.21'
managedNodeGroups:
- name: default-ng
  minSize: 1
  maxSize: 3
  desiredCapacity: 2
  iam:
    withAddonPolicies:
      certManager: true
      cloudWatch: true
EOF
eksctl create cluster -f eks-cluster-config.yaml

```
## installing istio


```
echo 'export ISTIO_VERSION="1.10.0"' >> ${HOME}/.bash_profile
source ${HOME}/.bash_profile

curl -L https://istio.io/downloadIstio | ISTIO_VERSION=${ISTIO_VERSION} sh -

cd ${PWD}/istio-${ISTIO_VERSION}
sudo cp -v bin/istioctl /usr/local/bin/
```

```
yes | istioctl install --set profile=demo
```


* verify whether istio is installed

```
kubectl -n istio-system get svc
```

* edit the label of the namespace of the your application pods

```
kubectl create namespace bookinfo
kubectl label namespace bookinfo istio-injection=enabled
kubectl get ns bookinfo --show-labels
```
* get the gateway endpoint

```
export GATEWAY_URL=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "http://${GATEWAY_URL}/productpage"
```

## Ingest metrics and configure permissions



```
#!/bin/bash
CLUSTER_NAME=$IAA_EKS_CLUSTER
OIDC_PROVIDER=$(aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")
PROM_SERVICE_ACCOUNT_NAMESPACE=istio-system
GRAFANA_SERVICE_ACCOUNT_NAMESPACE=istio-system
SERVICE_ACCOUNT_NAME=iamproxy-service-account
SERVICE_ACCOUNT_IAM_ROLE=EKS-AMP-ServiceAccount-Role
SERVICE_ACCOUNT_IAM_ROLE_DESCRIPTION= “IAM role for the K8s service account with write access to AMP”
SERVICE_ACCOUNT_IAM_POLICY=AWSManagedPrometheusWriteAccessPolicy
SERVICE_ACCOUNT_IAM_POLICY_ARN=arn:aws:iam::$IAA_ACCOUNT_ID:policy/$SERVICE_ACCOUNT_IAM_POLICY
#
# Setup a trust policy designed for a specific combination of K8s service account and namespace to sign in from a Kubernetes cluster that hosts the OIDC Idp.
# If the IAM role already exists, then add this new trust policy to the existing trust policy
#
echo “Creating a new trust policy”
read -r -d '' NEW_TRUST_RELATIONSHIP <<EOF
 [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${IAA_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${GRAFANA_SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${IAA_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${PROM_SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}"
        }
      }
    }
  ]
EOF
#
# Get the old trust policy, if one exists, and append it to the new trust policy
#
OLD_TRUST_RELATIONSHIP=$(aws iam get-role --role-name $SERVICE_ACCOUNT_IAM_ROLE --query 'Role.AssumeRolePolicyDocument.Statement[]' --output json)
COMBINED_TRUST_RELATIONSHIP=$(echo $OLD_TRUST_RELATIONSHIP $NEW_TRUST_RELATIONSHIP | jq -s add)
echo “Appending to the existing trust policy.”
read -r -d '' TRUST_POLICY <<EOF
{
  "Version": "2012-10-17",
  "Statement": ${COMBINED_TRUST_RELATIONSHIP}
}
EOF
echo "${TRUST_POLICY}" > TrustPolicy.json
#
# Setup the permission policy grants write permissions for all AMP workspaces
#
read -r -d '' PERMISSION_POLICY <<EOF
{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Effect":"Allow",
         "Action":[
            "aps:RemoteWrite",
            "aps:QueryMetrics",
            "aps:GetSeries",
            "aps:GetLabels",
            "aps:GetMetricMetadata"
         ],
         "Resource":"*"
      }
   ]
}
EOF
echo "${PERMISSION_POLICY}" > PermissionPolicy.json
#
# Create an IAM permission policy to be associated with the role, if the policy does not already exist
#
SERVICE_ACCOUNT_IAM_POLICY_ID=$(aws iam get-policy --policy-arn $SERVICE_ACCOUNT_IAM_POLICY_ARN --query 'Policy.PolicyId' --output text)
if [ "$SERVICE_ACCOUNT_IAM_POLICY_ID" = "" ]; 
then
  echo "Creating a new permission policy $SERVICE_ACCOUNT_IAM_POLICY"
  aws iam create-policy --policy-name $SERVICE_ACCOUNT_IAM_POLICY --policy-document file://PermissionPolicy.json 
else
  echo "Permission policy $SERVICE_ACCOUNT_IAM_POLICY already exists"
fi
#
# If the IAM role already exists, just update the trust policy.
# Otherwise, create one using the trust policy and permission policy
#
SERVICE_ACCOUNT_IAM_ROLE_ARN=$(aws iam get-role --role-name $SERVICE_ACCOUNT_IAM_ROLE --query 'Role.Arn' --output text)
if [ "$SERVICE_ACCOUNT_IAM_ROLE_ARN" = "" ]; 
then
  echo "$SERVICE_ACCOUNT_IAM_ROLE Role does not exist. Creating a new role with a trust and permission policy."
  #
  # Create an IAM role for the Kubernetes service account 
  #
  SERVICE_ACCOUNT_IAM_ROLE_ARN=$(aws iam create-role \
  --role-name $SERVICE_ACCOUNT_IAM_ROLE \
  --assume-role-policy-document file://TrustPolicy.json \
  --description "$SERVICE_ACCOUNT_IAM_ROLE_DESCRIPTION" \
  --query “Role.Arn” --output text)
  #
  # Attach the trust and permission policies to the Role.
  #
  aws iam attach-role-policy --role-name $SERVICE_ACCOUNT_IAM_ROLE --policy-arn $SERVICE_ACCOUNT_IAM_POLICY_ARN  
else
  echo "$SERVICE_ACCOUNT_IAM_ROLE_ARN Role already exists. Updating the trust policy"
  #
  # Update the IAM role for the Kubernetes service account a with the new trust policy
  #
  aws iam update-assume-role-policy --role-name $SERVICE_ACCOUNT_IAM_ROLE --policy-document file://TrustPolicy.json
fi
echo $SERVICE_ACCOUNT_IAM_ROLE_ARN
# EKS cluster hosts an OIDC provider with a public discovery endpoint.
# Associate this Idp with AWS IAM so that the latter can validate and accept the OIDC tokens issued by Kubernetes to service accounts.
# Doing this with eksctl is the more straightforward approach.
#
eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --approve

```

*  Amazon Managed Service for Prometheus doesn’t directly scrape operational metrics from containerized workloads in a Kubernetes cluster. It requires users to deploy and manage a standard Prometheus server or an OpenTelemetry agent – such as the AWS Distro for OpenTelemetry Collector – in their cluster to perform this task.




* Run the following commands to deploy the Prometheus server on the Amazon EKS cluster:


```
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
IAA_AMP_WORKSPACE_ID=$(aws amp list-workspaces --alias $IAA_AMP_WORKSPACE_NAME --region=${IAA_AWS_REGION} --query 'workspaces[0].[workspaceId]' --output text)
```


* Create a file called amp_ingest_override_values.yaml with the following content in it


```
cat > amp_ingest_override_values.yaml << EOF
## The following is a set of default values for prometheus server helm chart which enable remoteWrite to AMP
## For the rest of prometheus helm chart values see: https://github.com/prometheus-community/helm-charts/blob/main/charts/prometheus/values.yaml
##
serviceAccounts:
  server:
    name: iamproxy-service-account
    annotations: 
      eks.amazonaws.com/role-arn: ${SERVICE_ACCOUNT_IAM_ROLE_ARN}
server:
  remoteWrite:
    - url: https://aps-workspaces.${AWS_REGION}.amazonaws.com/workspaces/${IAA_AMP_WORKSPACE_ID}/api/v1/remote_write
      sigv4:
        region: ${IAA_AWS_REGION}
      queue_config:
        max_samples_per_send: 1000
        max_shards: 200
        capacity: 2500
EOF

```

* Run the following command to install the Prometheus server configuration and configure the remoteWrite endpoint:

```
helm install prometheus-for-amp prometheus-community/prometheus -n istio-system -f ./amp_ingest_override_values.yaml
```

* refer to this blog: https://aws.amazon.com/blogs/mt/monitor-istio-on-eks-using-amazon-managed-prometheus-and-amazon-managed-grafana/


* refer to this blog for cognito: https://aws.amazon.com/blogs/containers/introducing-oidc-identity-provider-authentication-amazon-eks/
