# Deployment Manifests for Minikube

This directory contains Kubernetes manifest files required to deploy the application in a **Minikube cluster**. These manifests define the necessary Deployments, Services, PersistentVolumeClaims, and Jobs to ensure the application runs as expected. The manifest files can be adapted to other Kubernetes environments as well. The test were performed on a VirtualBox Ubuntu 22.04 VM with 4 CPUs and 14GB of RAM.

## Usage

### Prerequisites

1. **Install Minikube**
   ```bash
   # Download the latest Minikube binary
   curl -LO https://github.com/kubernetes/minikube/releases/latest/download/minikube-linux-amd64
   
   # Install Minikube to your system and remove the downloaded file
   sudo install minikube-linux-amd64 /usr/local/bin/minikube && rm minikube-linux-amd64
   
   # Verify the installation
   minikube version
   ```

2. **Install kubectl**
   ```bash
   # Install kubectl using snap
   sudo snap install kubectl --classic
   
   # Verify the installation
   kubectl version --client
   ```

3. **System Requirements**
   - At least 3 CPUs
   - At least 12GB of RAM
   - At least 50GB of free disk space
   - Internet connection for pulling images

### 4. Start Minikube
Ensure Minikube is running before applying the manifests:
```bash
minikube start --memory=12288 --cpus=3 --disk-size=50g
```

### 5. Enable the registry addon for Minikube. 
Minikube has a docker engine independent from the host's docker engine.
```bash
minikube addons enable registry
```

### 6. Build and load the images to Minikube. 
Build your images locally (Ex: docker compose build) and load them to minikube. This process takes a while:
```bash
minikube image load msusel-ssp-manager-flask:latest 
minikube image load msusel-ssp-manager-react-app:latest
minikube image load oscalprocessing:latest
minikube image load arangodb:3.8.1
minikube image load bronbootstrap:latest 
minikube image load msusel-ssp-manager-driver:latest
```

If you make changes and rebuild the images, you have to load them again in minikube. 
```bash
minikube delete 
minikube start --memory=12288 --cpus=3 --disk-size=50g
minikube addons enable registry
Load all the images.
```

### 7. Create volumes in Minikube
```bash
minikube ssh
# Create directories for ArangoDB
sudo mkdir -p /var/lib/arangodb3
sudo mkdir -p /var/lib/arangodb3-apps
sudo mkdir -p /data  # This is for the bootstrap container

# Set correct ownership (arangodb runs as user 999)
sudo chown -R 999:docker /var/lib/arangodb3
sudo chown -R 999:docker /var/lib/arangodb3-apps
sudo chown -R 999:docker /data

exit
```

### 8. Apply Manifests
Create namespace
```bash
kubectl create namespace bron
```

A namespace in Kubernetes is a way to create a logical isolation between resources in your cluster. Think of it like a virtual cluster within your physical cluster. Namespaces help you:
1. Organize resources into groups (e.g., keeping all BRON-related resources together)
2. Avoid naming conflicts between different projects
3. Control resource access and quotas for different teams or projects
4. Keep your cluster resources organized and separated
Without specifying a namespace, all resources are created in the `default` namespace.

Create PVs first 
```bash
kubectl apply -f manifests/brondb-pv.yaml
```

Create PVCs 
```bash
kubectl apply -f manifests/brondb-data-container-persistentvolumeclaim.yaml
kubectl apply -f manifests/brondb-apps-data-container-persistentvolumeclaim.yaml
kubectl apply -f manifests/bootstrap-data-container-persistentvolumeclaim.yaml
```

Create database secret
```bash
kubectl apply -f manifests/arango-root-password-secret.yaml
```

Deploy ArangoDB
```bash
kubectl apply -f manifests/brondb-deployment.yaml
kubectl apply -f manifests/brondb-service.yaml
```

Wait for ArangoDB to be ready (important before proceeding, i.e., the database needs to be ready before we attempt to populate it.)
```bash
kubectl wait --for=condition=available -n bron deployment/brondb --timeout=300s
```

Deploy bootstrap job
```bash
kubectl apply -f manifests/bootstrap-deployment.yaml
```

Monitor bootstrap progress
```bash
kubectl logs -f -n bron job/bootstrap
```

Deploy driver job
```bash
kubectl apply -f manifests/driver-deployment.yaml
```

Apply PVs for the flask-backend and the OPA engine
```bash
kubectl apply -f manifests/flask-shared-pv.yaml
kubectl apply -f manifests/opa-cm0-configmap.yaml
```

Apply PVCs
```bash
kubectl apply -f manifests/flask-pvc.yaml
```

Apply deployments
```bash
kubectl apply -f manifests/flask-deployment.yaml
kubectl apply -f manifests/react-app-deployment.yaml
kubectl apply -f manifests/opa-deployment.yaml
```

Apply services
```bash
kubectl apply -f manifests/flask-service.yaml
kubectl apply -f manifests/react-app-service.yaml
kubectl apply -f manifests/opa-service.yaml
```

Get service information to access the applications
```bash
kubectl get services -n bron
```

Example output:
```
NAME        TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)          AGE
brondb      NodePort    10.109.54.192    <none>        8529:30529/TCP   11h
flask       ClusterIP   10.97.154.73     <none>        5000/TCP         32m
react-app   NodePort    10.104.126.101   <none>        3000:32000/TCP   32m

```

### 9. Access the Application

Get the Minikube IP address:
```bash
minikube ip
```

Example output:
```
192.168.49.2
```

You can now access the application components using:
- React frontend: `http://192.168.49.2:32000`
- Flask API: `http://192.168.49.2:31621`

Alternatively, you can use this command to get a URL and open it in your browser:
```bash
minikube service react-app -n bron --url
```

Key points to ensure communication works:

Same namespace: All services (brondb, flask, react-app) should be in the same namespace (bron).
Service discovery: Within the same namespace, services can reach each other using just the service name (e.g., http://brondb:8529).
External access: You mentioned accessing BronDB via http://192.168.49.2:30529. This works because the BronDB service is exposed as a NodePort service on port 30529. Similarly, your React app will be accessible at http://192.168.49.2:32000.
Environment variables: The Flask container needs the correct environment variables to connect to BronDB, which we've set in the deployment.
After applying these manifests, your Flask service should be able to communicate with BronDB using the URL http://brondb:8529, and your React app should be able to communicate with Flask using http://flask:5000.


### 10. Debugging

#### Inspecting Containers
You can execute commands inside containers to troubleshoot issues:

```bash
# View the current directory in the flask container
kubectl exec -it -n bron <flask-pod-name> -- pwd

# List files in the flask container
kubectl exec -it -n bron <flask-pod-name> -- ls

# List files in the shared volume
kubectl exec -it -n bron <flask-pod-name> -- ls /shared
```

#### Updating Images After Code Changes
When you make code changes, you must rebuild and reload the images:

```bash
# Build your Docker images locally
docker compose build

# Load the updated images into Minikube
minikube image load <image-name>:latest
```

#### Redeploying Components
To redeploy a component after image updates:

```bash
# Example: Redeploying the bootstrap job
kubectl delete job bootstrap -n bron
kubectl delete pods -l job-name=bootstrap -n bron
kubectl get pods -n bron

# Remove old image from Minikube
minikube ssh
docker@minikube:~$ docker rmi <imageID>
exit

# Load updated image and redeploy
minikube image load bronbootstrap:latest
kubectl apply -f manifests/bootstrap-deployment.yaml
```

#### Examining Job Data
To inspect data directories in job containers:

```bash
# List files in the bootstrap job's data directory
kubectl exec -it -n bron $(kubectl get pod -n bron -l job-name=bootstrap -o jsonpath='{.items[0].metadata.name}') -- ls -la /data/raw
```

### 11.Adapting to Other Environments
The provided manifests are tailored for Minikube but can be modified to support other Kubernetes environments, such as **Azure Kubernetes Service (AKS)** or **Amazon EKS**. Adjustments may include:
- **Storage settings**: Update `PersistentVolumeClaims` to match cloud provider storage classes.
- **Resource limits**: Modify `cpu` and `memory` requests/limits based on cluster capacity.
- **Ingress configuration**: Define an ingress controller if required.
