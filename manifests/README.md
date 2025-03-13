# BRON Database Kubernetes Deployment

This document describes the Kubernetes manifests used to deploy the BRON database system and its components.

## Components Overview

The deployment consists of three main components:
1. ArangoDB Database (brondb)
2. Bootstrap Job
3. Driver Job

### File Structure
```
manifests/
├── arango-root-password-secret.yaml    # Database credentials
├── brondb-pv.yaml                      # Persistent volumes for all components
├── brondb-data-container-persistentvolumeclaim.yaml     # PVC for ArangoDB data
├── brondb-apps-data-container-persistentvolumeclaim.yaml # PVC for ArangoDB apps
├── bootstrap-data-container-persistentvolumeclaim.yaml   # PVC for bootstrap data
├── brondb-deployment.yaml              # Main database deployment
├── brondb-service.yaml                 # Service exposing the database
├── bootstrap-deployment.yaml           # Job to populate initial data
└── driver-deployment.yaml              # Job to add NIST mappings
```

## Component Details

### Persistent Storage

The system uses three persistent volumes defined in `brondb-pv.yaml`:
- `brondb-data-pv`: Stores ArangoDB main data
- `brondb-apps-data-pv`: Stores ArangoDB applications data
- `bootstrap-data-pv`: Temporary storage for bootstrap process

Each PV has a corresponding PVC that claims it:
- `brondb-data-container-persistentvolumeclaim.yaml`
- `brondb-apps-data-container-persistentvolumeclaim.yaml`
- `bootstrap-data-container-persistentvolumeclaim.yaml`

### Database (ArangoDB)

**Files:**
- `brondb-deployment.yaml`: Deploys the ArangoDB instance
- `brondb-service.yaml`: Exposes the database on port 8529
- `arango-root-password-secret.yaml`: Stores database credentials

The database deployment uses the official ArangoDB image and mounts the persistent volumes for data storage. The service makes the database accessible to other pods in the cluster.

### Bootstrap Process

**File:** `bootstrap-deployment.yaml`

This job:
1. Waits for the database to be ready (using init container)
2. Downloads and processes the initial BRON datasets
3. Loads the processed data into ArangoDB
4. Terminates upon completion

### Driver Process

**File:** `driver-deployment.yaml`

This job:
1. Waits for the database to be ready
2. Connects to ArangoDB using the service name `brondb`
3. Adds NIST 800-53 mappings to the database
4. Terminates upon completion

## Deployment Order

1. Create namespace:
```bash
kubectl create namespace bron
```

2. Apply storage resources:
```bash
kubectl apply -f brondb-pv.yaml
kubectl apply -f brondb-data-container-persistentvolumeclaim.yaml
kubectl apply -f brondb-apps-data-container-persistentvolumeclaim.yaml
kubectl apply -f bootstrap-data-container-persistentvolumeclaim.yaml
```

3. Create database secret:
```bash
kubectl apply -f arango-root-password-secret.yaml
```

4. Deploy ArangoDB:
```bash
kubectl apply -f brondb-deployment.yaml
kubectl apply -f brondb-service.yaml
```

5. Run bootstrap job:
```bash
kubectl apply -f bootstrap-deployment.yaml
```

6. Run driver job:
```bash
kubectl apply -f driver-deployment.yaml
```

## Monitoring

Monitor job progress:
```bash
# For bootstrap job
kubectl logs -f -n bron job/bootstrap

# For driver job
kubectl logs -f -n bron job/driver
```

Check database status:
```bash
kubectl get pods -n bron -l io.kompose.service=brondb
```

## Cleanup

To remove all resources:
```bash
kubectl delete namespace bron
```

Note: This will delete all resources including PVs, PVCs, and any stored data.