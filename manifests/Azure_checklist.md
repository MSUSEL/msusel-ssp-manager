# ✅ Azure CI/CD Setup Checklist for Minikube Deployment

Use this checklist to **prepare Azure** before setting up the pipeline.

---

## **1️⃣ Create a Resource Group**
- [ ] Open **Azure CLI** or **Azure Portal**
- [ ] Run:  
  ```bash
  az group create --name MyResourceGroup --location eastus
  ```
- [ ] Confirm it appears in **Azure Portal → Resource Groups**

---

## **2️⃣ Set Up Azure Container Registry (ACR)**
- [ ] Run:  
  ```bash
  az acr create --resource-group MyResourceGroup --name MyACR --sku Basic --admin-enabled true
  ```
- [ ] Replace `MyACR` with a unique name
- [ ] Confirm it appears in **Azure Portal → Container Registries**
- [ ] Get login credentials for later use:  
  ```bash
  az acr credential show --name MyACR
  ```

---

## **3️⃣ Create an Azure DevOps Project**
- [ ] Go to [Azure DevOps](https://dev.azure.com/)
- [ ] Click **New Project**
- [ ] Set a name (e.g., `MyK8sProject`)
- [ ] Choose **Git as repo type**
- [ ] Confirm project appears in **Azure DevOps → Projects**

---

## **4️⃣ Set Up GitHub Service Connection**
- [ ] Go to **Azure DevOps → Project Settings → Service Connections**
- [ ] Click **New Service Connection** → Select **GitHub**
- [ ] Authenticate with GitHub & choose the repository
- [ ] Confirm the connection is listed in **Service Connections**

---

## **5️⃣ Give Azure DevOps Access to ACR**
- [ ] Get ACR credentials:  
  ```bash
  az acr credential show --name MyACR
  ```
- [ ] Go to **Azure DevOps → Pipelines → Library → Add Variable Group**
- [ ] Add these **secrets**:
  - `DOCKER_USERNAME`: ACR username
  - `DOCKER_PASSWORD`: ACR password

---

## **6️⃣ Store Kubernetes Configuration in Azure DevOps**
- [ ] Get Minikube **kubeconfig** (from local machine):  
  ```bash
  cat ~/.kube/config | base64 -w 0
  ```
- [ ] Copy the **base64 output**
- [ ] In **Azure DevOps → Pipelines → Library → Add Variable Group**
- [ ] Add:
  - `KUBECONFIG_SECRET`: Paste the base64 kubeconfig

---

## **7️⃣ Install Required Tools Locally (For Debugging)**
- [ ] **Install Azure CLI** (if not installed):  
  ```bash
  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
  ```
- [ ] **Install Kubectl** (if not installed):  
  ```bash
  sudo apt-get install -y kubectl
  ```
- [ ] Test Azure CLI Login:
  ```bash
  az login
  ```
- [ ] Test Kubectl Connection to Minikube:
  ```bash
  kubectl get nodes
  ```

---

## 🎯 Next Step: Create `azure-pipelines.yml` in Your Repo
Once **all items are checked**, you can **create your CI/CD pipeline**! 🚀

