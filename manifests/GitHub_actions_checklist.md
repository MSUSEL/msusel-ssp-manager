# ✅ GitHub Actions CI/CD Pipeline Setup Checklist

Use this checklist to set up a **GitHub Actions CI/CD pipeline** for deploying a Minikube-based application.

---

## **1️⃣ Create the GitHub Repository**
- [ ] Ensure your application code is stored in **GitHub**.
- [ ] Add the necessary **Dockerfiles** and **Kubernetes manifests (`k8s-manifests/`)**.
- [ ] (Optional) Add a `.gitignore` file to exclude unnecessary files.

---

## **2️⃣ Set Up GitHub Secrets**
- [ ] Go to **GitHub → Your Repository → Settings → Secrets and variables → Actions**.
- [ ] Click **"New repository secret"** and add the following:
  - `GHCR_USERNAME` → Your GitHub username.
  - `GHCR_TOKEN` → A **GitHub personal access token (PAT)** with `read:packages` and `write:packages` permissions.
  - `KUBECONFIG_SECRET` → Your Minikube `kubeconfig` (base64 encoded).

To encode the `kubeconfig`, run:
```bash
cat ~/.kube/config | base64 -w 0
```

---

## **3️⃣ Create the GitHub Actions Workflow File**
- [ ] In your repository, create the folder `.github/workflows/` (if it doesn't exist).
- [ ] Inside the folder, create a new file: `deploy.yml`.
- [ ] Copy the following minimal CI/CD pipeline:

```yaml
name: Minikube CI/CD

on:
  push:
    branches:
      - main

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Set up Docker
        uses: docker/setup-buildx-action@v2
      
      - name: Log in to GHCR
        run: echo "${{ secrets.GHCR_TOKEN }}" | docker login ghcr.io -u "${{ secrets.GHCR_USERNAME }}" --password-stdin
      
      - name: Build and push Docker image
        run: |
          docker build -t ghcr.io/${{ secrets.GHCR_USERNAME }}/my-app:latest .
          docker push ghcr.io/${{ secrets.GHCR_USERNAME }}/my-app:latest

  deploy:
    runs-on: ubuntu-latest
    needs: build-and-push
    steps:
      - name: Set up Kubectl
        run: |
          echo "${{ secrets.KUBECONFIG_SECRET }}" | base64 -d > kubeconfig
          export KUBECONFIG=kubeconfig
          kubectl apply -f k8s-manifests/
          kubectl rollout restart deployment my-app -n default
```

🔹 **What this does:**
1. **Triggers** on `git push` to the `main` branch.
2. **Builds and pushes** the Docker image to GitHub Container Registry (GHCR).
3. **Deploys** the updated application to Minikube using `kubectl`.

---

## **4️⃣ Commit and Push the Workflow File**
- [ ] Add the workflow file to GitHub:
  ```bash
  git add .github/workflows/deploy.yml
  git commit -m "Add GitHub Actions pipeline"
  git push origin main
  ```

---

## **5️⃣ Monitor the Pipeline Execution**
- [ ] Go to **GitHub → Your Repository → Actions**.
- [ ] Look for the **"Minikube CI/CD"** workflow and check its execution.
- [ ] If errors occur, click on the failed job to see logs and debug.

---

## **6️⃣ Validate the Deployment**
- [ ] Check if the new version is running in Minikube:
  ```bash
  kubectl get pods -n default
  ```
- [ ] Verify the logs of your application:
  ```bash
  kubectl logs -l app=my-app -n default
  ```

---

### 🎯 **Next Steps**
- [ ] Automate testing before deployment (e.g., add `pytest` step).
- [ ] Set up notifications for build failures (Slack, email, etc.).
- [ ] Implement rollbacks in case of failed deployments.

🚀 Your GitHub Actions CI/CD pipeline is now live! 🎉

