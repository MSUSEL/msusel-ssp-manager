# ✅ GitHub Actions CI/CD Pipeline Setup Checklist

Use this checklist to set up a **GitHub Actions CI/CD pipeline** for deploying a Minikube-based application.

---

## **1️⃣ Create the GitHub Repository**

-

---

## **2️⃣ Set Up GitHub Secrets**

-

To encode the `kubeconfig`, run:

```bash
cat ~/.kube/config | base64 -w 0
```

---

## **3️⃣ Create the GitHub Actions Workflow File**

-

```yaml
name: Minikube CI/CD

on:
  push:
    branches:
      - minikube

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Set up Docker
        uses: docker/setup-buildx-action@v2
      
      - name: Log in to GHCR
        run: echo "${{ secrets.GHCR_PAT }}" | docker login ghcr.io -u "${{ github.actor }}" --password-stdin
      
      - name: Build and push Docker images
        run: |
          docker build -t ghcr.io/${{ github.actor }}/app:latest -f app/Dockerfile ./app
          docker push ghcr.io/${{ github.actor }}/app:latest
          docker build -t ghcr.io/${{ github.actor }}/db:latest -f db/Dockerfile ./db
          docker push ghcr.io/${{ github.actor }}/db:latest
          docker build -t ghcr.io/${{ github.actor }}/flask:latest -f flask/Dockerfile ./flask
          docker push ghcr.io/${{ github.actor }}/flask:latest
          docker build -t ghcr.io/${{ github.actor }}/opa:latest -f opa/Dockerfile ./opa
          docker push ghcr.io/${{ github.actor }}/opa:latest
          docker build -t ghcr.io/${{ github.actor }}/react-app:latest -f react-app/Dockerfile ./react-app
          docker push ghcr.io/${{ github.actor }}/react-app:latest

  deploy:
    runs-on: ubuntu-latest
    needs: build-and-push
    steps:
      - name: Set up Kubectl
        run: |
          echo "${{ secrets.KUBECONFIG_SECRET }}" | base64 -d > kubeconfig
          export KUBECONFIG=kubeconfig
          kubectl apply -f manifests/
          kubectl rollout restart deployment app -n default
          kubectl rollout restart deployment db -n default
          kubectl rollout restart deployment flask -n default
          kubectl rollout restart deployment opa -n default
          kubectl rollout restart deployment react-app -n default
```

🔹 **What this does:**

1. **Triggers** on `git push` to the `minikube` branch.
2. **Builds and pushes** the Docker images for each service to GitHub Container Registry (GHCR).
3. **Deploys** the updated application to Minikube using `kubectl`.

---

## **4️⃣ Commit and Push the Workflow File**

-

---

## **5️⃣ Monitor the Pipeline Execution**

-

---

## **6️⃣ Validate the Deployment**

-

---

### 🎯 **Next Steps**

-

🚀 Your GitHub Actions CI/CD pipeline is now live! 🎉

