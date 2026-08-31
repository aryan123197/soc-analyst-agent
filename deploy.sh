#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="newproject-464521"
REGION="us-central1"
SERVICE_NAME="soc-analyst-agent"
AGENT_ENGINE_ID="5030737937319329792"
MODEL_ARMOR_TEMPLATE_ID="soc-analyst-armor-template"

echo "============================================================"
echo " SOC Analyst Agent — Cloud Run Automated Deployment"
echo " Target GCP Project : ${PROJECT_ID}"
echo " Region             : ${REGION}"
echo " Service Name       : ${SERVICE_NAME}"
echo "============================================================"

# Ensure gcloud configuration
gcloud config set project "${PROJECT_ID}" --quiet

echo "[1/3] Enabling Google Cloud Services (Run, Build, Artifact Registry)..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com --quiet

echo "[2/3] Building container image and deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --source . \
  --region "${REGION}" \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION},AGENT_ENGINE_ID=${AGENT_ENGINE_ID},MODEL_ARMOR_TEMPLATE_ID=${MODEL_ARMOR_TEMPLATE_ID}" \
  --quiet

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --platform managed --region "${REGION}" --format 'value(status.url)')

echo "============================================================"
echo " SUCCESS: SOC Analyst Agent deployed to Cloud Run!"
echo " Live Endpoint URL: ${SERVICE_URL}"
echo " Dashboard UI     : ${SERVICE_URL}/"
echo " Trace Inspector  : ${SERVICE_URL}/traces"
echo " Health Check     : ${SERVICE_URL}/health"
echo "============================================================"
