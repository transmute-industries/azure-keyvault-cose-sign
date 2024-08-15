source $1

gh secret set AZURE_TENANT_ID --body "$AZURE_TENANT_ID"
gh secret set AZURE_CLIENT_ID --body "$AZURE_CLIENT_ID"
gh secret set AZURE_CLIENT_SECRET --body "$AZURE_CLIENT_SECRET"
gh secret set AZURE_KEY_ID --body "$AZURE_KEY_ID"