# Deployment API failures

Identify the failed deployment call, target environment, response code, and whether the remote operation may have partially succeeded. Prefer a state verification step before retrying. Keep retries bounded and never treat a CI exit code as the only source of deployment truth.