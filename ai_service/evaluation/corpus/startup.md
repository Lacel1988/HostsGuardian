# Optional model readiness

Application liveness and optional model availability are different states. The AI service can start when the local inference runtime is absent. Health reports that the application is alive. Readiness must separately report unavailable dependencies without claiming live Engine diagnostic capability.
