# Process isolation

The AI analyst runs in a separate Python process on Windows. DNS packets are handled by the independent Linux Engine. A model crash must not interrupt name resolution. The Control Center is outside the DNS packet path. Retrieval is read-only and cannot change network policies.
