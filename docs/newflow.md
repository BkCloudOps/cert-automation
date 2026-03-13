```mermaid
flowchart TD

A[Scheduler Trigger] --> B[Scan ServiceNow tickets in timeframe]

B --> C[For each ticket]

C --> D{AD group exists in Azure AD}
D -- No --> X[Comment ticket: AD group not found and stop]

D -- Yes --> E{AD group naming follows IIQ standard}
E -- No --> X

E -- Yes --> F{User assigned to GitHub Enterprise App}

F -- No --> G[Assign user to GitHub Enterprise App]
G --> H

F -- Yes --> H{GitHub team already exists}

H -- No --> I[Create GitHub team]
I --> J

H -- Yes --> J{ACL visible in GitHub}

J -- No --> Y[Comment: Waiting for GitHub ACL sync]
Y --> Z[Stop processing this ticket]

J -- Yes --> K{Team already mapped to ACL}

K -- No --> L[Map team to ACL]

K -- Yes --> M[All steps already completed]

L --> N[Comment success on ticket]
M --> N

N --> O[Close or resolve request]
