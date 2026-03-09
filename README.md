## GitHub Access Automation Flow

```mermaid
flowchart TD

A[Start - Receive SNOW Request]

A --> B{Request Type Valid?}
B -- No --> R1[Reject Request]
B -- Yes --> C{User Identity Valid?}

C -- No --> R1
C -- Yes --> D{Access Scope Valid?}

D -- No --> R1
D -- Yes --> E{Business Justification Present?}

E -- No --> R1
E -- Yes --> F{Expiry Date Valid if Temporary?}

F -- No --> R1
F -- Yes --> G{Duplicate / Conflicting Request?}

G -- Yes --> R1
G -- No --> H{AD Group Exists in Azure?}

H -- No --> R1
H -- Yes --> I{AD Group Naming Valid?}

I -- No --> R1
I -- Yes --> J{AD Group Org Matches Request?}

J -- No --> R1
J -- Yes --> K{Permission Matches ACL Suffix?}

K -- No --> R1
K -- Yes --> L[All Validations Passed]

L --> M{User Already Onboarded to GitHub Enterprise?}

M -- No --> N[Assign User to Enterprise Application]
N --> O[Wait for GitHub Sync Window (Up to 45 min)]
O --> P{User Visible in GitHub?}

P -- No --> R2[Retry / Fail Request]
P -- Yes --> Q

M -- Yes --> Q{Access Already Exists?}

Q -- Yes --> S[Close Request - No Action Needed]
Q -- No --> T[Grant Access]

T --> U{Access Successfully Applied?}

U -- No --> R3[Raise Incident / Manual Review]
U -- Yes --> V[Close Request Successfully]

V --> Z[End]
