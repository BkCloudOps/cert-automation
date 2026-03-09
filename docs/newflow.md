flowchart TD

    A[Request submitted] --> B[Preflight validation]

    B --> C[Validate request type and scope]
    C -->|Fail| X[Cancel request]

    C --> D[Validate requested user identity]
    D -->|Fail| X

    D --> E[Validate organization]
    E -->|Fail| X

    E --> F{Repo access requested?}
    F -->|Yes| G[Validate repository exists in org]
    G -->|Fail| X
    G --> H[Validate repo state and governance]
    H -->|Fail| Y[Manual review]
    F -->|No| I[Validate business justification]

    H --> I[Validate business justification]
    I -->|Fail| X

    I --> J{Temporary access?}
    J -->|Yes| K[Validate expiry date]
    K -->|Fail| X
    J -->|No| L[Validate permission requested]
    K --> L

    L -->|Fail| X
    L --> M[Validate permission policy]
    M -->|Fail| Y

    M --> N[Check duplicate or conflicting request]
    N -->|Duplicate| W[Close as no action needed]
    N -->|Conflict| Y
    N --> O[Validate AD group exists in Azure]

    O -->|AD group not found| X
    O --> P[Validate AD group naming and org alignment]
    P -->|Fail| X

    P --> Q[Validate enterprise app assignment model]
    Q -->|Fail| Y

    Q --> R[Preflight passed]

    R --> S{User already onboarded to GitHub Enterprise?}
    S -->|Yes| T[Check GitHub team and IdP mapping]
    S -->|No| U[Assign AD group to enterprise application]

    U --> V[Wait up to 45 minutes for GitHub sync]
    V -->|Timeout| Y
    V --> T

    T -->|Team or mapping unsupported| Y
    T --> AA[Check if access already exists]

    AA -->|Already exists| W
    AA -->|Not present| AB[Grant org or repo access through team]

    AB -->|Fail| Y
    AB --> AC[Verify final state]

    AC -->|Fail| Y
    AC --> AD[Send success email]
    AD --> Z[Close ticket]

    X --> X1[Send cancellation email with exact reason]
    X1 --> Z

    Y --> Y1[Send manual review email]
    Y1 --> Z

    W --> W1[Send no action needed email]
    W1 --> Z
