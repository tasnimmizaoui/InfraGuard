### EventBridge:
is the central nervous system that connects AWS services and your Lambda functions. For security monitoring, it's like having automated security guards that react to events in real-time.
### How it works for our security monitoring case :

AWS Services (Security Events)
       ↓ (emit events)
┌─────────────────────────────┐
│     Amazon EventBridge      │ ← Event Router/Bus
│  (Event Bus - like a switch)│
└──────────────┬──────────────┘
               ↓ (routes to)
                 Lambda Functions
                 (Our Security Scanners)
               ↓
         Take Action:
        - Send alerts
        - Trigger scans  
        - Block attacks