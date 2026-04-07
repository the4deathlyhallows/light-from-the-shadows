# Detection Lifecycle

## Draft
- hypothesis defined
- required logs confirmed
- query compiles and returns useful fields

## Testing
- query run against recent history
- top noisy actors and hosts reviewed
- initial allowlists and exclusions captured
- severity and schedule justified

## Production
- peer reviewed
- owner assigned
- triage note added
- suppression strategy decided
- deployment path documented

## Review
Check after 7, 14, and 30 days:
- total alert volume
- unique incidents
- false positive sources
- whether exclusions should expire or be tightened
