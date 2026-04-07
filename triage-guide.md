# Triage Guide

## Identity
Review:
- actor
- source IP
- operation or sign-in result
- privilege level
- whether actor is approved for the action
- related activity nearby in time

## Control Plane
Review:
- caller
- caller IP
- resource affected
- operation name
- whether a change ticket or maintenance window exists
- whether security visibility or permissions were reduced

## Endpoint
Review:
- parent/child process chain
- command line
- network connections
- user context
- device role
- prevalence across your environment

## Escalate faster when
- a privileged identity is involved
- logging or security controls were changed
- new persistence was added
- browser or Office spawned a script interpreter with suspicious arguments
