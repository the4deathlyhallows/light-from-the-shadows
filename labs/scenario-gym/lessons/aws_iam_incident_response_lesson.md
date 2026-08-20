# AWS IAM & Incident-Response Deep Dive
### A gap-closing lesson built from your `svc-prod-backup` scenario

You already think like a threat hunter. What's missing is the AWS substrate under the hood — how identity, authentication, authorization, and telemetry actually relate to each other as *systems*, not as vocabulary. Everything below is built to fix that, using your scenario as the spine.

---

## 1. The AWS Identity Mental Model

Hold this chain in your head. Every AWS security question you'll ever ask is really "where in this chain did something go wrong, and what evidence does that step leave behind?"

```
Identity → Authentication → Session → Authorization → Resource → Telemetry
```

- **Identity** — a principal that AWS can name: an IAM user, an IAM role, an AWS account root, an AWS service, or a federated/external identity.
- **Authentication** — proving you *are* that identity. AWS does this by verifying a signed request (SigV4) using a credential: either a long-term access key (IAM user) or temporary credentials (STS-issued, for a role session).
- **Session** — the authenticated context that request executes in. For an IAM user with static keys, the "session" is really just "that user, always." For a role, STS mints an actual time-boxed **session** with its own temporary credentials.
- **Authorization** — AWS's policy engine (the "authorization evaluation logic," sometimes casually called the policy decision point) evaluates *every applicable policy* against the request to decide Allow or Deny. This happens on every single API call, not once at login.
- **Resource** — the thing being acted on: an S3 bucket, an IAM user object, an EC2 instance, another policy, etc.
- **Telemetry** — CloudTrail (and friends: VPC Flow Logs, S3 access logs, GuardDuty) records that the call happened. Telemetry is a *record of what was attempted and whether it was allowed*, not a description of what permissions existed in the abstract.

### Case 1: static IAM user credentials

```
IAM User (svc-prod-backup)
    │
  access key ID + secret access key  ← long-term credential, doesn't expire on its own
    ↓
Authenticate (SigV4 signature verified against the secret key)
    ↓
AWS evaluates authorization
  (identity-based policies attached to the user,
   any group policies, permissions boundary, SCP,
   any relevant resource-based policy)
    ↓
AWS API action executes (or is denied)
    ↓
Resource
```

Nothing here involves STS. The user's identity *is* the credential holder, permanently, until the key is deleted or rotated. This is exactly why long-lived IAM user keys are the credential type attackers love most — steal it once, use it until someone notices.

### Case 2: assumed-role session

```
IAM User (jdoe)
    ↓  sts:AssumeRole (jdoe must be authorized to assume this role,
    │   AND the role's trust policy must authorize jdoe to assume it —
    │   both checks must pass)
STS
    ↓  issues temporary security credentials:
    │  temporary access key ID, temporary secret key, session token
    │  (default 1hr, max up to the role's configured max session duration)
Temporary Role Session (e.g. "admin-operations" session, could be
    │  named jdoe-cli-session or similar in the ARN)
    ↓
AWS API activity, authenticated as the ROLE, not as jdoe directly
```

**What changes between the two:**

1. **Who is "the principal" for authorization purposes.** In case 2, once the role is assumed, the *role's* identity-based policies (and permissions boundary, if any) govern what's allowed — not jdoe's own user policies. jdoe's permissions only mattered for the single decision "was jdoe allowed to call `sts:AssumeRole` on this role."
2. **Credential lifetime.** Static keys don't expire. STS session credentials do (they self-destruct).
3. **What CloudTrail records as the actor.** This is the single most important operational difference for you as an investigator: every API call made during that session is logged with `userIdentity.type = AssumedRole`, showing the role ARN *and* a `sessionContext` that ties back to who assumed it. That linkage is your bridge from "role activity" back to "human/service that got the temporary creds." Without it, role sessions would be anonymous by design — which is exactly why `sessionContext` is gold in an investigation.
4. **Blast radius reasoning is now two-hop, not one-hop.** Compromising jdoe's static key doesn't automatically hand the attacker `admin-operations`' permissions — it hands them *jdoe's* permissions, one of which apparently included "may assume admin-operations." The role assumption is a privilege transition, and it's a distinct event you must find and evaluate on its own.

Keep this picture pinned mentally: **authentication answers "who is making this call," authorization answers "is this specific call allowed for that identity right now," and those are evaluated fresh on every single request** — there is no persistent "logged in with permissions X" state the way there might be in a traditional app session model.

---

## 2. Core Concepts: Definition → Purpose → Security Relevance → Attacker Abuse → Defender Visibility

### IAM user
- **Definition:** A named identity in an AWS account representing a person or a workload that needs long-term credentials or console access.
- **Purpose:** Give a specific, addressable identity to something that isn't naturally ephemeral — a legacy service, a human who needs console/API access, a CI system that predates role-based auth.
- **Security relevance:** Users can hold long-lived access keys. Long-lived = larger exposure window if leaked, and no automatic expiry to bound the blast radius.
- **Attacker abuse:** Steal or create access keys for a user; the user becomes a durable foothold. Creating a *new* IAM user entirely is a classic persistence move (`CreateUser` in your scenario).
- **Defender visibility:** CloudTrail shows `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy` events tied to a specific `userName`. IAM itself (not CloudTrail) shows you current state — which users exist right now and what's attached to them.

### IAM group
- **Definition:** A named collection of IAM users, used purely to attach policies to many users at once.
- **Purpose:** Simplify permission management — attach a policy to a group instead of to N individual users.
- **Security relevance:** Groups are **not principals**. You cannot assume a group, a group cannot be `userIdentity` in CloudTrail, and resource-based/trust policies can never reference a group. It's purely an administrative convenience layer.
- **Attacker abuse:** Adding a compromised or attacker-created user to a highly privileged group is a fast way to inherit broad permissions without touching that user's own policy directly (`AddUserToGroup` is worth hunting).
- **Defender visibility:** CloudTrail logs `AddUserToGroup` / `CreateGroup` / `AttachGroupPolicy`. To know a user's *effective* group-derived permissions at investigation time, you need current IAM config, not just event history (group membership can change again after the event you're looking at).

> **Correcting a common confusion up front:** a *group* is a permission-management container for users. A *role* is an assumable identity with its own trust boundary. They are not different flavors of the same thing — a group can never be authenticated against or assumed; a role can never contain users as "members."

### IAM role
- **Definition:** An identity with permissions policies attached, but with **no long-term credentials of its own** — it must be *assumed* by some trusted principal, which yields temporary credentials.
- **Purpose:** Let permissions be granted temporarily and contextually — to AWS services (Lambda execution roles, EC2 instance profiles), to federated users, to cross-account access, or to humans doing privileged work only when they explicitly elevate (like `admin-operations`).
- **Security relevance:** Two independent gates control who can use a role: (1) the role's **trust policy** (who is allowed to assume it) and (2) the **permissions** attached to the role (what it can do once assumed). Both matter; misconfiguring either creates risk.
- **Attacker abuse:** If an attacker can either satisfy an overly permissive trust policy, or compromise a principal that's already trusted, they can pivot into the role's permission set — often more powerful than their original foothold. Roles are also popular persistence targets: attackers modify trust policies to add themselves as trusted principals.
- **Defender visibility:** CloudTrail's `AssumeRole` event (an STS event, `eventSource: sts.amazonaws.com`) is the pivot point — it names both the role and the calling principal. Everything after that shows up as `AssumedRole` activity under the *role's* ARN with a `sessionContext` linking back.

### Principal
- **Definition:** The formal term for "an entity that can be authenticated and authorized to make requests to AWS" — an IAM user, an IAM role (specifically, a role session), the account root, or an AWS service principal (e.g., `lambda.amazonaws.com`).
- **Purpose:** It's the unit policies are written *about*. Trust policies specify allowed principals; identity-based policies apply *to* a principal.
- **Security relevance:** "Who can act" always reduces to "which principal," and every principal has a unique, traceable ARN represented in the calling context of every API request.
- **Attacker abuse:** N/A directly — but attackers are always trying to become, or act through, a more powerful principal than the one they started with. That escalation-of-principal framing is the core plot of almost every IAM compromise, including yours.
- **Defender visibility:** `userIdentity.arn` and `userIdentity.principalId` in CloudTrail identify the acting principal for every logged call.

### Access key ID
- **Definition:** The public, non-secret half of a long-term IAM user credential (format `AKIA...`). Also shows up in a different prefix (`ASIA...`) for temporary STS credentials.
- **Purpose:** Identifies which credential pair/key was used, without itself being sensitive.
- **Security relevance:** Safe to log, safe to appear in CloudTrail. It's how you correlate "this specific key" across many events without needing the secret.
- **Attacker abuse:** Attackers exfiltrate the access key ID *together with* the secret access key — the ID alone is useless for authentication.
- **Defender visibility:** `responseElements.accessKey.accessKeyId` on `CreateAccessKey`; also appears associated with subsequent authenticated calls in some contexts. Very useful as a pivot value to search "everything this specific key touched."

### Secret access key
- **Definition:** The private half of a long-term access key pair, used to compute the SigV4 signature that proves possession of the credential.
- **Purpose:** The actual authentication secret — analogous to a password, but never transmitted directly (used to derive a signature instead).
- **Security relevance:** This is *the* thing that must never leak. Unlike a session token, it doesn't expire.
- **Attacker abuse:** This is what got exfiltrated/misused in your scenario the moment `CreateAccessKey` succeeded against `svc-prod-backup`. Anyone holding it can authenticate as that user indefinitely, from anywhere, until the key is deactivated/deleted.
- **Defender visibility:** **Never appears in CloudTrail** (by design — it's only ever returned once, at creation time, to the caller, over TLS). CloudTrail can tell you a key was *created*; it cannot tell you the key's value, nor definitively where it ended up. This is a critical evidentiary boundary — more on it in Section 4.

### Session token
- **Definition:** A third credential component (alongside a temporary access key ID and temporary secret key) that STS issues for any temporary-credential session — role sessions, federated sessions, `GetSessionToken` results.
- **Purpose:** Must be presented alongside the temporary key pair on every request; without it, the temporary credentials don't validate. It's part of what makes the credential set "temporary" and revocable-by-expiry.
- **Security relevance:** Bounds the usable lifetime of stolen temporary credentials — if you steal a role session's credentials, you get at most until expiry (up to the role's max session duration), not indefinite access, unlike a stolen static key.
- **Attacker abuse:** Session tokens can still be stolen and used for the remainder of their validity window (e.g., stolen from an EC2 instance metadata service, a Lambda environment, or a compromised CI runner) — "temporary" reduces but doesn't eliminate risk.
- **Defender visibility:** Not directly logged in full in CloudTrail for privacy/security reasons, but `sessionContext` metadata (issue time, MFA status) is.

### Temporary credentials
- **Definition:** The (access key ID + secret key + session token) triple issued by STS for a bounded lifetime.
- **Purpose:** Enable authorization without ever handing out a durable secret — the AWS-preferred credential model for roles, federation, workloads, and increasingly for humans (SSO).
- **Security relevance:** Self-expiring, which is a huge defensive advantage: contain-by-waiting is a real (if slow) option, and revocation-by-policy is also possible (see role session revocation below).
- **Attacker abuse:** Still abusable within the validity window; attackers who get temporary creds often race to establish **persistent** (non-expiring) access before the window closes — which is exactly the shape of your scenario: assumed role → immediately create a *new, long-lived* access key. That's the attacker converting an expiring foothold into a durable one.
- **Defender visibility:** CloudTrail `sessionContext.attributes.creationDate` and `mfaAuthenticated` tell you when the session started and whether MFA was used to get it.

### AWS STS (Security Token Service)
- **Definition:** The AWS service that issues temporary security credentials.
- **Purpose:** Central mechanism behind `AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`, `GetFederationToken`, `GetSessionToken`.
- **Security relevance:** Every role-session credential on Earth traces back to an STS call — which means STS's own event log (`eventSource: sts.amazonaws.com` in CloudTrail) is the connective tissue of your identity chain.
- **Attacker abuse:** Attackers call STS the moment they have a foothold, to pivot into whatever role their stolen/compromised principal is trusted to assume.
- **Defender visibility:** `AssumeRole` events show the source principal (`userIdentity`), the target role (`requestParameters.roleArn`), the resulting session name, and whether it succeeded.

### AssumeRole
- **Definition:** The STS API call that exchanges "I am principal X, and I want to act as role Y" (subject to both X's own permission to call `sts:AssumeRole` on Y, and Y's trust policy naming X as trusted) for temporary credentials.
- **Purpose:** The actual mechanical act of privilege transition.
- **Security relevance:** This is your single most important pivot event in almost any IAM incident — it's the seam between two identities.
- **Attacker abuse:** The literal privilege-escalation or lateral-movement step, depending on whether the target role is more or equally privileged.
- **Defender visibility:** Full detail in CloudTrail: calling principal, target role ARN, source IP, MFA status, success/failure, resulting `sessionContext`. If it *fails*, `errorCode` will show `AccessDenied` — evidence someone *tried* and couldn't (still valuable).

### Role session
- **Definition:** The specific, time-boxed instantiation of "principal X assumed role Y," identified by a session name chosen at `AssumeRole` time (e.g., `jdoe`, `i-0abc123`, or an app-chosen string) and represented in the resulting ARN as `arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME`.
- **Purpose:** Gives each assumption instance a distinguishable identity in logs, even though many different principals might assume the same role over time.
- **Security relevance:** The session name is *attacker- or caller-chosen*, not independently verified — so don't over-trust it as identity proof by itself. What you trust is `sessionContext.sessionIssuer` and the surrounding chain.
- **Attacker abuse:** Attackers sometimes choose session names that blend in (mimicking legitimate naming conventions) to reduce analyst suspicion.
- **Defender visibility:** `userIdentity.arn` shows the full assumed-role ARN including session name on every subsequent call in that session.

### Managed policy
- **Definition:** A standalone, reusable IAM policy object (either AWS-managed, i.e. maintained by AWS, or customer-managed, i.e. created by your account) that can be attached to multiple users/groups/roles.
- **Purpose:** Reusability and centralized update — change the policy once, every attachment updates.
- **Security relevance:** Easy to audit in one place (you can list "everything this policy is attached to"), but also easy to *not notice* has drifted broad over time.
- **Attacker abuse:** `AttachUserPolicy` / `AttachRolePolicy` with a highly privileged managed policy (`AdministratorAccess` being the extreme case) is a fast, one-call privilege escalation.
- **Defender visibility:** `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy`, and `CreatePolicy`/`CreatePolicyVersion` events in CloudTrail; current attachments visible via IAM directly.

### Inline policy
- **Definition:** A policy document embedded directly on a single user/group/role, not reusable elsewhere, and deleted automatically if the identity is deleted.
- **Purpose:** Used for tightly-scoped, one-off permissions that shouldn't be reused or centrally managed.
- **Security relevance:** Harder to audit at scale (no central "list everyone using this policy" view — you have to check identity-by-identity), which is precisely why they're a favorite lever for attackers wanting to fly under the radar of policy-centric audits.
- **Attacker abuse:** `PutUserPolicy` / `PutRolePolicy` to silently grant broad permissions to a specific identity without creating a new named, listable managed-policy object.
- **Defender visibility:** `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy` events in CloudTrail — treat these as high-signal, since inline policy changes are less common in routine operations than managed policy attachment.

### Identity-based policy
- **Definition:** Any policy attached *to a principal* (user, group, or role) — inline or managed — defining what that principal is allowed to do.
- **Purpose:** The primary mechanism for granting permissions to "who can do what."
- **Security relevance:** This is the piece most people mean when they informally say "IAM policy." But it's only one of several inputs to the final authorization decision (see "effective permissions" below).
- **Attacker abuse:** Direct target of privilege escalation — attach/modify to grant more.
- **Defender visibility:** Fully queryable via IAM at any point in time (current state), and every *change* to one is a CloudTrail event.

### Resource-based policy
- **Definition:** A policy attached *to a resource* itself (an S3 bucket policy, an SNS topic policy, a KMS key policy, a role's *trust* policy is technically a special case of this pattern) — defining who is allowed to access *that resource*, potentially including principals from *other AWS accounts*.
- **Purpose:** Lets a resource owner grant access without needing to touch the calling principal's own account/policies at all — essential for cross-account and public-access scenarios.
- **Security relevance:** This is the mechanism behind most "public S3 bucket" incidents — a resource-based policy (or ACL) granting `Principal: "*"`.
- **Attacker abuse:** Modifying a bucket policy to grant an attacker-controlled account or `"*"` access to exfiltrate data, independent of any identity-based policy changes.
- **Defender visibility:** `PutBucketPolicy`, `GetBucketPolicy` (read/recon, as in your scenario!), `PutBucketAcl` events. `GetBucketPolicy`/`GetBucketEncryption` calls specifically indicate an attacker doing **reconnaissance on exfiltration feasibility**, not modification yet — an important distinction for severity.

### Permissions boundary
- **Definition:** A special managed policy attached to a user or role that sets the **maximum** permissions that identity can ever have, regardless of what identity-based policies grant it. It doesn't *grant* anything by itself — it only caps.
- **Purpose:** Delegate policy administration safely — e.g., let a team attach whatever managed policies they want to roles they create, but cap the ceiling so they can't self-escalate to admin.
- **Security relevance:** The effective permission for any action is the **intersection** of (identity-based policy allow) AND (permissions boundary allow, if one is set). An `s3:*` identity policy is neutered to nothing if the boundary doesn't also allow S3.
- **Attacker abuse:** Less commonly abused directly, but attackers who understand boundaries will look for identities *without* one, or will attempt to remove/modify the boundary itself (`DeleteUserPermissionsBoundary`, `PutUserPermissionsBoundary`) as an escalation path if they have `iam:*` on the target.
- **Defender visibility:** Visible in IAM as a distinct attribute on the user/role object; changes are their own CloudTrail events, separate from ordinary policy attach/detach.

### SCP (Service Control Policy)
- **Definition:** An AWS Organizations-level policy applied to an entire account or OU, setting the maximum permissions for *every* principal in that account/OU — including the account root.
- **Purpose:** Org-wide guardrails ("no account in this OU may ever disable CloudTrail," "no account may use regions outside us-east-1/us-west-2").
- **Security relevance:** Same intersection logic as permissions boundaries, but at a much larger blast radius — an SCP denying `cloudtrail:StopLogging` org-wide is a powerful, attacker-resistant control because even a fully-compromised admin identity *inside* the account can't override it (SCPs are managed at the Organizations management account level).
- **Attacker abuse:** Attackers generally can't touch SCPs unless they've compromised the Organizations management account itself — which is why "is there an SCP blocking `StopLogging`/`DeleteTrail` account-wide" is a great resilience question to ask *before* an incident.
- **Defender visibility:** Not in the compromised account's own IAM at all — you have to check AWS Organizations (in the management account) to see applicable SCPs.

### Role trust policy
- **Definition:** The resource-based policy attached to a role that determines **who is allowed to assume it** (`sts:AssumeRole`). Written from the role's perspective: "I trust these principals to become me."
- **Purpose:** The gatekeeper for privilege transition — separate and independent from what the role can *do* once assumed.
- **Security relevance:** A role can have minimal permissions but an overly broad trust policy (anyone can assume it, low value) or tight trust but massive permissions (few can assume it, but if they do, huge blast radius) — you must evaluate both dimensions.
- **Attacker abuse:** **Modifying a role's trust policy to add an attacker-controlled principal (often in another AWS account) is one of the most dangerous and stealthy persistence techniques that exists** — it creates cross-account access that doesn't require any new IAM user or access key inside the victim account at all, and is easy to overlook because analysts fixate on users/keys.
- **Defender visibility:** `UpdateAssumeRolePolicy` in CloudTrail — this should be a near-automatic high-severity alert in any mature environment, especially for privileged roles.

### Explicit Allow
- **Definition:** A policy statement with `"Effect": "Allow"` that matches the request's action/resource/condition.
- **Purpose:** Grants permission. By default, everything in AWS is implicitly denied; an explicit Allow is what turns that into permission.
- **Security relevance:** Multiple Allow statements across multiple policies are additive — permissions accumulate from every applicable identity-based policy, resource-based policy, etc. (subject to boundaries/SCPs capping the ceiling).
- **Attacker abuse:** N/A directly — but every escalation attackers pursue is: find or create an explicit Allow that covers what they want to do.
- **Defender visibility:** You must enumerate *every* applicable policy to know the full set of explicit Allows — no single document tells you "final effective permission" by itself. (Real tools exist for this: IAM Policy Simulator, or the more accurate `iam:GetAccountAuthorizationDetails` + evaluation logic, or AWS Access Analyzer.)

### Explicit Deny
- **Definition:** A policy statement with `"Effect": "Deny"`.
- **Purpose:** Override — explicit Deny **always wins**, no matter how many Allow statements exist elsewhere, no matter which policy type contains it.
- **Security relevance:** This is the single most important rule in the entire IAM evaluation model: **explicit Deny beats explicit Allow, always, everywhere.** SCPs and permissions boundaries work by combining implicit-deny-by-default with targeted explicit Denies/scoped Allows.
- **Attacker abuse:** Attackers look for gaps where no Deny exists rather than trying to fight one — a well-placed explicit Deny (e.g., "Deny `iam:*` unless MFA present") is extremely resistant to circumvention short of attacking the policy itself.
- **Defender visibility:** Same as Allow — must be found by enumerating all applicable policies. This is why "I read one policy and concluded X" is dangerous investigative shorthand (see Section 3).

### Least privilege
- **Definition:** The principle that a principal should hold only the permissions strictly necessary for its function, nothing more.
- **Purpose:** Shrinks blast radius — the entire point of a "what could this identity reach" containment question (Section 7) becomes smaller and faster to answer when least privilege is actually practiced.
- **Security relevance:** In your scenario, `svc-prod-backup` needing `iam:CreateAccessKey` on itself (or the compromised principal needing `iam:CreateAccessKey` on that user) is itself almost certainly a least-privilege violation worth flagging regardless of whether this was malicious — a backup service account should very rarely need IAM-modification permissions on itself.
- **Attacker abuse:** N/A directly — but it's the standing condition that made everything downstream in your scenario possible: something in the environment had far more reach than its job required.
- **Defender visibility:** Requires proactive review (Access Analyzer's "unused access" findings, IAM Access Advisor's last-used data), not incident-time CloudTrail digging.

### Effective permissions
- **Definition:** What a principal can *actually* do right now, computed as: (union of all applicable identity-based policy Allows) MINUS (any applicable explicit Deny) INTERSECTED WITH (any permissions boundary) INTERSECTED WITH (any applicable SCP) — and, separately, gated by any resource-based policy if the resource itself also requires explicit trust (cross-account access needs *both* sides to agree).
- **Purpose:** The only number that actually matters for "what could this identity have done."
- **Security relevance:** This is the concept your scenario's core misunderstanding collapsed into a false shortcut: *"the access key has permissions."* It doesn't. The key authenticates a principal; the principal's effective permission set (computed fresh, per-call, from all these layered inputs) is what determines authorization. Section 3 will drill this until it's reflexive.
- **Attacker abuse:** Attackers exploit gaps *between* what an analyst assumes is effective and what's actually effective — e.g., you see a scary-looking `s3:*` Allow and conclude "the bucket was exposed," without checking whether a boundary or explicit Deny neutered it, or conversely you see a narrow-looking policy and miss that a *second* attached policy or group membership makes it broad.
- **Defender visibility:** No CloudTrail event gives you this directly — it's a config-time computation, not a logged event. You need current (or point-in-time, if available) IAM state to compute it.

---

## 3. Reading IAM Policies Like an Investigator

### The anatomy

```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

- **`Effect`** — Allow or Deny. Nothing else matters if this doesn't resolve favorably (and remember: Deny anywhere wins).
- **`Action`** — the API operation(s) this statement covers, in `service:ApiName` form. Wildcards operate at multiple levels: `s3:*` = every S3 action; `s3:Get*` = every S3 read-style action starting with "Get"; `*` = literally every action in every service.
- **`Resource`** — the ARN(s) this statement applies to. `*` = every resource. Some actions (IAM-related, account-level actions) don't take a resource ARN at all and require `Resource: "*"` structurally even in a tightly scoped policy — don't over-read a bare `*` here as automatically reckless without checking what `Action` it's paired with.
- **Wildcards (`*`, `?`)** — `*` matches any sequence of characters (including none), `?` matches exactly one character. They're evaluated literally, not as regex.
- **`Condition`** — an optional block that narrows *when* the statement applies: source IP ranges (`aws:SourceIp`), MFA presence (`aws:MultiFactorAuthPresent`), time windows, tag matching, request encryption requirements, and dozens more. Conditions are where a scary-looking Allow often gets meaningfully narrowed — or where a seemingly narrow Allow gets *widened* in ways people miss (e.g., a Condition that's trivially satisfiable).

**This example, read as a whole:** grants unrestricted read/write/delete/configuration-change access to every S3 bucket and object in the account, with no conditions. If this is the *complete and final* effective policy for a principal, that's about as broad as S3 access gets. But — and this is the entire point of this section — **you don't yet know if it's the complete and final effective policy.**

### Progressively harder examples — work through the reasoning, not just the verdict

**Example A**
```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::prod-backups/*"
}
```
Scoped to objects (not the bucket itself — note the `/*`, which excludes bucket-level actions like `s3:ListBucket` or `s3:DeleteBucket`) inside one specific bucket. Read+write of objects only. No delete, no policy/ACL modification, no listing.

**Example B — same Allow, plus a Deny elsewhere**
```json
[
  {
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
  },
  {
    "Effect": "Deny",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": {
      "Bool": { "aws:MultiFactorAuthPresent": "false" }
    }
  }
]
```
Taken alone, statement 1 looks like unrestricted S3 access. Statement 2 changes the real-world answer entirely: **any session without MFA is denied everything S3-related**, because explicit Deny wins. So the actual effective permission depends on a fact you can't get from the policy JSON alone — was this specific session MFA-authenticated? (Which, notably, *is* something CloudTrail's `sessionContext.attributes.mfaAuthenticated` tells you per-session — this is a case where CloudTrail evidence and IAM policy evidence must be combined to get the real answer.)

**Example C — looks dangerous, permissions boundary changes the outcome**
```json
// Identity-based policy on the role:
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```
```json
// Permissions boundary attached to the same role:
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": "arn:aws:s3:::readonly-reports/*"
}
```
The identity policy alone reads as full account admin. But a permissions boundary caps effective permission at the **intersection** — and the boundary only allows two read-only S3 actions on one bucket. Effective permission: read-only access to `readonly-reports`, full stop, regardless of how alarming the identity policy looks in isolation. This is precisely the trap the exercise is warning you about: **stop concluding "this is the effective permission" from a single policy document.** Always ask: is there a permissions boundary? An applicable SCP? A relevant explicit Deny elsewhere? A resource-based policy that must *also* agree?

**Example D — resource-based policy required as the second signature**
```json
// Bucket policy on a bucket in Account B:
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::111111111111:role/admin-operations" },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::partner-data/*"
}
```
Even if `admin-operations`' own identity-based policy grants `s3:*` on `*`, this cross-account read only works if the **resource owner's** bucket policy also names that exact role as trusted. Same-account access generally only needs the identity-based side to say yes; cross-account access needs *both* sides to agree — the identity-based policy (their side) and the resource-based policy (your side, granting them in). Miss the resource-based half and you'll wrongly conclude a principal "could have" accessed something it actually couldn't, or vice versa.

**The reflex to build:** every time you see one policy statement, your very next thought should be *"what else applies to this principal and this resource that I haven't looked at yet?"* — boundary, SCP, other attached policies, group memberships, resource-based policy, explicit Denies anywhere in any of those. Effective permission is a computed intersection/union across all of them, not a single document's face value.

---

## 4. CloudTrail Investigation

### What a CloudTrail event actually is

A CloudTrail event is a record that **an API call was made against an AWS service**, captured at the API layer. It answers "a request matching this shape arrived and here's what AWS decided to do with it." It is not a network capture, not a data-plane content log (by default), and not a permissions calculator.

### Field-by-field

- **`eventTime`** — UTC timestamp of the API call. Foundation for sequencing your identity chain and building a timeline.
- **`eventSource`** — which AWS service handled the call (e.g., `iam.amazonaws.com`, `sts.amazonaws.com`, `s3.amazonaws.com`). Tells you *which* service's semantics apply to `eventName`.
- **`eventName`** — the specific API operation (`CreateAccessKey`, `AssumeRole`, `GetObject`, etc.).
- **`awsRegion`** — the region the call targeted. Note: IAM and STS are global/US-East-1-anchored for many purposes but calls can still show varied region metadata; S3/EC2/etc. are genuinely regional. Unusual regions for a normally single-region workload are a mild signal.
- **`sourceIPAddress`** — the IP AWS saw the request originate from. Valuable for spotting unfamiliar infrastructure (as in your scenario), but **can be an AWS-internal service IP** (e.g., when a service like CloudFormation or Lambda calls another service on your behalf) rather than an external attacker IP — don't assume it's always "the human's laptop IP."
- **`userAgent`** — the client software string (AWS CLI version, SDK, Console, Terraform, curl, etc.). Useful for spotting a mismatch (e.g., admin normally uses the Console, this event shows raw `Boto3`/`python-requests` — worth a question, not proof).
- **`userIdentity`** — the block describing the calling principal. This is your identity anchor for the whole event.
  - **`userIdentity.type`** — `IAMUser`, `AssumedRole`, `Root`, `AWSService`, `FederatedUser`, etc. Tells you *what kind* of principal made the call — this is where you distinguish "a static IAM user credential did this" from "a role session did this."
  - **`userIdentity.arn`** — full ARN of the principal (for `AssumedRole`, this includes the role name *and* session name).
  - **`userIdentity.principalId`** — a unique, stable internal identifier. Useful because ARNs can be reused conceptually (a role can be deleted and recreated with the same name) but `principalId` for the underlying entity changes — good for confirming "is this genuinely the same underlying role/user as before, or a recreated one with the same name."
  - **`userIdentity.sessionContext`** — present only for temporary-credential (assumed-role) calls. Contains `sessionIssuer` (which role was assumed, its ARN), `attributes.creationDate` (when the session/temp creds were minted), and `attributes.mfaAuthenticated` (whether MFA was present at credential-issuance time). **This is your literal bridge backward from role activity to the identity that assumed the role** — but note it tells you the role and issuance time, not automatically "which human" beyond what's encoded in the session name/arn; you still cross-reference the *originating* `AssumeRole` event to see who called it.
- **`requestParameters`** — what was requested (e.g., for `CreateAccessKey`, this shows `userName` — which user the key was created *for*). Critical for understanding intent/target, not just "what action."
- **`responseElements`** — what AWS returned (e.g., `accessKey.accessKeyId`, but **never** the secret key). For many mutating calls this confirms exactly what got created/changed, which is often more precise than the request (defaults get filled in).
- **`errorCode`** / **`errorMessage`** — present when the call failed. `AccessDenied` here is a **denied attempt**, still valuable evidence — someone/something *tried* to do X and couldn't, which tells you about intent and about what they didn't yet have.

### What CloudTrail can tell you vs. what it cannot

**Can tell you:** who (which principal/session) did what (which API action) to what (which resource, by ARN/name) when, from where (source IP as AWS saw it), using what client, and whether it succeeded.

**Cannot tell you (without other sources):**
- The **content** of data read via `GetObject` (management-event CloudTrail logs the *call*, not the object bytes — S3 *data events*, a separate, often-disabled CloudTrail configuration, or S3 access logs would be needed for that level of detail, and even then it's metadata about the read, not necessarily payload).
- The secret value of any credential, ever.
- Effective permissions at the time of the call — CloudTrail shows an Allow happened by virtue of the call succeeding, but doesn't enumerate *why* (which policy, boundary, condition made it succeed). You reconstruct the "why" from IAM config, ideally point-in-time if you have it (e.g., via AWS Config), otherwise current-state with the caveat that it may have changed since.
- Anything about a call that was never made — the *absence* of an event only tells you no logged API call happened; it says nothing about, e.g., credentials being copied out-of-band, or a call happening in a CloudTrail-blind window (before logging was enabled, or during a `StopLogging` gap — a strong reason `StopLogging`/`DeleteTrail` are treated as high severity independent of anything else observed).
- Ground truth about human intent — CloudTrail shows what happened technically; "was this malicious" is always an inference layered on top, corroborated by things like unfamiliar source IP, the administrator's denial, off-hours timing, unusual API sequencing, etc.

### Sample reconstruction

```json
{
  "eventTime": "2026-08-14T03:11:22Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.44",
  "userAgent": "aws-cli/2.15.0",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::111111111111:user/jdoe",
    "principalId": "AIDAEXAMPLE123",
    "accessKeyId": "AKIAEXAMPLE456"
  },
  "requestParameters": {
    "roleArn": "arn:aws:iam::111111111111:role/admin-operations",
    "roleSessionName": "jdoe"
  },
  "responseElements": {
    "credentials": { "accessKeyId": "ASIAEXAMPLE789" }
  },
  "errorCode": null
}
```
Reconstructed: at 03:11:22 UTC, the IAM user `jdoe`, authenticated via AWS CLI from `203.0.113.44` (a source IP that — per your scenario — the real jdoe doesn't recognize), successfully assumed the `admin-operations` role, naming the session `jdoe`, and was issued temporary credentials `ASIAEXAMPLE789`. This event *alone* proves the assumption happened and from where — it does not yet prove jdoe's static key was stolen (rather than, say, a session hijack or an insider), but combined with jdoe's denial and the unfamiliar IP, it strongly supports "jdoe's long-term credential was compromised and used by someone else" as the working hypothesis, to be corroborated (e.g., geolocation/ASN on that IP, any concurrent legitimate jdoe activity from a *different*, familiar IP at/around the same time, absence of MFA if jdoe normally MFAs, etc.).

```json
{
  "eventTime": "2026-08-14T03:11:40Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.44",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::111111111111:assumed-role/admin-operations/jdoe",
    "principalId": "AROAEXAMPLE999:jdoe",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "arn": "arn:aws:iam::111111111111:role/admin-operations"
      },
      "attributes": {
        "creationDate": "2026-08-14T03:11:22Z",
        "mfaAuthenticated": "false"
      }
    }
  },
  "requestParameters": { "userName": "svc-prod-backup" },
  "responseElements": {
    "accessKey": {
      "accessKeyId": "AKIANEWKEY000",
      "userName": "svc-prod-backup",
      "status": "Active"
    }
  }
}
```
Reconstructed: 18 seconds later, the *same session* (note `sessionIssuer` matches the role from the prior event, and the timestamp is consistent with that session still being active) called `CreateAccessKey` targeting `svc-prod-backup`, and a new active key `AKIANEWKEY000` was created. `mfaAuthenticated: false` is a meaningful aggravating detail if the admin's normal workflow requires MFA. This is the moment a temporary, expiring foothold (the role session) got converted into a durable, non-expiring one (the new key) — the persistence step.

---

## 5. Identity-Chain Investigation

Your instinct to reason forward from the malicious key was the gap. The correct discipline is to treat **every privileged event as a midpoint**, not an endpoint, and interrogate both directions:

```
                    ↑ upstream: how did this identity get here?
Original Principal (jdoe)
        ↓  AssumeRole            ← ask: was jdoe authorized to do this? was this normal for jdoe?
Temporary STS Session (admin-operations/jdoe)
        ↓  CreateAccessKey       ← ask: was this action normal for this session/role to take?
New Credential (svc-prod-backup's new key)
        ↓                       
Attacker Activity (GetCallerIdentity → discovery → collection...)
                    ↓ downstream: what did the attacker do with what they gained?
```

**Upstream questions, in order:**
1. *Who performed the sensitive action, per `userIdentity`?* (`admin-operations` session, per the CreateAccessKey event.)
2. *If it's an assumed role, who assumed it?* → walk back to the matching `AssumeRole` event via `sessionContext.sessionIssuer` + timestamp correlation → `jdoe`.
3. *What authenticated that upstream principal?* → was it jdoe's long-term access key, or an SSO/federated session, or MFA-backed console login? Check the `AssumeRole` event's own `userIdentity` and any preceding `ConsoleLogin`/`GetSessionToken` events for jdoe.
4. *Was that original principal's credential itself compromised, and how?* → this is often where CloudTrail alone runs out of answers — you may need endpoint telemetry (was jdoe's laptop compromised?), VPN/SSO logs (impossible travel, new device fingerprint), or simply corroborate via source IP reputation/geolocation and the human confirmation you already have ("the administrator confirmed they did not perform the action").
5. *Is there anything even further upstream* — e.g., did jdoe's key get created recently by someone else, suggesting jdoe's *account itself* isn't the true origin but rather a previously-compromised admin created jdoe's key too? (Always worth a quick check: when was jdoe's own key created, and by whom?)

**Downstream questions, in order (this is Section 6, applied procedurally):**
1. What did the new credential (or the role session, before it made the new credential) do *next*? Pull every event where `userIdentity.accessKeyId` (for the new key) or the session ARN (for the role session) appears, sorted by time.
2. Classify each action: discovery, collection, privilege escalation, persistence, defense evasion, impact (Section 6).
3. For every *creation* event downstream (new user, new key, new role, modified trust policy, new policy attachment), treat that as a **new branch of the chain** — it may itself have been used, or may still be dormant and waiting. `CreateUser` followed later by `AttachUserPolicy` in your scenario is exactly this: a second identity now needs its own upstream/downstream analysis, independent of the original key.

**The mental shift:** an identity chain investigation isn't a single line, it's a tree. Every `Create*` or `Attach*`/`Put*Policy` event downstream is a potential new root for a new branch. Section 7 (containment) exists specifically because stopping at the first node you found is how attackers keep access after you think you've evicted them.

---

## 6. Categorizing Attacker Activity After Credential Compromise

Mapping your scenario's activity onto these categories (loosely aligned to ATT&CK's structure, which is worth explicitly naming since you already think in these terms) turns a flat event list into an investigative narrative with clear next questions per category.

**Discovery** — `GetCallerIdentity`, `ListBuckets`, `GetBucketPolicy`, `GetBucketEncryption`
*What happened:* the attacker asked AWS "who am I" and then enumerated what's reachable and its protection posture.
*Why an attacker does this:* they rarely know in advance what a stolen credential is worth — discovery is how they build a map before deciding where to spend effort. `GetCallerIdentity` specifically is almost universal as literally the first call after obtaining any new credential, because it confirms the credential works and reveals the exact ARN/account they now hold.
*Investigate next:* what, specifically, did the enumeration reveal was reachable? Cross-reference `ListBuckets` results (in `responseElements`, if data events/detailed logging is on, or infer from subsequent `GetBucketPolicy`/`GetBucketEncryption` calls which named buckets they zeroed in on) — that's your shortlist for "what might have been targeted for collection."

**Collection / possible exfiltration** — `GetObject`, unusual bulk access patterns
*What happened:* actual object reads against S3.
*Why an attacker does this:* the payoff step — reading (and, if they have network egress, exfiltrating) data.
*Investigate next:* volume and selectivity. A handful of `GetObject` calls against config files reads very differently from thousands of calls sweeping an entire bucket. If S3 data-event logging or S3 access logs are enabled, check actual object keys touched, response byte sizes if available, and whether requests originated from AWS-internal IP ranges (data likely stayed in AWS, e.g., copied to an attacker-controlled bucket) vs. external IPs (more direct exfiltration signal).

**Privilege escalation** — attaching powerful policies, modifying permissions, obtaining a stronger role
*What happened:* the effective permission ceiling for some identity increased.
*Why an attacker does this:* the role/user they're currently authenticated as may not be enough for their objective (e.g., they need broader S3 access, or need `iam:*` to build persistence).
*Investigate next:* diff the identity's policy set before/after (if you have point-in-time config, e.g. via AWS Config) — what specifically got added, and does it exceed what the original chain (jdoe → admin-operations) already implied was reachable? If the escalation target *exceeds* admin-operations' own permissions, that's a second, distinct escalation worth its own root-cause question (how did a session with admin-operations' permissions grant itself something admin-operations couldn't already do? — usually it means admin-operations already had `iam:*`, which is itself the finding).

**Persistence** — `CreateUser`, `CreateAccessKey`, creating/modifying roles, modifying trust policies, adding auth mechanisms (e.g., adding an SSH key, an OIDC provider, a Console password), creating alternative access paths
*What happened:* the attacker established access that will outlive the original stolen credential.
*Why an attacker does this:* stolen credentials, especially temporary ones, get revoked. A durable, independent credential (a whole new IAM user, in your scenario) survives even full remediation of the original compromised identity if you don't find it.
*Investigate next:* this category is the one most likely to bite you if under-investigated — Section 8 goes deep on it.

**Defense evasion** — `StopLogging`, `DeleteTrail`, `UpdateTrail` (narrowing scope), `PutEventSelectors` (excluding certain events), deleting/modifying GuardDuty or Config
*What happened:* the attacker degraded your ability to see the rest of their activity.
*Why an attacker does this:* to buy time or permanently blind you to steps they don't want found.
*Investigate next:* **treat any successful defense-evasion event as evidence of a *logging gap*, and explicitly account for what you cannot see during that gap** rather than assuming "no events during that window" means "nothing happened." Also check whether it *failed* (`errorCode: AccessDenied`) — a failed attempt still tells you intent and is often a stronger indicator of malicious purpose than a successful quiet action, precisely because it's noisy and desperate.

**Why the categories matter during an investigation:** they turn "here's a list of 40 API calls" into "here's what the attacker was trying to accomplish, in order" — which lets you predict what to look for next (if you see privilege escalation, go look harder for persistence right after, because that's almost always the next move) and lets you communicate impact to non-technical stakeholders in terms of objectives, not API names.

---

## 7. Containment Reasoning: IOC Containment vs. Attack-Path Containment

**IOC containment** = neutralize the specific artifact you found. "Deactivate the malicious access key." It's necessary, cheap, fast — and by itself, dangerously incomplete, because it only addresses the *symptom* nearest to where you happened to start looking.

**Attack-path containment** = neutralize every point along the *entire chain*, upstream and downstream, that the attacker could still use to regain or retain access, even after the specific IOC is gone.

Applied to your scenario, the full containment checklist:

1. **Original compromised identity (jdoe)** — rotate/deactivate jdoe's static access key (the thing that was actually stolen, presumably); force a credential reset; if console access, force password reset + re-verify MFA enrollment (was it removed or a new MFA device added? — check for that specifically, it's a persistence vector too).
2. **Existing credentials** — enumerate *every* access key jdoe holds (there may be more than one active key on the user) and every other credential type (console password, CLI profile, SSH keys if applicable) — rotate/revoke all, not just the one you assume was used.
3. **STS sessions** — any *currently active* temporary sessions issued off jdoe's or admin-operations' trust cannot simply be "deleted" (STS doesn't support directly revoking a single issued session) — the standard technique is to attach a policy (to the role or via SCP) with a `Deny` conditioned on `aws:TokenIssueTime` earlier than your remediation time, which invalidates all sessions issued before that point the next time they're used. Know this mechanism exists — "you can't revoke STS sessions" is a common and dangerous misconception.
4. **Assumed roles** — for `admin-operations` specifically: has its trust policy been modified (check `UpdateAssumeRolePolicy` history)? Is its own permission set appropriate, or does *it* need tightening (e.g., should it really be able to call `iam:CreateAccessKey` on a backup service account)?
5. **Maliciously created credentials** — the new key on `svc-prod-backup`: deactivate/delete it. Also check whether `svc-prod-backup` had other keys created or reactivated around the same window.
6. **Persistence identities** — the new IAM user created via `CreateUser`: this is a *separate* identity with its own credentials/policies — it must be independently disabled/deleted, and everything *it* touched needs its own downstream check (did it, in turn, create anything?).
7. **Newly attached policies** — the `AttachUserPolicy` event: detach it, and confirm no other policy attachments (managed or inline) occurred elsewhere in the window that you haven't yet found — search broadly for `Attach*Policy`/`Put*Policy` events account-wide in the incident window, not just on the identities you already know about.
8. **Modified trust relationships** — audit every role's trust policy for unexpected principals added during the window (`UpdateAssumeRolePolicy` account-wide search), not just `admin-operations`'.
9. **Potentially compromised resources/data** — every bucket touched by `GetBucketPolicy`/`GetBucketEncryption`/`GetObject`: assess what was exposed/read, whether encryption/keys need rotating, whether affected data requires breach-notification analysis.

**Why attack-path containment must be instinctive:** an attacker who established persistence assumes you'll find and kill the *loudest* artifact (the new access key) and stop looking. Every containment action you take should be followed by the reflex question: *"if I were the attacker and I expected this specific thing to be found and killed, what would I have set up as a fallback?"* That question is what turns Section 8 into muscle memory rather than a checklist you consult once and forget.

---

## 8. IAM Persistence Hunting Reference

For each, the frame is **what happened → why an attacker does it → what to investigate next.**

**`CreateUser`**
*What happened:* a brand-new IAM identity, with its own independent credential lifecycle, now exists.
*Why:* a new user isn't tied to any existing session's expiry, isn't obviously connected to the original compromised identity by name, and gives the attacker a fresh start that survives remediation of everything upstream.
*Investigate next:* who created it (upstream chain again), what credentials/console access it was given, what policies were attached to it (often in the *same* burst of activity — check timestamps within seconds/minutes), whether its name is designed to blend in with legitimate naming conventions (a strong tell when it doesn't quite match your org's actual convention).

**`CreateAccessKey`** (on any user, not just newly created ones)
*What happened:* a new long-term credential now exists for some IAM user.
*Why:* converts a possibly-temporary or possibly-about-to-be-noticed foothold into a durable, independently-usable one — exactly what happened to `svc-prod-backup` in your scenario, and notably this doesn't require creating a *new* user at all; compromising an *existing* user's key inventory works just as well and is stealthier (no new principal to notice).
*Investigate next:* is this the user's only key or an additional one alongside a legitimate existing key (multiple active keys per user is itself worth flagging even outside an incident)? Has the key been used yet, and from where?

**Creating/modifying roles**
*What happened:* a new role exists, or an existing role's permissions/configuration changed.
*Why:* roles don't require a "user" at all to exist as a foothold — if trust is configured right, an attacker with cross-account or federated access can use a role without ever touching IAM users, keys, or anything that shows up in a "list all users" review.
*Investigate next:* what's the role's trust policy (who can assume it) and what's attached to it (what it can do)? Does it correspond to any legitimate change request/ticket?

**Modifying trust relationships (`UpdateAssumeRolePolicy`)**
*What happened:* the set of principals allowed to assume a role changed.
*Why:* as covered in Section 2, this is one of the stealthiest persistence techniques — especially adding an *external account* as a trusted principal, since it requires no visible new identity in your account at all.
*Investigate next:* diff old vs. new trust policy — what principal was added/changed? Is it an ARN in your own account (less alarming, still needs justification) or an external account ID (immediately urgent — cross-reference that account ID against anything known/owned by your org)?

**Adding authentication mechanisms** (new MFA device registration, new SSH public key, new Console login profile/password, new access key on an existing service account, federated identity provider changes — `CreateOpenIDConnectProvider`, `CreateSAMLProvider`, `UpdateSAMLProvider`)
*What happened:* the set of ways to authenticate as some identity, or the set of identity providers AWS will trust, expanded.
*Why:* adding a *federation trust* (new OIDC/SAML provider, or modifying an existing one) is a particularly high-leverage move — it can let an attacker mint valid AWS sessions from an entirely attacker-controlled external identity source, bypassing IAM users/keys altogether.
*Investigate next:* for identity-provider changes especially, treat as maximum severity — verify against change-management records immediately, since legitimate federation setup changes are rare and usually well-documented events.

**Creating alternative access paths** (new Lambda function with a broad execution role and a public function URL / API Gateway trigger, new EC2 instance with an attached privileged instance profile, modifying a Lambda's execution role, adding a resource-based policy granting external access)
*What happened:* compute or resource infrastructure now exists (or was modified) that carries privileged AWS permissions and is reachable independent of any IAM user/role-assumption flow you're watching.
*Why:* this route doesn't require STS `AssumeRole` calls tied to a human-looking principal at all — a Lambda function with a broad role just runs, on the attacker's trigger, and its CloudTrail footprint looks like "normal service activity," which is exactly the camouflage attackers want.
*Investigate next:* enumerate all compute resources created/modified in the incident window, and check what permissions their attached roles/profiles carry — this requires cross-referencing IAM *and* compute-service (Lambda/EC2/ECS) CloudTrail events together, not IAM events alone.

The underlying attacker objective across every item on this list is the same: **decouple future access from anything you're likely to remediate first.** Your hunting posture should mirror that: assume the first thing you found is not the only thing, and specifically go looking for the *quietest*, least user-centric persistence mechanisms (trust policy changes, federation providers, compute-attached roles) — those are the ones that survive a "delete the bad key, disable the bad user" response.

---

## 9. Detection Engineering

For each, the frame is **signal → required telemetry → important fields → correlation → false positives → enrichment → severity → investigation context.**

### 1. Unusual `CreateAccessKey`
- **Signal:** an access key created for a user where key creation is rare/unexpected (especially service accounts that shouldn't self-manage credentials).
- **Telemetry:** CloudTrail management events.
- **Fields:** `userIdentity` (who performed it), `requestParameters.userName` (target), `sourceIPAddress`, `userIdentity.sessionContext` if via assumed role.
- **Correlation:** baseline "who normally creates keys for this user" (ideally: nobody, or a specific automation role only) — deviation from that baseline is the real signal, not the raw event.
- **False positives:** legitimate key rotation by an authorized admin/automation; onboarding.
- **Enrichment:** resolve source IP to ASN/geo; check if the acting identity's session was MFA-authenticated; check target user's tags (is it flagged as a sensitive service account?).
- **Severity:** high if target is a privileged/service account and actor is not the designated rotation automation; escalate further if followed by usage from a new IP shortly after.
- **Investigation context:** immediately pull the upstream `AssumeRole`/authentication event for the acting principal.

### 2. Access key creation followed quickly by usage (this is stronger than #1 alone)
- **Signal:** `CreateAccessKey` followed within a short window (minutes) by an authenticated API call using that exact `accessKeyId`.
- **Telemetry:** CloudTrail, correlated across two event types by `accessKeyId`.
- **Fields:** `responseElements.accessKey.accessKeyId` (from the creation event) joined to `userIdentity.accessKeyId` on subsequent events.
- **Correlation:** this *is* the correlation — a single `CreateAccessKey` event is weak; `CreateAccessKey` → immediate use is a materially stronger composite signal, because legitimate key creation (e.g., handing a new key to a developer) is rarely followed by automated usage within seconds/minutes.
- **False positives:** CI/CD pipelines that programmatically rotate and immediately redeploy with a new key.
- **Enrichment:** compare the source IP of creation vs. first-use — same IP is more consistent with an automated legitimate flow; different IP/ASN is more consistent with exfiltration-then-use-elsewhere.
- **Severity:** high.
- **Investigation context:** this composite pattern is exactly what happened, structurally, in your scenario (new key on `svc-prod-backup`, followed by `GetCallerIdentity` etc.) — build this as an actual correlation rule, not two separate rules.

### 3. Access key creation followed by S3 enumeration
- **Signal:** new key usage immediately followed by `ListBuckets`/`GetBucketPolicy`/`GetBucketEncryption` calls.
- **Telemetry:** CloudTrail, correlated by `accessKeyId` across event types, time-windowed.
- **Fields:** as above, plus `eventName` sequence.
- **Correlation:** sequence matters more than any single event — this maps directly to the Discovery category from Section 6, and a `CreateAccessKey → Discovery` chain within minutes is a strong composite.
- **False positives:** legitimate new automation performing initial self-check/config validation on first run.
- **Enrichment:** did the discovery calls target buckets outside the credential's expected operational scope (e.g., a backup service account enumerating buckets it has no legitimate reason to touch)?
- **Severity:** high, trending critical if followed by `GetObject` against sensitive buckets.
- **Investigation context:** treat the full chain (creation → discovery → collection) as one investigation unit, not three alerts to triage separately.

### 4. `AssumeRole` from unusual infrastructure
- **Signal:** an `AssumeRole` call from a source IP/ASN/user-agent not previously associated with that principal.
- **Telemetry:** CloudTrail, joined against a rolling baseline (e.g., last-30/90-days seen IPs/ASNs per principal).
- **Fields:** `sourceIPAddress`, `userAgent`, `userIdentity.arn`, `requestParameters.roleArn`.
- **Correlation:** stronger when combined with `mfaAuthenticated: false` for a principal that normally MFAs, or with the role being higher-privilege than the principal's routine work.
- **False positives:** legitimate travel, new office/VPN egress IP, new laptop, CI runner IP rotation (cloud-provider IP pools change).
- **Enrichment:** IP reputation/threat-intel lookup, ASN ownership (residential/VPN/hosting provider vs. known corporate range), impossible-travel check against the principal's *other* recent authentication events.
- **Severity:** medium alone, high if the target role is privileged.
- **Investigation context:** exactly the "previously unseen source IP for the administrator" detail in your scenario — this should already be a standing detection, not something discovered ad hoc during triage.

### 5. Privileged role assumption followed by credential creation (the composite version of your whole scenario)
- **Signal:** `AssumeRole` into a privileged role, followed within the same session by `CreateAccessKey` or `CreateUser`.
- **Telemetry:** CloudTrail, correlated by session (match `userIdentity.arn`'s session component / `sessionContext.sessionIssuer` across events).
- **Fields:** role ARN, session name, subsequent `eventName`s within that session.
- **Correlation:** this is the single highest-value composite detection derivable from your scenario — individually, `AssumeRole` into an admin role is routine, and `CreateAccessKey` happens during normal ops too; the *combination within one session*, especially for a role whose normal usage pattern doesn't typically include IAM-credential-management calls, is rare and high-signal.
- **False positives:** legitimate admin onboarding/offboarding work, scripted credential rotation performed through that role by design.
- **Enrichment:** compare against a allowlist of "actions this role is expected to perform" (if you maintain one) or historical baseline of what that role's sessions typically do.
- **Severity:** critical.
- **Investigation context:** this is your scenario's actual shape — build it as a named detection, not a coincidence you noticed once.

### 6. `CreateUser` + privileged policy attachment
- **Signal:** `CreateUser` followed by `AttachUserPolicy`/`PutUserPolicy` granting broad permissions, within a short window.
- **Telemetry:** CloudTrail, correlated by `userName` in `requestParameters` across both events.
- **Fields:** `requestParameters.userName`, `requestParameters.policyArn` (for managed) or the inline policy document (for `PutUserPolicy`).
- **Correlation:** the pairing is the signal — a brand-new user immediately granted admin-tier access, especially outside normal provisioning workflows/ticketing systems.
- **False positives:** legitimate automated provisioning (Terraform/CloudFormation user creation) — differentiate by actor identity (was it your IaC pipeline's known role, or an ad hoc human/session?).
- **Enrichment:** cross-reference against change-management/ticketing system for a matching authorized request.
- **Severity:** critical if actor isn't the designated provisioning automation.
- **Investigation context:** directly mirrors the end of your scenario's kill chain.

### 7. Role trust-policy modifications
- **Signal:** any `UpdateAssumeRolePolicy` event, especially adding a new/external/unrecognized principal.
- **Telemetry:** CloudTrail.
- **Fields:** `requestParameters.policyDocument` (diff old vs. new — requires either storing previous state or pulling from AWS Config's configuration history), `requestParameters.roleName`.
- **Correlation:** even standalone, this event is rare enough in most environments to warrant near-100%-review alerting; correlate with actor identity and whether that identity normally administers IAM roles.
- **False positives:** legitimate infrastructure changes (new cross-account integration being set up on purpose).
- **Enrichment:** resolve any newly-added AWS account ID — is it a known partner/sub-account, or unrecognized?
- **Severity:** critical by default; this should be one of your lowest-tolerance alerts given how stealthy the technique is.
- **Investigation context:** Section 2/8 covered why this deserves outsized attention relative to how "quiet" a single event looks.

### 8. CloudTrail defense evasion
- **Signal:** `StopLogging`, `DeleteTrail`, `UpdateTrail` (narrowing multi-region/management-event scope), `PutEventSelectors` excluding event types.
- **Telemetry:** CloudTrail logging *itself* about changes to CloudTrail (and ideally a redundant/independent log stream — e.g., CloudTrail delivering to a security-account S3 bucket the primary account can't touch — since this is exactly the category an attacker might try to blind).
- **Fields:** `eventName`, `requestParameters.name` (trail name), actor identity.
- **Correlation:** treat any success here as maximal severity regardless of surrounding context — there's essentially no benign reason for this outside planned, ticketed maintenance.
- **False positives:** legitimate trail reconfiguration during infrastructure changes (should be rare and ticketed).
- **Enrichment:** confirm whether an SCP should have blocked this (and if it succeeded anyway, that's a control-gap finding in itself); check for a redundant log destination that captured activity during any resulting gap.
- **Severity:** critical, always.
- **Investigation context:** explicitly bound and report the time window of reduced visibility this created, and treat that window as evidentially uncertain rather than "clean" by absence of logged events.

### 9. Suspicious chains of IAM activity (the general pattern behind all of the above)
- **Signal:** any sequence combining 2+ of: unusual `AssumeRole` → credential/user creation → policy attachment/trust modification → discovery → collection → defense evasion, correlated by session/actor within a bounded time window.
- **Telemetry:** CloudTrail, correlated across event types and time.
- **Fields:** session/actor linkage fields across all involved events.
- **Correlation:** this is a state-machine/sequence-detection problem, not a single-event or even single-pair rule — the strongest version of this detection tracks a session's full activity graph and scores based on how many Section-6 categories it touches, in what order.
- **False positives:** decrease sharply as more categories chain together (a session that does discovery *and* creates persistent credentials *and* attaches broad policies is very rarely a benign coincidence).
- **Enrichment:** full timeline reconstruction per session, MITRE-style category tagging (Section 6) per event, source IP/ASN reputation.
- **Severity:** scales with number of categories/chain length — this is naturally your highest-confidence, highest-severity detection class.
- **Investigation context:** this is the shape Sentinel-Pipeline should grow toward (Section 10).

---

## 10. Mapping This Onto Sentinel-Pipeline

You currently: read JSON events, loop through them, inspect fields, and detect `CreateUser`/`DeleteTrail`/`StopLogging` as individual events. That's a solid, correct foundation — single-event detection logic. Everything below **extends** that, it doesn't replace it.

```
JSON events
   ↓
normalization
   ↓
identity extraction
   ↓
event classification
   ↓
correlation
   ↓
identity-chain reconstruction
   ↓
risk scoring
   ↓
MITRE mapping
   ↓
alert/investigation output
```

Here's how each stage grows naturally out of what you already have, kept at your current Python level (dicts, loops, functions — no need for a framework or a database yet):

**Normalization** — you're already doing `event["eventName"]`-style field access. Formalize it: write one function, `normalize(event) -> dict`, that pulls the handful of fields you actually care about (`eventTime`, `eventName`, `eventSource`, `sourceIPAddress`, `userIdentity.type`, `userIdentity.arn`, `userIdentity.sessionContext`, `requestParameters`, `responseElements`, `errorCode`) into a flat, consistent shape, so every later stage works off the same clean structure instead of re-navigating nested JSON everywhere.

**Identity extraction** — a function, `extract_identity(event) -> dict`, returning something like `{"type": "AssumedRole", "arn": ..., "session_name": ..., "assumed_role_arn": ..., "access_key_id": ...}`. This is what lets later stages ask "which events belong to the same principal/session" without re-parsing ARNs every time.

**Event classification** — you already detect specific `eventName`s. Generalize the pattern you have into a lookup: a dict mapping `eventName → category` (Discovery, Collection, Persistence, PrivilegeEscalation, DefenseEvasion), built directly from Section 6's lists. `CreateUser`/`DeleteTrail`/`StopLogging` slot straight in — you're just adding more entries and a category label alongside your existing per-event checks, not rewriting them.

**Correlation** — the first genuinely new capability: group your normalized events by a shared key (session ARN, or `access_key_id`) using a plain `dict` of lists (`sessions[key].append(event)`), then within each group, check for the *pairs* from Section 9 (e.g., a `CreateAccessKey` followed within N minutes by a usage event with that same key). This is still just loops and dict/list logic — no new libraries required.

**Identity-chain reconstruction** — for a given session's events, walk backward: find the `AssumeRole` event (if any) whose resulting session matches this session's identity, then note *its* caller as the upstream principal. A small function, `find_upstream(session_events, all_events) -> arn | None`, doing exactly this lookup is a natural, scoped next feature.

**Risk scoring** — once events are categorized (stage 3) and grouped (stage 4), a simple additive score per session (e.g., +2 for Persistence, +2 for PrivilegeEscalation, +1 for Discovery, +3 for DefenseEvasion, +1 for unusual source IP if you maintain a simple seen-IPs baseline file) gives you a ranked output instead of an undifferentiated event list — still just arithmetic over your classified events, no ML needed yet.

**MITRE mapping** — extend your category-lookup dict (stage 3) with an extra field per entry: the ATT&CK technique ID (e.g., `CreateAccessKey → Persistence → T1098` "Account Manipulation," `AssumeRole` misuse → `T1550`/`T1078` territory, `StopLogging`/`DeleteTrail` → `T1562.008` "Impair Defenses: Disable Cloud Logs"). This is a data addition to something you've already built, not new logic.

**Alert/investigation output** — for each scored session, print/write a small structured summary: identity chain, categorized event list in order, score, and the top-line "what happened" — essentially Section 5 and Section 6 of this lesson, generated automatically from your own pipeline's output.

**Suggested next concrete step**, sized to not overreach your current stage: take your existing single-event detector, add the classification-dict step (stage 3) alongside it, and build *just* the `CreateAccessKey`-followed-by-usage correlation (stage 5, detection #2 from Section 9) as your first correlation feature. That's a self-contained, testable unit that directly operationalizes the scenario you just worked through, and every later stage builds on the same grouping logic you'll write for it.

---

## 11. Defender's Reference Sheet

**Identity**
Who performed this — an IAM user directly, or a role session (check `userIdentity.type`)? If a role session, what authenticated the principal that assumed it — a static key, federation, console MFA? What is the *effective* permission set for that principal right now — have you checked identity-based policy, permissions boundary, SCP, and any relevant resource-based policy, not just one document?

**Activity**
What API calls occurred, in what order? What resources (by ARN) did they touch? For each call: read, modify, create, or delete — and which Section-6 category does it belong to (discovery / collection / privilege escalation / persistence / defense evasion / impact)?

**Blast radius**
What could this identity reach, given its full effective permission set — not just the one action you happened to alert on? What credentials did it create? What other roles did it (or anything it created) assume or gain trust to assume?

**Persistence**
Were any users, keys, roles, policies, or trust relationships created or modified during the window? Does every `Create*`/`Attach*`/`Put*`/`Update*Policy` event have an independent, legitimate explanation you've actually verified — not assumed?

**Containment**
Have you killed the specific credential (IOC containment)? Have you also killed the upstream access path that produced it (attack-path containment)? Have you removed every persistence mechanism you found, and actively hunted for the quiet ones (trust policy edits, federation provider changes, compute-attached roles)? Have you determined, with evidence rather than assumption, whether data/resources were actually affected?

---

*(Section 12 — your test scenario — follows in the chat as an interactive exercise, not in this file, since I'll be reacting to your answers one at a time rather than handing you a static write-up.)*
