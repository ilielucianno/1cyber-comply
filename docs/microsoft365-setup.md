# Connecting Microsoft 365 / Entra ID

1cyber Comply reads your tenant through Microsoft Graph with an **app registration that can only
read**. Nothing is changed in your tenant, and you can revoke access at any time by deleting the
app registration. The setup takes about 10 minutes and needs a Global Administrator once, to
grant consent.

## What is checked

| Check | NIS2 control | Needs Entra ID P1? |
|---|---|---|
| MFA enforced (security defaults or a Conditional Access policy for all users) and registered by every enabled member account | 21(2)(j) MFA | No. With P1 the registration report is used; without it, each user's methods are read |
| 2-4 Global Administrators, every admin has MFA | 21(2)(i) least privilege | No |
| No enabled account unused for 90+ days (members and guests) | 21(2)(i) joiner/mover/leaver | **Yes** (last sign-in dates). Without P1 the check reports *unknown* |

Microsoft 365 Business Premium, E3 and E5 include Entra ID P1.

## 1. Register the app

1. Sign in to the **Microsoft Entra admin center** (https://entra.microsoft.com) as a Global Administrator.
2. **Identity → Applications → App registrations → New registration**.
3. Name: `1cyber Comply (read-only)`. Supported account types: *this organizational directory only*.
   Redirect URI: leave empty. Click **Register**.
4. On the overview page, copy the **Application (client) ID** and the **Directory (tenant) ID**.

## 2. Grant read-only permissions

1. **API permissions → Add a permission → Microsoft Graph → Application permissions**.
2. Add exactly these permissions, all read-only:

| Permission | Why |
|---|---|
| `User.Read.All` | list users, guests and whether accounts are enabled |
| `Policy.Read.All` | security defaults and Conditional Access policies |
| `RoleManagement.Read.Directory` | who holds administrator roles |
| `AuditLog.Read.All` | MFA registration report and last sign-in dates (Entra ID P1) |
| `UserAuthenticationMethod.Read.All` | **only for tenants without Entra ID P1**: each user's MFA methods |

3. Remove the default delegated `User.Read` permission if you want the minimum.
4. Click **Grant admin consent for <your organisation>** and confirm. Every permission must show a
   green check.

## 3. Create a client secret

1. **Certificates & secrets → Client secrets → New client secret**.
2. Description `1cyber Comply`, expiry **12 months**. Click **Add**.
3. Copy the **Value** immediately (it is shown only once). Not the Secret ID.

Write the expiry date in your calendar: when the secret expires, the Microsoft 365 checks turn
*unknown* until you create a new one.

## 4. Configure 1cyber Comply

Add to `/opt/1cyber-comply/.env`:

```
M365_TENANT_ID=<Directory (tenant) ID>
M365_CLIENT_ID=<Application (client) ID>
M365_CLIENT_SECRET=<secret value>
M365_STALE_DAYS=90
```

Apply and test:

```bash
cd /opt/1cyber-comply && sudo docker compose up -d --force-recreate
```

In the dashboard, **Microsoft 365 → Test connection** should show your tenant name, then
**Collect now**.

## Revoking access

Delete the app registration (**App registrations → 1cyber Comply (read-only) → Delete**), or just
the client secret. 1cyber Comply stops reading immediately; evidence already collected stays in
its database.

## Privacy note

The checks read user principal names, account state, admin roles, sign-in dates and which MFA
method types are registered. They do not read mail, files, phone numbers or passwords. Results
are stored only in your 1cyber Comply database.
