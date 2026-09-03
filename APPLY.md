# First apply (Robert)

Do this on **DESKTOP-DMVUP78**. Open PowerShell in this folder. The command is `terraform` (not `tf`).

Do **not** apply from an agent. Do **not** skip steps. Do **not** start with a bare `terraform apply`.

Git default for switches is **15,000**. A bare `terraform apply` pushes all of them. First apply on a blank ISE is **no switches**.

This first apply still pushes policy, **150,000** endpoints, and **8** lab users. That can take many hours. Stay on this PC. Do not close the window.

## If apply dies

**STOP.**

- Do **not** run `terraform destroy`
- Do **not** start a second apply
- Do **not** toast the ISE box
- Leave this folder as it is. The state file in this folder is how we recover. You cannot fix a half-imported ISE.
- Tell CoS

A 150k test was killed at about 5 hours on a VM. Same rule: stop. Tell CoS.

---

## 1. New ISE box is up

The new ISE must already be running.

In the ISE GUI:

1. **Administration → System → Settings → API Settings**
2. Turn on **ERS**
3. Turn on **Open API**
4. Confirm **Device Admin / TACACS** is licensed

This is still required **before** Terraform. It was never lifted. If ERS, Open API, or Device Admin is off, stop. Tell CoS. Do not apply.

## 2. ISE user named `terraform`

Terraform logs in as a Super Admin user named **`terraform`**.

This is **not** the first-boot user `iseadmin`. Do not mix the two passwords.

- `.env.example` still shows `ISE_USERNAME=iseadmin` (that line is for first-boot setup)
- For apply you must set `ISE_USERNAME=terraform`

If the `terraform` user is missing, stop. Tell CoS. Do not apply as `iseadmin`.

## 3. Pull this folder

Open PowerShell **in this folder**.

Paste this. Look at the output. It must show `github.com/QB4DEVOPS/ise-nac`. If it shows `cisco` or anything else, stop. Tell CoS.

```
git remote -v
```

Then paste:

```
git pull origin main
```

Your clone may still track `cisco/main`. Origin for this work is **https://github.com/QB4DEVOPS/ise-nac**. Pull `main` from that origin.

## 4. Fill `.env`

If `.env` is missing, paste:

```
copy .env.example .env
```

Then:

```
notepad .env
```

Set these lines. Do not change the first-boot lines (`ISE_HOSTNAME`, gateway, DNS, and the rest).

```
ISE_HOST=192.168.1.90
ISE_USERNAME=terraform
ISE_PASSWORD=
NAD_TACACS_SECRET=
NAD_RADIUS_SECRET=
USER_PASSWORD_DEFAULT=
```

- `ISE_PASSWORD` is the **`terraform` user** password. Not the `iseadmin` password.
- Fill `NAD_TACACS_SECRET`, `NAD_RADIUS_SECRET`, and `USER_PASSWORD_DEFAULT`.
- You may leave `USER_ENABLE_PASSWORD_DEFAULT` empty. It reuses the login password.

Save. Close Notepad.

**Never commit `.env`.** Do not send it. Do not paste passwords into chat.

## 5. Load `.env` into this window

If PowerShell says scripts are disabled, paste this first:

```
Set-ExecutionPolicy -Scope Process Bypass
```

Then paste (same window):

```
. .\load-env.ps1
```

That reads `.env` for this window only. Keep this window open for the rest of the steps.

## 6. `terraform init`

Paste:

```
terraform init
```

ISE does **not** need to be reachable for init. Init only downloads the Cisco ISE plugin.

Wait until it finishes. If init fails, stop. Tell CoS. Do not apply.

## 7. First apply — no switches

Stay in the **same** PowerShell window.

Paste **both** lines. Do not skip the first line.

```
$env:TF_VAR_nad_count = "0"
terraform apply
```

When it asks you to confirm, type `yes` and press Enter.

Git default `nad_count` is **15000**. If you forget the first line, Terraform pushes **15,000 switches**. Set `0` unless you want 15,000 switches.

## 8. Endpoints are 150,000 — not 110

You do **not** set an endpoint count. The Git default is **150000**.

That file is `endpoints_enterprise.csv`:

- 71,000 desks (phone and PC on the same port)
- 8,000 other gear
- 11 groups
- VLANs 10–70

The small lab file `endpoints.csv` (**110**) stays in Git only. Terraform does not apply it.

Do **not** apply 150,000 plus 110. A Small ISE tops out at 150,000.

## 9. Users are 8

You do **not** set a user count. The Git default is **8**.

Passwords come from `.env` (`USER_PASSWORD_DEFAULT`). Not from Git.

## 10. Optional checks (recommended)

Do these in the **same** window **before** apply, after step 6. Skip them if Python or the check is not installed. They do not talk to ISE except `terraform plan`.

Check the files (same commands as README):

```
pip install nac-validate
nac-validate nac.yaml sites.yaml location_ndgs.yaml endpoint_identity_groups.yaml endpoints.yaml allowed_protocols.yaml authorization_profiles.yaml network_access.yaml users.yaml -s .schema.yaml -r .rules
```

If that prints errors, do not apply. Tell CoS.

See the plan (no switches):

```
$env:TF_VAR_nad_count = "0"
terraform plan
```

Then apply (step 7). Set `0` again if you opened a new window.

---

## After a good first apply

Leave this folder as it is. Tell CoS it finished.

Do not run `terraform apply` again unless CoS says so.

Do not run `terraform destroy`.

15,000 switches is a later apply. That is not this runbook.
