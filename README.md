# CRTO I — Study Pack

Exam-day reference and mock walkthrough for the Zero Point Security **Certified Red Team Operator (Red Team Ops I)** practical exam.

## Files

| File | What it is |
|---|---|
| **`CRTO-Playbook.html`** | **Open this during the exam.** Self-contained, offline. Search (`/`), collapsible sections, dark/light theme. |
| `CRTO-Playbook.pdf` | 95-page print version (A4) — cover page, expanded sections, page-break rules. |
| `CRTO-Playbook.md` | Editable source; grep it, add your own notes and action log. |
| **`CRTO-Mock-Exam.html`** | Interactive end-to-end walkthrough with decision points and hidden answers. |
| `CRTO-Mock-Exam.pdf` | 12-page print version of the walkthrough. |
| `CRTO-Mock-Exam.md` | Editable source of the walkthrough. |
| `src/` | Playbook section sources (one file per phase/appendix). |
| `build/build.py` | Rebuilds the playbook `.md` and `.html` from `src/`. |
| `build/build_mock.py` | Rebuilds the mock exam `.html` from its `.md`. |
| `build/make_pdfs.ps1` | Regenerates both PDFs with headless Chrome/Edge. |

## Open

```powershell
start CRTO-Playbook.html
start CRTO-Playbook.pdf
start CRTO-Mock-Exam.html
```

## Rebuild

```powershell
# 1. Rebuild the HTML/Markdown
python build/build.py
python build/build_mock.py

# 2. Rebuild both PDFs (Chrome or Edge)
powershell -ExecutionPolicy Bypass -File build/make_pdfs.ps1
```

Requires the Python `markdown` package (already installed).

## How to use the pack

### Playbook (exam day)

1. Open `CRTO-Playbook.html`.
2. Press `/` to search — e.g. "kerberoast", "rportfwd", "4662", "AppLocker".
3. Click any section heading to collapse/expand it.
4. Use the sidebar to move between phases.
5. Keep `CRTO-Playbook.md` open in an editor for your own action log.

### Mock exam (study)

1. Open `CRTO-Mock-Exam.html`.
2. Read the brief and each **Decision Point**.
3. Write your answer before opening the `<details>` answer.
4. Run the scenario in a lab if you can — command recall is the point.
5. Score yourself with Section 12.

## Important

- **Verify the current exam format** in your Candidate Handbook/portal — it has changed more than once. Public reports disagree on 24 vs 48 active hours.
- Items marked **⚠** in the playbook are version/build/kit dependent; test them in the lab.
- The mock scenario is **fictional** — invented domain, hosts, users, and objective. It is not the real exam.
- This is a study aid. The exam grades execution and OPSEC, not recall.
- Use only in authorized labs and the exam environment.
