# SOC Alert Triage and Investigation Assistant

An AI-powered, hybrid detection system that helps Security Operations Center (SOC) analysts triage network security alerts faster — combining machine learning, behavioral anomaly detection, MITRE ATT&CK mapping, real-time threat intelligence, and LLM-based reasoning, all wrapped in a live-updating dashboard.

**Live demo:** [soc-ai-alert-triage.streamlit.app](https://soc-ai-alert-triage.streamlit.app/)

---

## Screenshots

**Live dashboard**
![Dashboard overview](<img width="1920" height="1200" alt="Live-Dashboard-Demo" src="https://github.com/user-attachments/assets/27763ece-b1c6-42b5-8247-da0fc2c8ec46" />
)

**Terminal output — model training and detection report**
![Terminal classification report](<img width="1920" height="1200" alt="Terminal-output" src="https://github.com/user-attachments/assets/f7680413-babf-4ecd-a572-12f2069eba6a" />
)

**Architecture diagram**
![Architecture diagram](<img width="892" height="1024" alt="architecture" src="https://github.com/user-attachments/assets/d0df41a0-da3c-44f7-bdae-ec59823cb81f" />
)

**Process flowchart**
![Flowchart](<img width="770" height="1024" alt="Flowchart" src="https://github.com/user-attachments/assets/e1dd8135-5654-4a06-8648-f1352bd69b93" />
)

---

## Why this project exists

SOC analysts are overwhelmed by alert volume, and most of it is noise. This project explores a practical question: **can a layered AI pipeline reduce that noise while keeping a human in control of every consequential decision?**

Rather than building a single black-box classifier, this project deliberately separates detection into independent layers — each with a clear job, a measurable limitation, and a human checkpoint at the end. The goal was not just to build something that works on clean data, but to understand *where* and *why* AI-based detection breaks down, and to design around those failure points honestly.

---

## Architecture

```
Network flow data (CICIDS2017)
        |
        v
Layer 1 — Signature-based detection (Random Forest)
        |  known attack type + confidence score
        v
Layer 2 — Behavioral anomaly detection (Isolation Forest)
        |  flags novel / low-confidence patterns
        v
Enrichment — MITRE ATT&CK mapping + VirusTotal threat intelligence
        |  technique, tactic, real-world IP reputation
        v
Layer 3 — AI reasoning
        |  plain-language summary, risk level, suggested action
        v
Live dashboard (Streamlit)
        |  auto-refreshing alert feed
        v
SOC analyst — final decision
   escalate / block IP / ignore / mark false positive
```

Every alert that reaches the analyst carries its full reasoning trail — what triggered it, how confident the model was, what MITRE technique it maps to, whether the source IP has a real-world reputation, and a plain-language explanation of the risk. The system never takes an irreversible action on its own; it recommends, the analyst decides.

---

## What each layer does

### Layer 1 — Signature-based detection
A Random Forest classifier trained on the CICIDS2017 dataset (2.3M+ network flow records across 8 attack categories) to recognize known attack signatures — DDoS, port scans, brute-force attempts, botnet traffic, and web attacks. Extremely rare classes (fewer than 50 samples, e.g. Heartbleed, SQL injection) were grouped into a single `Rare_Attack` category rather than force-fit into a supervised model that couldn't realistically learn them — that responsibility was handed to Layer 2 instead.

Every prediction carries a confidence score. Low-confidence predictions are treated differently downstream rather than being trusted blindly.

### Layer 2 — Behavioral anomaly detection
An Isolation Forest trained exclusively on benign traffic, so it learns what "normal" looks like rather than what any specific attack looks like. This lets it catch patterns Layer 1 was never trained on.

**Honest finding:** row-level anomaly detection performs well on volume-based attacks (DoS Hulk: 81.7% flagged, DoS Slowhttptest: 79%) but performs poorly on sequential attacks like SSH/FTP brute-force (0% flagged). The reason is structural, not a tuning problem — a single brute-force login attempt looks identical to a normal login at the row level; the signal only exists across many rows over time. Fixing this properly would require session-based or time-windowed features, which the flow-level dataset used here doesn't support. This is documented rather than hidden, because understanding a model's blind spots matters more than a clean-looking metric.

### Enrichment — MITRE ATT&CK + threat intelligence
Every detected attack type is mapped to its corresponding MITRE ATT&CK technique and tactic (e.g. PortScan → T1046, Discovery), giving analysts a standardized reference point instead of a raw label.

Source IPs are checked against the VirusTotal API for real-world reputation data. This surfaced genuinely interesting corroborating evidence during testing — one detected "Bot" alert resolved to a known Tor exit node with 15 vendor malicious flags, and a detected "DDoS" alert resolved to an unconfigured nginx server (a common pattern for cheap, disposable C2 infrastructure) with 18 vendor flags. Threat intelligence is used to *support* the ML signal, not replace it — a Tor exit node isn't proof of an attacker, just increased risk that the analyst should weigh with context.

### Layer 3 — AI reasoning
Takes the combined output of Layers 1, 2, MITRE mapping, and threat intel, and produces a plain-language summary, a risk level (Low/Medium/High), and a suggested next step. The system is explicitly designed to be provider-agnostic — the reasoning function can run on a lightweight rule-based fallback or a full LLM API call without changing anything downstream, so it degrades gracefully rather than breaking if an API is unavailable.

The output always ends with the same line: **this is a recommendation only — final action must be confirmed by a human SOC analyst.**

### Live dashboard
A Streamlit dashboard that auto-refreshes to simulate a real-time alert feed, pulling live predictions from the actual trained model rather than static mock data. Analysts can escalate, block, ignore, or mark an alert as a false positive — and that decision is permanently reflected on the alert card, creating a simple audit trail of what action was taken and by implication, when.

---

## Why human-in-the-loop, deliberately

This was a design principle from the start, not an afterthought:

- **False negatives are dangerous** — a model can miss a real attack it wasn't trained to recognize.
- **False positives cause alert fatigue** — an oversensitive model burns analyst trust and attention.
- **LLMs can hallucinate** — an AI-generated explanation is treated as a summary to verify, never as ground truth.
- **Threat intelligence needs context** — a "malicious" flag on a Tor exit node means something different than the same flag on a residential IP.

No layer in this system is allowed to take a final, irreversible action by itself. The AI's job is to reduce the analyst's search space and explain its reasoning; the decision authority stays with the human.

---

## Tech stack

| Component | Technology |
|---|---|
| Dataset | CICIDS2017 (network flow data) |
| Known attack detection | scikit-learn (Random Forest) |
| Anomaly detection | scikit-learn (Isolation Forest) |
| Threat intelligence | VirusTotal API |
| AI reasoning | Rule-based fallback / LLM API (provider-agnostic) |
| Dashboard | Streamlit, custom CSS |
| Deployment | Streamlit Community Cloud |

---

## Known limitations

Documented deliberately, because a project that only shows what works isn't a complete picture:

- Sequential/temporal attacks (brute-force, some scanning) are harder to catch with row-level features — see Layer 2 findings above.
- Class imbalance in the training data means very rare attack types have limited supervised signal; they're routed to anomaly detection instead of forced through the classifier.
- Threat intelligence lookups depend on VirusTotal's free-tier rate limits.
- The live dashboard uses a representative sample of IPs for demonstration; it is not connected to live production network traffic.

---

## Running locally

```bash
git clone https://github.com/gauravkale391-blip/soc-ai-alert-triage.git
cd soc-ai-alert-triage
python3 -m venv soc_env
source soc_env/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

You'll need a VirusTotal API key (free tier) in a `.env` file:
```
VIRUSTOTAL_API_KEY=your_key_here
```

---

## What's next

- Session/time-windowed features to improve sequential attack detection in Layer 2
- Persistent storage for alert history instead of in-session state
- Support for additional threat intelligence sources beyond VirusTotal
- A feedback loop where analyst-marked false positives retrain the model over time

---

## Author

Built by Gaurav B Kale as a hands-on project to understand how AI actually fits into SOC operations — not just as a black box that flags things, but as a system whose reasoning, confidence, and limitations are all visible to the person who has to act on it.
