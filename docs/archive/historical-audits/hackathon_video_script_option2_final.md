# VigilAgent Hackathon Video Script - Option 2 Final

Target duration: 4 minutes 20 seconds  
Submission mode: Video, not presentation  
Hackathon theme: Agentic and Autonomous Systems  
Project: VigilAgent, an autonomous AI-powered penetration testing platform  

Poster rule fit:
- Explain the problem.
- Explain the solution.
- Show key features.
- Show a real demo or clearly label a workflow/architecture demo.
- Keep the video between 2 and 5 minutes.
- Make the project understandable from the video alone.
- Include the GitHub repository link in the submission and final video screen.

Important honesty note: Do not claim a live exploit, live backend scan, or live vulnerability result unless it is visible and actually running during recording. If the backend is not stable during recording, use the contingency line in Scene 3.

---

## Why This Version Is Better Than The 8-Minute Draft

The partner draft has strong technical content, but it is too long for Option 2 and spends too much time on internal architecture. Judges need to understand the project quickly: problem, solution, demo, why it is agentic, real-world impact, and what is actually built.

This version keeps the strongest parts: Hive Mind agents, scoped scanning, live dashboard, browser extension, AI reasoning, evidence validation, reports, and backend depth. It removes overly detailed implementation claims, avoids "zero false positives" language, and fits the 2-5 minute video rule.

---

## Video Structure

| Time | Segment | What To Show |
| --- | --- | --- |
| 0:00-0:20 | Hook | Dashboard opening, project name, theme |
| 0:20-0:55 | Problem | Dashboard risk cards and threat monitor |
| 0:55-1:45 | Demo workflow | New Scan page, scope, modules, auth, controls |
| 1:45-2:35 | Agentic system | Library page, Hive Mind agents, Arsenal |
| 2:35-3:20 | Evidence and reporting | Live Monitor, AI Decision Logic, Scans/reports |
| 3:20-3:55 | Technical proof | Repository folders and architecture files |
| 3:55-4:20 | Impact and close | Dashboard final screen, GitHub link |

Recommended video title:
`VigilAgent - Autonomous AI Security Swarm | FAR AWAY 2026`

---

## Final Voiceover Script

### Scene 1 - Opening Hook, 0:00-0:20

Visual:
Open the VigilAgent dashboard. Start on the main page with the name, live risk score, activity cards, and threat monitor visible. Move slowly; do not rush the first impression.

On-screen text:
`VigilAgent - Autonomous AI Security Swarm`

Voiceover:
"Hi, we are Team [TEAM NAME], and this is VigilAgent, our project for the Agentic and Autonomous Systems theme.

VigilAgent is an autonomous AI-powered penetration testing platform. Instead of acting like a normal scanner, it works like a coordinated security swarm that can plan, investigate, validate, explain, and report security risks."

---

### Scene 2 - Problem, 0:20-0:55

Visual:
Show the dashboard cards: live risk score, active scans, injection-related cards, deceptive UI detection, scan activity, and live threat monitor.

On-screen text:
`Problem: Modern security testing is slow, fragmented, and hard to explain`

Voiceover:
"Modern applications change very fast. New APIs, authentication flows, payment logic, hidden endpoints, and AI prompt surfaces can appear before a security team has time for a full manual review.

Traditional tools usually test one layer at a time and often produce noisy results. Developers then have to ask: what happened, why does it matter, and is there real evidence?

VigilAgent is designed to solve that gap by combining automation, agentic reasoning, live monitoring, and explainable evidence in one workflow."

---

### Scene 3 - Demo: New Scan Workflow, 0:55-1:45

Visual:
Go to `Scans` or `New Scan`. Enter a safe demo target, preferably a local intentionally vulnerable lab or authorized demo target. Show scope controls, filters, modules, authentication options, request-rate controls, concurrency controls, and the launch action.

On-screen text:
`Scope -> Modules -> Controls -> Evidence`

Voiceover:
"This is the New Scan workflow. The operator starts by defining a target scope, because in security automation, scope control is critical.

Then VigilAgent lets us choose the risk areas and attack modules. The system includes modules for SQL injection, JWT weaknesses, authentication bypass, REST fuzzing, IDOR, privilege escalation, workflow bypass, race conditions, and financial logic tampering.

We can also provide authentication context, tune request rate and concurrency, and connect browser-side intelligence through the companion extension. The goal is not uncontrolled scanning. The goal is a guided, authorized assessment where every action stays inside the defined scope."

Contingency line if backend is not running during recording:
"For this recording, we are showing the frontend workflow and system architecture. The backend engine is included in the repository, but this video focuses on the submission demo interface and design."

Do not use the contingency line if a real backend scan is running successfully.

---

### Scene 4 - Agentic Architecture: The Hive Mind, 1:45-2:35

Visual:
Open `Library`. Show the Hive Mind agent cards and the Arsenal modules. Scroll slowly enough that judges can read agent names.

On-screen text:
`Hive Mind: specialized agents working together`

Voiceover:
"The core innovation is the Hive Mind. VigilAgent is built around specialized agents, each with a clear role.

Omega acts as the strategist and coordinates the campaign.
Alpha maps the attack surface through reconnaissance.
Beta tests technical weaknesses and executes safe payload checks.
Gamma validates findings and looks for supporting evidence.
Sigma helps generate payloads and scoring context.
Kappa stores patterns and memory from previous scans.
Zeta manages safety, throttling, and governance.

This is what makes the project agentic. The system is not just running scripts. Agents share context, react to events, and use previous observations to decide what should happen next."

---

### Scene 5 - Live Monitoring, Explainability, and Reports, 2:35-3:20

Visual:
Return to the dashboard or open `Live Monitor`. Show live event rows if available. Show `AI Decision Logic` or any panel that explains findings. Then show the Scans/report area.

On-screen text:
`Live Threat Monitor + AI Decision Logic + Reports`

Voiceover:
"During an assessment, VigilAgent streams activity into a live security console. Events can include the responsible agent, target, threat category, severity, confidence, and risk score.

One of the most important features is explainability. VigilAgent is designed to explain not only what it found, but why the finding matters and what evidence supports it.

The reporting workflow is built for real teams. Security engineers need technical detail, developers need remediation guidance, and leadership needs a clear risk summary. VigilAgent aims to connect all three."

---

### Scene 6 - Technical Proof From The Repository, 3:20-3:55

Visual:
Switch briefly to the repository. Show these folders/files:
- `src/components`
- `backend/agents`
- `backend/core`
- `backend/ai` if present, or `backend/core/cognitive_router.py` and `backend/core/llm_router.py`
- `extension`
- `docker-compose.yml`
- `README.md`

On-screen text:
`React + FastAPI + WebSockets + Agent Swarm + Browser Extension + Docker`

Voiceover:
"Behind the interface, VigilAgent is a full-stack project.

The frontend is built with React, Vite, Tailwind, and Framer Motion. The backend uses FastAPI, WebSockets, asynchronous orchestration, scope enforcement, an event-driven core, and agent modules for reconnaissance, attack simulation, validation, memory, governance, and learning.

The browser extension adds client-side inspection for DOM analysis, prompt injection surfaces, secret detection, and deceptive UI monitoring. Docker support provides a path toward repeatable deployment."

---

### Scene 7 - Impact, Future Scope, and Close, 3:55-4:20

Visual:
Return to the dashboard or Library page. End on a clean final screen with:
- Project name
- Team name
- GitHub repository link
- Theme name

On-screen text:
`VigilAgent - A Hive Mind for Modern Application Security`

Voiceover:
"VigilAgent is our vision for autonomous security assessment: define the scope, activate the swarm, monitor the evidence, understand the reasoning, and export the report.

Our next steps are backend hardening, safer vulnerable-lab demos, stronger reporting, deeper learning between scans, and integrations for enterprise security teams.

This is VigilAgent, a Hive Mind for modern application security. Thank you."

---

## Natural Presenter Version

Use this if you do not want to sound like you are reading word-for-word:

"VigilAgent is not just a vulnerability scanner. It is an autonomous security swarm.

The operator defines the scope, chooses modules, configures authentication and performance, and then the agents work together. Omega plans, Alpha scouts, Beta tests, Gamma validates, Sigma builds payload context, Kappa remembers patterns, and Zeta keeps the system controlled.

The dashboard gives live risk, scan activity, threat monitoring, AI decision logic, and reporting. The browser extension adds DOM inspection, prompt injection detection, secret detection, and deceptive UI monitoring.

The main value is explainability. VigilAgent is designed to show what was found, why it matters, and what evidence supports it. That makes the output useful for developers, auditors, and security teams."

---

## Recording Checklist

1. Keep the video between 2 and 5 minutes. Aim for 4:20.
2. Show the actual app interface within the first 10 seconds.
3. Show a real workflow, not only slides.
4. Use an authorized demo target only.
5. Mention the hackathon theme: Agentic and Autonomous Systems.
6. Explain problem, solution, features, demo, and impact.
7. Show the repository briefly to prove implementation depth.
8. Show the GitHub repository link before the video ends.
9. Avoid saying "zero false positives"; say "evidence-backed validation" instead.
10. Avoid saying a live scan is running unless it actually is visible.

---

## Final Screen Text

`VigilAgent`

`Autonomous AI-Powered Penetration Testing Platform`

`Theme: Agentic and Autonomous Systems`

`Team: [TEAM NAME]`

`GitHub: [YOUR REPOSITORY LINK]`

`FAR AWAY 2026`

---

## One-Line Pitch

VigilAgent is an autonomous security swarm that helps teams scope, test, validate, explain, and report application security risks through coordinated AI agents.

