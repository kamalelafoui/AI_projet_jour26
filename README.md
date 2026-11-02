# j26 — Threat Modeling d'agents IA (AI in Inclusive Education)

Pipeline Langflow : **Architecture → Menaces → Priorisation (Risque = P × I) → Agent Card Security**, appliqué à un agent de service client (SupportBot : LLM + RAG ChromaDB + outils SQL/Email). Référentiels : OWASP LLM Top 10 (2025), MITRE ATLAS, Goal Guarding.

## Structure
| Chemin | Contenu |
|---|---|
| `langflow/Correction AI in inclusive education.json` | Workflow Langflow final (3 prompts, 3 × Gemini 2.5 Flash) |
| `main.py` | Pipeline + serveur du dashboard (stdlib uniquement) |
| `dashboard.html` | Dashboard : menu, KPI, graphiques SVG, formulaire |
| `j26_Threat_Modeling.ipynb` | Notebook : exécution, matrice de risque |
| `assets/` | Logo et schémas d'architecture |
| `docs/` | Documentation (docx) et présentation (pptx) |

## Lancement
```bash
python main.py            # http://localhost:8000
python main.py --cli --offline
export GOOGLE_API_KEY=...  # optionnel : active Gemini
```
Sans clé ou sans accès réseau (ex. réseau filtré), le moteur hors-ligne prend le relais automatiquement.

## Docker
```bash
cp .env.example .env        # optionnel : renseigner GOOGLE_API_KEY
docker compose up --build   # http://localhost:8000
# ou : docker build -t j26-threat . && docker run -p 8000:8000 -e GOOGLE_API_KEY=... j26-threat
```
Sans clé (ou réseau filtré), le conteneur fonctionne en mode hors-ligne.

## Langflow
Importer `langflow/Correction AI in inclusive education.json`, renseigner la clé Google dans la variable globale `Key2`, lancer le Playground.

## Sécurité
Ne jamais committer de clé API : utiliser une variable d'environnement (`.env` est ignoré par git).

Auteur : Kamal El Afoui — ESI Rabat, équipe ITQAN, laboratoire LYRICA.
