#!/usr/bin/env python3
"""j26 - Threat Modeling d'un agent IA (AI in inclusive education / sécurité agentique).
Pipeline : Architecture -> Menaces -> Priorisation (P x I) -> Agent Card Security.
Mode Gemini si GOOGLE_API_KEY est défini et accessible, sinon moteur hors-ligne (réseau ESI filtré).
Lancement : python main.py   ->  http://localhost:8001
Aucune dépendance externe (bibliothèque standard uniquement)."""
import json, os, re, sys, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", 8001))
MODEL = "gemini-2.5-flash"
DEFAULT_ARCH = ("Un agent assistant de service client nommé 'SupportBot'. Il utilise un LLM connecté à une base "
    "vectorielle (ChromaDB) contenant l'historique des tickets clients et les documentations internes (système RAG). "
    "L'agent a accès à un outil (Tool) via une API qui lui permet de requêter la base de données SQL des clients pour "
    "voir leurs factures, et un autre outil pour envoyer automatiquement des emails de remboursement en cas de "
    "réclamation justifiée. Les utilisateurs interagissent avec l'agent via un simple chat sur le site web public.")

# ---------- Prompts (identiques au JSON Langflow final) ----------
def _flow_prompts():
    d = json.load(open(os.path.join(HERE, "langflow", "Correction AI in inclusive education.json"), encoding="utf-8"))
    out = {}
    for n in d["data"]["nodes"]:
        if n["data"]["type"] == "Prompt Template":
            out[n["data"]["node"]["display_name"]] = n["data"]["node"]["template"]["template"]["value"]
    return out

# ---------- Moteur hors-ligne (règles OWASP LLM Top 10 2025 / MITRE ATLAS) ----------
def detect(arch):
    a = arch.lower()
    return dict(rag=bool(re.search(r"rag|chroma|vector|vectoriel|embedding", a)),
                sql=bool(re.search(r"sql|base de donn", a)),
                mail=bool(re.search(r"email|mail|rembours|paiement|virement", a)),
                public=bool(re.search(r"public|chat|web|internet", a)),
                code=bool(re.search(r"exécut|execut|code|interpr|shell", a)))

def name_of(arch):
    m = re.search(r"nomm[ée]\s+['\"«]?([\w\- ]+?)['\"»]?[\s.,]", arch)
    return m.group(1).strip() if m else "Agent"

def threats(arch):
    f = detect(arch); T = []
    T.append(dict(n="Injection de prompt indirecte via documents RAG", cible="Mémoire RAG", ref="OWASP LLM01 + LLM08 / ATLAS AML.T0051 (LLM Prompt Injection)", P=4, I=4,
      d="Un attaquant dépose un ticket ou un message contenant des instructions cachées ; indexé dans ChromaDB, il est récupéré par similarité et injecté dans le contexte, où le LLM l'exécute comme une instruction (changement d'intention).",
      j="Probabilité forte (chat public, ingestion ouverte), impact fort sur l'intégrité des réponses et des outils."))
    T.append(dict(n="Empoisonnement de la base vectorielle (RAG poisoning)", cible="Mémoire RAG", ref="OWASP LLM04 + LLM08 / ATLAS AML.T0020 (Poison Training Data)", P=3, I=4,
      d="Injection massive de tickets falsifiés (politique de remboursement erronée, faux numéros de support) qui deviennent des 'faits' de référence : l'agent diffuse des informations fausses et prend des décisions biaisées durablement.",
      j="Probabilité moyenne (nécessite une ingestion sans contrôle), impact fort et persistant sur toutes les réponses."))
    T.append(dict(n="Action non autorisée : remboursement frauduleux (Excessive Agency)", cible="Actions Tools", ref="OWASP LLM06 + LLM01 / ATLAS AML.T0051 -> abus d'outil", P=4, I=5,
      d="Par injection (directe ou indirecte), l'attaquant force l'appel de l'outil d'emails de remboursement avec des arguments forgés (montant, destinataire) : perte financière sans validation humaine ni schéma strict.",
      j="Probabilité forte (outil à effet direct, pas de Human-in-the-loop), impact maximal : perte financière et fraude."))
    T.append(dict(n="Escalade de privilèges et exfiltration de PII via l'outil SQL", cible="Actions Tools", ref="OWASP LLM02 + LLM06 + LLM05 / ATLAS AML.T0025 (Exfiltration)", P=3, I=5,
      d="L'agent, avec les droits élevés de l'API SQL, est manipulé pour générer des requêtes hors périmètre (factures d'autres clients, IDOR/BOLA, injection SQL) puis les restitue ou les envoie par email à l'attaquant.",
      j="Probabilité moyenne (dépend du RBAC), impact très élevé : fuite de données personnelles et conformité (RGPD / loi 09-08)."))
    T.append(dict(n="Déni de service par boucles de raisonnement et appels massifs", cible="Actions Tools", ref="OWASP LLM10 (Unbounded Consumption) / ATLAS AML.T0029 (Denial of ML Service)", P=4, I=2,
      d="Requêtes conçues pour provoquer des boucles Chain-of-Thought infinies ou des appels répétés à l'API SQL / au LLM, épuisant quotas, coûts et disponibilité du chat public.",
      j="Probabilité forte (chat anonyme), impact modéré : indisponibilité et surcoût, sans compromission de données."))
    return T

def level(s): return "Critique" if s >= 20 else "Élevé" if s >= 12 else "Moyen" if s >= 6 else "Faible"

def offline_pipeline(arch):
    T = threats(arch); name = name_of(arch)
    s1 = "\n".join(f"- [{t['n']}] | Cible : {t['cible']} | Réf : {t['ref']} : {t['d']}" for t in T)
    R = sorted(T, key=lambda t: -t["P"] * t["I"])
    s2 = "\n".join(f"{i}. [{t['n']}] — Niveau : {level(t['P']*t['I'])} — P={t['P']} x I={t['I']} = {t['P']*t['I']} — {t['j']}" for i, t in enumerate(R, 1))
    top = R[0]
    s3 = f"""###  AGENT CARD – SECURITY

| Élément | Spécification de Sécurité |
| :--- | :--- |
| **Nom de l'Agent ciblé** | {name} (assistant service client RAG + outils SQL/Email) |
| **Scénario d'Attaque Principal** | {top['n']} : {top['d']} |
| **Vecteur d'Attaque** | Chat web public -> contexte de l'agent (ou ticket empoisonné récupéré par ChromaDB) -> appel d'outil email de remboursement -> effet financier |
| **Impact RAG / Système** | {level(top['P']*top['I'])} — compromission de l'intention de l'agent, déclenchement d'effets réels (emails/remboursements) et risque d'accès aux données SQL clients |
| **Référentiels (OWASP / ATLAS)** | {top['ref']} ; complémentaires : LLM02, LLM04, LLM08, LLM10 |
| **Mitigation (Technique & Workflow)** | (1) Validation Pydantic/JSON Schema des arguments d'outils (montant plafonné, destinataire = email du client authentifié) ; (2) Human-in-the-loop obligatoire au-delà d'un seuil + agent Judge/Guard qui compare l'action au Goal initial ; (3) System Message immuable réinjecté à chaque tour ; (4) RBAC / moindre privilège, SQL paramétré en lecture seule filtré par client_id ; (5) filtrage et provenance des documents RAG ; (6) quotas, timeouts et limite d'itérations |"""
    return s1, s2, s3

# ---------- Mode Gemini ----------
def gemini(prompt, system):
    key = os.environ.get("GOOGLE_API_KEY")
    if not key: raise RuntimeError("GOOGLE_API_KEY absent")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={key}"
    body = {"contents": [{"parts": [{"text": prompt}]}], "systemInstruction": {"parts": [{"text": system}]},
            "generationConfig": {"temperature": 0.1}}
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["candidates"][0]["content"]["parts"][0]["text"].strip()

def run_pipeline(arch, force_offline=False):
    arch = (arch or DEFAULT_ARCH).strip()
    if not force_offline:
        try:
            P = _flow_prompts()
            s1 = gemini(P["Threat Modeling"].replace("{architecture}", arch), "Tu es un Red Teamer spécialisé en sécurité des agents IA.")
            s2 = gemini(P["Évaluation et Priorisation des Risques"].replace("{menaces_identifiees}", s1), "Tu es un analyste GRC rigoureux.")
            s3 = gemini(P["Agent Card – Security"].replace("{architecture}", arch).replace("{risques_priorises}", s2), "Tu es un architecte sécurité.")
            return dict(mode="Gemini 2.5 Flash", menaces=s1, risques=s2, agent_card=s3)
        except Exception as e:
            err = str(e)[:120]
    else:
        err = "forcé"
    s1, s2, s3 = offline_pipeline(arch)
    return dict(mode=f"Hors-ligne (moteur de règles) — {err}", menaces=s1, risques=s2, agent_card=s3)

# ---------- Serveur ----------
class H(BaseHTTPRequestHandler):
    def _send(self, code, ctype, data):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        p = self.path.split("?")[0]
        files = {"/": ("dashboard.html", "text/html; charset=utf-8"), "/logo.png": ("assets/logo.png", "image/png")}
        if p in files:
            fn, ct = files[p]
            return self._send(200, ct, open(os.path.join(HERE, fn), "rb").read())
        if p == "/api/default": return self._send(200, "application/json", json.dumps({"architecture": DEFAULT_ARCH}).encode())
        self._send(404, "text/plain", b"404")
    def do_POST(self):
        if self.path != "/api/analyze": return self._send(404, "text/plain", b"404")
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
        res = run_pipeline(body.get("architecture"), body.get("offline", False))
        self._send(200, "application/json; charset=utf-8", json.dumps(res, ensure_ascii=False).encode())
    def log_message(self, *a): pass

if __name__ == "__main__":
    if "--cli" in sys.argv:
        r = run_pipeline(DEFAULT_ARCH, "--offline" in sys.argv)
        print(r["mode"], "\n", r["menaces"], "\n\n", r["risques"], "\n\n", r["agent_card"])
    else:
        print(f"Dashboard : http://localhost:{PORT}  (Ctrl+C pour arrêter)")
        HTTPServer(("0.0.0.0", PORT), H).serve_forever()
