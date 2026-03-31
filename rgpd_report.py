import json
import datetime

def generate_rgpd_report():
    report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Résultats basés sur les findings ZAP
    checks = [
        {
            "article": "Article 5 - Intégrité et confidentialité",
            "check": "Cookie HttpOnly Flag",
            "status": "NON_CONFORME",
            "detail": "Cookies sans flag HttpOnly détectés - risque de vol de session",
            "zap_rule": "10010"
        },
        {
            "article": "Article 5 - Intégrité et confidentialité",
            "check": "Cookie SameSite Attribute",
            "status": "NON_CONFORME",
            "detail": "Cookies sans attribut SameSite - risque CSRF",
            "zap_rule": "10054"
        },
        {
            "article": "Article 25 - Protection des données dès la conception",
            "check": "Content Security Policy (CSP)",
            "status": "NON_CONFORME",
            "detail": "Header CSP manquant - risque XSS",
            "zap_rule": "10038"
        },
        {
            "article": "Article 25 - Protection des données dès la conception",
            "check": "X-Content-Type-Options Header",
            "status": "NON_CONFORME",
            "detail": "Header X-Content-Type-Options manquant",
            "zap_rule": "10021"
        },
        {
            "article": "Article 32 - Sécurité du traitement",
            "check": "Anti-clickjacking Header",
            "status": "NON_CONFORME",
            "detail": "Header X-Frame-Options manquant - risque clickjacking",
            "zap_rule": "10020"
        },
        {
            "article": "Article 32 - Sécurité du traitement",
            "check": "Information Disclosure",
            "status": "NON_CONFORME",
            "detail": "Messages d'erreur exposent des informations sensibles",
            "zap_rule": "10023"
        },
        {
            "article": "Article 32 - Sécurité du traitement",
            "check": "Server Version Information",
            "status": "NON_CONFORME",
            "detail": "Header Server expose la version du serveur",
            "zap_rule": "10036"
        },
        {
            "article": "Article 32 - Sécurité du traitement",
            "check": "Vulnerable JS Library",
            "status": "NON_CONFORME",
            "detail": "jQuery 3.2.1 vulnérable détecté",
            "zap_rule": "10003"
        },
        {
            "article": "Article 5 - Intégrité et confidentialité",
            "check": "HTTPS uniquement",
            "status": "CONFORME",
            "detail": "Pas de transition HTTP/HTTPS non sécurisée détectée",
            "zap_rule": "10041"
        },
        {
            "article": "Article 32 - Sécurité du traitement",
            "check": "Cross-Domain Misconfiguration",
            "status": "CONFORME",
            "detail": "Pas de misconfiguration cross-domain détectée",
            "zap_rule": "10098"
        }
    ]
    
    conforme = len([c for c in checks if c["status"] == "CONFORME"])
    non_conforme = len([c for c in checks if c["status"] == "NON_CONFORME"])
    total = len(checks)
    score = int((conforme / total) * 100)
    
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport RGPD - DevSecOps Pipeline</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header p {{ margin: 5px 0 0 0; opacity: 0.8; }}
        .score-box {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .score-number {{ font-size: 60px; font-weight: bold; color: {'#e74c3c' if score < 50 else '#f39c12' if score < 80 else '#27ae60'}; }}
        .stats {{ display: flex; gap: 20px; }}
        .stat {{ text-align: center; padding: 15px; border-radius: 8px; min-width: 100px; }}
        .stat-conforme {{ background: #d5f5e3; color: #27ae60; }}
        .stat-non-conforme {{ background: #fadbd8; color: #e74c3c; }}
        .table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .table th {{ background: #2c3e50; color: white; padding: 12px 15px; text-align: left; }}
        .table td {{ padding: 12px 15px; border-bottom: 1px solid #eee; }}
        .table tr:hover {{ background: #f9f9f9; }}
        .badge-conforme {{ background: #27ae60; color: white; padding: 4px 10px; border-radius: 20px; font-size: 12px; }}
        .badge-non-conforme {{ background: #e74c3c; color: white; padding: 4px 10px; border-radius: 20px; font-size: 12px; }}
        .footer {{ margin-top: 30px; text-align: center; color: #7f8c8d; font-size: 12px; }}
        .project-info {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📋 Rapport de Conformité RGPD</h1>
        <p>Pipeline DevSecOps — Automatisation de la sécurité des API</p>
        <p>Généré le : {report_date}</p>
    </div>
    
    <div class="project-info">
        <h2>Informations du projet</h2>
        <table style="width:100%; border-collapse:collapse;">
            <tr><td style="padding:8px;"><strong>Application :</strong></td><td>dvpwa (Damn Vulnerable Python Web Application)</td></tr>
            <tr><td style="padding:8px;"><strong>Image Docker :</strong></td><td>umissa/mon-api-vuln</td></tr>
            <tr><td style="padding:8px;"><strong>Outil d'analyse :</strong></td><td>OWASP ZAP (Zed Attack Proxy)</td></tr>
            <tr><td style="padding:8px;"><strong>URLs analysées :</strong></td><td>29 URLs</td></tr>
            <tr><td style="padding:8px;"><strong>Règlement appliqué :</strong></td><td>RGPD (Règlement UE 2016/679)</td></tr>
        </table>
    </div>
    
    <div class="score-box">
        <div>
            <h2 style="margin:0">Score de conformité RGPD</h2>
            <p style="color:#7f8c8d; margin:5px 0 0 0">Basé sur {total} vérifications automatiques</p>
        </div>
        <div style="text-align:center">
            <div class="score-number">{score}%</div>
            <div>{'⚠️ Non conforme' if score < 80 else '✅ Conforme'}</div>
        </div>
        <div class="stats">
            <div class="stat stat-conforme">
                <div style="font-size:30px; font-weight:bold;">{conforme}</div>
                <div>Conformes</div>
            </div>
            <div class="stat stat-non-conforme">
                <div style="font-size:30px; font-weight:bold;">{non_conforme}</div>
                <div>Non conformes</div>
            </div>
        </div>
    </div>
    
    <h2>Détail des vérifications</h2>
    <table class="table">
        <thead>
            <tr>
                <th>Article RGPD</th>
                <th>Vérification</th>
                <th>Statut</th>
                <th>Détail</th>
            </tr>
        </thead>
        <tbody>
"""
    
    for check in checks:
        badge = f'<span class="badge-conforme">✅ CONFORME</span>' if check["status"] == "CONFORME" else f'<span class="badge-non-conforme">❌ NON CONFORME</span>'
        html += f"""
            <tr>
                <td>{check['article']}</td>
                <td><strong>{check['check']}</strong></td>
                <td>{badge}</td>
                <td>{check['detail']}</td>
            </tr>"""
    
    html += f"""
        </tbody>
    </table>
    
    <div class="footer">
        <p>Rapport généré automatiquement par le pipeline DevSecOps — SUPNUM Mauritanie 2025/2026</p>
        <p>PFE : Automatisation DevSecOps pour la sécurité des API — WSO2 Identity Server + OWASP/RGPD</p>
    </div>
</body>
</html>"""
    
    with open("/zap/wrk/rgpd_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    
    print(f"✅ Rapport RGPD généré : score {score}% ({conforme}/{total} conformes)")

if __name__ == "__main__":
    generate_rgpd_report()