"""
Renders ATT&CK matrix as dict/JSON/CSV/HTML for Enterprise, Mobile, ICS.
"""
import json
import csv
from io import StringIO
from typing import Dict, List
from .index import ATTACKIndex
from .models import Domain, Technique, SubTechnique, Tactic


class ATTACKMatrix:
    def __init__(self, index: ATTACKIndex):
        self.index = index

    def to_dict(self, domain: Domain = Domain.ENTERPRISE) -> Dict:
        tactics = [t for t in self.index._tactics.values() if t.domain == domain]
        tactics_sorted = sorted(tactics, key=lambda t: t.attack_id)
        matrix = {"domain": domain.value, "tactics": []}
        for tac in tactics_sorted:
            techs = self.index.by_tactic(tac.attack_id)
            techs = [t for t in techs if t.domain == domain and not t.is_subtechnique]
            techs_sorted = sorted(techs, key=lambda t: t.attack_id)
            tactic_data = {
                "tactic_id": tac.attack_id,
                "tactic_name": tac.name,
                "techniques": []
            }
            for tech in techs_sorted:
                subs = [s for s in self.index._by_id.values()
                        if s.is_subtechnique and s.parent_id == tech.attack_id and s.domain == domain]
                tactic_data["techniques"].append({
                    "technique_id": tech.attack_id,
                    "technique_name": tech.name,
                    "subtechniques": [
                        {"subtechnique_id": s.attack_id, "subtechnique_name": s.name}
                        for s in subs
                    ]
                })
            matrix["tactics"].append(tactic_data)
        return matrix

    def to_json(self, domain: Domain = Domain.ENTERPRISE, indent: int = 2) -> str:
        return json.dumps(self.to_dict(domain), indent=indent)

    def to_csv(self, domain: Domain = Domain.ENTERPRISE) -> str:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["Tactic ID", "Tactic Name", "Technique ID", "Technique Name", "Sub-technique ID", "Sub-technique Name"])
        matrix = self.to_dict(domain)
        for tac in matrix["tactics"]:
            for tech in tac["techniques"]:
                if tech["subtechniques"]:
                    for sub in tech["subtechniques"]:
                        writer.writerow([tac["tactic_id"], tac["tactic_name"], tech["technique_id"], tech["technique_name"], sub["subtechnique_id"], sub["subtechnique_name"]])
                else:
                    writer.writerow([tac["tactic_id"], tac["tactic_name"], tech["technique_id"], tech["technique_name"], "", ""])
        return output.getvalue()

    def to_html(self, domain: Domain = Domain.ENTERPRISE) -> str:
        matrix = self.to_dict(domain)
        html = ['<table border="1" cellpadding="4" cellspacing="0" style="border-collapse:collapse;">']
        html.append('<tr><th>Tactic</th><th>Techniques / Sub-techniques</th></tr>')
        for tac in matrix["tactics"]:
            tech_html = []
            for tech in tac["techniques"]:
                tech_html.append(f'<strong>{tech["technique_id"]}: {tech["technique_name"]}</strong>')
                if tech["subtechniques"]:
                    subs = ", ".join(f'{s["subtechnique_id"]}: {s["subtechnique_name"]}' for s in tech["subtechniques"])
                    tech_html.append(f'<small style="color:#666;">{subs}</small>')
            html.append(f'<tr><td><strong>{tac["tactic_id"]}: {tac["tactic_name"]}</strong></td><td>{"<br>".join(tech_html)}</td></tr>')
        html.append('</table>')
        return "\n".join(html)