export const generateMitreAnalysis = (result) => {
    if (!result.mitre_details) return '<p class="text-muted">Ingen MITRE ATT&CK analyse tilgjengelig</p>';
    
    return `
        <div class="mitre-analysis mt-3">
            <h4 class="text-primary">MITRE ATT&CK Analyse</h4>
            
            ${generateTechniquesSection(result.mitre_details)}
            ${generateTacticsSection(result.mitre_details)}
            ${generateRiskScore(result.mitre_details)}
        </div>
    `;
};

const generateTechniquesSection = (mitreDetails) => {
    return `
        <div class="techniques-container">
            <h5>Identifiserte Teknikker (${mitreDetails.techniques.length}):</h5>
            ${mitreDetails.techniques.length > 0 ? 
                mitreDetails.techniques.map(tech => generateTechniqueCard(tech)).join('') : 
                '<p class="text-muted">Ingen teknikker identifisert</p>'
            }
        </div>
    `;
};

const generateTechniqueCard = (tech) => {
    return `
        <div class="technique-card mb-2">
            <h6 class="technique-id">${tech.id} - ${tech.name}</h6>
            <p class="technique-description">${tech.description}</p>
            <div class="technique-tactics">
                <small>Relaterte Taktikker: ${tech.tactics.join(', ') || 'Ingen'}</small>
            </div>
        </div>
    `;
};

const generateTacticsSection = (mitreDetails) => {
    return `
        <div class="tactics-container mt-3">
            <h5>Taktikker (${mitreDetails.tactics.length}):</h5>
            ${mitreDetails.tactics.length > 0 ? `
                <ul class="tactics-list">
                    ${mitreDetails.tactics.map(tactic => `
                        <li class="tactic-item">${tactic}</li>
                    `).join('')}
                </ul>
            ` : '<p class="text-muted">Ingen taktikker identifisert</p>'}
        </div>
    `;
};

const generateRiskScore = (mitreDetails) => {
    return `
        <div class="risk-score mt-3">
            <h5>MITRE Risikoscore: 
                <span class="badge ${
                    mitreDetails.risk_score > 70 ? 'bg-danger' : 
                    mitreDetails.risk_score > 40 ? 'bg-warning' : 
                    'bg-success'
                }">
                    ${mitreDetails.risk_score}
                </span>
            </h5>
        </div>
    `;
}; 