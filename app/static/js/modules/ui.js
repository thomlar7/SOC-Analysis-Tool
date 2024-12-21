import { generateMitreAnalysis } from './mitre.js';

export const renderResults = (data) => {
    const resultsDiv = document.getElementById('results');
    
    if (data.error) {
        showError(data.error, data.details);
        return;
    }
    
    resultsDiv.innerHTML = data.results.map(result => generateResultCard(result)).join('');
};

export const renderSummary = (summary) => {
    const summaryDiv = document.getElementById('summary');
    summaryDiv.innerHTML = `
        <p>Total Analyzed: ${summary.total_analyzed}</p>
        <h6>Risk Distribution:</h6>
        <ul>
            ${Object.entries(summary.risk_distribution).map(([category, data]) => `
                <li>${category}: ${data.antall} URLs</li>
            `).join('')}
        </ul>
    `;
};

const generateResultCard = (result) => {
    return `
        <div class="card result-card risk-${result.risk_category}">
            <div class="card-body">
                <h5 class="card-title">${result.url}</h5>
                <p>Risk Category: ${result.risk_category}</p>
                <p>Risk Score: ${result.risk_score}</p>
                <p>Action Required: ${result.action_required}</p>
                ${result.permalink ? `<a href="${result.permalink}" target="_blank">View on VirusTotal</a>` : ''}
                
                ${generateMitreAnalysis(result)}
            </div>
        </div>
    `;
}; 