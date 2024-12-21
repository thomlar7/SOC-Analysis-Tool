import { handleAnalysis } from './modules/analysis.js';
import { handleExport } from './modules/export.js';

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('analyzeForm').addEventListener('submit', (e) => {
        e.preventDefault();
        const urls = document.getElementById('urls').value;
        handleAnalysis(urls);
    });
    
    document.getElementById('exportBtn').addEventListener('click', handleExport);
}); 