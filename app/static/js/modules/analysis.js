import { renderResults, renderSummary } from './ui.js';
import { showError } from './utils.js';

export const handleAnalysis = async (urls) => {
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `urls=${encodeURIComponent(urls)}`
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Analyse feilet');
        }
        
        const data = await response.json();
        console.log('Full response data:', data);
        
        renderResults(data);
        renderSummary(data.summary);
        
    } catch (error) {
        console.error('Error:', error);
        showError(error.message);
    }
}; 