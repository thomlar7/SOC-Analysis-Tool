import { showError } from './utils.js';

export const handleExport = async () => {
    try {
        const response = await fetch('/export');
        
        if (response.ok) {
            await downloadFile(response);
        } else {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Eksport feilet');
        }
    } catch (error) {
        console.error('Export error:', error);
        showError(`Feil ved eksport av rapport: ${error.message}`);
    }
};

const downloadFile = async (response) => {
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = response.headers.get('content-disposition')?.split('filename=')[1] || 'soc_report.xlsx';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
}; 