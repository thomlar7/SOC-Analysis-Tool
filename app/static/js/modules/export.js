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

export const handleReportGeneration = async () => {
    try {
        console.log("Starting report generation...");
        
        const response = await fetch('/generate_report', {
            method: 'POST',
            headers: {
                'Accept': 'application/pdf'
            }
        });
        
        console.log("Response status:", response.status);
        console.log("Response headers:", response.headers);
        
        if (response.ok) {
            const contentType = response.headers.get('content-type');
            console.log("Content type:", contentType);
            
            if (contentType && contentType.includes('application/pdf')) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = response.headers.get('content-disposition')?.split('filename=')[1] || 'soc_report.pdf';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
            } else {
                const data = await response.json();
                throw new Error(data.error || 'Uventet respons-type');
            }
        } else {
            const errorData = await response.json();
            console.error("Server error:", errorData);
            throw new Error(errorData.error || 'Rapport-generering feilet');
        }
    } catch (error) {
        console.error('Report generation error:', error);
        console.error('Full error object:', error);
        alert(`Feil ved generering av rapport: ${error.message}`);
    }
}; 