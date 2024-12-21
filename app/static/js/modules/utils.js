export const showError = (message, details = '') => {
    document.getElementById('results').innerHTML = `
        <div class="alert alert-danger">
            <strong>Feil:</strong> ${message}
            ${details ? `<br><small>${details}</small>` : ''}
        </div>
    `;
}; 