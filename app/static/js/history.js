document.addEventListener('DOMContentLoaded', () => {
    const dateFrom = document.querySelector('input[name="date_from"]');
    const dateTo = document.querySelector('input[name="date_to"]');
    
    // Håndter hurtigvalg for datoer
    document.querySelectorAll('.quick-filters button').forEach(button => {
        button.addEventListener('click', () => {
            const period = button.dataset.period;
            const today = new Date();
            
            switch(period) {
                case 'today':
                    dateFrom.value = formatDate(today);
                    dateTo.value = formatDate(today);
                    break;
                    
                case 'week':
                    const weekAgo = new Date(today);
                    weekAgo.setDate(today.getDate() - 7);
                    dateFrom.value = formatDate(weekAgo);
                    dateTo.value = formatDate(today);
                    break;
                    
                case 'month':
                    const monthAgo = new Date(today);
                    monthAgo.setDate(today.getDate() - 30);
                    dateFrom.value = formatDate(monthAgo);
                    dateTo.value = formatDate(today);
                    break;
                    
                case 'custom':
                    dateFrom.value = '';
                    dateTo.value = '';
                    break;
            }
            
            // Automatisk submit av skjema når hurtigvalg velges
            if (period !== 'custom') {
                document.querySelector('form').submit();
            }
        });
    });
});

function formatDate(date) {
    return date.toISOString().split('T')[0];
} 