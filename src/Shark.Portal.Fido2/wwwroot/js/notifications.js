// Initialize Notyf
const notyf = new Notyf({
    duration: 5000,
    position: {
        x: 'right',
        y: 'top',
    },
    ripple: false,
    types: [
        {
            type: 'info',
            background: '#0d6efd',
            icon: {
                className: 'fas fa-info-circle',
                tagName: 'span',
                color: '#fff'
            }
        },
        {
            type: 'warning',
            background: '#ffc107',
            icon: {
                className: 'fas fa-exclamation-circle',
                tagName: 'span',
                color: '#fff'
            }
        },
        {
            type: 'error',
            background: '#dc3545',
            duration: 6000,
            dismissible: true
        },
        {
            type: 'success',
            background: '#198754',
            duration: 4000,
            dismissible: true
        }
    ]
});

const notify = {
    info: function(message, title) {
        if (title) {
            message = `<strong>${title}</strong><br>${message}`;
        }
        notyf.open({
            type: 'info',
            message: message
        });
    },
    success: function(message, title) {
        if (title) {
            message = `<strong>${title}</strong><br>${message}`;
        }
        notyf.success(message);
    },
    warning: function(message, title) {
        if (title) {
            message = `<strong>${title}</strong><br>${message}`;
        }
        notyf.open({
            type: 'warning',
            message: message
        });
    },
    error: function(message, title) {
        if (title) {
            message = `<strong>${title}</strong><br>${message}`;
        }
        notyf.error(message);
    }
};
