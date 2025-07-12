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
            background: '#34a853',
            duration: 3000,
            dismissible: true,
            icon: {
                className: 'notyf__icon fa-solid fa-circle-info',
                tagName: 'i'
            }
        },
        {
            type: 'warning',
            background: '#ffc107',
            dismissible: true,
            icon: {
                className: 'notyf__icon fa-solid fa-triangle-exclamation',
                tagName: 'i'
            }
        },
        {
            type: 'error',
            background: '#dc3545',
            duration: 6000,
            dismissible: true,
            icon: {
                className: 'notyf__icon fa-solid fa-circle-xmark',
                tagName: 'i'
            }
        },
        {
            type: 'success',
            background: '#198754',
            duration: 3000,
            dismissible: true,
            icon: {
                className: 'notyf__icon fa-solid fa-circle-check',
                tagName: 'i'
            }
        }
    ]
});

const notify = {
    info: function (message, title) {
        if (title) {
            message = `<strong>${title}</strong><br>${message}`;
        }
        notyf.open({
            type: 'info',
            message: message
        });
    },
    success: function (message, title) {
        if (title) {
            message = `<strong>${title}</strong><br>${message}`;
        }
        notyf.success(message);
    },
    warning: function (message, title) {
        if (title) {
            message = `<strong>${title}</strong><br>${message}`;
        }
        notyf.open({
            type: 'warning',
            message: message
        });
    },
    error: function (message, title) {
        if (title) {
            message = `<strong>${title}</strong><br>${message}`;
        }
        notyf.error(message);
    }
};
