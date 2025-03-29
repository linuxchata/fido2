toastr.options = {
    "positionClass": "toast-top-right",
    "timeOut": "2500",
    "closeButton": true,
    "showEasing": "swing",
    "hideEasing": "linear",
    "showMethod": "fadeIn",
    "hideMethod": "fadeOut"
};

function onRegister() {
    let button = document.getElementById('register');
    let previousText = button.innerHTML;
    button.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Processing...';
    button.disabled = true;

    requestCreateCredentialOptions()
        .then(() => {
            button.innerHTML = previousText;
            button.disabled = false;
        });
}

function onAuthenticate() {
    let button = document.getElementById('authenticate');
    let previousText = button.innerHTML;
    button.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Processing...';
    button.disabled = true;

    requestVerifyCredentialOptions()
        .then(() => {
            button.innerHTML = previousText;
            button.disabled = false;
        });
}

window.onRegister = onRegister;
window.onAuthenticate = onAuthenticate;