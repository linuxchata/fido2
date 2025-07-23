document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById('docs')) {
        if (typeof Prism !== 'undefined') {
            Prism.highlightAll();
        }
    }
});