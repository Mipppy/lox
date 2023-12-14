var registrationForm = document.getElementById('registration-form');
if (registrationForm) {
    registrationForm.addEventListener('submit', (e) => {
        registrationForm.querySelector('button[type="submit"]').setAttribute('disabled', 'disabled');
    });
}