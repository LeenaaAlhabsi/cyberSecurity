// Password validation for registration
document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const passwordInput = document.getElementById('password');
    const passwordHint = document.getElementById('passwordHint');

    if (registerForm) {
        registerForm.addEventListener('submit', (e) => {
            const password = passwordInput.value;
            const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;

            if (!passwordRegex.test(password)) {
                e.preventDefault();
                alert('Password does not meet the requirements!');
            }
        });
    }

    // File validation for upload
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('file');
    const fileHint = document.getElementById('fileHint');

    if (uploadForm) {
        uploadForm.addEventListener('submit', (e) => {
            const file = fileInput.files[0];
            if (file && file.type !== 'application/pdf') {
                e.preventDefault();
                alert('Only PDF files are allowed!');
            }
        });
    }
});