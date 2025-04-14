const addSubmitListener = (formId, listener) => {
    document.getElementById(formId).addEventListener("submit", event => {
        event.preventDefault();
        saveInputValues();
        listener(event.target);
    });
};

const saveInputValues = () => {
    forEachFormInput(input => {
        localStorage.setItem(input.name, input.value)
    })
}

const restoreInputValues = () => {
    forEachFormInput(input => {
        input.value = localStorage.getItem(input.name)
    })
}

const forEachFormInput = doThis => {
    document.querySelectorAll('form input').forEach(doThis)
}

const makeRegistrationRequestFrom = form => ({
    "relyingParty": {
        "id": window.psl.parse(window.location.hostname).domain,
        "name": "ACME Corp."
    },
    "user": {
        "id": form.userId.value,
        "name": form.username.value,
        "displayName": form.userDisplayName.value
    },
    "attestation": "none"
});

const makeRequestHeaders = form => ({
        'x-mfa-apikey': form.apiKey.value,
        'x-mfa-apisecret': form.apiSecret.value,
        'x-mfa-RPDisplayName': "Demo Site",
        'x-mfa-RPID': window.psl.parse(window.location.hostname).domain,
        'x-mfa-RPOrigin': "https://"+window.psl.parse(window.location.hostname).subdomain + "." + window.psl.parse(window.location.hostname).domain,
        'x-mfa-UserUUID': form.userId.value,
        'x-mfa-Username': form.username.value ?? '',
        'x-mfa-UserDisplayName': form.userDisplayName.value ?? '',
});

const rejectIfNotOk = async response => {
    if (!response.ok) {
        console.log('Not ok:', response)
        throw new Error(JSON.stringify(await response.json()))
    }
    console.log('Ok:', response)
    return response
};

const sendWebauthnRegistrationToServer = async (apiBaseUrl, apiKey, apiSecret, registrationCredential, form) => {
    fetch(apiBaseUrl, {
        method: 'PUT',
        headers: makeRequestHeaders(form),
        body: JSON.stringify(registrationCredential)
    }).then(
        rejectIfNotOk
    ).then(
        () => alert('Successfully registered WebAuthn key')
    );
};
const sendWebauthnAuthenticationToServer = async (apiBaseUrl, apiKey, apiSecret, authenticationCredential, form) => {
    fetch(apiBaseUrl, {
        method: 'PUT',
        headers: makeRequestHeaders(form),
        body: JSON.stringify(authenticationCredential)
    }).then(
        rejectIfNotOk
    ).then(
        () => alert('Successfully authenticated WebAuthn key')
    );
};

const onWebauthnAuthenticationFormSubmit = async form => {
    const apiBaseUrl = form.apiBaseUrl.value;
    const apiKey = form.apiKey.value;
    const apiSecret = form.apiSecret.value;
    createWebauthnAuthentication(apiBaseUrl, apiKey, apiSecret, form)
};

const onWebauthnRegistrationFormSubmit = async form => {
    const apiBaseUrl = form.apiBaseUrl.value;
    const registrationRequest = makeRegistrationRequestFrom(form);
    console.log(registrationRequest)
    const apiKey = form.apiKey.value;
    const apiSecret = form.apiSecret.value;
    createWebauthnRegistration(apiBaseUrl, apiKey, apiSecret, registrationRequest, form)
};

const createWebauthnAuthentication = (apiBaseUrl, apiKey, apiSecret, form) => {
    fetch(apiBaseUrl, {
        method: 'POST',
        headers: makeRequestHeaders(form),
    }).then(
        rejectIfNotOk
    ).then(
        response => {
            console.log('createWebauthnAuthentication response:', response); // TEMP
            return response.json()
        }
    ).then(
        loginChallenge => {
            console.log('loginChallenge:', loginChallenge); // TEMP
            console.log('Modified loginChallenge:', loginChallenge); // TEMP
            return SimpleWebAuthnBrowser.startAuthentication(loginChallenge.publicKey);
        }
    ).then(
        authenticationCredential => sendWebauthnAuthenticationToServer(
          apiBaseUrl,
          apiKey,
          apiSecret,
          authenticationCredential,
          form
        )
    );
};

const createWebauthnRegistration = (apiBaseUrl, apiKey, apiSecret, registrationRequest, form) => {
    let heads = makeRequestHeaders(form)
    heads["x-mfa-UserUUID"] = ""
    fetch(apiBaseUrl, {
        method: 'POST',
        headers: heads,
        body: JSON.stringify(registrationRequest)
    }).then(
        rejectIfNotOk
    ).then(
        response => response.json()
    ).then(
        options => {
            form.userId.value = options.uuid
            return SimpleWebAuthnBrowser.startRegistration({
                excludeCredentials: [],
                ...options.publicKey,
            })
        }
    ).then(
        registrationCredential => sendWebauthnRegistrationToServer(
            apiBaseUrl,
            apiKey,
            apiSecret,
            registrationCredential,
            form
        )
    );
};

window.addSubmitListener = addSubmitListener;
window.restoreInputValues = restoreInputValues;

window.onWebauthnRegistrationFormSubmit = onWebauthnRegistrationFormSubmit;
window.onWebauthnAuthenticationFormSubmit = onWebauthnAuthenticationFormSubmit;

window.onunhandledrejection = promiseRejectionEvent => {
    alert(promiseRejectionEvent.reason)
};
