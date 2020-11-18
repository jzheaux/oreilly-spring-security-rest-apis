const pkce = {
    _random: function () {
        const array = new Uint32Array(28);
        window.crypto.getRandomValues(array);
        return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
    },
    _sha256: function (plain) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plain);
        return window.crypto.subtle.digest('SHA-256', data);
    },
    _base64urlencode: function (str) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
    state: {
        create: function () {
            const state = pkce._random();
            localStorage.setItem("pkce_state", state);
            return state;
        },
        get: function () {
            return localStorage.getItem("pkce_state");
        },
        remove: function () {
            localStorage.removeItem("pkce_state");
        }
    },
    codeVerifier: {
        create: function () {
            const codeVerifier = pkce._random();
            localStorage.setItem("pkce_code_verifier", codeVerifier);
            return codeVerifier;
        },
        get: function () {
            return localStorage.getItem("pkce_code_verifier");
        },
        remove: function () {
            localStorage.removeItem("pkce_code_verifier");
        }
    },
    codeChallenge: async function (codeVerifier) {
        const hashed = await pkce._sha256(codeVerifier);
        return pkce._base64urlencode(hashed);
    },
    authorize: async function () {
        const state = pkce.state.create();
        const codeVerifier = pkce.codeVerifier.create();
        const codeChallenge = await pkce.codeChallenge(codeVerifier);
        const url = "http://idp:8083/oauth2/authorize" +
            "?response_type=code" +
            "&client_id=goals-client" +
            "&redirect_uri=http://localhost:8081/bearer.html" +
            "&scope=goal:read+goal:write+user:read" +
            "&state=" + state +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method=S256";
        location.href = url;
    },
    token: function (params) {
        if (!params.get("code")) {
            return Promise.resolve();
        }
        const code = params.get("code");
        const verifier = pkce.codeVerifier.get();
        const state = pkce.state.get();
        if (params.get("state") !== state) {
            return Promise.resolve();
        }
        const data = "grant_type=authorization_code"
            + "&client_id=goals-client"
            + "&code=" + encodeURIComponent(code)
            + "&code_verifier=" + encodeURIComponent(verifier)
            + "&redirect_uri=http://localhost:8081/bearer.html";
        return new Promise((resolve, reject) =>
            $.ajax("http://idp:8083/oauth2/token",
                {
                    method: 'POST',
                    data: data,
                    success: (data) => {
                        pkce.state.remove();
                        pkce.codeVerifier.remove();
                        resolve(data.access_token);
                    },
                    error: (error) => {
                        reject(error);
                    }
                }));
    }
};