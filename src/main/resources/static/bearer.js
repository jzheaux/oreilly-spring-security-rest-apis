$(document).ajaxSend((event, xhr) => {
    if (security.accessToken) {
        xhr.setRequestHeader("Authorization", "Bearer " + security.accessToken);
    }
    if (security.csrf.value) {
        xhr.setRequestHeader(security.csrf.header, security.csrf.value);
    }
});

$(document).ajaxSuccess((event, xhr) => {
    security.success(xhr);
});

$(document).ajaxComplete((event, xhr) => {
    if (xhr.status === 401 || xhr.status === 403) {
        return pkce.authorize();
    }
});

const security = {
    csrf: {
        header: "x-csrf-token"
    },
    success: (xhr) => {
        security.csrf.value = xhr.getResponseHeader(security.csrf.header);
    }
}