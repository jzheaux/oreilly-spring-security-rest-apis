$(document).ajaxSend((event, xhr) => {
    xhr.withCredentials = true;
    if (security.csrf.value) {
        xhr.setRequestHeader(security.csrf.header, security.csrf.value);
    }
});

$(document).ajaxSuccess((event, xhr) => {
    security.success(xhr);
});

const security = {
    csrf: {
        header: "x-csrf-token"
    },
    success: (xhr) => {
        security.csrf.value = xhr.getResponseHeader(security.csrf.header);
    }
}