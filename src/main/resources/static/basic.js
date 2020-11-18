$(document).ajaxSend((event, xhr) => {
    if (security.csrf.value) {
        xhr.setRequestHeader(security.csrf.header, security.csrf.value);
    }
});

$(document).ajaxSuccess((event, xhr) => {
    security.success(xhr);
});

$.ajaxSetup({
    xhrFields: {
        withCredentials: true
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