const emailRegex = /^(([^<>()\[\]\\.,;:\s@"]{1,64}(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".{1,62}"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]{1,63}\.)+[a-zA-Z]{2,63}))$/;

const $ = e => document.getElementById(e);

const ei = $("email");
const lb = $("login");
const change = e => {
    if (e.target.value.match(emailRegex)) return lb.removeAttribute("disabled");
    return lb.setAttribute("disabled", "");
};

const f = async (path, jsonData) => {
    return await fetch(path, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Accept: "application/json"
        },
        body: JSON.stringify(jsonData)
    })
        .then(res =>
            res.json().catch(() => {
                return { message: "Error parsing Json response", error: true };
            })
        )
        .catch(() => {
            return { message: "Error during fetch", error: true };
        });
};

const login = async () => {
    $("form").classList.add("hidden");
    $("waiting").classList.remove("hidden");
    const req = await f("/v1/login", { email: ei.value });
    if (req.message === "Success") {
        $("waiting").classList.add("hidden");
        $("success").classList.remove("hidden");
    } else {
        $("form").classList.remove("hidden");
        $("waiting").classList.add("hidden");
        $("statusMessage").innerText = req.message;
    }
};

ei.onchange = change;
ei.onkeyup = change;
ei.onclick = change;
ei.onkeydown = e => {
    if (e.keyCode === 13 && e.target.value.match(emailRegex)) return login();
};
lb.onclick = login;
