
"use strict";

const loginLink = document.getElementById("stk-login");
const account = document.getElementById("stk-account");
const username = document.getElementById("stk-username");
const form = document.getElementById("stk-application");
const statusText = document.getElementById("stk-status");
const logoutButton = document.getElementById("stk-logout");
const staffPanel = document.getElementById("stk-staff");
const staffList = document.getElementById("stk-staff-list");

let csrfToken = "";

async function api(url, options = {}) {
    const headers = Object.assign({}, options.headers || {});

    if (options.body) {
        headers["Content-Type"] = "application/json";
    }

    if (options.method && options.method !== "GET") {
        headers["X-STK-CSRF"] = csrfToken;
    }

    const response = await fetch(url, {
        ...options,
        headers: headers,
        credentials: "same-origin"
    });

    const data = await response.json().catch(function () {
        return {};
    });

    if (!response.ok) {
        throw new Error(data.error || "Request failed.");
    }

    return data;
}

function showMessage(message) {
    if (statusText) {
        statusText.textContent = message;
    }
}

async function refreshApplication() {
    const data = await api("/api/my-application");

    if (!data.application) {
        showMessage("No application submitted yet.");
        return;
    }

    showMessage(
        "Application #" +
        data.application.id +
        ": " +
        data.application.status
    );
}

async function loadStaffApplications() {
    const data = await api("/api/staff/applications");

    if (!staffList) {
        throw new Error("Staff list element is missing from index.html.");
    }

    staffList.replaceChildren();

    if (!data.applications || data.applications.length === 0) {
        staffList.textContent = "No applications yet.";
        return;
    }

    data.applications.forEach(function (application) {
        const card = document.createElement("article");
        const heading = document.createElement("h4");
        const details = document.createElement("p");
        const experience = document.createElement("p");
        const reason = document.createElement("p");

        heading.textContent =
            "#" + application.id + " - " +
            application.username + " (" +
            application.status + ")";

        details.textContent =
            "Discord ID: " + application.discord_id +
            " | Platform: " + application.platform +
            " | Timezone: " + (application.timezone || "Not provided") +
            " | Age: " + application.age;

        experience.textContent =
            "Experience: " + application.experience;

        reason.textContent =
            "Reason: " + application.reason;

        card.append(heading, details, experience, reason);

        if (application.status === "pending") {
            ["approve", "reject"].forEach(function (decision) {
                const button = document.createElement("button");

                button.type = "button";
                button.textContent =
                    decision === "approve" ? "Approve" : "Reject";

                button.addEventListener("click", async function () {
                    button.disabled = true;

                    try {
                        await api(
                            "/api/staff/applications/" +
                            application.id + "/review",
                            {
                                method: "POST",
                                body: JSON.stringify({
                                    decision: decision
                                })
                            }
                        );

                        await loadStaffApplications();
                        await refreshApplication();
                    } catch (error) {
                        alert(error.message);
                        button.disabled = false;
                    }
                });

                card.appendChild(button);
            });
        }

        staffList.appendChild(card);
    });
}

async function start() {
    try {
        const config = await api("/api/config");

        csrfToken = config.csrfToken || "";

        if (!config.user) {
            if (loginLink) loginLink.hidden = false;
            if (account) account.hidden = true;
            if (staffPanel) staffPanel.hidden = true;
            return;
        }

        if (loginLink) loginLink.hidden = true;
        if (account) account.hidden = false;
        if (username) username.textContent = config.user.username;

        await refreshApplication();

        if (staffPanel) {
            staffPanel.hidden = !config.isStaff;
        }

        if (config.isStaff) {
            await loadStaffApplications();
        }
    } catch (error) {
        showMessage(error.message);
        console.error("STK startup error:", error);
    }
}

if (form) {
    form.addEventListener("submit", async function (event) {
        event.preventDefault();

        const submitButton =
            form.querySelector('button[type="submit"]');

        if (submitButton) {
            submitButton.disabled = true;
        }

        try {
            const values = Object.fromEntries(
                new FormData(form).entries()
            );

            const result = await api("/api/applications", {
                method: "POST",
                body: JSON.stringify(values)
            });

            showMessage(result.message || "Application submitted.");
            form.reset();

            await refreshApplication();
        } catch (error) {
            showMessage(error.message);
        } finally {
            if (submitButton) {
                submitButton.disabled = false;
            }
        }
    });
}

if (logoutButton) {
    logoutButton.addEventListener("click", async function () {
        try {
            await api("/auth/logout", {
                method: "POST"
            });

            window.location.reload();
        } catch (error) {
            showMessage(error.message);
        }
    });
}

start();