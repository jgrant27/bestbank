// Best Bank account page. Served from /static so the Content-Security-Policy
// can forbid inline scripts. All server-provided values are inserted with
// textContent, never as HTML.
"use strict";

(function () {
    var TOAST_MS = 6000;
    var KIND_LABELS = {
        deposit: "deposit",
        withdrawal: "withdrawal",
        transfer_out: "sent to",
        transfer_in: "received from",
    };

    function $(id) {
        return document.getElementById(id);
    }

    function csrfToken() {
        return document.querySelector('meta[name="csrf-token"]').content;
    }

    // Show a dismissable notification. kind: "success" | "error" | "info".
    function toast(message, kind) {
        var el = document.createElement("div");
        el.className = "toast " + (kind || "success");
        el.setAttribute("role", kind === "error" ? "alert" : "status");
        el.textContent = message;
        el.title = "Click to dismiss";
        el.addEventListener("click", function () { el.remove(); });
        $("toasts").appendChild(el);
        setTimeout(function () { el.remove(); }, TOAST_MS);
    }

    function describe(tx) {
        var what = KIND_LABELS[tx.kind] || tx.kind;
        return tx.counterparty ? what + " " + tx.counterparty : what;
    }

    function renderTransactions(transactions) {
        var table = document.createElement("table");
        table.className = "transactions";
        if (transactions.length === 0) {
            var cell = table.insertRow().insertCell();
            cell.className = "empty";
            cell.textContent = "No transactions yet.";
        }
        transactions.forEach(function (tx) {
            var row = table.insertRow();
            row.insertCell().textContent = tx.time;
            row.insertCell().textContent = describe(tx);
            var amount = row.insertCell();
            amount.className = "amount";
            amount.textContent = "💵" + tx.amount;
        });
        $("transactions").replaceChildren(table);
    }

    function accountInfo() {
        return fetch("/json/account_info")
            .then(function (res) {
                if (res.status === 401) {
                    window.location.assign("/login");
                    throw new Error("not logged in");
                }
                if (!res.ok) { throw new Error("HTTP " + res.status); }
                return res.json();
            })
            .then(function (data) {
                $("name").textContent = data.user_name;
                $("balance").textContent = data.balance;
                renderTransactions(data.transactions);
            })
            .catch(function (err) {
                if (err.message !== "not logged in") {
                    toast("Couldn't load your account. Try reloading.", "error");
                }
            });
    }

    function transaction(type) {
        var button = $(type);
        button.disabled = true;
        var body = { amount: parseFloat($("transaction_amount").value) };
        if (type === "transfer") {
            body.to = $("transfer_to").value;
        }
        fetch("/json/" + type, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken(),
            },
            body: JSON.stringify(body),
        })
            .then(function (res) {
                return res.json().catch(function () {
                    return { success: false, message: "Request failed (HTTP " + res.status + ")." };
                });
            })
            .then(function (data) {
                if (!data.success) {
                    toast(data.message || "Request failed.", "error");
                }
            })
            .catch(function () {
                toast("Network error. Please try again.", "error");
            })
            .finally(function () {
                button.disabled = false;
            });
    }

    function connectEvents() {
        if (!("WebSocket" in window)) {
            toast("Your browser doesn't support live updates.", "info");
            return;
        }
        // Same origin as the page; the session cookie authenticates us.
        var scheme = window.location.protocol === "https:" ? "wss://" : "ws://";
        var ws = new WebSocket(scheme + window.location.host + "/ws");
        ws.addEventListener("message", function (evt) {
            toast(evt.data, "success");
            accountInfo();
        });
        ws.addEventListener("close", function () {
            toast("Live updates stopped. Reload the page to reconnect.", "info");
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        document.querySelectorAll("[data-action]").forEach(function (button) {
            button.addEventListener("click", function () {
                transaction(button.dataset.action);
            });
        });
        connectEvents();
        accountInfo();
    });
})();
