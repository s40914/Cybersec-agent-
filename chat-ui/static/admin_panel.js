document.addEventListener('DOMContentLoaded', function () {
  const triggerSection = document.getElementById("admin-panel-trigger-section");
  const panelBtn = document.getElementById("admin-panel-btn");
  const overlay = document.getElementById("admin-panel-overlay");
  const content = document.getElementById("admin-panel-content");
  const closeBtn = document.getElementById("admin-panel-close");

  function showAdminButtonIfNeeded() {
    const user = window.currentUser;
    if (user && user.is_admin) {
      triggerSection.style.display = "block";
    } else {
      triggerSection.style.display = "none";
    }
  }

  // window.currentUser jest ustawiane przez login.js po zalogowaniu/
  // weryfikacji sesji. Sprawdzamy okresowo, bo login.js moze ustawic
  // je pozniej niz ten skrypt sie zaladuje.
  const checkInterval = setInterval(() => {
    if (window.currentUser !== undefined) {
      showAdminButtonIfNeeded();
    }
  }, 300);

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
  }

  async function loadAuditLog() {
    content.textContent = "ladowanie...";
    const token = window.getSessionToken ? window.getSessionToken() : null;
    if (!token) {
      content.textContent = "Brak sesji.";
      return;
    }

    try {
      const resp = await fetch("/api/audit_log?session_token=" + encodeURIComponent(token) + "&limit=200");
      const data = await resp.json();

      if (!resp.ok) {
        content.textContent = "Blad: " + (data.detail || "nieznany blad");
        return;
      }

      if (!data.logs || data.logs.length === 0) {
        content.textContent = "Brak wpisow w logu.";
        return;
      }

      let html = '<table style="width:100%; border-collapse: collapse; font-size: 13px;">';
      html += '<tr style="text-align:left; border-bottom: 1px solid rgba(255,255,255,0.2);">' +
              '<th style="padding:6px;">Czas</th>' +
              '<th style="padding:6px;">Osoba</th>' +
              '<th style="padding:6px;">Zdarzenie</th>' +
              '<th style="padding:6px;">Narzedzie</th>' +
              '<th style="padding:6px;">Cel</th>' +
              '<th style="padding:6px;">Status</th></tr>';

      for (const log of data.logs) {
        html += '<tr style="border-bottom: 1px solid rgba(255,255,255,0.08);">' +
                '<td style="padding:6px;">' + escapeHtml(log.timestamp) + '</td>' +
                '<td style="padding:6px;">' + escapeHtml((log.first_name || "") + " " + (log.last_name || "") + " (" + (log.email || "brak") + ")") + '</td>' +
                '<td style="padding:6px;">' + escapeHtml(log.event_type) + '</td>' +
                '<td style="padding:6px;">' + escapeHtml(log.tool_name) + '</td>' +
                '<td style="padding:6px;">' + escapeHtml(log.target) + '</td>' +
                '<td style="padding:6px;">' + escapeHtml(log.status) + '</td>' +
                '</tr>';
      }
      html += "</table>";
      content.innerHTML = html;
    } catch (err) {
      content.textContent = "Nie mozna polaczyc sie z serwerem.";
    }
  }

  panelBtn.addEventListener("click", () => {
    overlay.classList.remove("hidden");
    loadAuditLog();
  });

  closeBtn.addEventListener("click", () => {
    overlay.classList.add("hidden");
  });
});
