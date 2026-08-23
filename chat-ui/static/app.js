(function () {
  "use strict";

  // Fallback UUID v4 - generateUUID() wymaga "secure context" (HTTPS lub
  // dosłownie hostname "localhost"), a niestandardowe hosty jak np.
  // "cybersec-agent" wskazujące na 127.0.0.1 przez plik hosts NIE są
  // automatycznie traktowane jako bezpieczny kontekst przez przeglądarki.
  function generateUUID() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.generateUUID();
    }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      const r = (Math.random() * 16) | 0;
      const v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  const threadIdEl = document.getElementById("thread-id");
  const newSessionBtn = document.getElementById("new-session");
  const toolsListEl = document.getElementById("tools-list");
  const toolsAllBtn = document.getElementById("tools-all");
  const toolsNoneBtn = document.getElementById("tools-none");
  const tabCybersecBtn = document.getElementById("tab-cybersec");
  const tabPentestingBtn = document.getElementById("tab-pentesting");
  const modelsListEl = document.getElementById("models-list");
  const pulseBar = document.getElementById("pulse-bar");
  const pulseIdle = document.getElementById("pulse-idle");
  const pulseTrack = document.getElementById("pulse-track");
  const toolControlsEl = document.createElement("div");
  toolControlsEl.id = "tool-controls";
  toolControlsEl.className = "tool-controls hidden";
  toolControlsEl.innerHTML = `
    <span class="tool-elapsed">00:00</span>
    <button type="button" class="stop-btn">■ Zatrzymaj</button>`;
  pulseBar.insertAdjacentElement("afterend", toolControlsEl);
  const elapsedEl = toolControlsEl.querySelector(".tool-elapsed");
  const stopBtn = toolControlsEl.querySelector(".stop-btn");

  const liveOutputEl = document.createElement("pre");
  liveOutputEl.id = "live-output";
  liveOutputEl.className = "live-output hidden";
  toolControlsEl.insertAdjacentElement("afterend", liveOutputEl);

  let elapsedTimer = null;
  let elapsedStart = null;

  function startElapsedTimer() {
    elapsedStart = Date.now();
    if (elapsedTimer) clearInterval(elapsedTimer);
    elapsedTimer = setInterval(() => {
      const secs = Math.floor((Date.now() - elapsedStart) / 1000);
      const m = String(Math.floor(secs / 60)).padStart(2, "0");
      const s = String(secs % 60).padStart(2, "0");
      elapsedEl.textContent = `${m}:${s}`;
    }, 1000);
  }

  function stopElapsedTimer() {
    if (elapsedTimer) {
      clearInterval(elapsedTimer);
      elapsedTimer = null;
    }
  }

  stopBtn.addEventListener("click", async () => {
    if (!threadId) return;
    stopBtn.disabled = true;
    stopBtn.textContent = "Zatrzymywanie…";
    try {
      const res = await fetch(`/api/stop/${threadId}`, { method: "POST" });
      const data = await res.json();
      if (data.status === "stopped") {
        stopBtn.textContent = "Zatrzymano";
      } else if (data.status === "not_running") {
        stopBtn.textContent = "Nic do zatrzymania";
      } else {
        stopBtn.textContent = "Błąd zatrzymania";
      }
    } catch (e) {
      stopBtn.textContent = "Błąd komunikacji";
    }
    setTimeout(() => {
      stopBtn.disabled = false;
      stopBtn.textContent = "■ Zatrzymaj";
    }, 2000);
  });

  const threadEl = document.getElementById("thread");
  const composer = document.getElementById("composer");
  const composerInput = document.getElementById("composer-input");
  const composerSend = document.getElementById("composer-send");
  const exampleSelect = document.getElementById("example-select");

  let threadId = null;
  let selectedTools = new Set();
  let allTools = [];
  let activeCategory = "cybersec";
  let modelConfig = null;
  let pipelineOrder = [];
  let pollTimer = null;
  let pendingResolve = null;
  let isBusy = false;

  function saveThreadId(id) {
    try { sessionStorage.setItem("cybersec_thread_id", id); } catch (e) {}
  }
  function newSession() {
    threadId = generateUUID();
    saveThreadId(threadId);
    threadIdEl.textContent = threadId.slice(0, 8) + "…";
    threadEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-mark">🛡</div>
        <div class="empty-title">Gotowy do audytu</div>
        <div class="empty-sub">Wybierz narzędzia po lewej (opcjonalnie) i zadaj pytanie o bezpieczeństwo serwera.</div>
      </div>`;
    resetPulse();
  }
  async function resumeSession() {
    let savedId = null;
    try { savedId = sessionStorage.getItem("cybersec_thread_id"); } catch (e) {}
    if (!savedId) { newSession(); return; }
    try {
      const res = await fetch(`/api/status/${savedId}`);
      if (!res.ok) { newSession(); return; }
      const status = await res.json();
      const activeStages = ["security_agent", "report_writers", "critic"];
      if (!status || !activeStages.includes(status.stage)) {
        newSession();
        return;
      }
      // Wznawiamy sesję, która była w trakcie przetwarzania w momencie
      // odświeżenia strony (threadId żyje tylko w JS, ginie przy reload -
      // ale pipeline po stronie orchestratora działa dalej w tle).
      threadId = savedId;
      threadIdEl.textContent = threadId.slice(0, 8) + "…";
      threadEl.innerHTML = "";
      appendUserMessage("(wznowiono po odświeżeniu strony)");
      const bubble = appendAssistantPending();
      liveOutputEl.classList.add("hidden");
      liveOutputEl.textContent = "";
      toolControlsEl.classList.add("hidden");
      stopBtn.disabled = false;
      stopBtn.textContent = "■ Zatrzymaj";
      isBusy = true;
      composerSend.disabled = true;
      startElapsedTimer();
      startPolling();
      try {
        const finalStatus = await new Promise((resolve) => { pendingResolve = resolve; });
        if (finalStatus.stage === "error") {
          appendErrorMessage(bubble, finalStatus.detail || "Błąd podczas przetwarzania");
        } else {
          renderMarkdown(bubble, finalStatus.result || "(brak treści raportu)");
          if (finalStatus.suggested_tools && finalStatus.suggested_tools.length > 0) {
            renderSuggestions(bubble, finalStatus.suggested_tools);
          }
        }
      } catch (e) {
        appendErrorMessage(bubble, `Błąd komunikacji z serwerem: ${e.message}`);
        stopPolling();
      } finally {
        liveOutputEl.classList.add("hidden");
        toolControlsEl.classList.add("hidden");
        stopElapsedTimer();
        isBusy = false;
        composerSend.disabled = false;
        threadEl.scrollTop = threadEl.scrollHeight;
      }
    } catch (e) {
      newSession();
    }
  }

  newSessionBtn.addEventListener("click", newSession);

  async function loadTools() {
    try {
      const res = await fetch("/api/tools");
      const data = await res.json();
      allTools = data.tools || [];
      renderToolsList();
    } catch (e) {
      toolsListEl.innerHTML = `<div class="tools-loading">błąd ładowania narzędzi</div>`;
    }
  }

  function renderToolsList() {
    toolsListEl.innerHTML = "";
    const filtered = allTools.filter((t) => (t.category || "cybersec") === activeCategory);
    if (filtered.length === 0) {
      toolsListEl.innerHTML = `<div class="tools-loading">brak narzędzi w tej kategorii</div>`;
      return;
    }
    filtered.forEach((t) => {
      const row = document.createElement("label");
      row.className = "tool-item";
      const shortDesc = t.description.split("\n")[0].trim();
      row.innerHTML = `
        <input type="checkbox" data-tool="${t.name}">
        <span>
          <span class="tool-name">${t.name}</span>
          <span class="tool-desc">${shortDesc}</span>
        </span>`;
      const cb = row.querySelector("input");
      cb.checked = selectedTools.has(t.name);
      cb.addEventListener("change", () => {
        if (cb.checked) selectedTools.add(t.name);
        else selectedTools.delete(t.name);
      });
      toolsListEl.appendChild(row);
    });
  }

  function switchTab(category) {
    activeCategory = category;
    tabCybersecBtn.classList.toggle("mode-tab-active", category === "cybersec");
    tabPentestingBtn.classList.toggle("mode-tab-active", category === "pentesting");
    renderToolsList();
  }

  tabCybersecBtn.addEventListener("click", () => switchTab("cybersec"));
  tabPentestingBtn.addEventListener("click", () => switchTab("pentesting"));

  toolsAllBtn.addEventListener("click", () => {
    toolsListEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
      cb.checked = true;
      selectedTools.add(cb.dataset.tool);
    });
  });

  toolsNoneBtn.addEventListener("click", () => {
    toolsListEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
      cb.checked = false;
      selectedTools.delete(cb.dataset.tool);
    });
  });

  async function loadModels() {
    try {
      const res = await fetch("/api/models");
      modelConfig = await res.json();

      pipelineOrder = [{ key: "security_agent", label: modelConfig.tool_model }];
      modelConfig.report_models.forEach((m, i) => {
        pipelineOrder.push({ key: `writer:${i}`, label: shortModelName(m) });
      });
      pipelineOrder.push({ key: "critic", label: modelConfig.critic_model });

      renderModelsList();
      buildPulseTrack();
    } catch (e) {
      modelsListEl.innerHTML = `<div class="tools-loading">błąd ładowania modeli</div>`;
    }
  }

  function shortModelName(name) {
    return name.split("/").pop();
  }

  function renderModelsList() {
    modelsListEl.innerHTML = "";
    const roles = [
      { label: "AGENT", model: modelConfig.tool_model },
      ...modelConfig.report_models.map((m) => ({ label: "WRITER", model: m })),
      { label: "CRITIC", model: modelConfig.critic_model },
    ];
    roles.forEach((r, i) => {
      const row = document.createElement("div");
      row.className = "model-row";
      row.dataset.pipelineIndex = i;
      row.innerHTML = `<span class="model-dot" data-dot="${i}"></span> ${shortModelName(r.model)} <span class="model-role">${r.label}</span>`;
      modelsListEl.appendChild(row);
    });
  }

  function buildPulseTrack() {
    pulseTrack.innerHTML = "";
    pipelineOrder.forEach((node, i) => {
      const el = document.createElement("div");
      el.className = "pulse-node";
      el.dataset.index = i;
      el.innerHTML = `
        <div class="pulse-node-line"></div>
        <div class="pulse-node-circle">${i + 1}</div>
        <div class="pulse-node-label">${node.label}</div>`;
      pulseTrack.appendChild(el);
    });
  }

  function resetPulse() {
    pulseBar.classList.remove("active");
    pulseTrack.classList.remove("show");
    document.querySelectorAll(".pulse-node").forEach((n) => n.classList.remove("active", "done", "error"));
    document.querySelectorAll(".model-dot").forEach((d) => d.classList.remove("active", "done"));
    const statusText = pulseBar.querySelector(".pulse-status-text");
    if (statusText) statusText.remove();
  }

  function updatePulse(status) {
    const stage = status.stage;
    pulseBar.classList.add("active");
    pulseTrack.classList.add("show");

    let currentIdx = -1;
    if (stage === "security_agent") currentIdx = 0;
    else if (stage === "report_writers") {
      const match = /\((\d+)\/(\d+)\)/.exec(status.detail || "");
      const idx = match ? parseInt(match[1], 10) : 1;
      currentIdx = idx;
    } else if (stage === "critic") currentIdx = pipelineOrder.length - 1;
    else if (stage === "done") currentIdx = pipelineOrder.length;
    else if (stage === "error") currentIdx = -2;

    pipelineOrder.forEach((node, i) => {
      const el = pulseTrack.querySelector(`.pulse-node[data-index="${i}"]`);
      const dot = modelsListEl.querySelector(`.model-dot[data-dot="${i}"]`);
      el.classList.remove("active", "done", "error");
      if (dot) dot.classList.remove("active", "done");

      if (stage === "error") {
        return;
      }
      if (i < currentIdx) {
        el.classList.add("done");
        if (dot) dot.classList.add("done");
      } else if (i === currentIdx) {
        el.classList.add("active");
        if (dot) dot.classList.add("active");
      }
    });

    let statusText = pulseBar.querySelector(".pulse-status-text");
    if (!statusText) {
      statusText = document.createElement("div");
      statusText.className = "pulse-status-text";
      pulseBar.appendChild(statusText);
    }
    let percentSuffix = "";
    if (stage !== "error" && currentIdx >= 0 && pipelineOrder.length > 0) {
      const percent = Math.min(100, Math.round(((currentIdx + 1) / pipelineOrder.length) * 100));
      percentSuffix = ` (${percent}%)`;
    }
    statusText.textContent = (status.detail || stage) + percentSuffix;
  }

  async function pollToolOutput() {
    if (!threadId) return;
    try {
      const res = await fetch(`/api/tool_output/${threadId}`);
      const data = await res.json();
      if (data.lines && data.lines.length > 0) {
        liveOutputEl.classList.remove("hidden");
        toolControlsEl.classList.remove("hidden");
        const header = data.tool ? `$ ${data.tool}\n` : "";
        liveOutputEl.textContent = header + data.lines.join("\n");
        liveOutputEl.scrollTop = liveOutputEl.scrollHeight;
      }
    } catch (e) {}
  }

  async function pollStatus() {
    if (!threadId) return;
    try {
      const res = await fetch(`/api/status/${threadId}`);
      const status = await res.json();
      updatePulse(status);
      pollToolOutput();
      if (status.stage === "done" || status.stage === "error") {
        stopPolling();
        if (pendingResolve) {
          pendingResolve(status);
          pendingResolve = null;
        }
      }
    } catch (e) {}
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(pollStatus, 1000);
    pollStatus();
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function clearEmptyState() {
    const empty = threadEl.querySelector(".empty-state");
    if (empty) empty.remove();
  }

  function appendUserMessage(text) {
    clearEmptyState();
    const div = document.createElement("div");
    div.className = "msg msg-user";
    div.innerHTML = `<div class="msg-bubble"></div>`;
    div.querySelector(".msg-bubble").textContent = text;
    threadEl.appendChild(div);
    threadEl.scrollTop = threadEl.scrollHeight;
  }

  function appendAssistantPending() {
    const div = document.createElement("div");
    div.className = "msg msg-assistant";
    div.innerHTML = `
      <div class="msg-label">RAPORT</div>
      <div class="msg-bubble pending">Uruchamiam pipeline diagnostyczny…</div>`;
    threadEl.appendChild(div);
    threadEl.scrollTop = threadEl.scrollHeight;
    return div.querySelector(".msg-bubble");
  }

  const FINDING_ICON = { high: "\ud83d\udd34", medium: "\ud83d\udfe0", low: "\ud83d\udfe2" };
  const FINDING_LABEL = { high: "KRYTYCZNE", medium: "OSTRZEŻENIE", low: "INFO" };

  function escapeHtml(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  function renderMarkdown(bubbleEl, text) {
    bubbleEl.classList.remove("pending");

    const findingRe = /::finding\[(\w+)\]\{concern="([^"]*)"\s+title="([^"]*)"\}\n?([\s\S]*?)::/g;
    let out = "";
    let lastIndex = 0;
    let match;

    while ((match = findingRe.exec(text)) !== null) {
      const [full, type, concern, title, body] = match;
      const before = text.slice(lastIndex, match.index);
      out += window.marked ? window.marked.parse(before) : before;

      const cls = FINDING_ICON[type] ? type : "medium";
      const icon = FINDING_ICON[cls];
      const label = FINDING_LABEL[cls];
      const bodyHtml = body.trim()
        ? (window.marked ? window.marked.parse(body.trim()) : escapeHtml(body.trim()))
        : "";

      out += `
        <div class="finding-card finding-${cls}">
          <div class="finding-head">
            <span class="finding-icon">${icon}</span>
            <span class="finding-label">${label}</span>
            <span class="finding-title">${escapeHtml(title)}</span>
          </div>
          ${bodyHtml ? `<div class="finding-body">${bodyHtml}</div>` : ""}
          <div class="finding-concern">${escapeHtml(concern)}</div>
        </div>`;

      lastIndex = match.index + full.length;
    }

    out += window.marked ? window.marked.parse(text.slice(lastIndex)) : text.slice(lastIndex);
    bubbleEl.innerHTML = out;
  }

  function appendErrorMessage(bubbleEl, text) {
    bubbleEl.closest(".msg").classList.add("msg-error");
    bubbleEl.classList.remove("pending");
    bubbleEl.textContent = text;
  }

  const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  let lastTargetGuess = null;

  function renderSuggestions(bubble, tools) {
    const msgDiv = bubble.closest(".msg");
    if (!msgDiv) return;
    const box = document.createElement("div");
    box.className = "suggestions-box";
    const itemsHtml = tools.map((t) => `
      <label class="suggestion-item">
        <input type="checkbox" data-tool="${escapeHtml(t.name)}" checked>
        <div>
          <div class="suggestion-name">${escapeHtml(t.name)}</div>
          <div class="suggestion-desc">${escapeHtml(t.description)}</div>
        </div>
      </label>`).join("");
    box.innerHTML = `
      <div class="suggestions-title">⚠ Audyt sugeruje weryfikację pentestem</div>
      ${itemsHtml}
      <button type="button" class="run-suggested-btn">Uruchom pentest z zaznaczonymi</button>`;
    msgDiv.insertAdjacentElement("afterend", box);

    box.querySelector(".run-suggested-btn").addEventListener("click", () => {
      const checked = Array.from(box.querySelectorAll('input[type="checkbox"]:checked'))
        .map((el) => el.getAttribute("data-tool"));
      if (checked.length === 0) return;
      selectedTools = new Set(checked);
      box.remove();
      const target = lastTargetGuess ? ` na ${lastTargetGuess}` : "";
      sendMessage(`Przeprowadź weryfikację pentestową narzędziami: ${checked.join(", ")}${target}`);
    });
  }

  async function sendMessage(text) {
    if (isBusy || !text.trim()) return;
    const ipMatch = text.match(IPV4_RE);
    if (ipMatch) lastTargetGuess = ipMatch[0];
    isBusy = true;
    composerSend.disabled = true;

    appendUserMessage(text);
    const bubble = appendAssistantPending();
    liveOutputEl.classList.add("hidden");
    liveOutputEl.textContent = "";
    toolControlsEl.classList.add("hidden");
    stopBtn.disabled = false;
    stopBtn.textContent = "■ Zatrzymaj";
    startElapsedTimer();
    // WAŻNE: resetujemy pasek WIZUALNIE od razu, zanim cokolwiek pójdzie
    // do backendu - inaczej przez chwilę widać stary, zakończony ("done")
    // stan poprzedniego zapytania w tej samej sesji.
    resetPulse();

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text,
          thread_id: threadId,
          selected_tools: selectedTools.size > 0 ? Array.from(selectedTools) : null,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        appendErrorMessage(bubble, `Błąd: ${data.detail || "nieznany błąd orchestratora"}`);
      } else {
        threadId = data.thread_id;
        saveThreadId(threadId);
        threadIdEl.textContent = threadId.slice(0, 8) + "…";
        // KLUCZOWA ZMIANA: zaczynamy polling DOPIERO PO otrzymaniu
        // potwierdzenia od backendu (który w /chat synchronicznie ustawia
        // status_store na "starting" PRZED zwróceniem odpowiedzi) - to
        // eliminuje wyścig, w którym pierwsze poll(e) trafiały jeszcze na
        // stary status "done" z poprzedniego zapytania w tej samej sesji.
        startPolling();
        // Pipeline działa teraz w tle po stronie orchestratora - czekamy na
        // wynik przez ten sam mechanizm pollingu /status, zamiast trzymać
        // otwarte jedno długie połączenie HTTP (które przy pipeline'ach
        // trwających kilkanaście-kilkadziesiąt minut było zawodne).
        const status = await new Promise((resolve) => { pendingResolve = resolve; });
        if (status.stage === "error") {
          appendErrorMessage(bubble, status.detail || "Błąd podczas przetwarzania");
        } else {
          renderMarkdown(bubble, status.result || "(brak treści raportu)");
          if (status.suggested_tools && status.suggested_tools.length > 0) {
            renderSuggestions(bubble, status.suggested_tools);
          }
        }
      }
    } catch (e) {
      appendErrorMessage(bubble, `Błąd komunikacji z serwerem: ${e.message}`);
      stopPolling();
    } finally {
      liveOutputEl.classList.add("hidden");
      toolControlsEl.classList.add("hidden");
      stopElapsedTimer();
      isBusy = false;
      composerSend.disabled = false;
      threadEl.scrollTop = threadEl.scrollHeight;
    }
  }

  composer.addEventListener("submit", (e) => {
    e.preventDefault();
    const text = composerInput.value;
    composerInput.value = "";
    sendMessage(text);
  });

  exampleSelect.addEventListener("change", () => {
    if (exampleSelect.value) {
      composerInput.value = exampleSelect.value;
      composerInput.focus();
      exampleSelect.selectedIndex = 0;
    }
  });

  resumeSession();
  loadTools();
  loadModels();
})();
