(function () {
  const overlay = document.getElementById("login-overlay");
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");

  const loginEmail = document.getElementById("login-email");
  const loginPassword = document.getElementById("login-password");
  const loginError = document.getElementById("login-error");
  const loginSubmitBtn = document.getElementById("login-submit-btn");

  const registerFirstName = document.getElementById("register-first-name");
  const registerLastName = document.getElementById("register-last-name");
  const registerEmail = document.getElementById("register-email");
  const registerPassword = document.getElementById("register-password");
  const registerError = document.getElementById("register-error");
  const registerSubmitBtn = document.getElementById("register-submit-btn");

  const showRegisterBtn = document.getElementById("show-register-btn");
  const showLoginBtn = document.getElementById("show-login-btn");

  const SESSION_KEY = "cybersec_session_token";

  function showRegister() {
    loginForm.classList.add("hidden");
    registerForm.classList.remove("hidden");
  }

  function showLogin() {
    registerForm.classList.add("hidden");
    loginForm.classList.remove("hidden");
  }

  showRegisterBtn.addEventListener("click", showRegister);
  showLoginBtn.addEventListener("click", showLogin);

  function hideOverlay() {
    overlay.classList.add("hidden");
    // Po zalogowaniu pokaz ekran ostrzezenia/zgody na ryzyko (splash-overlay),
    // ktory jest domyslnie ukryty, zeby nie nakladal sie na ekran logowania.
    const splash = document.getElementById("splash-overlay");
    if (splash) splash.classList.remove("hidden");
  }

  function storeSession(token, user) {
    // sessionStorage (nie localStorage) - sesja konczy sie z zamknieciem
    // karty przegladarki, spojnie z tym ze wiele osob moze uzywac tego
    // samego komputera (patrz komentarz przy splash-overlay).
    sessionStorage.setItem(SESSION_KEY, token);
    window.currentUser = user;
  }

  async function doLogin() {
    loginError.classList.add("hidden");
    const email = loginEmail.value.trim();
    const password = loginPassword.value;

    if (!email || !password) {
      loginError.textContent = "Podaj e-mail i haslo.";
      loginError.classList.remove("hidden");
      return;
    }

    try {
      const resp = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await resp.json();

      if (!resp.ok) {
        loginError.textContent = data.detail || "Blad logowania.";
        loginError.classList.remove("hidden");
        return;
      }

      storeSession(data.token, data.user);
      hideOverlay();
    } catch (err) {
      loginError.textContent = "Nie mozna polaczyc sie z serwerem.";
      loginError.classList.remove("hidden");
    }
  }

  async function doRegister() {
    registerError.classList.add("hidden");
    const first_name = registerFirstName.value.trim();
    const last_name = registerLastName.value.trim();
    const email = registerEmail.value.trim();
    const password = registerPassword.value;

    if (!first_name || !last_name || !email || !password) {
      registerError.textContent = "Wypelnij wszystkie pola.";
      registerError.classList.remove("hidden");
      return;
    }
    if (password.length < 8) {
      registerError.textContent = "Haslo musi miec co najmniej 8 znakow.";
      registerError.classList.remove("hidden");
      return;
    }

    try {
      const resp = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ first_name, last_name, email, password }),
      });
      const data = await resp.json();

      if (!resp.ok) {
        registerError.textContent = data.detail || "Blad zakladania konta.";
        registerError.classList.remove("hidden");
        return;
      }

      // Po udanej rejestracji od razu loguj.
      loginEmail.value = email;
      loginPassword.value = password;
      showLogin();
      await doLogin();
    } catch (err) {
      registerError.textContent = "Nie mozna polaczyc sie z serwerem.";
      registerError.classList.remove("hidden");
    }
  }

  loginSubmitBtn.addEventListener("click", doLogin);
  registerSubmitBtn.addEventListener("click", doRegister);

  // Pozwol wcisnac Enter zamiast klikac przycisk.
  [loginEmail, loginPassword].forEach((el) =>
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doLogin();
    })
  );
  [registerFirstName, registerLastName, registerEmail, registerPassword].forEach((el) =>
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doRegister();
    })
  );

  // Sprawdz przy starcie czy jest juz wazna sesja (np. po odswiezeniu strony).
  async function checkExistingSession() {
    const token = sessionStorage.getItem(SESSION_KEY);
    if (!token) return;

    try {
      const resp = await fetch("/api/verify_session?token=" + encodeURIComponent(token));
      if (resp.ok) {
        const data = await resp.json();
        window.currentUser = data.user;
        hideOverlay();
      } else {
        sessionStorage.removeItem(SESSION_KEY);
      }
    } catch (err) {
      // Brak polaczenia - zostaw overlay widoczny, nie blokuj na bledzie sieci.
    }
  }

  checkExistingSession();

  // Eksponujemy funkcje pomocnicza dla app.js - zeby moglo dolaczac token
  // sesji do naglowkow przy wywolaniach /api/chat itd.
  window.getSessionToken = function () {
    return sessionStorage.getItem(SESSION_KEY);
  };
})();
