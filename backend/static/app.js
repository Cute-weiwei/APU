(() => {
  "use strict";
  const state = {
    token: localStorage.getItem("apu_token") || "",
    user: null,
    jobs: [],
    jobsTotal: 0,
    jobsOffset: 0,
    jobsLimit: 20,
    jobStatus: "",
    uploads: {},
    storage: null,
    devices: [],
    engines: {},
    providers: [],
    agents: [],
    skills: [],
    mcps: [],
    presets: null,
    lessons: [],
    lessonStats: {},
    lessonKind: "",
    lessonSelection: new Set(),
    lessonEditId: null,
    selectedJob: null,
    selectedEvents: [],
    callItems: [],
    callFilters: { tool: true, mcp: true, skill: true, lesson: true, agent: true },
    stream: null,
    poll: null,
    tab: "jobs",
    engineChoice: "",
    adminPane: "overview",
    editingProvider: null,
    editingAgent: null,
    editingSkill: null,
    editingMcp: null,
    chatAgents: [],
    chats: [],
    chat: null,
    chatMessages: [],
    chatPendingFiles: [],
    chatSending: false,
    chatAbort: null,
    chatDraft: "",
    armRuntimeError: "",
    lang: localStorage.getItem("apu_lang") || "zh",
  };
  state.lang = window.ApuI18n?.lang || state.lang || "zh";
  const ADMIN_ONLY_PANES = ["overview", "storage", "users", "models", "system", "audit"];

  function isAdmin() {
    return state.user?.role === "admin";
  }

  function canManage(item) {
    if (isAdmin()) return true;
    return item?.owner_id != null && Number(item.owner_id) === Number(state.user?.id);
  }

  function ownershipBadge(item) {
    if (item?.shared) return '<span class="badge run">共享</span>';
    return '<span class="badge ok">我的</span>';
  }

  function syncAdminVisibility() {
    const admin = isAdmin();
    const adminTab = document.querySelector('.tab[data-tab="admin"]');
    if (adminTab) adminTab.classList.remove("hidden");
    document.querySelectorAll(".admin-tab, .admin-pane").forEach((element) => {
      const pane = element.dataset.adminPane;
      element.classList.toggle("admin-locked", !admin && ADMIN_ONLY_PANES.includes(pane));
    });
    if (!admin && ADMIN_ONLY_PANES.includes(state.adminPane)) state.adminPane = "agents";
    document.querySelectorAll(".lesson-admin").forEach((element) => {
      element.classList.toggle("hidden", !admin);
    });
    document.querySelectorAll(".admin-only-option").forEach((element) => {
      element.classList.toggle("hidden", !admin);
    });
    if (!admin) {
      state.lessonSelection.clear();
      if (state.lessonEditId) closeLessonEdit();
      if (state.lessons.length) renderLessons();
    }
    if ($("admin-title")) $("admin-title").textContent = admin ? "管理后台" : "个人资源";
    if ($("admin-desc")) {
      $("admin-desc").textContent = admin
        ? "账号权限、模型协议、Agent / Skill / MCP 工具链与运行环境"
        : "新增并管理我的 Agent / Skill / MCP；共享资源由管理员维护，只读使用。";
    }
  }

  function updateLangToggle() {
    const button = $("lang-toggle");
    if (!button) return;
    button.textContent = state.lang === "en" ? "中文" : "English";
    button.title = state.lang === "en" ? "Switch to Chinese" : "Switch to English";
  }

  function toggleLanguage() {
    const next = state.lang === "en" ? "zh" : "en";
    if (window.ApuI18n) window.ApuI18n.setLanguage(next);
    state.lang = next;
    updateLangToggle();
  }

  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const jsonPreview = (value, limit = 900) => {
    try { return JSON.stringify(value).slice(0, limit); } catch (e) { return String(value ?? "").slice(0, limit); }
  };

  function tr(value) {
    if (state.lang !== "en") return value;
    const text = String(value ?? "");
    const translated = window.ApuI18n?.translateText?.(text);
    return translated || text;
  }

  // Native dialogs are not part of the DOM, so translate their messages here.
  const nativeConfirm = window.confirm.bind(window);
  const nativePrompt = window.prompt.bind(window);
  const nativeAlert = window.alert.bind(window);
  window.confirm = (message) => nativeConfirm(tr(message));
  window.prompt = (message, defaultValue) => nativePrompt(tr(message), defaultValue);
  window.alert = (message) => nativeAlert(tr(message));

  function toast(message, isError = false) {
    const node = $("toast");
    node.textContent = message;
    node.style.borderColor = isError ? "#73313b" : "#263252";
    node.classList.remove("hidden");
    clearTimeout(node._timer);
    node._timer = setTimeout(() => node.classList.add("hidden"), isError ? 7000 : 3500);
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ "X-Requested-With": "XMLHttpRequest" }, options.headers || {});
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    if (options.body && !(options.body instanceof FormData) && typeof options.body !== "string") {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(options.body);
    }
    const response = await fetch(path, Object.assign({}, options, { headers }));
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
    if (!response.ok) {
      const message = data?.error?.message || `HTTP ${response.status}`;
      const error = new Error(message);
      error.status = response.status;
      error.code = data?.error?.code || "";
      error.body = data;
      throw error;
    }
    return data;
  }

  function showLogin() {
    $("login-view").classList.remove("hidden");
    $("app-view").classList.add("hidden");
    if (state.stream) { state.stream.close(); state.stream = null; }
  }

  function updateAccount() {
    if ($("account-name")) $("account-name").textContent = state.user?.username || "-";
    if ($("account-role")) {
      $("account-role").textContent = state.user?.role === "admin" ? "管理员" : "普通用户";
      $("account-role").className = `badge ${state.user?.role === "admin" ? "ok" : "run"}`;
    }
  }

  function showApp() {
    $("login-view").classList.add("hidden");
    $("app-view").classList.remove("hidden");
    $("who-name").textContent = state.user ? `${state.user.username} (${state.user.role})` : "";
    updateAccount();
    syncAdminVisibility();
  }

  async function login(event) {
    event.preventDefault();
    const error = $("login-error");
    error.textContent = "";
    try {
      const data = await api("/api/v1/auth/login", {
        method: "POST",
        body: { username: $("login-user").value.trim(), password: $("login-pass").value },
      });
      state.token = data.token;
      state.user = data.user;
      localStorage.setItem("apu_token", state.token);
      showApp();
      await bootstrapData();
    } catch (exc) {
      error.textContent = exc.message;
    }
  }

  async function logout() {
    try { await api("/api/v1/auth/logout", { method: "POST" }); } catch (e) {}
    state.token = "";
    state.user = null;
    localStorage.removeItem("apu_token");
    showLogin();
  }

  async function loadMe() {
    if (!state.token) { showLogin(); return false; }
    try {
      const data = await api("/api/v1/auth/me");
      state.user = data.user;
      showApp();
      return true;
    } catch (e) {
      state.token = "";
      localStorage.removeItem("apu_token");
      showLogin();
      return false;
    }
  }

  // ------------------------------------------------------------------ engines / devices
  function connectedArmDevices() {
    return (state.devices || []).filter(
      (device) => device && !device.error && device.connected && /arm64|aarch64/i.test(String(device.arch || ""))
    );
  }

  function updateArmAvailabilityNote() {
    const note = $("arm-note");
    if (!note) return;
    const arm = connectedArmDevices();
    if (arm.length) {
      note.textContent = `已检测到在线 ARM64 设备：${arm.map((device) => device.serial).join(", ")}；勾选后优先使用（QEMU 较慢）。`
        + (state.armRuntimeError ? ` 注意：最近任务报告 ARM64 运行时不可用：${state.armRuntimeError}` : "");
      return;
    }
    if (state.armRuntimeError) {
      note.textContent = `ARM64 运行时最近报告不可用：${state.armRuntimeError}。仍可勾选，但准备失败会明确返回 arm_runtime_unavailable。`;
      return;
    }
    note.textContent = "未检测到在线 ARM64 设备；勾选后任务会尝试自动准备 ARM64 redroid（QEMU 很慢），失败会返回 arm_runtime_unavailable，不会假装可用。";
  }

  function noteArmAvailabilityFromJob(job) {
    const code = job?.error?.code || "";
    if (code !== "arm_runtime_unavailable") return;
    state.armRuntimeError = String(job.error.message || code).slice(0, 240);
    updateArmAvailabilityNote();
  }

  async function loadDevices() {
    try {
      const data = await api("/api/v1/devices");
      state.devices = data.devices || [];
    } catch (e) { state.devices = []; }
    const select = $("serial");
    const current = select.value;
    select.innerHTML = '<option value="">自动/默认</option>';
    for (const device of state.devices) {
      if (!device.serial) continue;
      const option = document.createElement("option");
      option.value = device.serial;
      option.textContent = `${device.name || device.serial} · ${device.serial}${device.connected ? "" : " · 离线"}`;
      select.appendChild(option);
    }
    if (current) select.value = current;
    updateArmAvailabilityNote();
    if (!$("devices-list")) return;
    $("devices-list").innerHTML = state.devices.length
      ? state.devices.map((device) => {
          if (device.error) {
            return `<div class="lesson"><b class="error">设备扫描失败</b><span class="muted">${esc(device.error.message || device.error.code || "")}</span></div>`;
          }
          const admin = isAdmin();
          const controls = admin ? `<div class="row">
            ${device.serial && String(device.serial).includes(":") ? `<button class="ghost" data-connect-device="${esc(device.serial)}">连接</button>` : ""}
            <button class="ghost" data-edit-device="${esc(device.serial)}">编辑</button>
            <button class="ghost danger" data-delete-device="${esc(device.serial)}">删除</button>
          </div>` : "";
          return `<div class="lesson">
            <b>${esc(device.name || device.serial)} <span class="badge ${device.connected ? "ok" : "fail"}">${device.connected ? "在线" : "离线"}</span>
              <span class="badge run">${esc(device.kind || "auto")}</span> <span class="badge">${esc(device.source || "auto")}</span>
              ${device.arch ? `<span class="badge ${device.arch === "arm64" ? "warn" : ""}">${esc(device.arch === "arm64" ? "ARM64 · 慢速回退" : device.arch)}</span>` : ""}
              <span class="muted small">${esc(device.serial)}</span></b>
            <span class="muted">${esc(device.address || device.serial)}${device.notes ? ` · ${esc(device.notes)}` : ""}${device.last_seen_at ? ` · 最近在线 ${esc(formatTime(device.last_seen_at))}` : ""}</span>
            ${controls}
          </div>`;
        }).join("")
      : '<div class="muted">未发现设备</div>';
    $("devices-list").querySelectorAll("[data-connect-device]").forEach((button) => {
      button.onclick = () => connectDevice(button.dataset.connectDevice);
    });
    $("devices-list").querySelectorAll("[data-edit-device]").forEach((button) => {
      button.onclick = () => editDevice(button.dataset.editDevice);
    });
    $("devices-list").querySelectorAll("[data-delete-device]").forEach((button) => {
      button.onclick = () => deleteDevice(button.dataset.deleteDevice);
    });
  }

  async function addDevice() {
    const serial = $("device-serial").value.trim();
    try {
      const data = await api("/api/v1/devices", {
        method: "POST",
        body: {
          serial,
          name: $("device-name").value.trim(),
          kind: $("device-kind").value,
          connect: serial ? $("device-connect").checked : false,
        },
      });
      if (data.auto) {
        const parts = [];
        if (data.new_count) parts.push(`新增 ${data.new_count} 台`);
        if (data.restored_count) parts.push(`恢复 ${data.restored_count} 台`);
        toast(parts.length ? `设备已更新：${parts.join("，")}` : "没有发现新的在线设备");
      } else {
        toast("设备已添加");
      }
      $("device-serial").value = "";
      $("device-name").value = "";
      $("device-connect").checked = false;
      await loadDevices();
    } catch (e) { toast(e.message, true); }
  }

  async function connectDevice(serial) {
    try {
      const data = await api(`/api/v1/devices/${encodeURIComponent(serial)}/connect`, { method: "POST", body: {} });
      toast(data.connected ? "设备已连接" : "连接失败，请检查地址", !data.connected);
      await loadDevices();
    } catch (e) { toast(e.message, true); }
  }

  async function editDevice(serial) {
    const device = state.devices.find((item) => item.serial === serial);
    if (!device) return;
    const name = prompt("设备名称", device.name || serial);
    if (name === null) return;
    const notes = prompt("备注", device.notes || "");
    if (notes === null) return;
    try {
      await api(`/api/v1/devices/${encodeURIComponent(serial)}`, { method: "PATCH", body: { name, notes } });
      toast("设备已更新");
      await loadDevices();
    } catch (e) { toast(e.message, true); }
  }

  async function deleteDevice(serial) {
    if (!confirm(`从设备列表隐藏 ${serial}？这不会断开 adb，设备仍保持连接。`)) return;
    try {
      await api(`/api/v1/devices/${encodeURIComponent(serial)}`, { method: "DELETE" });
      toast("设备已隐藏");
      await loadDevices();
    } catch (e) { toast(e.message, true); }
  }

  function engineLabel(id) {
    const engine = state.engines[id];
    if (!engine) return id;
    return engine.label || engine.name || id;
  }

  function isNativeEngine(id, engine) {
    return id === "agent-native" || engine?.kind === "native";
  }

  // DeepSeek OpenAI-protocol model agent is preferred; deterministic is second.
  function engineRank(id, engine) {
    const provider = String(engine?.provider_id || "").toLowerCase();
    if (id === "agent-deepseek-openai") return 0;
    if (provider === "deepseek-openai") return 1;
    if (provider.includes("deepseek") && engine?.protocol === "openai") return 2;
    if (provider.includes("deepseek")) return 3;
    return 4;
  }

  function engineComparator(entries) {
    const availableModels = entries.filter(
      ([id, engine]) => engine?.available !== false && !isNativeEngine(id, engine)
    );
    const hasPreferred = availableModels.some(([id, engine]) => engineRank(id, engine) === 0);
    const weight = ([id, engine]) => {
      const available = engine?.available !== false;
      const native = isNativeEngine(id, engine);
      if (available) {
        if (!native) {
          if (hasPreferred) return engineRank(id, engine) === 0 ? 0 : 2;
          return 0;
        }
        return hasPreferred || availableModels.length ? 1 : 0;
      }
      if (native) return 8;
      return 9 + engineRank(id, engine);
    };
    return (a, b) => weight(a) - weight(b) || a[0].localeCompare(b[0]);
  }

  function defaultEngineId(entries) {
    const available = entries.filter(([, engine]) => engine?.available !== false);
    const model = available.find(([id, engine]) => !isNativeEngine(id, engine));
    if (model) return model[0];
    const native = available.find(([id, engine]) => isNativeEngine(id, engine));
    if (native) return native[0];
    return entries[0]?.[0] || "";
  }

  async function loadEngines() {
    try {
      const data = await api("/api/v1/engines");
      state.engines = data.engines || {};
    } catch (e) { state.engines = {}; }
    const select = $("engine");
    const previous = state.engineChoice || select.value;
    const entries = Object.entries(state.engines);
    entries.sort(engineComparator(entries));
    select.innerHTML = "";
    for (const [id, engine] of entries) {
      const option = document.createElement("option");
      option.value = id;
      option.disabled = !engine.available;
      const kind = engine.kind === "llm" ? `${engine.protocol}/${engine.model}` : "deterministic";
      option.textContent = `${engine.label || engine.name || id} · ${kind}${engine.available ? "" : ` · ${engine.reason || "不可用"}`}`;
      select.appendChild(option);
    }
    const previousAvailable = entries.some(([id, engine]) => id === previous && engine?.available !== false);
    const desired = previousAvailable ? previous : defaultEngineId(entries);
    if (desired) select.value = desired;
    state.engineChoice = select.value;

    const enginesHtml = entries.map(([id, engine]) => {
      const skills = (engine.skills || []).map((item) => item.name).filter(Boolean).join(", ");
      const mcp = (engine.mcp || []).map((item) => `${item.name}(${item.tools?.length || 0})`).filter(Boolean).join(", ");
      return `<div class="lesson">
        <b>${esc(engine.label || engine.name || id)} <span class="badge ${engine.available ? "ok" : "fail"}">${engine.available ? "可用" : "不可用"}</span>
          <span class="badge run">${esc(engine.kind || "llm")}</span> <span class="muted small">${esc(id)}</span></b>
        <span class="muted">${esc(engine.protocol || "")}${engine.model ? ` · ${esc(engine.model)}` : ""}${engine.context_window ? ` · ctx ${esc(engine.context_window)}` : ""} · ${esc(engine.reason || "")}</span>
        ${skills ? `<div class="muted small">Skills: ${esc(skills)}</div>` : ""}
        ${mcp ? `<div class="muted small">MCP: ${esc(mcp)}</div>` : ""}
        ${engine.provider ? `<div class="muted small">Provider: ${esc(engine.provider)}${engine.base_url ? ` · ${esc(engine.base_url)}` : ""}</div>` : ""}
      </div>`;
    }).join("") || '<div class="muted">无引擎信息</div>';
    for (const id of ["engines-list", "engines-list-system"]) {
      const box = $(id);
      if (box) box.innerHTML = enginesHtml;
    }
  }

  // ------------------------------------------------------------------ providers
  async function loadProviderPresets() {
    if (state.presets) return;
    try {
      state.presets = await api("/api/v1/providers/presets");
    } catch (e) { state.presets = null; }
    const box = $("provider-presets");
    if (!box) return;
    const presets = state.presets?.providers || [];
    box.innerHTML = presets.map((preset) => `<button class="ghost small" data-preset="${esc(preset.id)}">${esc(preset.name)}</button>`).join("");
    box.querySelectorAll("[data-preset]").forEach((button) => {
      button.onclick = () => {
        const preset = presets.find((item) => item.id === button.dataset.preset);
        openProviderForm(null, preset || null);
      };
    });
  }

  function protocolLabel(protocol) {
    return ({ openai: "OpenAI", anthropic: "Anthropic", auto: "自动" })[protocol] || protocol || "-";
  }

  function protocolDefaults(protocol) {
    return state.presets?.protocols?.[protocol] || {
      base_url: protocol === "anthropic" ? "https://api.deepseek.com/anthropic" : "https://api.deepseek.com",
      model: "deepseek-chat",
      context_window: 65536,
      max_tokens: 8192,
      max_steps: 24,
      timeout_s: 180,
      temperature: 0.1,
    };
  }

  function applyProtocolDefaults(protocol, force = false) {
    const defaults = protocolDefaults(protocol);
    const fields = [
      ["pv-base-url", defaults.base_url],
      ["pv-model", defaults.model],
      ["pv-context", defaults.context_window],
      ["pv-max-tokens", defaults.max_tokens],
      ["pv-steps", defaults.max_steps],
      ["pv-timeout", defaults.timeout_s],
      ["pv-temperature", defaults.temperature],
    ];
    for (const [id, value] of fields) {
      if (force || !$(id).value) $(id).value = value;
    }
    updateModelList(protocol);
  }

  function updateModelList(protocol) {
    const models = state.presets?.models?.[protocol] || ["deepseek-chat"];
    $("pv-model-list").innerHTML = models.map((model) => `<option value="${esc(model)}"></option>`).join("");
  }

  async function loadProviders() {
    await loadProviderPresets();
    try {
      const data = await api("/api/v1/providers");
      state.providers = data.items || [];
    } catch (e) { state.providers = []; }
    $("providers-list").innerHTML = state.providers.length ? state.providers.map((provider) => `
      <div class="lesson provider-row">
        <b>${esc(provider.name)} <span class="badge ${provider.available ? "ok" : "fail"}">${provider.available ? "可用" : "不可用"}</span>
          <span class="badge run">${esc(protocolLabel(provider.protocol))}</span></b>
        <span class="muted">${esc(provider.model)} · ${esc(provider.base_url)} · ctx ${esc(provider.context_window)} · max ${esc(provider.max_tokens)} · key ${provider.api_key_set ? esc(provider.api_key_hint || "已配置") : "未配置"}</span>
        <span class="muted small">${esc(provider.endpoint || "")}${provider.reason && !provider.available ? ` · ${esc(provider.reason)}` : ""}</span>
        <div class="row">
          <button class="ghost" data-edit-provider="${esc(provider.id)}">编辑</button>
          <button class="ghost" data-test-provider="${esc(provider.id)}">测试</button>
          <button class="ghost danger" data-delete-provider="${esc(provider.id)}">删除</button>
        </div>
      </div>`).join("") : '<div class="muted">暂无模型，点击“新增模型”或上方预设。</div>';
    $("providers-list").querySelectorAll("[data-edit-provider]").forEach((button) => {
      button.onclick = () => {
        const provider = state.providers.find((item) => item.id === button.dataset.editProvider);
        if (provider) openProviderForm(provider);
      };
    });
    $("providers-list").querySelectorAll("[data-test-provider]").forEach((button) => {
      button.onclick = () => testSavedProvider(button.dataset.testProvider);
    });
    $("providers-list").querySelectorAll("[data-delete-provider]").forEach((button) => {
      button.onclick = () => deleteProvider(button.dataset.deleteProvider);
    });
  }

  function showOutput(id, value) {
    const node = $(id);
    node.classList.remove("hidden");
    node.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }

  function openProviderForm(provider = null, preset = null) {
    state.editingProvider = provider ? provider.id : null;
    $("provider-form-card").classList.remove("hidden");
    $("provider-form-title").textContent = provider ? `编辑模型 · ${provider.name}` : "新增模型";
    $("pv-output").classList.add("hidden");
    if (provider) {
      $("pv-id").value = provider.id;
      $("pv-name").value = provider.name || "";
      $("pv-protocol").value = provider.protocol || "auto";
      $("pv-base-url").value = provider.base_url || "";
      $("pv-model").value = provider.model || "";
      $("pv-context").value = provider.context_window || 65536;
      $("pv-max-tokens").value = provider.max_tokens || 8192;
      $("pv-steps").value = provider.max_steps || 24;
      $("pv-timeout").value = provider.timeout_s || 180;
      $("pv-temperature").value = provider.temperature ?? 0.1;
      $("pv-enabled").checked = !!provider.enabled;
      $("pv-api-key").value = "";
      $("pv-key-state").textContent = provider.api_key_set ? `已配置：${provider.api_key_hint || "已保存"}（留空不修改）` : "未配置 API Key";
      updateModelList(provider.protocol || "auto");
    } else {
      $("pv-id").value = "";
      $("pv-name").value = preset ? preset.name : "";
      $("pv-protocol").value = preset ? preset.protocol : "auto";
      $("pv-api-key").value = "";
      $("pv-enabled").checked = true;
      $("pv-key-state").textContent = "";
      applyProtocolDefaults(preset ? preset.protocol : "auto", true);
      if (preset) {
        $("pv-name").value = preset.name || "";
        $("pv-base-url").value = preset.base_url || "";
        $("pv-model").value = preset.model || "";
        $("pv-context").value = preset.context_window || 65536;
        $("pv-max-tokens").value = preset.max_tokens || 8192;
        $("pv-steps").value = preset.max_steps || 24;
        $("pv-timeout").value = preset.timeout_s || 180;
        $("pv-temperature").value = preset.temperature ?? 0.1;
      }
    }
    $("provider-form-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function providerFormBody() {
    return {
      name: $("pv-name").value.trim(),
      protocol: $("pv-protocol").value,
      base_url: $("pv-base-url").value.trim(),
      model: $("pv-model").value.trim(),
      context_window: Number($("pv-context").value || 65536),
      max_tokens: Number($("pv-max-tokens").value || 8192),
      max_steps: Number($("pv-steps").value || 24),
      timeout_s: Number($("pv-timeout").value || 180),
      temperature: Number($("pv-temperature").value || 0.1),
      enabled: $("pv-enabled").checked,
    };
  }

  async function saveProvider() {
    try {
      const body = providerFormBody();
      const key = $("pv-api-key").value.trim();
      if (key) body.api_key = key;
      const id = $("pv-id").value;
      if (!body.name) throw new Error("名称必填");
      if (!body.base_url) throw new Error("Base URL 必填");
      if (!body.model) throw new Error("模型必填");
      if (id) await api(`/api/v1/providers/${id}`, { method: "PATCH", body });
      else await api("/api/v1/providers", { method: "POST", body });
      toast("模型配置已保存");
      $("provider-form-card").classList.add("hidden");
      await Promise.all([loadProviders(), loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  async function testProviderForm() {
    try {
      const body = providerFormBody();
      const id = $("pv-id").value;
      if (id) body.provider_id = id;
      const key = $("pv-api-key").value.trim();
      if (key) body.api_key = key;
      $("pv-output").classList.remove("hidden");
      $("pv-output").textContent = "测试中…";
      showOutput("pv-output", await api("/api/v1/providers/test", { method: "POST", body }));
    } catch (e) { showOutput("pv-output", { ok: false, error: e.message }); }
  }

  async function testSavedProvider(id) {
    try {
      const provider = state.providers.find((item) => item.id === id);
      if (provider) openProviderForm(provider);
      $("pv-output").classList.remove("hidden");
      $("pv-output").textContent = "测试中…";
      const result = await api(`/api/v1/providers/${id}/test`, { method: "POST", body: {} });
      showOutput("pv-output", result);
      $("pv-output").scrollIntoView({ behavior: "smooth", block: "nearest" });
      toast(result.ok ? `连接成功 · ${result.latency_ms}ms` : `连接失败：${result.error || "unknown"}`, !result.ok);
    } catch (e) { toast(e.message, true); }
  }

  async function fetchProviderModels() {
    try {
      const id = $("pv-id").value;
      let result;
      if (id) {
        result = await api(`/api/v1/providers/${id}/models`);
      } else {
        const body = providerFormBody();
        const key = $("pv-api-key").value.trim();
        if (key) body.api_key = key;
        result = await api("/api/v1/providers/models", { method: "POST", body });
      }
      const models = result.models || [];
      $("pv-model-list").innerHTML = models.map((model) => `<option value="${esc(model)}"></option>`).join("");
      showOutput("pv-output", result);
      toast(models.length ? `发现 ${models.length} 个模型` : "没有发现模型，保留预设", !models.length);
    } catch (e) { toast(e.message, true); }
  }

  async function clearProviderKey() {
    const id = $("pv-id").value;
    if (!id) { toast("先保存模型再清空 Key", true); return; }
    if (!confirm("确认清空该模型的 API Key？")) return;
    try {
      await api(`/api/v1/providers/${id}`, { method: "PATCH", body: { clear_api_key: true } });
      $("pv-key-state").textContent = "未配置 API Key";
      toast("API Key 已清空");
      await Promise.all([loadProviders(), loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  async function deleteProvider(id) {
    if (!confirm("删除该模型？绑定的 Agent 也会被删除。")) return;
    try {
      await api(`/api/v1/providers/${id}`, { method: "DELETE" });
      toast("模型已删除");
      await Promise.all([loadProviders(), loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  // ------------------------------------------------------------------ agents
  async function loadAgents() {
    try {
      const data = await api("/api/v1/agents");
      state.agents = data.items || [];
    } catch (e) { state.agents = []; }
    $("agents-list").innerHTML = state.agents.length ? state.agents.map((agent) => {
      const skills = (agent.skills || []).map((item) => item.name).filter(Boolean).join(", ");
      const mcp = (agent.mcp || []).map((item) => `${item.name}(${item.tools?.length || 0})`).filter(Boolean).join(", ");
      const managed = agent.builtin || (agent.provider_id && agent.id === `agent-${agent.provider_id}`);
      const editable = canManage(agent);
      const controls = editable ? `<div class="row">
          ${agent.kind === "native" ? "" : `<button class="ghost" data-edit-agent="${esc(agent.id)}">编辑</button>`}
          <button class="ghost" data-toggle-agent="${esc(agent.id)}" data-enabled="${agent.enabled ? "1" : "0"}">${agent.enabled ? "停用" : "启用"}</button>
          ${managed ? "" : `<button class="ghost danger" data-delete-agent="${esc(agent.id)}">删除</button>`}
        </div>` : '<div class="muted small">共享 Agent · 仅管理员可修改</div>';
      return `<div class="lesson">
        <b>${esc(agent.name)} <span class="badge ${agent.available ? "ok" : "fail"}">${agent.available ? "可用" : "不可用"}</span>
          <span class="badge run">${esc(agent.kind)}</span> ${ownershipBadge(agent)} ${agent.builtin ? '<span class="badge warn">内置</span>' : ""}
          <span class="muted small">${esc(agent.id)}</span></b>
        <span class="muted">${agent.provider ? `${esc(agent.provider)} · ${esc(agent.protocol || "")}/${esc(agent.model || "")}` : "确定性工作流"}${agent.context_window ? ` · ctx ${esc(agent.context_window)}` : ""} · ${esc(agent.reason || "")}</span>
        ${skills ? `<div class="muted small">Skills: ${esc(skills)}</div>` : ""}
        ${mcp ? `<div class="muted small">MCP: ${esc(mcp)}</div>` : ""}
        ${controls}
      </div>`;
    }).join("") : '<div class="muted">暂无 Agent</div>';
    $("agents-list").querySelectorAll("[data-edit-agent]").forEach((button) => {
      button.onclick = () => {
        const agent = state.agents.find((item) => item.id === button.dataset.editAgent);
        if (agent) openAgentForm(agent);
      };
    });
    $("agents-list").querySelectorAll("[data-toggle-agent]").forEach((button) => {
      button.onclick = () => toggleAgent(button.dataset.toggleAgent, button.dataset.enabled !== "1");
    });
    $("agents-list").querySelectorAll("[data-delete-agent]").forEach((button) => {
      button.onclick = () => deleteAgent(button.dataset.deleteAgent);
    });
  }

  function populateSelect(select, items, selected = [], labelFn = (item) => item.name || item.id) {
    select.innerHTML = "";
    for (const item of items) {
      const option = document.createElement("option");
      option.value = item.id;
      option.textContent = labelFn(item);
      option.selected = selected.includes(item.id);
      select.appendChild(option);
    }
  }

  function openAgentForm(agent = null) {
    if (agent && agent.kind === "native") { toast("内置确定性 Agent 只能启用/停用", true); return; }
    state.editingAgent = agent ? agent.id : null;
    $("agent-form-card").classList.remove("hidden");
    $("agent-form-title").textContent = agent ? `编辑 Agent · ${agent.name}` : "新增 Agent";
    $("ag-id").value = agent ? agent.id : "";
    $("ag-name").value = agent ? agent.name : "";
    $("ag-enabled").checked = agent ? !!agent.enabled : true;
    $("ag-prompt").value = agent ? (agent.system_prompt || "") : "";
    populateSelect($("ag-provider"), state.providers);
    populateSelect($("ag-skills"), state.skills, agent ? (agent.skill_ids || []) : (state.skills[0] ? [state.skills[0].id] : []));
    populateSelect($("ag-mcp"), state.mcps, agent ? (agent.mcp_ids || []) : [], (item) => `${item.name} (${item.transport})`);
    if (agent && agent.provider_id) $("ag-provider").value = agent.provider_id;
    const managed = agent && agent.provider_id && agent.id === `agent-${agent.provider_id}`;
    $("ag-provider").disabled = !!managed;
    $("agent-form-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function selectedValues(select) {
    return Array.from(select.selectedOptions).map((option) => option.value);
  }

  async function saveAgent() {
    try {
      const body = {
        name: $("ag-name").value.trim(),
        provider_id: $("ag-provider").value,
        skill_ids: selectedValues($("ag-skills")),
        mcp_ids: selectedValues($("ag-mcp")),
        system_prompt: $("ag-prompt").value,
        enabled: $("ag-enabled").checked,
      };
      if (!body.name) throw new Error("Agent 名称必填");
      if (!body.provider_id) throw new Error("请选择模型 Provider");
      const id = $("ag-id").value;
      if (id) await api(`/api/v1/agents/${id}`, { method: "PATCH", body });
      else await api("/api/v1/agents", { method: "POST", body });
      toast("Agent 已保存");
      $("agent-form-card").classList.add("hidden");
      await Promise.all([loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  async function toggleAgent(id, enabled) {
    try {
      await api(`/api/v1/agents/${id}`, { method: "PATCH", body: { enabled } });
      toast(enabled ? "Agent 已启用" : "Agent 已停用");
      await Promise.all([loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  async function deleteAgent(id) {
    if (!confirm("删除该 Agent？")) return;
    try {
      await api(`/api/v1/agents/${id}`, { method: "DELETE" });
      toast("Agent 已删除");
      await Promise.all([loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  // ------------------------------------------------------------------ skills
  async function loadSkills() {
    try {
      const data = await api("/api/v1/skills");
      state.skills = data.items || [];
    } catch (e) { state.skills = []; }
    $("skills-list").innerHTML = state.skills.length ? state.skills.map((skill) => {
      const editable = canManage(skill);
      return `<div class="lesson">
        <b>${esc(skill.name)} <span class="badge ${skill.enabled ? "ok" : "fail"}">${skill.enabled ? "启用" : "停用"}</span>
          <span class="badge run">${esc(skill.source)}</span> ${ownershipBadge(skill)} <span class="muted small">${esc(skill.id)} · ${esc(skill.chars)} chars</span></b>
        <span class="muted">${esc(skill.description || "")}</span>
        ${editable ? `<div class="row">
          <button class="ghost" data-edit-skill="${esc(skill.id)}">${skill.builtin ? "查看/启用" : "编辑"}</button>
          ${skill.builtin ? "" : `<button class="ghost danger" data-delete-skill="${esc(skill.id)}">删除</button>`}
        </div>` : '<div class="muted small">共享 Skill · 只读</div>'}
      </div>`;
    }).join("") : '<div class="muted">暂无 Skill</div>';
    $("skills-list").querySelectorAll("[data-edit-skill]").forEach((button) => {
      button.onclick = () => {
        const skill = state.skills.find((item) => item.id === button.dataset.editSkill);
        if (skill) openSkillForm(skill);
      };
    });
    $("skills-list").querySelectorAll("[data-delete-skill]").forEach((button) => {
      button.onclick = () => deleteSkill(button.dataset.deleteSkill);
    });
  }

  function openSkillForm(skill = null) {
    state.editingSkill = skill ? skill.id : null;
    $("skill-form-card").classList.remove("hidden");
    $("skill-form-title").textContent = skill ? `Skill · ${skill.name}` : "新增 Skill";
    $("sk-id").value = skill ? skill.id : "";
    $("sk-name").value = skill ? skill.name : "";
    $("sk-desc").value = skill ? (skill.description || "") : "";
    $("sk-enabled").checked = skill ? !!skill.enabled : true;
    $("sk-content").value = skill ? (skill.content || "") : "";
    const builtin = skill && skill.builtin;
    $("sk-name").disabled = !!builtin;
    $("sk-desc").disabled = !!builtin;
    $("sk-content").readOnly = !!builtin;
    $("skill-form-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function saveSkill() {
    try {
      const id = $("sk-id").value;
      const builtin = state.skills.find((item) => item.id === id)?.builtin;
      const body = builtin
        ? { enabled: $("sk-enabled").checked }
        : {
            name: $("sk-name").value.trim(),
            description: $("sk-desc").value.trim(),
            content: $("sk-content").value,
            enabled: $("sk-enabled").checked,
          };
      if (!builtin && (!body.name || !body.content.trim())) throw new Error("名称和内容必填");
      if (id) await api(`/api/v1/skills/${id}`, { method: "PATCH", body });
      else await api("/api/v1/skills", { method: "POST", body });
      toast("Skill 已保存");
      $("skill-form-card").classList.add("hidden");
      await Promise.all([loadSkills(), loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  async function deleteSkill(id) {
    if (!confirm("删除该 Skill？")) return;
    try {
      await api(`/api/v1/skills/${id}`, { method: "DELETE" });
      toast("Skill 已删除");
      await Promise.all([loadSkills(), loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  // ------------------------------------------------------------------ MCP
  async function loadMcps() {
    try {
      const data = await api("/api/v1/mcp-servers");
      state.mcps = data.items || [];
    } catch (e) { state.mcps = []; }
    $("mcp-list").innerHTML = state.mcps.length ? state.mcps.map((server) => {
      const tools = (server.tools || []).map((tool) => tool.name).filter(Boolean);
      const editable = canManage(server);
      return `<div class="lesson">
        <b>${esc(server.name)} <span class="badge ${server.available ? "ok" : "fail"}">${server.available ? "可用" : "不可用"}</span>
          <span class="badge run">${esc(server.transport)}</span> ${ownershipBadge(server)} <span class="muted small">${esc(server.id)}</span></b>
        <span class="muted">${esc(server.transport === "http" ? server.url : server.command)} · ${server.has_secrets ? "有 Headers/Env" : "无密钥"} · ${esc(server.last_status || "未测试")}</span>
        ${tools.length ? `<div class="muted small">Tools: ${esc(tools.join(", "))}</div>` : ""}
        ${editable ? `<div class="row">
          <button class="ghost" data-edit-mcp="${esc(server.id)}">编辑</button>
          <button class="ghost" data-test-mcp="${esc(server.id)}">测试工具</button>
          <button class="ghost danger" data-delete-mcp="${esc(server.id)}">删除</button>
        </div>` : '<div class="muted small">共享 MCP · 只读</div>'}
      </div>`;
    }).join("") : '<div class="muted">暂无 MCP 服务器</div>';
    $("mcp-list").querySelectorAll("[data-edit-mcp]").forEach((button) => {
      button.onclick = () => {
        const server = state.mcps.find((item) => item.id === button.dataset.editMcp);
        if (server) openMcpForm(server);
      };
    });
    $("mcp-list").querySelectorAll("[data-test-mcp]").forEach((button) => {
      button.onclick = () => testMcpById(button.dataset.testMcp);
    });
    $("mcp-list").querySelectorAll("[data-delete-mcp]").forEach((button) => {
      button.onclick = () => deleteMcp(button.dataset.deleteMcp);
    });
  }

  function toggleMcpFields() {
    const http = $("mc-transport").value === "http";
    $("mc-url").disabled = !http;
    $("mc-command").disabled = http;
  }

  function openMcpForm(server = null) {
    state.editingMcp = server ? server.id : null;
    $("mcp-form-card").classList.remove("hidden");
    $("mcp-form-title").textContent = server ? `MCP · ${server.name}` : "新增 MCP Server";
    $("mc-id").value = server ? server.id : "";
    $("mc-name").value = server ? server.name : "";
    $("mc-transport").value = server ? server.transport : "http";
    const stdioOption = $("mc-transport").querySelector('option[value="stdio"]');
    if (stdioOption) stdioOption.disabled = !isAdmin();
    if (!isAdmin() && $("mc-transport").value === "stdio") $("mc-transport").value = "http";
    $("mc-url").value = server ? (server.url || "") : "";
    $("mc-command").value = server ? (server.command || "") : "";
    $("mc-enabled").checked = server ? !!server.enabled : true;
    $("mc-headers").value = "";
    $("mc-env").value = "";
    $("mc-clear-secrets").checked = false;
    $("mc-headers").placeholder = server?.header_names?.length ? `已有: ${server.header_names.join(", ")}（留空保持不变）` : '{"Authorization":"Bearer ..."}';
    $("mc-env").placeholder = server?.env_names?.length ? `已有: ${server.env_names.join(", ")}（留空保持不变）` : '{"TOKEN":"..."}';
    $("mc-output").classList.add("hidden");
    toggleMcpFields();
    $("mcp-form-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function jsonField(id, label) {
    const text = $(id).value.trim();
    if (!text) return undefined;
    let value;
    try { value = JSON.parse(text); } catch (e) { throw new Error(`${label} 不是合法 JSON`); }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} 必须是 JSON 对象`);
    return value;
  }

  async function saveMcp() {
    const body = {
      name: $("mc-name").value.trim(),
      transport: $("mc-transport").value,
      url: $("mc-url").value.trim() || null,
      command: $("mc-command").value.trim() || null,
      enabled: $("mc-enabled").checked,
      clear_secrets: $("mc-clear-secrets").checked,
    };
    if (!body.name) throw new Error("名称必填");
    const headers = jsonField("mc-headers", "Headers");
    const env = jsonField("mc-env", "Env");
    if (headers !== undefined) body.headers = headers;
    if (env !== undefined) body.env = env;
    const id = $("mc-id").value;
    const data = id
      ? await api(`/api/v1/mcp-servers/${id}`, { method: "PATCH", body })
      : await api("/api/v1/mcp-servers", { method: "POST", body });
    toast("MCP 已保存");
    $("mcp-form-card").classList.add("hidden");
    await Promise.all([loadMcps(), loadAgents(), loadEngines()]);
    return data.server?.id || id;
  }

  async function saveMcpSafe() {
    try { return await saveMcp(); } catch (e) { toast(e.message, true); return null; }
  }

  async function testMcpById(id) {
    try {
      $("mc-output").classList.remove("hidden");
      $("mc-output").textContent = "连接中…";
      const result = await api(`/api/v1/mcp-servers/${id}/test`, { method: "POST", body: {} });
      showOutput("mc-output", result);
      toast(result.ok ? `MCP 连接成功，${(result.tools || []).length} 个工具` : "MCP 测试失败", !result.ok);
      await Promise.all([loadMcps(), loadEngines()]);
    } catch (e) { showOutput("mc-output", { ok: false, error: e.message }); toast(e.message, true); }
  }

  async function testMcpForm() {
    try {
      if ($("mc-id").value) {
        await testMcpById($("mc-id").value);
      } else {
        const id = await saveMcpSafe();
        if (id) await testMcpById(id);
      }
    } catch (e) { toast(e.message, true); }
  }

  async function deleteMcp(id) {
    if (!confirm("删除该 MCP Server？已绑定它的 Agent 会失去该工具。")) return;
    try {
      await api(`/api/v1/mcp-servers/${id}`, { method: "DELETE" });
      toast("MCP 已删除");
      await Promise.all([loadMcps(), loadAgents(), loadEngines()]);
    } catch (e) { toast(e.message, true); }
  }

  // ------------------------------------------------------------------ uploads / jobs
  async function loadUploads() {
    try {
      const data = await api("/api/v1/uploads?limit=1000");
      state.uploads = {};
      for (const upload of data.items || []) state.uploads[upload.id] = upload;
    } catch (e) { state.uploads = {}; }
  }

  async function loadJobs(options = {}) {
    if (!options.silent) await loadUploads();
    const params = new URLSearchParams({ limit: String(state.jobsLimit), offset: String(state.jobsOffset) });
    if (state.jobStatus) params.set("status", state.jobStatus);
    try {
      const data = await api(`/api/v1/jobs?${params.toString()}`);
      state.jobs = data.items || [];
      state.jobsTotal = Number(data.total || 0);
      if (!state.jobs.length && state.jobsOffset > 0 && state.jobsTotal > 0) {
        state.jobsOffset = Math.max(0, Math.floor((state.jobsTotal - 1) / state.jobsLimit) * state.jobsLimit);
        return loadJobs(options);
      }
    } catch (e) {
      state.jobs = [];
      state.jobsTotal = 0;
    }
    renderJobs();
  }

  function statusBadge(job) {
    const status = job.status || "queued";
    const cls = status === "succeeded" ? "ok" : status === "failed" ? "fail" : status === "partial" || status === "cancelled" ? "warn" : "run";
    return `<span class="badge ${cls}">${esc(status)}</span>`;
  }

  function formatTime(value) {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  }

  function renderJobs() {
    const box = $("jobs-list");
    const total = state.jobsTotal;
    const start = total ? state.jobsOffset + 1 : 0;
    const end = Math.min(state.jobsOffset + state.jobs.length, total);
    $("jobs-summary").textContent = total ? `共 ${total} 个任务 · 每页 ${state.jobsLimit} 条` : "暂无任务";
    $("jobs-page-info").textContent = total ? `第 ${start}–${end} 条 / 共 ${total} 条` : "";
    $("jobs-prev").disabled = state.jobsOffset <= 0;
    $("jobs-next").disabled = state.jobsOffset + state.jobsLimit >= total;
    if (!state.jobs.length) {
      box.innerHTML = '<div class="job-empty muted">暂无任务</div>';
      return;
    }
    box.innerHTML = state.jobs.map((job) => {
      const upload = state.uploads[job.upload_id] || {};
      const active = ["queued", "running"].includes(job.status);
      return `<article class="job-item" data-job="${esc(job.id)}">
        <div class="job-main">
          <div class="job-title">
            ${statusBadge(job)}
            <code>${esc(job.id.slice(0, 16))}</code>
            <span class="job-file">${esc(upload.filename || job.upload_id.slice(0, 10))}</span>
          </div>
          <div class="job-meta">
            <span>${esc(engineLabel(job.engine))}</span>
            <span>阶段：${esc(job.stage || "-")}</span>
            <span>${esc(formatTime(job.created_at))}</span>
            ${upload.size ? `<span>${esc(formatBytes(upload.size))}</span>` : ""}
          </div>
        </div>
        <div class="job-actions">
          <button class="ghost" data-open="${esc(job.id)}">详情</button>
          ${active ? `<button class="ghost danger" data-cancel="${esc(job.id)}">取消</button>` : ""}
          ${["failed", "cancelled", "partial"].includes(job.status) ? `<button class="ghost" data-retry="${esc(job.id)}">重试</button>` : ""}
          ${active ? "" : `<button class="ghost danger" data-delete-job="${esc(job.id)}">删除</button>`}
        </div>
      </article>`;
    }).join("");
    box.querySelectorAll("[data-open]").forEach((button) => button.onclick = () => openJob(button.dataset.open));
    box.querySelectorAll("[data-cancel]").forEach((button) => button.onclick = () => cancelJob(button.dataset.cancel));
    box.querySelectorAll("[data-retry]").forEach((button) => button.onclick = () => retryJob(button.dataset.retry));
    box.querySelectorAll("[data-delete-job]").forEach((button) => button.onclick = () => deleteJob(button.dataset.deleteJob));
  }

  async function cancelJob(jobId) {
    try { await api(`/api/v1/jobs/${jobId}/cancel`, { method: "POST" }); toast("已请求取消"); await loadJobs(); }
    catch (e) { toast(e.message, true); }
  }

  async function retryJob(jobId) {
    try {
      const data = await api(`/api/v1/jobs/${jobId}/retry`, { method: "POST" });
      toast("已创建重试任务");
      state.jobsOffset = 0;
      await loadJobs();
      openJob(data.job.id);
    } catch (e) { toast(e.message, true); }
  }

  async function deleteJob(jobId) {
    if (!confirm("确认删除该任务及其 DEX、源码、证据、日志和运行目录？此操作不可恢复。")) return;
    try {
      await api(`/api/v1/jobs/${jobId}`, { method: "DELETE" });
      if (state.selectedJob?.id === jobId) {
        state.selectedJob = null;
        $("job-detail").classList.add("hidden");
        if (state.stream) { state.stream.close(); state.stream = null; }
      }
      toast("任务已删除");
      await loadJobs();
    } catch (e) { toast(e.message, true); }
  }

  async function cleanupJob(jobId) {
    if (!jobId) return;
    if (!confirm("确认清理该任务在设备上留下的改动（端口转发、重命名库、frida-server、临时文件）？已安装的 APK 不会自动卸载。")) return;
    const button = $("detail-cleanup");
    if (button) button.disabled = true;
    try {
      const data = await api(`/api/v1/jobs/${encodeURIComponent(jobId)}/cleanup`, { method: "POST" });
      const restored = Array.isArray(data?.restored) ? data.restored.length : null;
      const incomplete = Boolean(data?.cleanup_incomplete);
      const message = data?.message || (incomplete ? "设备清理不完整，请查看任务详情" : "设备清理完成");
      toast(message + (restored != null ? `（已恢复 ${restored} 项）` : ""), incomplete);
      await refreshSelectedJob();
      await loadJobs({ silent: true });
    } catch (e) {
      if (e.status === 404) toast("任务不存在或已删除，无法清理", true);
      else if (e.status === 409) toast(`当前无法清理：${e.message}`, true);
      else if (e.status === 501 || e.code === "cleanup_not_supported") toast("当前后端尚未提供设备清理接口（cleanup_not_supported）", true);
      else toast(e.message || "清理失败", true);
    } finally {
      if (button) {
        const status = state.selectedJob?.status || "";
        button.disabled = ["queued", "running"].includes(status);
      }
    }
  }

  async function openJob(jobId) {
    try {
      const data = await api(`/api/v1/jobs/${jobId}`);
      state.selectedJob = data.job;
      state.selectedEvents = [];
      $("job-detail").classList.remove("hidden");
      $("detail-title").textContent = `任务 ${data.job.id}`;
      renderJobDetail(data);
      const terminal = ["succeeded", "partial", "failed", "cancelled"].includes(data.job.status);
      const lastSeq = (data.events || []).reduce((max, event) => Math.max(max, Number(event.seq) || 0), 0);
      if (terminal) {
        $("stream-state").textContent = "已结束";
        if (state.stream) { state.stream.close(); state.stream = null; }
      } else {
        startStream(jobId, lastSeq);
      }
      $("job-detail").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) { toast(e.message, true); }
  }

  async function refreshSelectedJob() {
    if (!state.selectedJob) return;
    try {
      const data = await api(`/api/v1/jobs/${state.selectedJob.id}`);
      state.selectedJob = data.job;
      renderJobDetail(data);
      const terminal = ["succeeded", "partial", "failed", "cancelled"].includes(data.job.status);
      if (terminal) $("stream-state").textContent = "已结束";
    } catch (e) {}
  }

  function renderEngineConfig(events, job) {
    const configEvent = [...events].reverse().find((event) => event.kind === "engine_config");
    const box = $("engine-config");
    if (!configEvent) {
      const engine = state.engines[job.engine];
      box.innerHTML = engine ? `
        <div><b>Agent</b>${esc(engine.label || engine.name)}</div>
        <div><b>类型</b>${esc(engine.kind || "llm")}</div>
        <div><b>模型</b>${esc(engine.model || "-")}</div>
        <div><b>协议</b>${esc(engine.protocol || "-")}</div>
        <div><b>上下文</b>${esc(engine.context_window || "-")}</div>` : "";
      return;
    }
    const data = configEvent.data || {};
    const skills = (data.skills || []).map((item) => `${item.name || item.id}${item.references?.length ? ` · ${item.references.length} 份参考文档` : ""}`).filter(Boolean).join(", ");
    const mcp = (data.mcp || []).map((item) => `${item.name}(${(item.tools || []).length})`).filter(Boolean).join(", ");
    box.innerHTML = `
      <div><b>Agent</b>${esc(data.agent || "-")}</div>
      <div><b>Provider</b>${esc(data.provider || "-")}</div>
      <div><b>协议 / 模型</b>${esc(data.protocol || "-")} / ${esc(data.model || "-")}</div>
      <div><b>上下文</b>${esc(data.context_window || "-")} · 输出 ${esc(data.max_tokens || "-")}</div>
      <div><b>Skills</b>${esc(skills || "-")}</div>
      <div><b>MCP</b>${esc(mcp || "-")}</div>
      ${data.base_url ? `<div style="grid-column:1/-1"><b>Base URL</b>${esc(data.base_url)}</div>` : ""}
    `;
  }

  function eventToCall(event) {
    const kind = event.kind || "";
    const data = event.data || {};
    const ts = event.ts || "";
    if (kind === "tool_call") {
      return { source: "tool", title: `调用 ${event.message || ""}`, detail: jsonPreview(data.arguments || {}), ts };
    }
    if (kind === "tool_result") {
      const result = data.result || {};
      const failure = result.error || result;
      const detail = data.is_error
        ? [failure.code, failure.message, failure.details?.stop_reason].filter(Boolean).join(" · ") || "ERROR"
        : "OK";
      return { source: "tool", title: `结果 ${event.message || ""}`, detail, status: data.is_error ? "error" : "ok", ts };
    }
    if (kind === "mcp_tool_call") {
      return { source: "mcp", title: `MCP ${event.message || ""}`, detail: jsonPreview(data.arguments || {}), ts };
    }
    if (kind === "mcp_tool_result") {
      return { source: "mcp", title: `MCP 结果 ${event.message || ""}`, detail: data.is_error ? "ERROR" : "OK", status: data.is_error ? "error" : "ok", ts };
    }
    if (kind === "mcp_connected" || kind === "mcp_error") {
      return { source: "mcp", title: event.message || kind, detail: jsonPreview(data), status: kind === "mcp_error" ? "error" : "", ts };
    }
    if (kind === "skill_loaded" || kind === "engine_context_trimmed" || kind === "engine_context_pressure") {
      return { source: "skill", title: event.message || kind, detail: jsonPreview(data), ts };
    }
    if (
      kind === "lesson_recorded" ||
      kind === "lesson_record_failed" ||
      kind === "lesson_skipped" ||
      kind === "memory_recorded" ||
      kind === "memory_record_failed" ||
      kind === "agent.memory_recorded" ||
      kind === "agent.memory_record_failed"
    ) {
      return {
        source: "lesson",
        title: event.message || kind,
        detail: jsonPreview(data),
        status: kind.includes("failed") ? "error" : "",
        ts,
      };
    }
    if (kind === "engine_config") {
      return { source: "agent", title: `Agent ${data.agent || ""}`, detail: `${data.provider || ""} · ${data.protocol || ""}/${data.model || ""}`, ts };
    }
    if (kind.startsWith("agent.")) {
      if (kind === "agent.stdout" || kind === "agent.stderr") return null;
      return { source: "agent", title: event.message || kind, detail: jsonPreview(data), ts };
    }
    return null;
  }

  function callSourceBadge(source) {
    const cls = source === "mcp" ? "run" : source === "skill" ? "warn" : source === "agent" ? "ok" : source === "lesson" ? "ok" : "";
    const label = source === "mcp" ? "MCP" : source === "skill" ? "Skill" : source === "lesson" ? "经验" : source === "agent" ? "Agent" : "工具";
    return `<span class="badge ${cls}">${label}</span>`;
  }

  function renderCalls() {
    const container = $("calls");
    const items = state.callItems.filter((item) => state.callFilters[item.source] !== false);
    if (!items.length) {
      container.innerHTML = '<div class="muted">暂无调用记录</div>';
      return;
    }
    container.innerHTML = items.slice(-300).map((item) => {
      const time = item.ts ? new Date(item.ts).toLocaleTimeString() : "";
      const status = item.status === "error" ? '<span class="badge fail">error</span>' : item.status === "ok" ? '<span class="badge ok">ok</span>' : "";
      return `<div class="event">
        <span class="t">${esc(time)}</span>${callSourceBadge(item.source)} ${esc(item.title)} ${status}
        <span class="muted">${esc(item.detail || "")}</span>
      </div>`;
    }).join("");
    container.scrollTop = container.scrollHeight;
  }

  function appendCall(event) {
    const item = eventToCall(event);
    if (!item) return;
    state.callItems.push(item);
    if (state.callItems.length > 1000) state.callItems.splice(0, state.callItems.length - 1000);
    renderCalls();
  }

  function renderJobDetail(data) {
    const job = data.job;
    const upload = data.upload || {};
    const events = data.events || [];
    noteArmAvailabilityFromJob(job);
    const cleanupStatus = String(job.cleanup_status || "").trim();
    const cleanupError = String(job.cleanup_error || "").trim();
    const cleanupIncomplete = Boolean(job.cleanup_incomplete);
    const sourceIssue = {
      jadx_timeout: "DEX 已通过校验；JADX 运行超时，已保留现有源码。可调大高级选项中的 JADX 时限后重试。",
      jadx_memory: "DEX 已通过校验；JADX 的 Java 堆内存耗尽，主源码输出不完整。延长超时不能解决内存不足。",
      jadx_process_error: "DEX 已通过校验；JADX 进程异常退出，主源码覆盖范围无法确认。现有输出和备用指令视图已保留。",
      jadx_incomplete: "DEX 已通过校验；JADX 源码重建存在错误或警告，不能据此判断脱壳失败。",
      partial_bytecode: "已恢复业务 DEX，允许保留局部缺失并继续 JADX 还原。现有 DEX 和可读源码可下载，零填充、缺失范围及反编译错误详见质量报告。",
      runtime_dump_failed: "业务 DEX 提取失败。现有下载内容仅包含静态壳代码或资源，不代表脱壳成功；请查看动态提取步骤的具体错误。",
      packed_static_only: "尚未恢复加固 APK 的业务 DEX。静态壳代码和资源不能作为脱壳成功的依据。",
      sources_only: "仅保留了源码或资源输出，尚无通过校验的目标 DEX。",
    }[job.error?.code];
    const fallbackCount = job.error?.details?.fallback_covered_file_count;
    const fallbackNote = Number.isInteger(fallbackCount) && fallbackCount > 0
      ? ` 已为 ${fallbackCount} 个含警告文件提供备用指令视图，见源码包 recovery/fallback/（不可直接编译）。` : "";
    const cleanupClass = cleanupStatus === "ok" || cleanupStatus === "complete" || cleanupStatus === "completed" || cleanupStatus === "clean"
      ? "ok"
      : cleanupStatus ? "warn" : "";
    $("detail-meta").innerHTML = `
      <div><b>文件</b>${esc(upload.filename || "-")} · ${esc(upload.size || "-")} bytes</div>
      <div><b>Agent / 模型</b>${esc(engineLabel(job.engine))}</div>
      <div><b>状态</b>${statusBadge(job)}</div>
      <div><b>阶段</b>${esc(job.stage === "done" ? "已结束" : job.stage || "-")}</div>
      <div><b>Run</b>${esc(job.run_id || "-")}</div>
      <div><b>设备</b>${esc(job.serial || "默认")}</div>
      ${cleanupStatus || cleanupIncomplete
        ? `<div><b>设备清理</b>${cleanupStatus ? `<span class="badge ${cleanupClass}">${esc(cleanupStatus)}</span>` : ""}${cleanupIncomplete ? '<span class="badge fail">不完整</span>' : ""}</div>`
        : ""}
      ${job.error ? `<div style="grid-column:1/-1"><b>${sourceIssue ? "结果说明" : "错误"}</b>${esc((sourceIssue || job.error.message || JSON.stringify(job.error)) + fallbackNote)}</div>` : ""}
      ${cleanupError ? `<div style="grid-column:1/-1"><b>清理错误</b><span class="error">${esc(cleanupError)}</span></div>` : ""}
    `;
    const cleanupButton = $("detail-cleanup");
    if (cleanupButton) {
      const active = ["queued", "running"].includes(job.status);
      cleanupButton.disabled = active;
      cleanupButton.title = active ? "任务运行结束后才能清理设备" : "清理该任务在设备上的转发、重命名库与临时文件（不卸载 APK）";
    }
    renderEngineConfig(events, job);
    $("downloads").innerHTML = "";
    const links = [
      ["dex", "下载 DEX", job.artifacts?.dex_zip],
      ["source", "下载源码", job.artifacts?.source_zip],
      ["evidence", "下载证据", job.artifacts?.evidence_zip],
      ["logs", "下载日志", job.artifacts?.logs_zip],
      ["full", "完整包", job.artifacts?.full_zip],
    ];
    for (const [kind, label, exists] of links) {
      const button = document.createElement("button");
      button.className = "ghost";
      button.textContent = label;
      button.disabled = !exists;
      button.onclick = () => downloadArtifact(job.id, kind);
      $("downloads").appendChild(button);
    }
    state.selectedEvents = events.slice();
    state.callItems = [];
    for (const event of events) {
      const item = eventToCall(event);
      if (item) state.callItems.push(item);
    }
    renderCalls();
    const container = $("events");
    container.innerHTML = "";
    for (const event of events) appendEvent(event, false);
    container.scrollTop = container.scrollHeight;
  }

  function startStream(jobId, afterSeq = 0) {
    if (state.stream) state.stream.close();
    const url = `/api/v1/jobs/${jobId}/stream?token=${encodeURIComponent(state.token)}&after_seq=${afterSeq}`;
    const stream = new EventSource(url);
    state.stream = stream;
    $("stream-state").textContent = "连接中…";
    stream.onopen = () => { $("stream-state").textContent = "实时"; };
    stream.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data);
        state.selectedEvents.push(event);
        appendEvent(event, true);
        appendCall(event);
        if (event.kind === "job_finished") {
          $("stream-state").textContent = "已结束";
          setTimeout(loadJobs, 300);
          loadLessons();
        }
      } catch (e) {}
    };
    stream.addEventListener("stream_end", () => {
      $("stream-state").textContent = "结束";
      stream.close();
      if (state.stream === stream) state.stream = null;
      refreshSelectedJob();
    });
    stream.onerror = () => { $("stream-state").textContent = "重连中…"; };
  }

  function appendEvent(event, scroll) {
    const container = $("events");
    if (!container) return;
    const kind = event.kind || "event";
    const cls = kind.includes("error") || event.level === "error" ? "error" : kind === "stage" ? "stage" : "";
    const time = event.ts ? new Date(event.ts).toLocaleTimeString() : "";
    const message = event.message || "";
    const data = event.data && Object.keys(event.data).length ? ` ${jsonPreview(event.data)}` : "";
    const node = document.createElement("div");
    node.className = `event ${cls}`;
    node.innerHTML = `<span class="t">${esc(time)}</span><span class="k">${esc(kind)}</span> ${esc(message)}<span class="muted">${esc(data)}</span>`;
    container.appendChild(node);
    while (container.children.length > 800) container.removeChild(container.firstChild);
    if (scroll) container.scrollTop = container.scrollHeight;
  }

  async function downloadArtifact(jobId, kind) {
    try {
      const response = await fetch(`/api/v1/jobs/${jobId}/download/${kind}`, {
        headers: state.token ? { Authorization: `Bearer ${state.token}` } : {},
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data?.error?.message || `HTTP ${response.status}`);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${jobId}_${kind}.zip`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    } catch (e) { toast(e.message, true); }
  }

  const BUNDLE_FILE_PATTERN = /\.(apks|xapk)$/i;
  const BUNDLE_MESSAGE = ".apks / .xapk 是 APK 分卷包，后端不支持（bundle_not_supported）；请先转换为单个 .apk 文件。";

  function isBundleFile(file) {
    return BUNDLE_FILE_PATTERN.test(String(file?.name || ""));
  }

  function showFileNote(message) {
    const node = $("file-note");
    if (!node) return;
    node.textContent = message || "";
    node.classList.toggle("hidden", !message);
  }

  function collectAdvancedOptions() {
    const options = {};
    const numeric = [
      ["opt-freeze-timeout", "freeze_timeout_ms"],
      ["opt-dump-region-max", "dump_region_max"],
      ["opt-jadx-timeout", "jadx_timeout_s"],
      ["opt-timeout", "timeout_s"],
    ];
    for (const [id, name] of numeric) {
      const input = $(id);
      if (!input) continue;
      const raw = String(input.value || "").trim();
      if (!raw) continue;
      const value = Number(raw);
      if (!Number.isFinite(value) || value < 0) throw new Error(`${name} 必须是非负数字`);
      options[name] = Math.trunc(value);
    }
    options.force_dump = Boolean($("opt-force-dump")?.checked);
    options.inner_bypass = Boolean($("opt-inner-bypass")?.checked);
    options.prune_raw = Boolean($("opt-prune-raw")?.checked);
    // A server-side path is only exposed to administrators.
    if (isAdmin()) {
      const serverPath = String($("opt-frida-server-path")?.value || "").trim();
      if (serverPath) options.frida_server_path = serverPath;
    }
    return options;
  }

  async function uploadAndStart() {
    const file = $("file").files[0];
    if (!file) { toast("请先选择 APK", true); return; }
    if (isBundleFile(file)) { showFileNote(BUNDLE_MESSAGE); toast(BUNDLE_MESSAGE, true); return; }
    showFileNote("");
    const button = $("start-job");
    button.disabled = true;
    try {
      const options = Object.assign(
        {
          install: $("opt-install").checked,
          jadx: $("opt-jadx").checked,
          cleanup: $("opt-cleanup").checked,
          keep_device_files: $("opt-keep").checked,
          auto_emulator_bypass: $("opt-bypass").checked,
          arm_device: $("opt-arm").checked,
        },
        collectAdvancedOptions()
      );
      const uploadId = await uploadFile(file);
      const data = await api("/api/v1/jobs", {
        method: "POST",
        body: { upload_id: uploadId, engine: $("engine").value, serial: $("serial").value || null, options },
      });
      toast("任务已创建");
      state.jobsOffset = 0;
      await loadJobs();
      openJob(data.job.id);
    } catch (e) {
      toast(e.message, true);
    } finally {
      button.disabled = false;
    }
  }

  function uploadFile(file) {
    return new Promise((resolve, reject) => {
      const form = new FormData();
      form.append("file", file, file.name);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/v1/uploads");
      xhr.setRequestHeader("Authorization", `Bearer ${state.token}`);
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      $("upload-progress").classList.remove("hidden");
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          $("upload-bar").style.width = `${Math.round((event.loaded / event.total) * 100)}%`;
        }
      };
      xhr.onload = () => {
        try {
          const data = JSON.parse(xhr.responseText || "{}");
          if (xhr.status >= 200 && xhr.status < 300 && data.upload) {
            resolve(data.upload.id);
          } else {
            reject(new Error(data?.error?.message || `HTTP ${xhr.status}`));
          }
        } catch (e) { reject(e); }
      };
      xhr.onerror = () => reject(new Error("上传失败"));
      xhr.send(form);
    });
  }

  // ------------------------------------------------------------------ lessons / admin misc
  function renderLessonStats() {
    const node = $("lesson-stats");
    if (!node) return;
    const stats = state.lessonStats || {};
    const shells = Object.entries(stats.by_shell || {}).map(([shell, count]) => `${shell}:${count}`).join(" · ");
    node.innerHTML = `
      <span class="badge ok">总计 ${esc(stats.total || 0)}</span>
      <span class="badge run">自动 ${esc(stats.observed || 0)}</span>
      <span class="badge warn">手工 ${esc(stats.analyst || 0)}</span>
      ${shells ? `<span class="muted small">壳分布 ${esc(shells)}</span>` : ""}`;
  }

  function visibleLessons() {
    return state.lessons.filter((lesson) => !state.lessonKind || lesson.kind === state.lessonKind);
  }

  function findLesson(lessonId) {
    return state.lessons.find((lesson) => String(lesson.lesson_id || "") === String(lessonId));
  }

  function updateLessonSelectionUi(lessons = visibleLessons()) {
    const visibleIds = new Set(lessons.map((lesson) => String(lesson.lesson_id || "")).filter(Boolean));
    const selectedVisible = [...state.lessonSelection].filter((id) => visibleIds.has(id)).length;
    const totalSelected = state.lessonSelection.size;
    const selectAll = $("lesson-select-all");
    if (selectAll) {
      selectAll.checked = visibleIds.size > 0 && selectedVisible === visibleIds.size;
      selectAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleIds.size;
    }
    if ($("lesson-selected-count")) {
      $("lesson-selected-count").textContent = totalSelected ? `已选择 ${totalSelected} 条经验` : "";
    }
    if ($("lesson-delete-selected")) $("lesson-delete-selected").disabled = !isAdmin() || !totalSelected;
  }

  function renderLessons() {
    const lessons = visibleLessons();
    const admin = isAdmin();
    $("lessons-list").innerHTML = lessons.length ? lessons.map((lesson) => {
      const kind = lesson.kind === "manual" ? "手工" : "自动";
      const kindClass = lesson.kind === "manual" ? "warn" : "ok";
      const occurrences = Number(lesson.occurrences || 1);
      const successes = Number(lesson.success_count || 0);
      const rate = occurrences ? Math.round((successes / occurrences) * 100) : 0;
      const symptoms = (lesson.symptoms || []).slice(0, 4);
      const failed = (lesson.failed_methods || []).map((item) => {
        const code = item.code ? ` [${item.code}]` : "";
        return `${item.method || "?"}${code}`;
      });
      const tags = (lesson.tags || []).slice(0, 12);
      const lessonId = String(lesson.lesson_id || "");
      const selected = state.lessonSelection.has(lessonId);
      const untrusted = lesson.trusted === false || lesson.untrusted === true;
      const select = admin
        ? `<input type="checkbox" class="lesson-select" data-lesson-id="${esc(lessonId)}" aria-label="选择经验" ${selected ? "checked" : ""}>`
        : "";
      const actions = admin
        ? `<div class="row lesson-actions">
            <button class="ghost lesson-edit" type="button" data-lesson-id="${esc(lessonId)}">编辑</button>
            <button class="ghost danger lesson-delete" type="button" data-lesson-id="${esc(lessonId)}">删除</button>
          </div>`
        : "";
      return `<div class="lesson">
        <div class="row lesson-head">
          ${select}
          <b>${esc(lesson.title)}
            <span class="badge ${kindClass}">${kind}</span>
            <span class="badge ${lesson.confidence === "analyst" ? "warn" : "run"}">${esc(lesson.confidence || "observed")}</span>
            ${untrusted ? '<span class="badge fail" title="未验证的导入经验，不参与主路线/回退排序">未验证导入</span>' : ""}
            <span class="badge run">${esc(lesson.shell || "unknown")}</span>
            <span class="badge">${esc(lesson.winning_method || "no-method")}</span>
          </b>
        </div>
        <span class="muted">设备 ${esc(lesson.device_abi || "unknown")} · APK ${esc(lesson.apk_abi_class || "unknown")} · occ ${occurrences} · 成功 ${successes}/${occurrences} (${rate}%) · 最近 ${esc(lesson.last_seen || "")}</span>
        <div class="muted">场景：${esc(lesson.scenario || "-")}</div>
        ${lesson.root_cause ? `<div>根因：${esc(lesson.root_cause)}</div>` : ""}
        <div>解法：${esc(lesson.solution || "-")}</div>
        ${symptoms.length ? `<div class="muted">症状：${symptoms.map((item) => esc(item)).join("；")}</div>` : ""}
        ${failed.length ? `<div class="muted">失败方法：${esc(failed.join(" + "))}</div>` : ""}
        ${lesson.framework ? `<div class="muted small">框架：${esc(lesson.framework)}</div>` : ""}
        ${tags.length ? `<div class="tags">${tags.map((tag) => `<span class="badge">${esc(tag)}</span>`).join(" ")}</div>` : ""}
        ${(lesson.evidence_links || []).length ? `<div class="muted small">证据：${esc((lesson.evidence_links || []).slice(0, 4).join(", "))}</div>` : ""}
        ${lesson.edited_at ? `<div class="muted small">人工编辑：${esc(lesson.edited_at)}</div>` : ""}
        ${actions}
      </div>`;
    }).join("") : '<div class="muted">暂无经验。完成任务后会自动生成并保存。</div>';
    updateLessonSelectionUi(lessons);
  }

  async function loadLessons(query = "") {
    const url = `/api/v1/lessons?limit=100${query ? `&query=${encodeURIComponent(query)}` : ""}`;
    try {
      const data = await api(url);
      const lessons = data.lessons || [];
      const ids = new Set(lessons.map((lesson) => String(lesson.lesson_id || "")).filter(Boolean));
      state.lessonSelection = new Set([...state.lessonSelection].filter((id) => ids.has(id)));
      state.lessons = lessons;
      state.lessonStats = data.stats || {};
      if (state.lessonEditId && !ids.has(String(state.lessonEditId))) closeLessonEdit();
      renderLessonStats();
      renderLessons();
    } catch (e) { toast(e.message, true); }
  }

  async function addLesson() {
    try {
      const payload = {
        title: $("lesson-title").value.trim(),
        scenario: $("lesson-scenario").value.trim(),
        solution: $("lesson-solution").value.trim(),
        shell: $("lesson-shell").value.trim() || null,
        device_abi: $("lesson-abi").value.trim() || null,
        confidence: "analyst",
        scope: "global",
      };
      if (!payload.title || !payload.scenario || !payload.solution) throw new Error("标题/场景/解法必填");
      await api("/api/v1/lessons", { method: "POST", body: payload });
      $("lesson-title").value = "";
      $("lesson-scenario").value = "";
      $("lesson-solution").value = "";
      toast("经验已保存");
      await loadLessons();
    } catch (e) { toast(e.message, true); }
  }

  async function downloadLessons() {
    try {
      const response = await fetch("/api/v1/lessons/export", {
        headers: {
          Authorization: `Bearer ${state.token}`,
          "X-Requested-With": "XMLHttpRequest",
        },
      });
      if (!response.ok) {
        let message = `HTTP ${response.status}`;
        try { const data = await response.json(); message = data?.error?.message || message; } catch (e) {}
        throw new Error(message);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `apu-lessons-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast("经验库已下载");
    } catch (e) { toast(e.message, true); }
  }

  async function importLessonsFile(file) {
    if (!file) return;
    if (file.size > 8 * 1024 * 1024) { toast("导入文件不能超过 8 MB", true); return; }
    try {
      const text = await file.text();
      let payload = JSON.parse(text);
      if (Array.isArray(payload)) payload = { lessons: payload };
      if (!payload || typeof payload !== "object" || !Array.isArray(payload.lessons)) {
        throw new Error("文件格式错误：需要包含 lessons 数组");
      }
      if (!confirm(`确认导入 ${payload.lessons.length} 条经验？只添加新经验，不覆盖已有经验。`)) return;
      const data = await api("/api/v1/lessons/import", { method: "POST", body: payload });
      toast(`导入完成：新增 ${data.imported || 0}，跳过 ${data.skipped || 0}，无效 ${data.invalid || 0}`);
      await loadLessons();
    } catch (e) {
      toast(e.message, true);
    } finally {
      if ($("lesson-import-file")) $("lesson-import-file").value = "";
    }
  }

  function closeLessonEdit() {
    state.lessonEditId = null;
    if ($("lesson-edit-card")) $("lesson-edit-card").classList.add("hidden");
    if ($("lesson-edit-id")) $("lesson-edit-id").textContent = "";
  }

  function openLessonEdit(lessonId) {
    if (!isAdmin()) { toast("仅管理员可以修改或删除经验", true); return; }
    const lesson = findLesson(lessonId);
    if (!lesson) { toast("经验不存在，请刷新后重试", true); return; }
    state.lessonEditId = String(lessonId);
    $("le-title").value = lesson.title || "";
    $("le-shell").value = lesson.shell || "";
    $("le-abi").value = lesson.device_abi || "";
    $("le-framework").value = lesson.framework || "";
    $("le-tags").value = (lesson.tags || []).join(", ");
    $("le-scenario").value = lesson.scenario || "";
    $("le-root-cause").value = lesson.root_cause || "";
    $("le-solution").value = lesson.solution || "";
    if ($("lesson-edit-id")) $("lesson-edit-id").textContent = state.lessonEditId;
    $("lesson-edit-card").classList.remove("hidden");
    $("lesson-edit-card").scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  async function saveLessonEdit() {
    if (!isAdmin()) { toast("仅管理员可以修改或删除经验", true); return; }
    if (!state.lessonEditId) return;
    const payload = {
      title: $("le-title").value.trim(),
      scenario: $("le-scenario").value.trim(),
      root_cause: $("le-root-cause").value.trim(),
      solution: $("le-solution").value.trim(),
      shell: $("le-shell").value.trim() || null,
      device_abi: $("le-abi").value.trim() || null,
      framework: $("le-framework").value.trim() || null,
      tags: $("le-tags").value.split(",").map((tag) => tag.trim()).filter(Boolean),
    };
    if (!payload.title) { toast("标题不能为空", true); return; }
    try {
      await api(`/api/v1/lessons/${encodeURIComponent(state.lessonEditId)}`, { method: "PATCH", body: payload });
      closeLessonEdit();
      toast("经验已更新");
      await loadLessons($("lesson-query").value.trim());
    } catch (e) { toast(e.message, true); }
  }

  async function deleteLesson(lessonId) {
    if (!isAdmin()) { toast("仅管理员可以修改或删除经验", true); return; }
    const lesson = findLesson(lessonId);
    const title = lesson?.title || lessonId;
    if (!confirm(`确认删除经验 “${title}”？此操作不可恢复。`)) return;
    try {
      await api(`/api/v1/lessons/${encodeURIComponent(lessonId)}`, { method: "DELETE" });
      state.lessonSelection.delete(String(lessonId));
      if (String(state.lessonEditId) === String(lessonId)) closeLessonEdit();
      toast("经验已删除");
      await loadLessons($("lesson-query").value.trim());
    } catch (e) { toast(e.message, true); }
  }

  async function deleteSelectedLessons() {
    if (!isAdmin()) { toast("仅管理员可以修改或删除经验", true); return; }
    const ids = [...state.lessonSelection];
    if (!ids.length) { toast("请选择要删除的经验", true); return; }
    if (!confirm(`确认删除选中的 ${ids.length} 条经验？此操作不可恢复。`)) return;
    try {
      const data = await api("/api/v1/lessons/batch-delete", { method: "POST", body: { lesson_ids: ids } });
      ids.forEach((id) => state.lessonSelection.delete(id));
      if (ids.includes(String(state.lessonEditId))) closeLessonEdit();
      toast(`已删除 ${data.deleted ?? 0} 条经验`);
      await loadLessons($("lesson-query").value.trim());
    } catch (e) { toast(e.message, true); }
  }

  function formatBytes(value) {
    const n = Number(value || 0);
    if (!Number.isFinite(n) || n <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let index = 0;
    let v = n;
    while (v >= 1024 && index < units.length - 1) { v /= 1024; index++; }
    return `${v.toFixed(index ? 1 : 0)} ${units[index]}`;
  }

  async function loadStats() {
    try {
      const data = await api("/api/v1/stats");
      const jobs = data.jobs || {};
      const jobText = Object.entries(jobs).map(([key, value]) => `${key} ${value}`).join(" · ") || "0";
      const disk = data.disk || {};
      const diskPct = disk.total ? Math.round((Number(disk.used || 0) / Number(disk.total)) * 100) : 0;
      const cards = [
        ["用户", `${data.users ?? 0}`, `管理员 ${data.admins ?? 0} · 可用 ${data.active_admins ?? 0}`],
        ["任务", `${Object.values(jobs).reduce((a, b) => a + Number(b || 0), 0)}`, jobText],
        ["上传文件", `${data.uploads?.count ?? 0}`, formatBytes(data.uploads?.bytes)],
        ["经验库", `${data.lessons?.total ?? 0}`, `自动 ${data.lessons?.observed ?? 0} · 手工 ${data.lessons?.analyst ?? 0}`],
        ["运行底座", `${data.engines?.available ?? 0}/${data.engines?.total ?? 0}`, "可用 / 总数"],
        ["磁盘", `${diskPct}%`, `${formatBytes(disk.used)} / ${formatBytes(disk.total)}`],
      ];
      $("stats-grid").innerHTML = cards.map(([label, value, hint]) => `
        <div class="stat-card">
          <span class="muted small">${esc(label)}</span>
          <strong>${esc(value)}</strong>
          <span class="muted small">${esc(hint)}</span>
        </div>`).join("");
    } catch (e) {
      $("stats-grid").innerHTML = `<div class="stat-card"><span class="muted small">统计加载失败：${esc(e.message)}</span></div>`;
    }
  }

  async function refreshUsersAndStats() {
    await Promise.all([loadUsers(), loadStats()]);
  }

  async function loadStorage() {
    try {
      const data = await api("/api/v1/storage");
      state.storage = data;
      renderStorage();
    } catch (e) {
      if ($("storage-stats")) {
        $("storage-stats").innerHTML = `<div class="stat-card"><span class="muted small">存储统计加载失败：${esc(e.message)}</span></div>`;
      }
    }
  }

  function renderStorage() {
    const data = state.storage;
    if (!data || !$("storage-stats")) return;
    const uploads = data.uploads || {};
    const jobs = data.jobs || {};
    const runs = data.runs || {};
    const orphans = data.orphans || {};
    const disk = data.disk || {};
    const cards = [
      ["上传 APK", `${uploads.count ?? 0}`, formatBytes(uploads.bytes)],
      ["任务产物", `${jobs.count ?? 0}`, formatBytes(jobs.bytes)],
      ["运行目录", `${runs.count ?? 0}`, formatBytes(runs.bytes)],
      ["磁盘空间", formatBytes(disk.free), `可用 / 共 ${formatBytes(disk.total)}`],
      ["孤立数据", `${(orphans.uploads || 0) + (orphans.runs || 0) + (orphans.job_dirs || 0)}`, `上传 ${orphans.uploads || 0} · 运行 ${orphans.runs || 0} · 任务目录 ${orphans.job_dirs || 0}`],
    ];
    $("storage-stats").innerHTML = cards.map(([label, value, hint]) => `
      <div class="stat-card">
        <span class="muted small">${esc(label)}</span>
        <strong>${esc(value)}</strong>
        <span class="muted small">${esc(hint)}</span>
      </div>`).join("");
    const items = data.items || [];
    $("uploads-summary").textContent = items.length ? `共 ${items.length} 个上传文件 · ${formatBytes(uploads.bytes)}` : "暂无上传文件";
    $("storage-uploads").innerHTML = items.length ? items.map((upload) => `
      <article class="upload-item">
        <div class="upload-main">
          <div class="upload-name"><b>${esc(upload.filename)}</b></div>
          <div class="upload-meta">
            <span>${esc(formatBytes(upload.size))}</span>
            <span>${esc(formatTime(upload.created_at))}</span>
            <span>关联任务 ${Number(upload.job_count || 0)}</span>
            <span class="muted">${esc(upload.id)}</span>
          </div>
        </div>
        <div class="upload-actions">
          <button class="ghost danger" data-delete-upload="${esc(upload.id)}" data-name="${esc(upload.filename)}" data-jobs="${Number(upload.job_count || 0)}">删除</button>
        </div>
      </article>`).join("") : '<div class="job-empty muted">暂无上传文件</div>';
    $("storage-uploads").querySelectorAll("[data-delete-upload]").forEach((button) => {
      button.onclick = () => deleteUpload(button.dataset.deleteUpload, button.dataset.name, Number(button.dataset.jobs || 0));
    });
  }

  async function cleanupStorage(target, label) {
    const days = Number($("storage-days")?.value || 0);
    const scope = days > 0 ? `${days} 天前的` : "全部符合条件的";
    if (!confirm(`确认清理${scope}${label}？删除后不可恢复。`)) return;
    try {
      const data = await api("/api/v1/storage/cleanup", { method: "POST", body: { target, older_than_days: days } });
      toast(`清理完成：任务 ${data.deleted_jobs || 0} · 上传 ${data.deleted_uploads || 0} · 运行目录 ${data.deleted_runs || 0} · 释放 ${formatBytes(data.freed_bytes)}`);
      await Promise.all([loadStorage(), loadJobs(), loadUploads(), loadStats()]);
    } catch (e) { toast(e.message, true); }
  }

  async function deleteUpload(uploadId, filename, jobCount) {
    const extra = jobCount > 0 ? `，并删除关联的 ${jobCount} 个任务及产物` : "";
    if (!confirm(`确认删除上传文件 “${filename}”${extra}？此操作不可恢复。`)) return;
    try {
      const data = await api(`/api/v1/uploads/${uploadId}`, { method: "DELETE" });
      toast(`上传已删除${data.deleted_jobs ? `，同时删除 ${data.deleted_jobs} 个任务` : ""}`);
      await Promise.all([loadStorage(), loadJobs(), loadUploads(), loadStats()]);
    } catch (e) { toast(e.message, true); }
  }

  async function loadUsers() {
    try {
      const data = await api("/api/v1/users");
      const items = data.items || [];
      if ($("user-admin-count")) {
        $("user-admin-count").textContent = `管理员 ${data.admins ?? 0} · 可用 ${data.active_admins ?? 0}`;
      }
      $("users-list").innerHTML = items.length ? `
        <table class="data-table">
          <thead><tr><th>用户</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
          <tbody>
            ${items.map((user) => `
              <tr>
                <td><b>${esc(user.username)}</b>${Number(user.id) === Number(state.user?.id) ? ' <span class="muted small">(当前)</span>' : ""}</td>
                <td><span class="badge ${user.role === "admin" ? "ok" : "run"}">${esc(user.role)}</span></td>
                <td>${user.disabled ? '<span class="badge fail">已禁用</span>' : '<span class="badge ok">正常</span>'}</td>
                <td class="muted small">${esc(user.created_at || "")}</td>
                <td class="row user-actions">
                  <button class="ghost small" data-user-role="${esc(user.id)}" data-role="${user.role === "admin" ? "user" : "admin"}">${user.role === "admin" ? "设为普通用户" : "设为管理员"}</button>
                  <button class="ghost small ${user.disabled ? "" : "danger"}" data-user-disabled="${esc(user.id)}" data-disabled="${user.disabled ? "0" : "1"}">${user.disabled ? "启用" : "禁用"}</button>
                  <button class="ghost small" data-user-reset="${esc(user.id)}">重置密码</button>
                  <button class="ghost small danger" data-user-delete="${esc(user.id)}" data-name="${esc(user.username)}">删除</button>
                </td>
              </tr>`).join("")}
          </tbody>
        </table>` : '<div class="muted">暂无用户</div>';
      const box = $("users-list");
      box.querySelectorAll("[data-user-role]").forEach((button) => {
        button.onclick = async () => {
          try {
            await api(`/api/v1/users/${button.dataset.userRole}`, { method: "PATCH", body: { role: button.dataset.role } });
            toast("用户角色已更新");
            await refreshUsersAndStats();
          } catch (e) { toast(e.message, true); }
        };
      });
      box.querySelectorAll("[data-user-disabled]").forEach((button) => {
        button.onclick = async () => {
          try {
            await api(`/api/v1/users/${button.dataset.userDisabled}`, { method: "PATCH", body: { disabled: button.dataset.disabled === "1" } });
            toast(button.dataset.disabled === "1" ? "用户已禁用" : "用户已启用");
            await refreshUsersAndStats();
          } catch (e) { toast(e.message, true); }
        };
      });
      box.querySelectorAll("[data-user-reset]").forEach((button) => {
        button.onclick = async () => {
          const password = prompt("输入新的密码（至少 4 位）");
          if (password === null) return;
          if (password.length < 4) { toast("密码至少 4 位", true); return; }
          try {
            await api(`/api/v1/users/${button.dataset.userReset}/reset`, { method: "POST", body: { password } });
            toast("密码已重置，目标账号会话已失效");
          } catch (e) { toast(e.message, true); }
        };
      });
      box.querySelectorAll("[data-user-delete]").forEach((button) => {
        button.onclick = async () => {
          if (!confirm(`确认删除用户 “${button.dataset.name}”？此操作不可恢复。`)) return;
          try {
            await api(`/api/v1/users/${button.dataset.userDelete}`, { method: "DELETE" });
            toast("用户已删除");
            await refreshUsersAndStats();
          } catch (e) { toast(e.message, true); }
        };
      });
    } catch (e) { toast(e.message, true); }
  }

  async function createUser() {
    try {
      await api("/api/v1/users", { method: "POST", body: { username: $("new-user").value.trim(), password: $("new-pass").value, role: $("new-role").value } });
      $("new-user").value = ""; $("new-pass").value = "";
      toast("用户已创建");
      await refreshUsersAndStats();
    } catch (e) { toast(e.message, true); }
  }

  async function changePassword(event) {
    event.preventDefault();
    const message = $("pw-msg");
    const current = $("pw-current").value;
    const next = $("pw-new").value;
    if (next !== $("pw-confirm").value) { message.textContent = "两次输入的新密码不一致"; message.className = "error"; return; }
    try {
      await api("/api/v1/auth/password", { method: "POST", body: { current_password: current, new_password: next } });
      $("pw-current").value = ""; $("pw-new").value = ""; $("pw-confirm").value = "";
      message.textContent = "密码已更新";
      message.className = "muted small";
      toast("密码已更新");
    } catch (e) {
      message.textContent = e.message;
      message.className = "error";
    }
  }

  async function loadAdmin() {
    if (isAdmin()) {
      await Promise.all([loadStats(), loadProviders(), loadAgents(), loadSkills(), loadMcps(), loadDevices(), loadEngines(), loadUsers(), loadAudit()]);
      return;
    }
    await Promise.all([loadProviders(), loadAgents(), loadSkills(), loadMcps()]);
  }

  function switchAdminPane(name) {
    if (!isAdmin() && ADMIN_ONLY_PANES.includes(name)) name = "agents";
    state.adminPane = name;
    document.querySelectorAll(".admin-tab").forEach((button) => button.classList.toggle("active", button.dataset.adminPane === name));
    document.querySelectorAll(".admin-pane").forEach((pane) => pane.classList.toggle("hidden", pane.dataset.adminPane !== name));
    if (name === "overview") loadStats();
    if (name === "storage") loadStorage();
    if (name === "users") loadUsers();
    if (name === "models") loadProviders();
    if (name === "agents") loadAgents();
    if (name === "skills") loadSkills();
    if (name === "mcp") loadMcps();
    if (name === "system") { loadDevices(); loadEngines(); }
    if (name === "audit") loadAudit();
  }

  async function loadAudit() {
    try {
      const data = await api("/api/v1/audit?limit=100");
      $("audit-list").innerHTML = (data.items || []).map((item) => `
        <div class="event"><span class="t">${esc(new Date(item.ts).toLocaleString())}</span><span class="k">${esc(item.action)}</span> ${esc(item.target || "")}</div>
      `).join("") || '<div class="muted">暂无审计</div>';
    } catch (e) { toast(e.message, true); }
  }

  async function runDoctor() {
    $("doctor-output").textContent = "检查中…";
    try {
      const data = await api("/api/v1/doctor");
      $("doctor-output").textContent = JSON.stringify(data, null, 2);
    } catch (e) { $("doctor-output").textContent = e.message; }
  }

  // ------------------------------------------------------------------ chat
  function chatAgentById(agentId) {
    return state.chatAgents.find((agent) => agent.id === agentId) || null;
  }

  function selectedChatAgent() {
    const selected = $("chat-agent")?.value || "";
    return chatAgentById(selected);
  }

  function updateChatAgentInfo() {
    const agent = selectedChatAgent();
    const box = $("chat-agent-info");
    if (!box) return;
    if (!agent) {
      box.textContent = "没有可用的 Agent。请在管理 → Agents 新增个人 Agent，或由管理员配置模型 Provider。";
      return;
    }
    const skills = (agent.skills || []).map((item) => item.name || item.id).filter(Boolean);
    const mcp = (agent.mcp || []).map((item) => item.name || item.id).filter(Boolean);
    box.textContent = `${agent.provider || agent.id} · ${agent.protocol || ""}/${agent.model || ""} · Skills ${skills.length} · MCP ${mcp.length}${agent.available ? "" : ` · ${agent.reason || "不可用"}`}`;
    box.title = [skills.length ? `Skills: ${skills.join(", ")}` : "", mcp.length ? `MCP: ${mcp.join(", ")}` : ""].filter(Boolean).join("\n");
  }

  async function uploadPackage(file, kind) {
    if (!file) return;
    if (!/\.zip$/i.test(file.name)) { toast("请选择 .zip 压缩包", true); return; }
    try {
      const form = new FormData();
      form.append("file", file, file.name);
      toast("正在分析并安装 ZIP 包…");
      const data = await api("/api/v1/packages/import", { method: "POST", body: form });
      const summary = data.summary || {};
      const installed = summary.installed || 0;
      const skipped = summary.skipped || 0;
      const errors = data.errors || [];
      const text = `安装完成：新增 ${installed}，跳过 ${skipped}${errors.length ? `，错误 ${errors.length}：${errors[0]}` : ""}`;
      toast(text, errors.length > 0);
      await Promise.all([loadAgents(), loadSkills(), loadMcps(), loadEngines(), loadProviders()]);
      if ($("chat-agent")) loadChatAgents();
    } catch (e) {
      toast(e.message, true);
    } finally {
      const input = document.querySelector(`[data-package-file="${kind}"]`);
      if (input) input.value = "";
    }
  }

  async function loadChatAgents() {
    try {
      const data = await api("/api/v1/chat/agents");
      state.chatAgents = data.items || [];
    } catch (e) { state.chatAgents = []; }
    const select = $("chat-agent");
    if (!select) return;
    const desired = state.chat?.agent_id || select.value || "";
    select.innerHTML = state.chatAgents.map((agent) => {
      const disabled = agent.available ? "" : " disabled";
      const detail = `${agent.protocol || ""}/${agent.model || ""}`;
      const reason = agent.available ? "" : ` · ${agent.reason || "不可用"}`;
      return `<option value="${esc(agent.id)}"${disabled}>${esc(agent.label || agent.name || agent.id)} · ${esc(detail)}${esc(reason)}</option>`;
    }).join("");
    if (!state.chatAgents.length) {
      select.innerHTML = '<option value="">暂无可用 Agent</option>';
      updateChatAgentInfo();
      return;
    }
    if (desired && [...select.options].some((option) => option.value === desired)) select.value = desired;
    else {
      const first = [...select.options].find((option) => !option.disabled);
      select.value = (first || select.options[0]).value;
    }
    updateChatAgentInfo();
  }

  async function loadChatData() {
    await loadChatAgents();
    await loadChats(true);
  }

  async function loadChats(autoOpen = false) {
    try {
      const data = await api("/api/v1/chats");
      state.chats = data.items || [];
    } catch (e) { state.chats = []; }
    renderChatSessions();
    if (state.chat && !state.chats.some((chat) => chat.id === state.chat.id)) {
      state.chat = null;
      state.chatMessages = [];
    }
    if (autoOpen && !state.chat && state.chats.length) {
      await openChat(state.chats[0].id);
    } else {
      renderChatMessages();
      updateChatHeader();
    }
    if (!state.chats.length && autoOpen) {
      state.chat = null;
      state.chatMessages = [];
      renderChatMessages();
      updateChatHeader();
    }
  }

  function renderChatSessions() {
    const box = $("chat-sessions");
    if (!box) return;
    box.innerHTML = state.chats.length ? state.chats.map((chat) => {
      const active = state.chat?.id === chat.id ? " active" : "";
      return `<div class="chat-session${active}" data-chat-open="${esc(chat.id)}" role="button" tabindex="0">
        <div class="chat-session-main">
          <span class="chat-session-title">${esc(chat.title || "新聊天")}</span>
          <span class="chat-session-meta">${esc(chat.agent_name || chat.agent_id || "")} · ${esc(chat.message_count || 0)} 条 · ${esc(formatTime(chat.updated_at))}</span>
        </div>
        <button class="ghost danger" data-chat-delete="${esc(chat.id)}" title="删除聊天">删除</button>
      </div>`;
    }).join("") : '<div class="muted">暂无聊天</div>';
    box.querySelectorAll("[data-chat-open]").forEach((row) => {
      const open = () => {
        setChatSidebar(false);
        openChat(row.dataset.chatOpen);
      };
      row.onclick = open;
      row.onkeydown = (event) => { if (event.key === "Enter") open(); };
    });
    box.querySelectorAll("[data-chat-delete]").forEach((button) => {
      button.onclick = (event) => { event.stopPropagation(); deleteChat(button.dataset.chatDelete); };
    });
  }

  function renderPendingFiles() {
    const box = $("chat-pending-files");
    if (!box) return;
    box.innerHTML = state.chatPendingFiles.map((file, index) => `
      <span class="chat-file-chip">
        <span>${esc(file.name)} · ${esc(formatBytes(file.size))}</span>
        <button type="button" class="ghost" data-remove-pending="${index}" title="移除">×</button>
      </span>`).join("");
    box.querySelectorAll("[data-remove-pending]").forEach((button) => {
      button.onclick = () => {
        state.chatPendingFiles.splice(Number(button.dataset.removePending), 1);
        renderPendingFiles();
      };
    });
    updateChatSendButton();
  }

  function addChatFiles(files) {
    const incoming = Array.from(files || []);
    for (const file of incoming) {
      if (state.chatPendingFiles.length >= 5) { toast("每条消息最多上传 5 个附件", true); break; }
      if (file.size > 20 * 1024 * 1024) { toast(`附件 ${file.name} 超过 20 MB`, true); continue; }
      state.chatPendingFiles.push(file);
    }
    renderPendingFiles();
    const input = $("chat-files");
    if (input) input.value = "";
  }

  async function uploadChatFile(chatId, file, signal) {
    const form = new FormData();
    form.append("file", file, file.name);
    const data = await api(`/api/v1/chats/${chatId}/files`, { method: "POST", body: form, signal });
    return data.file;
  }

  async function downloadChatFile(fileId, filename) {
    if (!state.chat) return;
    try {
      const response = await fetch(`/api/v1/chats/${state.chat.id}/files/${fileId}`, {
        headers: {
          Authorization: `Bearer ${state.token}`,
          "X-Requested-With": "XMLHttpRequest",
        },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename || "attachment";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    } catch (e) { toast(e.message, true); }
  }

  function renderChatEvent(event) {
    const data = event.data || {};
    if (event.kind === "mcp_tool_call") {
      const name = `${data.server_name || data.server || ""}/${data.tool || ""}`;
      return `<div class="chat-tool"><b>MCP 调用</b> ${esc(name)} <span class="muted">${esc(jsonPreview(data.arguments || {}, 240))}</span></div>`;
    }
    if (event.kind === "mcp_tool_result") {
      const text = typeof data.result === "string" ? data.result : jsonPreview(data.result || {}, 260);
      return `<div class="chat-tool"><b>MCP 返回</b> ${esc(data.tool || "")} ${data.is_error ? '<span class="error">错误</span>' : ""} <span class="muted">${esc(text)}</span></div>`;
    }
    if (event.kind === "chat_tool_call") {
      return `<div class="chat-tool"><b>资源工具</b> ${esc(data.tool || "")} <span class="muted">${esc(jsonPreview(data.arguments || {}, 240))}</span></div>`;
    }
    if (event.kind === "chat_tool_result") {
      const text = typeof data.result === "string" ? data.result : jsonPreview(data.result || {}, 260);
      return `<div class="chat-tool"><b>资源返回</b> ${esc(data.tool || "")} <span class="muted">${esc(text)}</span></div>`;
    }
    if (event.kind === "mcp_error" || event.kind === "tool_error") {
      return `<div class="chat-tool"><span class="error">${esc(event.message || data.error || "工具错误")}</span></div>`;
    }
    return "";
  }

  function renderChatMessages(forceScroll = false) {
    const box = $("chat-messages");
    if (!box) return;
    const wasNearBottom = !box.firstElementChild || box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    const previousTop = box.scrollTop;
    if (!state.chat) {
      box.innerHTML = '<div class="chat-empty muted">新建聊天并发送第一条消息</div>';
      return;
    }
    if (!state.chatMessages.length) {
      box.innerHTML = '<div class="chat-empty muted">还没有消息，输入内容开始对话</div>';
      return;
    }
    const agent = chatAgentById(state.chat.agent_id);
    box.innerHTML = state.chatMessages.map((message) => {
      const role = message.role === "user" ? "user" : "assistant";
      const label = role === "user" ? "你" : (agent?.label || state.chat.agent_name || "Agent");
      const events = (message.meta?.events || []).filter((event) => ["mcp_tool_call", "mcp_tool_result", "chat_tool_call", "chat_tool_result", "mcp_error", "tool_error"].includes(event.kind));
      const tools = events.length ? `<div class="chat-tools">${events.slice(-10).map(renderChatEvent).join("")}</div>` : "";
      const attachments = (message.meta?.attachments || []).map((file) => `
        <button type="button" class="chat-file-chip chat-attachment" data-chat-download="${esc(file.id)}" data-filename="${esc(file.filename || "attachment")}">
          📎 ${esc(file.filename || "attachment")} · ${esc(formatBytes(file.size))}
        </button>`).join("");
      return `<div class="chat-message ${role}">
        <div class="chat-message-head"><span>${esc(label)}</span><span>${esc(formatTime(message.created_at))}</span></div>
        <div class="chat-message-body" data-no-i18n>${esc(message.content || "")}</div>
        ${attachments ? `<div class="chat-attachments">${attachments}</div>` : ""}
        ${tools}
      </div>`;
    }).join("");
    box.querySelectorAll("[data-chat-download]").forEach((button) => {
      button.onclick = () => downloadChatFile(button.dataset.chatDownload, button.dataset.filename);
    });
    if (forceScroll || wasNearBottom) scrollChatBottom();
    else box.scrollTop = previousTop;
  }

  function scrollChatBottom() {
    const box = $("chat-messages");
    if (box) box.scrollTop = box.scrollHeight;
  }

  function updateChatSendButton() {
    const input = $("chat-input");
    const button = $("chat-send");
    if (!input || !button) return;
    const hasPayload = Boolean(input.value.trim() || state.chatPendingFiles.length);
    button.disabled = state.chatSending || !hasPayload;
    button.textContent = tr(state.chatSending ? "发送中…" : "发送");
    button.setAttribute("aria-busy", state.chatSending ? "true" : "false");
    const stop = $("chat-stop");
    if (stop) stop.classList.toggle("hidden", !state.chatSending);
  }

  function setChatSidebar(open) {
    const grid = document.querySelector("#tab-chat .chat-grid");
    const toggle = $("chat-sidebar-toggle");
    if (!grid) return;
    grid.classList.toggle("chat-sidebar-open", Boolean(open));
    if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  function updateChatHeader() {
    const title = $("chat-title");
    const meta = $("chat-meta");
    if (!title) return;
    updateChatSendButton();
    if (!state.chat) {
      title.textContent = "新聊天";
      meta.textContent = "选择 Agent 后开始对话";
      return;
    }
    title.textContent = state.chat.title || "新聊天";
    const agent = chatAgentById(state.chat.agent_id);
    meta.textContent = `${agent?.label || state.chat.agent_name || state.chat.agent_id || ""} · ${state.chatMessages.length} 条消息`;
    $("chat-rename").disabled = false;
    $("chat-clear").disabled = false;
    $("chat-delete").disabled = false;
  }

  async function createChat(options = {}) {
    const agent = selectedChatAgent();
    if (!agent) { toast("请先选择 Agent", true); return null; }
    if (!agent.available) { toast(agent.reason || "该 Agent 不可用", true); return null; }
    try {
      const data = await api("/api/v1/chats", { method: "POST", body: { agent_id: agent.id } });
      state.chat = data.chat;
      state.chatMessages = [];
      state.chats = [data.chat, ...state.chats.filter((chat) => chat.id !== data.chat.id)];
      renderChatSessions();
      renderChatMessages(true);
      updateChatHeader();
      if (!options.silent) toast("已创建新聊天");
      return state.chat;
    } catch (e) { toast(e.message, true); return null; }
  }

  async function openChat(chatId) {
    try {
      const data = await api(`/api/v1/chats/${chatId}`);
      state.chat = data.chat;
      state.chatMessages = data.messages || [];
      state.chatPendingFiles = [];
      renderPendingFiles();
      if ($("chat-agent") && data.chat.agent_id) $("chat-agent").value = data.chat.agent_id;
      updateChatAgentInfo();
      renderChatSessions();
      renderChatMessages(true);
      updateChatHeader();
      $("chat-state").textContent = "";
    } catch (e) { toast(e.message, true); }
  }

  async function sendChat(event) {
    event.preventDefault();
    if (state.chatSending) return;
    const input = $("chat-input");
    const content = input.value.trim();
    const pending = state.chatPendingFiles.slice();
    if (!content && !pending.length) return;
    if (!state.chat) {
      const created = await createChat({ silent: true });
      if (!created) return;
    }
    const agent = chatAgentById(state.chat.agent_id) || selectedChatAgent();
    if (!agent) { toast("请先选择 Agent", true); return; }
    if (!agent.available) { toast(agent.reason || "该 Agent 不可用", true); return; }
    const controller = new AbortController();
    state.chatAbort = controller;
    state.chatSending = true;
    input.value = "";
    state.chatDraft = "";
    updateChatSendButton();
    const uploaded = [];
    try {
      for (let index = 0; index < pending.length; index++) {
        $("chat-state").textContent = `上传附件 ${index + 1}/${pending.length}…`;
        uploaded.push(await uploadChatFile(state.chat.id, pending[index], controller.signal));
      }
      const finalContent = content || "请分析附件。";
      $("chat-state").textContent = "思考中…";
      const temp = {
        role: "user",
        content: finalContent,
        created_at: new Date().toISOString(),
        meta: uploaded.length ? { attachments: uploaded } : {},
        _temp: true,
      };
      state.chatMessages.push(temp);
      renderChatMessages(true);
      const data = await api(`/api/v1/chats/${state.chat.id}/messages`, {
        method: "POST",
        body: { content: finalContent, file_ids: uploaded.map((file) => file.id) },
        signal: controller.signal,
      });
      state.chat = data.chat;
      state.chatMessages = state.chatMessages.filter((message) => !message._temp);
      state.chatMessages.push(data.user, data.assistant);
      state.chatPendingFiles = [];
      renderPendingFiles();
      const chatInList = state.chats.find((chat) => chat.id === state.chat.id);
      if (chatInList) {
        chatInList.title = state.chat.title;
        chatInList.agent_id = state.chat.agent_id;
        chatInList.agent_name = agent.label || agent.name || agent.id;
        chatInList.message_count = (Number(chatInList.message_count) || 0) + 2;
        chatInList.updated_at = state.chat.updated_at;
      }
      $("chat-state").textContent = (data.warnings || []).length ? data.warnings.join(" · ") : "完成";
      renderChatSessions();
      renderChatMessages(true);
      updateChatHeader();
    } catch (e) {
      if (e.name === "AbortError") {
        state.chatMessages = state.chatMessages.filter((message) => !message._temp);
        renderChatMessages();
        $("chat-state").textContent = tr("已停止");
        if (!input.value) {
          input.value = content;
          state.chatDraft = content;
        }
      } else {
        toast(e.message, true);
        $("chat-state").textContent = "";
        if (state.chat) {
          state.chatPendingFiles = [];
          renderPendingFiles();
          await openChat(state.chat.id);
        }
        if (!input.value) {
          input.value = content;
          state.chatDraft = content;
        }
      }
    } finally {
      if (state.chatAbort === controller) state.chatAbort = null;
      state.chatSending = false;
      updateChatSendButton();
      input.focus();
    }
  }

  async function requestChatStop(chatId) {
    try {
      await api(`/api/v1/chats/${encodeURIComponent(chatId)}/stop`, { method: "POST" });
    } catch (e) {
      // Older backends (404) or backends without cancellation (501) are fine:
      // the local AbortController already stopped this browser request.
      if ([404, 501, 503].includes(Number(e?.status))) return;
      if (window.console?.warn) console.warn("chat stop request failed", e);
    }
  }

  function stopChatSend() {
    if (!state.chatSending || !state.chatAbort) return;
    $("chat-state").textContent = tr("正在停止…");
    const chatId = state.chat?.id;
    // Abort the local fetch first so the UI stops immediately, then ask the
    // backend to cancel the in-flight generation.
    state.chatAbort.abort();
    if (chatId) requestChatStop(chatId);
  }

  async function deleteChat(chatId) {
    const target = state.chats.find((chat) => chat.id === chatId);
    if (!confirm(`确认删除聊天 “${target?.title || chatId}”？聊天记录不可恢复。`)) return;
    try {
      await api(`/api/v1/chats/${chatId}`, { method: "DELETE" });
      state.chats = state.chats.filter((chat) => chat.id !== chatId);
      if (state.chat?.id === chatId) {
        state.chat = null;
        state.chatMessages = [];
        state.chatPendingFiles = [];
        renderPendingFiles();
        renderChatMessages();
        updateChatHeader();
      }
      renderChatSessions();
      toast("聊天已删除");
    } catch (e) { toast(e.message, true); }
  }

  async function clearChat() {
    if (!state.chat) return;
    if (!confirm("确认清空当前聊天记录？")) return;
    try {
      await api(`/api/v1/chats/${state.chat.id}/clear`, { method: "POST" });
      state.chatMessages = [];
      state.chatPendingFiles = [];
      renderPendingFiles();
      renderChatMessages();
      updateChatHeader();
      const item = state.chats.find((chat) => chat.id === state.chat.id);
      if (item) item.message_count = 0;
      renderChatSessions();
      toast("聊天已清空");
    } catch (e) { toast(e.message, true); }
  }

  async function renameChat() {
    if (!state.chat) return;
    const title = prompt("聊天标题", state.chat.title || tr("新聊天"));
    if (title === null) return;
    try {
      const data = await api(`/api/v1/chats/${state.chat.id}`, { method: "PATCH", body: { title } });
      state.chat = data.chat;
      const item = state.chats.find((chat) => chat.id === state.chat.id);
      if (item) item.title = state.chat.title;
      renderChatSessions();
      updateChatHeader();
    } catch (e) { toast(e.message, true); }
  }

  function switchChatAgent() {
    updateChatAgentInfo();
    if (!state.chat) return;
    const agent = selectedChatAgent();
    if (!agent || agent.id === state.chat.agent_id) return;
    if (!agent.available) { toast(agent.reason || "该 Agent 不可用", true); return; }
    api(`/api/v1/chats/${state.chat.id}`, { method: "PATCH", body: { agent_id: agent.id } })
      .then((data) => {
        state.chat = data.chat;
        const item = state.chats.find((chat) => chat.id === state.chat.id);
        if (item) { item.agent_id = agent.id; item.agent_name = agent.label || agent.name; }
        renderChatSessions();
        updateChatHeader();
        toast("已切换聊天 Agent");
      })
      .catch((e) => toast(e.message, true));
  }

  function switchTab(tab) {
    state.tab = tab;
    document.querySelectorAll(".tab").forEach((button) => button.classList.toggle("active", button.dataset.tab === tab));
    for (const name of ["jobs", "chat", "lessons", "account", "admin"]) {
      $(`tab-${name}`).classList.toggle("hidden", name !== tab);
    }
    document.querySelector("main")?.classList.toggle("chat-mode", tab === "chat");
    if (tab !== "chat") setChatSidebar(false);
    if (tab === "chat") {
      if (!$("chat-input").value && state.chatDraft) $("chat-input").value = state.chatDraft;
      updateChatSendButton();
      loadChatData();
    }
    if (tab === "lessons") loadLessons();
    if (tab === "account") updateAccount();
    if (tab === "admin") {
      syncAdminVisibility();
      switchAdminPane(state.adminPane || (isAdmin() ? "overview" : "agents"));
      loadAdmin();
    }
  }

  function wireEvents() {
    $("lang-toggle").addEventListener("click", toggleLanguage);
    window.addEventListener("apu:langchange", () => {
      state.lang = window.ApuI18n?.lang || state.lang;
      updateLangToggle();
      updateChatSendButton();
      if (state.jobsTotal || state.jobs.length) renderJobs();
      if (state.storage) renderStorage();
      if (state.chats.length || state.chat) {
        renderChatSessions();
        renderChatMessages();
        updateChatHeader();
      }
      if (state.lessons.length) renderLessons();
      updateAccount();
    });
    $("login-form").addEventListener("submit", login);
    $("logout").addEventListener("click", logout);
    document.querySelectorAll(".tab").forEach((button) => button.onclick = () => switchTab(button.dataset.tab));
    $("file").addEventListener("change", () => {
      const file = $("file").files[0];
      if (!file) { showFileNote(""); return; }
      $("file-label").textContent = file.name;
      if (isBundleFile(file)) {
        $("file-meta").textContent = "不支持的分卷包";
        showFileNote(BUNDLE_MESSAGE);
        $("start-job").disabled = true;
        return;
      }
      showFileNote("");
      $("file-meta").textContent = `${(file.size / 1024 / 1024).toFixed(1)} MB`;
      $("start-job").disabled = false;
    });
    const dropzone = $("dropzone");
    dropzone.addEventListener("dragover", (event) => { event.preventDefault(); dropzone.style.borderColor = "#5b8cff"; });
    dropzone.addEventListener("dragleave", () => { dropzone.style.borderColor = ""; });
    dropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropzone.style.borderColor = "";
      if (event.dataTransfer.files.length) {
        $("file").files = event.dataTransfer.files;
        $("file").dispatchEvent(new Event("change"));
      }
    });
    $("start-job").addEventListener("click", uploadAndStart);
    $("engine").addEventListener("change", () => {
      state.engineChoice = $("engine").value;
    });
    $("refresh-jobs").addEventListener("click", () => loadJobs());
    $("job-status-filter").addEventListener("change", () => {
      state.jobStatus = $("job-status-filter").value;
      state.jobsOffset = 0;
      loadJobs();
    });
    $("jobs-prev").addEventListener("click", () => {
      state.jobsOffset = Math.max(0, state.jobsOffset - state.jobsLimit);
      loadJobs();
    });
    $("jobs-next").addEventListener("click", () => {
      if (state.jobsOffset + state.jobsLimit < state.jobsTotal) {
        state.jobsOffset += state.jobsLimit;
        loadJobs();
      }
    });
    $("refresh-storage").addEventListener("click", loadStorage);
    $("cleanup-completed-jobs").addEventListener("click", () => cleanupStorage("completed_jobs", "已结束任务"));
    $("cleanup-orphan-uploads").addEventListener("click", () => cleanupStorage("orphan_uploads", "无引用上传"));
    $("cleanup-orphan-runs").addEventListener("click", () => cleanupStorage("orphan_runs", "孤立运行目录"));
    $("cleanup-all").addEventListener("click", () => cleanupStorage("all", "已结束任务、无引用上传与孤立运行目录"));
    $("refresh-devices").addEventListener("click", loadDevices);
    $("device-add").addEventListener("click", addDevice);
    $("refresh-engines").addEventListener("click", loadEngines);
    if ($("refresh-engines-system")) $("refresh-engines-system").addEventListener("click", loadEngines);
    $("refresh-users").addEventListener("click", loadUsers);
    $("refresh-audit").addEventListener("click", loadAudit);
    $("run-doctor").addEventListener("click", runDoctor);
    $("add-user").addEventListener("click", createUser);
    $("refresh-admin").addEventListener("click", loadAdmin);
    $("overview-refresh").addEventListener("click", loadStats);
    $("password-form").addEventListener("submit", changePassword);
    document.querySelectorAll(".admin-tab").forEach((button) => {
      button.onclick = () => switchAdminPane(button.dataset.adminPane);
    });
    document.querySelectorAll("[data-admin-jump]").forEach((button) => {
      button.onclick = () => switchAdminPane(button.dataset.adminJump);
    });
    $("lesson-search").addEventListener("click", () => loadLessons($("lesson-query").value.trim()));
    $("lesson-refresh").addEventListener("click", () => loadLessons($("lesson-query").value.trim()));
    $("lesson-kind").addEventListener("change", () => {
      state.lessonKind = $("lesson-kind").value;
      renderLessons();
    });
    $("lesson-add").addEventListener("click", addLesson);
    $("lesson-download").addEventListener("click", downloadLessons);
    $("lesson-import").addEventListener("click", () => $("lesson-import-file").click());
    $("lesson-import-file").addEventListener("change", () => importLessonsFile($("lesson-import-file").files[0]));
    $("lesson-select-all").addEventListener("change", () => {
      const checked = $("lesson-select-all").checked;
      for (const lesson of visibleLessons()) {
        const id = String(lesson.lesson_id || "");
        if (!id) continue;
        if (checked) state.lessonSelection.add(id);
        else state.lessonSelection.delete(id);
      }
      renderLessons();
    });
    $("lesson-delete-selected").addEventListener("click", deleteSelectedLessons);
    $("lesson-edit-save").addEventListener("click", saveLessonEdit);
    $("lesson-edit-cancel").addEventListener("click", closeLessonEdit);
    $("lessons-list").addEventListener("click", (event) => {
      const target = event.target instanceof Element ? event.target : null;
      if (!target) return;
      const edit = target.closest(".lesson-edit");
      if (edit) {
        event.stopPropagation();
        openLessonEdit(edit.dataset.lessonId);
        return;
      }
      const remove = target.closest(".lesson-delete");
      if (remove) {
        event.stopPropagation();
        deleteLesson(remove.dataset.lessonId);
        return;
      }
      if (target.closest(".lesson-select")) event.stopPropagation();
    });
    $("lessons-list").addEventListener("change", (event) => {
      const target = event.target instanceof Element ? event.target : null;
      const checkbox = target?.closest(".lesson-select");
      if (!checkbox) return;
      event.stopPropagation();
      const id = String(checkbox.dataset.lessonId || "");
      if (checkbox.checked) state.lessonSelection.add(id);
      else state.lessonSelection.delete(id);
      updateLessonSelectionUi();
    });

    $("chat-new").addEventListener("click", () => createChat());
    $("chat-attach").addEventListener("click", () => $("chat-files").click());
    $("chat-files").addEventListener("change", () => addChatFiles($("chat-files").files));
    $("chat-form").addEventListener("submit", sendChat);
    $("chat-stop").addEventListener("click", stopChatSend);
    $("chat-sidebar-toggle").addEventListener("click", () => {
      const grid = document.querySelector("#tab-chat .chat-grid");
      setChatSidebar(!grid?.classList.contains("chat-sidebar-open"));
    });
    let chatComposing = false;
    const chatInput = $("chat-input");
    chatInput.addEventListener("compositionstart", () => { chatComposing = true; });
    chatInput.addEventListener("compositionend", () => { chatComposing = false; });
    chatInput.addEventListener("input", () => {
      state.chatDraft = chatInput.value;
      updateChatSendButton();
    });
    chatInput.addEventListener("keydown", (event) => {
      if (event.isComposing || chatComposing || event.keyCode === 229) return;
      if (event.key === "Enter" && !event.shiftKey && !event.altKey) {
        event.preventDefault();
        $("chat-form").requestSubmit();
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") setChatSidebar(false);
    });
    updateChatSendButton();
    $("chat-agent").addEventListener("change", switchChatAgent);
    $("chat-rename").addEventListener("click", renameChat);
    $("chat-clear").addEventListener("click", clearChat);
    $("chat-delete").addEventListener("click", () => state.chat && deleteChat(state.chat.id));

    $("new-provider").addEventListener("click", () => openProviderForm(null));
    $("refresh-providers").addEventListener("click", loadProviders);
    $("provider-form-close").addEventListener("click", () => $("provider-form-card").classList.add("hidden"));
    $("pv-protocol").addEventListener("change", () => applyProtocolDefaults($("pv-protocol").value, true));
    $("pv-save").addEventListener("click", saveProvider);
    $("pv-test").addEventListener("click", testProviderForm);
    $("pv-models").addEventListener("click", fetchProviderModels);
    $("pv-clear-key").addEventListener("click", clearProviderKey);

    document.querySelectorAll("[data-package-import]").forEach((button) => {
      button.addEventListener("click", () => {
        const input = document.querySelector(`[data-package-file="${button.dataset.packageImport}"]`);
        if (input) input.click();
      });
    });
    document.querySelectorAll("[data-package-file]").forEach((input) => {
      input.addEventListener("change", () => uploadPackage(input.files[0], input.dataset.packageFile));
    });
    $("new-agent").addEventListener("click", () => openAgentForm(null));
    $("refresh-agents").addEventListener("click", loadAgents);
    $("agent-form-close").addEventListener("click", () => $("agent-form-card").classList.add("hidden"));
    $("ag-save").addEventListener("click", saveAgent);
    $("ag-cancel").addEventListener("click", () => $("agent-form-card").classList.add("hidden"));

    $("new-skill").addEventListener("click", () => openSkillForm(null));
    $("refresh-skills").addEventListener("click", loadSkills);
    $("skill-form-close").addEventListener("click", () => $("skill-form-card").classList.add("hidden"));
    $("sk-save").addEventListener("click", saveSkill);
    $("sk-cancel").addEventListener("click", () => $("skill-form-card").classList.add("hidden"));

    $("new-mcp").addEventListener("click", () => openMcpForm(null));
    $("refresh-mcp").addEventListener("click", loadMcps);
    $("mcp-form-close").addEventListener("click", () => $("mcp-form-card").classList.add("hidden"));
    $("mc-transport").addEventListener("change", toggleMcpFields);
    $("mc-save").addEventListener("click", () => { saveMcpSafe(); });
    $("mc-test").addEventListener("click", testMcpForm);
    $("mc-cancel").addEventListener("click", () => $("mcp-form-card").classList.add("hidden"));

    document.querySelectorAll(".call-filter").forEach((checkbox) => {
      checkbox.addEventListener("change", () => {
        state.callFilters[checkbox.value] = checkbox.checked;
        renderCalls();
      });
    });

    $("detail-close").addEventListener("click", () => {
      $("job-detail").classList.add("hidden");
      if (state.stream) { state.stream.close(); state.stream = null; }
    });
    $("detail-cancel").addEventListener("click", () => state.selectedJob && cancelJob(state.selectedJob.id));
    $("detail-cleanup").addEventListener("click", () => state.selectedJob && cleanupJob(state.selectedJob.id));
    $("detail-retry").addEventListener("click", () => state.selectedJob && retryJob(state.selectedJob.id));
  }

  async function bootstrapData() {
    await Promise.all([loadDevices(), loadEngines()]);
    await loadJobs();
    if (state.tab === "jobs") loadLessons();
    state.poll = setInterval(() => loadJobs({ silent: true }), 5000);
  }

  async function init() {
    wireEvents();
    updateLangToggle();
    if (!(await loadMe())) return;
    await bootstrapData();
  }

  window.addEventListener("DOMContentLoaded", init);
})();
