/**
 * LossLogic — Apple Liquid Glass & Monochrome Design System
 * Real WebGL Shader Engine + Dual Theme (Light Studio Crystal & Dark Obsidian Glass)
 */
(function() {
  "use strict";

  // =========================================================================
  // 1. Application State & Persistent Theme Manager
  // =========================================================================
  const urlParams = new URLSearchParams(window.location.search);
  const themeParam = urlParams.get("theme");
  const savedTheme = (themeParam === "light" || themeParam === "dark") ? themeParam : (localStorage.getItem("crq_theme") || "dark");
  const tabParam = urlParams.get("tab");
  const initialTab = (tabParam === "technical" || tabParam === "executive" || tabParam === "demo") ? tabParam : "executive";

  const state = {
    theme: savedTheme,
    currency: "INR",
    usdToInr: 83.5,
    budget: 4500000.0, // ₹45 Lakhs default
    whatIfControls: new Set(["CTRL-MFA", "CTRL-PATCH"]),
    delayDays: 0,
    activeTab: initialTab,
    data: null,
    // Demo & BharatCart State
    activeAttack: null,
    activeAttackData: null,
    tickerTimer: null,
    vendorCatalog: [],
    purchasedVendors: new Set(),
    demoStats: {
      posture: 84.6,
      riskFactor: 4.8,
      ealInr: 48200000.0,
      baselineEalInr: 48200000.0,
      totalSpendInr: 0.0,
      riskMitigatedInr: 0.0,
      supPct: 0.0,
      activeShields: 5,
    },
    modalVendor: null,
  };

  // Set theme immediately on root
  document.documentElement.setAttribute("data-theme", state.theme);

  // Canonical High-Fidelity Dataset
  const defaultData = {
    totalEalInr: 48200000.0,
    var90Inr: 82000000.0,
    var95Inr: 124000000.0,
    var99Inr: 241000000.0,
    compliancePct: 84.6,
    controls: [
      { id: "CTRL-MFA", name: "Hardware MFA Enforcement", costInr: 350000.0, eff: 0.88, cat: "IAM" },
      { id: "CTRL-PATCH", name: "Automated Vulnerability Patching", costInr: 500000.0, eff: 0.92, cat: "Vuln" },
      { id: "CTRL-EDR", name: "Next-Gen EDR Behavioral Agent", costInr: 800000.0, eff: 0.85, cat: "EDR" },
      { id: "CTRL-S3-ENCR", name: "Cloud S3 Encryption Guardrails", costInr: 250000.0, eff: 0.95, cat: "CSPM" },
      { id: "CTRL-SIEM-AI", name: "AI SIEM Correlation & SOAR", costInr: 1200000.0, eff: 0.78, cat: "SOC" }
    ],
    findings: [
      { id: "VULN-001", asset: "Core Banking PostgreSQL Primary", domain: "Vulnerability", sev: "CRITICAL", cvss: 9.8, lossInr: 18500000.0, ctrl: "CTRL-PATCH" },
      { id: "IAM-001", asset: "AWS Production IAM Core", domain: "IAM", sev: "CRITICAL", cvss: 8.9, lossInr: 11000000.0, ctrl: "CTRL-MFA" },
      { id: "SIEM-001", asset: "Internet API Gateway", domain: "SIEM", sev: "HIGH", cvss: 7.5, lossInr: 8200000.0, ctrl: "CTRL-SIEM-AI" },
      { id: "CSPM-001", asset: "Customer Archive S3 Bucket", domain: "CSPM", sev: "CRITICAL", cvss: 9.1, lossInr: 6000000.0, ctrl: "CTRL-S3-ENCR" },
      { id: "EDR-001", asset: "Trading Floor Workstation 104", domain: "EDR", sev: "HIGH", cvss: 7.8, lossInr: 4500000.0, ctrl: "CTRL-EDR" }
    ],
    frameworks: {
      "ISO_27001": { name: "ISO/IEC 27001:2022", score: 83.3, passing: 5, total: 6 },
      "NIST_CSF": { name: "NIST CSF 2.0", score: 80.0, passing: 4, total: 6 },
      "CIS_V8": { name: "CIS Controls v8", score: 81.5, passing: 4, total: 5 },
      "RBI_CSF": { name: "RBI Cyber Security Framework", score: 85.7, passing: 4, total: 5 },
      "SEBI_CSCRF": { name: "SEBI Cyber Resilience Framework", score: 86.2, passing: 4, total: 5 }
    }
  };

  // Currency Formatting Utility
  function formatMoney(amountInr) {
    if (state.currency === "INR") {
      const val = amountInr;
      if (Math.abs(val) >= 10000000.0) {
        return `₹ ${(val / 10000000.0).toFixed(2)} Cr`;
      } else if (Math.abs(val) >= 100000.0) {
        return `₹ ${(val / 100000.0).toFixed(2)} L`;
      } else {
        return `₹ ${Math.round(val).toLocaleString("en-IN")}`;
      }
    } else {
      const val = amountInr / state.usdToInr;
      if (Math.abs(val) >= 1000000.0) {
        return `$ ${(val / 1000000.0).toFixed(2)} M`;
      } else if (Math.abs(val) >= 1000.0) {
        return `$ ${(val / 1000.0).toFixed(1)} K`;
      } else {
        return `$ ${Math.round(val).toLocaleString("en-US")}`;
      }
    }
  }

  // =========================================================================
  // 2. liquidGL Professional WebGL Shader Engine
  // =========================================================================
  const LiquidGLEngine = {
    gl: null,
    program: null,
    canvas: null,
    uniforms: {},
    mouse: { x: 0.5, y: 0.5, targetX: 0.5, targetY: 0.5 },
    startTime: performance.now(),
    animId: null,

    // Vertex Shader (Fullscreen Quad with UV)
    vsSource: `
      attribute vec2 a_position;
      varying vec2 v_uv;
      void main() {
        v_uv = (a_position + 1.0) * 0.5;
        gl_Position = vec4(a_position, 0.0, 1.0);
      }
    `,

    // Fragment Shader (Aggressive Liquid Glass Caustics, Prismatic Refraction & Dynamic Fluid Optics)
    fsSource: `
      precision highp float;
      varying vec2 v_uv;
      uniform vec2 u_resolution;
      uniform vec2 u_mouse;
      uniform float u_time;
      uniform float u_is_light;

      // High-energy multi-harmonic fluid heightfield with domain warping
      float liquidHeight(vec2 p, float t) {
        vec2 q = vec2(
          sin(p.x * 1.35 + t * 0.85) + cos(p.y * 1.65 - t * 0.65),
          cos(p.y * 1.45 + t * 0.75) + sin(p.x * 1.55 - t * 0.55)
        );
        vec2 r = vec2(
          sin(p.x * 2.5 + q.x * 1.6 + t * 0.95),
          cos(p.y * 2.3 + q.y * 1.5 - t * 0.85)
        );
        float h1 = sin(p.x * 1.9 + r.x * 1.3 + t * 0.75);
        float h2 = cos(p.y * 2.1 + r.y * 1.2 - t * 0.9);
        float h3 = sin((p.x * 1.4 + p.y * 1.6) + (r.x + r.y) * 0.85 + t * 1.2);
        float h4 = cos(length(p - vec2(1.0, 0.8) + q * 0.4) * 3.8 - t * 1.4) * 0.6;
        return (h1 + h2 + h3 + h4) * 0.22;
      }

      void main() {
        vec2 uv = gl_FragCoord.xy / u_resolution.xy;
        float aspect = u_resolution.x / u_resolution.y;
        vec2 p = vec2(uv.x * aspect, uv.y) * 2.6;
        float t = u_time * 0.255;

        // Base liquid height (pure ambient fluid flow without cursor-following wave)
        float h = liquidHeight(p, t);

        // Finite-difference surface normals
        float eps = 0.018;
        float hR = liquidHeight(vec2(p.x + eps, p.y), t);
        float hU = liquidHeight(vec2(p.x, p.y + eps), t);
        vec2 norm = vec2(hR - h, hU - h) / eps;

        // Refraction & subtle dispersion
        float refr = 0.040;
        float aber = 0.012;

        float cR = liquidHeight((p + norm * (refr - aber)), t * 1.15);
        float cG = liquidHeight((p + norm * refr), t * 1.15);
        float cB = liquidHeight((p + norm * (refr + aber)), t * 1.15);

        // Balanced optical caustics
        float causticR = pow(clamp(cR * 0.55 + 0.5, 0.0, 1.0), 3.8);
        float causticG = pow(clamp(cG * 0.55 + 0.5, 0.0, 1.0), 3.8);
        float causticB = pow(clamp(cB * 0.55 + 0.5, 0.0, 1.0), 3.8);

        // Fresnel contour & ambient top-lit specular sheen (independent of cursor)
        float fresnel = clamp(length(norm) * 0.45, 0.0, 1.0);
        vec2 lightRef = vec2(aspect * 1.3, 2.4);
        float dLight = distance(p, lightRef);
        float spec = pow(clamp(1.0 - dLight * 0.22 + h * 0.35, 0.0, 1.0), 3.5) * 0.20;

        if (u_is_light > 0.5) {
          // Apple Light Studio: Refined liquid crystal with soft silver-titanium shadows
          vec3 baseLight = vec3(0.95, 0.965, 0.98);
          vec3 liquidShadow = vec3(0.80, 0.84, 0.90);
          float depthFactor = clamp(h * 0.55 + 0.5, 0.0, 1.0);
          vec3 fluidBody = mix(liquidShadow, baseLight, depthFactor);

          // Refractive valleys & edge contours
          fluidBody -= vec3(fresnel * 0.08);

          // Prismatic caustic crests
          float causticAvg = (causticR + causticG + causticB) * 0.3333;
          vec3 caustics = vec3(
            mix(causticAvg, causticR, 0.20),
            mix(causticAvg, causticG, 0.20),
            mix(causticAvg, causticB, 0.20)
          ) * 0.20;

          // Specular glint
          vec3 col = fluidBody + caustics + vec3(spec * 0.16);
          gl_FragColor = vec4(col, 1.0);
        } else {
          // Apple Dark Obsidian: Deep obsidian void with elegant, balanced liquid silver caustics (toned to 8)
          vec3 baseDark = vec3(0.015, 0.018, 0.024);
          vec3 fluidDeep = vec3(0.05, 0.058, 0.070);
          float depthFactor = clamp(h * 0.55 + 0.5, 0.0, 1.0);
          vec3 fluidBody = mix(baseDark, fluidDeep, depthFactor);

          // Liquid silver / platinum caustics (toned to 8)
          float causticAvg = (causticR + causticG + causticB) * 0.3333;
          vec3 caustics = vec3(
            mix(causticAvg, causticR, 0.25),
            mix(causticAvg, causticG, 0.25),
            mix(causticAvg, causticB, 0.25)
          );

          vec3 col = fluidBody + caustics * 0.70 + vec3(fresnel * 0.10) + vec3(spec * 0.22);
          gl_FragColor = vec4(col, 1.0);
        }
      }
    `,


    init() {
      this.canvas = document.getElementById("liquid-canvas");
      if (!this.canvas) return;

      const gl = this.canvas.getContext("webgl", { alpha: false, antialias: true }) ||
                 this.canvas.getContext("experimental-webgl");
      if (!gl) {
        console.warn("WebGL unavailable, falling back to 2D canvas simulation.");
        initLiquidCanvasFallback();
        return;
      }
      this.gl = gl;

      // Compile Shaders & Link Program
      const vs = this.compileShader(gl.VERTEX_SHADER, this.vsSource);
      const fs = this.compileShader(gl.FRAGMENT_SHADER, this.fsSource);
      if (!vs || !fs) return;

      const program = gl.createProgram();
      gl.attachShader(program, vs);
      gl.attachShader(program, fs);
      gl.linkProgram(program);

      if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
        console.error("LiquidGL shader link failed:", gl.getProgramInfoLog(program));
        return;
      }
      this.program = program;
      gl.useProgram(program);

      // Create Fullscreen Quad Buffer
      const positionBuffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
      const quad = new Float32Array([
        -1.0, -1.0,
         1.0, -1.0,
        -1.0,  1.0,
        -1.0,  1.0,
         1.0, -1.0,
         1.0,  1.0,
      ]);
      gl.bufferData(gl.ARRAY_BUFFER, quad, gl.STATIC_DRAW);

      const aPos = gl.getAttribLocation(program, "a_position");
      gl.enableVertexAttribArray(aPos);
      gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

      // Cache Uniform Locations
      this.uniforms = {
        resolution: gl.getUniformLocation(program, "u_resolution"),
        mouse: gl.getUniformLocation(program, "u_mouse"),
        time: gl.getUniformLocation(program, "u_time"),
        isLight: gl.getUniformLocation(program, "u_is_light"),
      };

      this.resize();
      window.addEventListener("resize", () => this.resize());

      // Mouse listener
      window.addEventListener("mousemove", (e) => {
        this.mouse.targetX = e.clientX / window.innerWidth;
        this.mouse.targetY = 1.0 - (e.clientY / window.innerHeight);
      });

      // Start Render Loop
      this.render();

      // Bind Apple 3D Tilt & Specular Light Tracking on Glass Cards
      this.initInteractiveTilt();
    },

    compileShader(type, src) {
      const s = this.gl.createShader(type);
      this.gl.shaderSource(s, src.trim());
      this.gl.compileShader(s);
      if (!this.gl.getShaderParameter(s, this.gl.COMPILE_STATUS)) {
        console.error("Shader compile error:", this.gl.getShaderInfoLog(s));
        this.gl.deleteShader(s);
        return null;
      }
      return s;
    },

    resize() {
      if (!this.canvas || !this.gl) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = window.innerWidth;
      const h = window.innerHeight;
      this.canvas.width = w * dpr;
      this.canvas.height = h * dpr;
      this.gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    },

    updateTheme(isLight) {
      if (!this.gl || !this.program) return;
      this.gl.useProgram(this.program);
      this.gl.uniform1f(this.uniforms.isLight, isLight ? 1.0 : 0.0);
    },

    render() {
      const gl = this.gl;
      if (!gl || !this.program) return;

      // Smooth mouse follow
      this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.045;
      this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.045;

      const elapsed = (performance.now() - this.startTime) * 0.001;

      gl.useProgram(this.program);
      gl.uniform2f(this.uniforms.resolution, this.canvas.width, this.canvas.height);
      gl.uniform2f(this.uniforms.mouse, this.mouse.x, this.mouse.y);
      gl.uniform1f(this.uniforms.time, elapsed);
      gl.uniform1f(this.uniforms.isLight, state.theme === "light" ? 1.0 : 0.0);

      gl.drawArrays(gl.TRIANGLES, 0, 6);

      this.animId = requestAnimationFrame(() => this.render());
    },

    initInteractiveTilt() {
      const targets = document.querySelectorAll(".glass-panel, .kpi-card, header.liquid-nav");
      targets.forEach(el => {
        el.addEventListener("mousemove", (e) => {
          const rect = el.getBoundingClientRect();
          const x = e.clientX - rect.left;
          const y = e.clientY - rect.top;
          const centerX = rect.width / 2;
          const centerY = rect.height / 2;
          const rotateX = ((y - centerY) / centerY) * -3.5;
          const rotateY = ((x - centerX) / centerX) * 3.5;

          el.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateY(-2px)`;
          el.style.setProperty("--mouse-x", `${(x / rect.width) * 100}%`);
          el.style.setProperty("--mouse-y", `${(y / rect.height) * 100}%`);
        });

        el.addEventListener("mouseleave", () => {
          el.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px)`;
        });
      });
    }
  };

  // 2D Canvas Fallback (if WebGL context fails)
  function initLiquidCanvasFallback() {
    const canvas = document.getElementById("liquid-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    window.addEventListener("resize", () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    });

    const particles = [];
    for (let i = 0; i < 20; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.12,
        vy: (Math.random() - 0.5) * 0.12,
        radius: 160 + Math.random() * 200,
        intensity: 0.018 + Math.random() * 0.02,
      });
    }

    let time = 0;
    function renderFallback() {
      time += 0.00375;
      ctx.clearRect(0, 0, width, height);
      const isLight = state.theme === "light";

      particles.forEach((p, idx) => {
        p.x += p.vx + Math.sin(time + idx) * 0.08;
        p.y += p.vy + Math.cos(time + idx * 0.8) * 0.08;

        if (p.x < -p.radius) p.x = width + p.radius;
        if (p.x > width + p.radius) p.x = -p.radius;
        if (p.y < -p.radius) p.y = height + p.radius;
        if (p.y > height + p.radius) p.y = -p.radius;

        const grad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.radius);
        if (isLight) {
          grad.addColorStop(0, `rgba(0, 0, 0, ${p.intensity * 0.35})`);
          grad.addColorStop(1, "rgba(255, 255, 255, 0)");
        } else {
          grad.addColorStop(0, `rgba(255, 255, 255, ${p.intensity})`);
          grad.addColorStop(1, "rgba(0, 0, 0, 0)");
        }
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fill();
      });

      requestAnimationFrame(renderFallback);
    }
    renderFallback();
  }

  // =========================================================================
  // 3. DOM Elements Registry
  // =========================================================================
  const els = {
    tabBtns: document.querySelectorAll(".tab-pill, .tab-btn"),
    tabContents: document.querySelectorAll(".tab-content"),
    btnCurrency: document.getElementById("btn-currency"),
    btnTheme: document.getElementById("btn-theme"),
    btnExport: document.getElementById("btn-export"),

    // Executive Elements
    kpiEal: document.getElementById("kpi-eal"),
    kpiVar90: document.getElementById("kpi-var90"),
    kpiVar95: document.getElementById("kpi-var95"),
    kpiVar99: document.getElementById("kpi-var99"),
    kpiCompliance: document.getElementById("kpi-compliance"),
    chartLEC: document.getElementById("chart-lec"),
    chartTrajectory: document.getElementById("chart-trajectory"),
    sliderBudget: document.getElementById("slider-budget"),
    budgetDisplay: document.getElementById("budget-display"),
    optSpend: document.getElementById("opt-spend"),
    optReduction: document.getElementById("opt-reduction"),
    optResidual: document.getElementById("opt-residual"),
    optRosi: document.getElementById("opt-rosi"),
    chartFrontier: document.getElementById("chart-frontier"),
    nlqInput: document.getElementById("nlq-input"),
    btnNlq: document.getElementById("btn-nlq"),
    nlqResult: document.getElementById("nlq-result"),

    // Technical Elements
    cntVuln: document.getElementById("cnt-vuln"),
    cntSiem: document.getElementById("cnt-siem"),
    cntIam: document.getElementById("cnt-iam"),
    cntEdr: document.getElementById("cnt-edr"),
    cntCspm: document.getElementById("cnt-cspm"),
    tableBacklog: document.getElementById("table-backlog"),
    heatmapGrid: document.getElementById("heatmap-grid"),

    // What-If Simulator Elements
    whatIfToggles: document.getElementById("what-if-toggles"),
    sliderDelay: document.getElementById("slider-delay"),
    delayDisplay: document.getElementById("delay-display"),
    wiDelta: document.getElementById("wi-delta"),
    wiSimEal: document.getElementById("wi-simeal"),
    wiPenalty: document.getElementById("wi-penalty"),

    // Live SOC Telemetry Ticker & Attack Alert Banner
    socTickerBanner: document.getElementById("soc-ticker-banner"),
    tickerEps: document.getElementById("ticker-eps"),
    tickerTef: document.getElementById("ticker-tef"),
    tickerAlerts: document.getElementById("ticker-alerts"),
    tickerPostureQuick: document.getElementById("ticker-posture-quick"),
    tickerStatus: document.getElementById("ticker-status"),
    tickerLastSync: document.getElementById("ticker-last-sync"),
    attackAlertBanner: document.getElementById("attack-alert-banner"),
    aabTimestamp: document.getElementById("aab-timestamp"),
    aabTitle: document.getElementById("aab-title"),
    aabVector: document.getElementById("aab-vector"),
    aabTarget: document.getElementById("aab-target"),
    aabTefSpike: document.getElementById("aab-tef-spike"),
    aabLossSurge: document.getElementById("aab-loss-surge"),
    aabCountermeasureText: document.getElementById("aab-countermeasure-text"),
    btnAlertMitigate: document.getElementById("btn-alert-mitigate"),
    btnAlertReset: document.getElementById("btn-alert-reset"),
    btnAlertDismiss: document.getElementById("btn-alert-dismiss"),

    // Live Jury Demo Dials & Metrics
    demoPostureBadge: document.getElementById("demo-posture-badge"),
    postureMeterBar: document.getElementById("posture-meter-bar"),
    demoPostureVal: document.getElementById("demo-posture-val"),
    demoPostureSubtext: document.getElementById("demo-posture-subtext"),
    demoRiskBadge: document.getElementById("demo-risk-badge"),
    demoRfVal: document.getElementById("demo-rf-val"),
    demoRfIndicator: document.getElementById("demo-rf-indicator"),
    demoRfSubtext: document.getElementById("demo-rf-subtext"),
    demoSupBadge: document.getElementById("demo-sup-badge"),
    demoSupVal: document.getElementById("demo-sup-val"),
    demoSupDetail: document.getElementById("demo-sup-detail"),
    demoEalBadge: document.getElementById("demo-eal-badge"),
    demoEalVal: document.getElementById("demo-eal-val"),
    demoEalDelta: document.getElementById("demo-eal-delta"),
    demoEalSubtext: document.getElementById("demo-eal-subtext"),
    demoShieldsBadge: document.getElementById("demo-shields-badge"),
    demoShieldsVal: document.getElementById("demo-shields-val"),
    demoVendorsFunded: document.getElementById("demo-vendors-funded"),

    // BharatCart Multi-Laptop Attack Simulator Elements
    btnResetDemo: document.getElementById("btn-reset-demo"),
    demoTargetNode: document.getElementById("demo-target-node"),
    attackBtns: document.querySelectorAll(".attack-btn"),
    curlCommandDisplay: document.getElementById("curl-command-display"),
    btnCopyCurl: document.getElementById("btn-copy-curl"),
    demoTerminalFeed: document.getElementById("demo-terminal-feed"),

    // CEO Vendor Matrix & Spend Summary Elements
    vssTotalSpend: document.getElementById("vss-total-spend"),
    vssCount: document.getElementById("vss-count"),
    vssCapitalSaved: document.getElementById("vss-capital-saved"),
    vendorBenchmarkCards: document.getElementById("vendor-benchmark-cards"),

    // Future Threat Immunity Modal Elements
    modalThreatImmunity: document.getElementById("modal-threat-immunity"),
    modalVendorName: document.getElementById("modal-vendor-name"),
    modalVendorDesc: document.getElementById("modal-vendor-desc"),
    modalShieldsGrid: document.getElementById("modal-shields-grid"),
    btnModalProcure: document.getElementById("btn-modal-procure"),
    btnCloseModal: document.getElementById("btn-close-modal"),
    btnModalCloseBottom: document.getElementById("btn-modal-close-bottom"),

    // AI Copilot Drawer Elements
    copilotDrawer: document.getElementById("copilot-drawer"),
    copilotBackdrop: document.getElementById("copilot-backdrop"),
    btnOpenCopilot: document.getElementById("btn-open-copilot"),
    fabOpenCopilot: document.getElementById("fab-open-copilot"),
    btnCloseCopilot: document.getElementById("btn-close-copilot"),
    copilotForm: document.getElementById("copilot-form"),
    copilotInput: document.getElementById("copilot-input"),
    copilotChatStream: document.getElementById("copilot-chat-stream"),
  };

  // Switch Active View Tab
  function setTab(tabName) {
    state.activeTab = tabName;
    els.tabBtns.forEach(b => {
      const target = b.dataset.tab;
      b.classList.toggle("active", target === tabName);
    });
    els.tabContents.forEach(c => {
      c.classList.toggle("active", c.id === `tab-${tabName}`);
    });
  }

  // Toggle Theme (Dark / Light)
  function toggleTheme() {
    state.theme = state.theme === "dark" ? "light" : "dark";
    localStorage.setItem("crq_theme", state.theme);
    document.documentElement.setAttribute("data-theme", state.theme);

    if (els.btnTheme) {
      els.btnTheme.innerHTML = state.theme === "dark"
        ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg> Dark`
        : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg> Light`;
    }

    LiquidGLEngine.updateTheme(state.theme === "light");
    renderLEC();
    renderTrajectory();
    updateOptimization();
  }

  // Toggle Currency (INR / USD)
  function toggleCurrency() {
    state.currency = state.currency === "INR" ? "USD" : "INR";
    if (els.btnCurrency) {
      els.btnCurrency.innerHTML = state.currency === "INR"
        ? `<span style="font-size:0.9rem;">₹</span> INR`
        : `<span style="font-size:0.9rem;">$</span> USD`;
    }
    updateAllViews();
    if (typeof fetchVendorCatalog === "function") {
      fetchVendorCatalog();
    }
  }

  // =========================================================================
  // 4. Apple Liquid Glass Monochrome SVG Visualizations
  // =========================================================================

  function getThemeColors() {
    const isPrinting = document.body.classList.contains("printing") || (window.matchMedia && window.matchMedia("print").matches);
    const isLight = state.theme === "light" || isPrinting;
    return {
      isLight: isLight,
      curveColor: isLight ? "#09090b" : "#ffffff",
      glowAttr: isLight ? "" : 'filter="url(#liquidGlow)"',
      gridColor: isLight ? "rgba(0, 0, 0, 0.12)" : "rgba(255, 255, 255, 0.16)",
      gridSubtle: isLight ? "rgba(0, 0, 0, 0.06)" : "rgba(255, 255, 255, 0.08)",
      textColor: isLight ? "#18181b" : "#f4f4f6",
      nodeRingFill: isLight ? "rgba(0, 0, 0, 0.08)" : "rgba(255, 255, 255, 0.16)",
      nodeRingStroke: isLight ? "rgba(0, 0, 0, 0.40)" : "rgba(255, 255, 255, 0.60)",
      nodeFill: isLight ? "#09090b" : "#ffffff",
      nodeStroke: isLight ? "#ffffff" : "#000000",
      frontierCurve: isLight ? "#18181b" : "#f4f4f6",
    };
  }

  /**
   * Render Loss Exceedance Curve (LEC)
   */
  function renderLEC() {
    if (!els.chartLEC) return;
    const width = 500;
    const height = 230;
    const padX = 45;
    const padY = 30;
    const maxLoss = defaultData.var99Inr;
    const c = getThemeColors();

    const points = [
      { p: 0.10, loss: 15000000.0, label: "P10" },
      { p: 0.25, loss: 28000000.0, label: "P25" },
      { p: 0.50, loss: defaultData.totalEalInr, label: "Median" },
      { p: 0.75, loss: 76000000.0, label: "P75" },
      { p: 0.90, loss: defaultData.var90Inr, label: "VaR 90%" },
      { p: 0.95, loss: defaultData.var95Inr, label: "VaR 95%" },
      { p: 0.99, loss: defaultData.var99Inr, label: "VaR 99%" },
    ];

    let pathD = "";
    const coords = [];

    points.forEach((pt, i) => {
      const x = padX + (pt.p) * (width - 2 * padX);
      const y = height - padY - (pt.loss / maxLoss) * (height - 2 * padY);
      coords.push({ x, y, ...pt });
      pathD += (i === 0 ? "M " : "L ") + `${x.toFixed(1)} ${y.toFixed(1)} `;
    });

    const first = coords[0];
    const last = coords[coords.length - 1];
    const areaD = pathD + `L ${last.x.toFixed(1)} ${(height - padY).toFixed(1)} L ${first.x.toFixed(1)} ${(height - padY).toFixed(1)} Z`;

    let dotsSvg = "";
    coords.forEach(pt => {
      dotsSvg += `
        <g class="lec-node" style="cursor:pointer;" data-tooltip="${pt.label} (${(pt.p * 100).toFixed(0)}%): ${formatMoney(pt.loss)} • Exceedance Loss">
          <circle cx="${pt.x}" cy="${pt.y}" r="8" fill="${c.nodeRingFill}" stroke="${c.nodeRingStroke}" stroke-width="1"/>
          <circle cx="${pt.x}" cy="${pt.y}" r="4" fill="${c.nodeFill}" stroke="${c.nodeStroke}" stroke-width="1.5"/>
        </g>
      `;
    });

    const gradOpacity = c.isLight ? 0.08 : 0.22;

    els.chartLEC.innerHTML = `
      <svg viewBox="0 0 ${width} ${height}" style="width:100%; height:100%; overflow:visible;">
        <defs>
          <linearGradient id="lecGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="${c.curveColor}" stop-opacity="${gradOpacity}" />
            <stop offset="100%" stop-color="${c.curveColor}" stop-opacity="0" />
          </linearGradient>
          <filter id="liquidGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        <line x1="${padX}" y1="${height - padY}" x2="${width - padX}" y2="${height - padY}" stroke="${c.gridColor}" stroke-width="1"/>
        <line x1="${padX}" y1="${padY}" x2="${padX}" y2="${height - padY}" stroke="${c.gridColor}" stroke-width="1"/>
        <line x1="${padX}" y1="${padY + (height - 2 * padY) * 0.5}" x2="${width - padX}" y2="${padY + (height - 2 * padY) * 0.5}" stroke="${c.gridSubtle}" stroke-dasharray="3,3"/>
        <line x1="${padX + (width - 2 * padX) * 0.5}" y1="${padY}" x2="${padX + (width - 2 * padX) * 0.5}" y2="${height - padY}" stroke="${c.gridSubtle}" stroke-dasharray="3,3"/>

        <text x="${padX + (width - 2 * padX) * 0.5}" y="${height - 8}" fill="${c.textColor}" font-size="10" font-weight="600" text-anchor="middle">Exceedance Probability</text>
        <text x="14" y="${padY + (height - 2 * padY) * 0.5}" fill="${c.textColor}" font-size="10" font-weight="600" text-anchor="middle" dominant-baseline="central" transform="rotate(-90 14 ${padY + (height - 2 * padY) * 0.5})">Loss Exposure</text>

        <path d="${areaD}" fill="url(#lecGradient)" />
        <path d="${pathD}" fill="none" stroke="${c.curveColor}" stroke-width="2.5" ${c.glowAttr} stroke-linecap="round" stroke-linejoin="round"/>

        ${dotsSvg}
      </svg>
    `;
  }

  /**
   * Render 90-Day Predictive Threat Trajectory Chart
   */
  function renderTrajectory() {
    if (!els.chartTrajectory) return;
    const width = 500;
    const height = 230;
    const padX = 45;
    const padY = 30;
    const eal = defaultData.totalEalInr;
    const c = getThemeColors();

    const days = [
      { d: "Today", val: eal, high: eal * 1.02, low: eal * 0.98 },
      { d: "+30d", val: eal * 1.07, high: eal * 1.12, low: eal * 1.02 },
      { d: "+60d", val: eal * 1.16, high: eal * 1.24, low: eal * 1.09 },
      { d: "+90d", val: eal * 1.29, high: eal * 1.42, low: eal * 1.18 },
    ];
    const maxVal = eal * 1.45;

    let pathD = "";
    let coneUpper = "";
    let coneLower = "";
    let nodesSvg = "";

    days.forEach((pt, i) => {
      const x = padX + (i / (days.length - 1)) * (width - 2 * padX);
      const y = height - padY - (pt.val / maxVal) * (height - 2 * padY);
      const yHigh = height - padY - (pt.high / maxVal) * (height - 2 * padY);
      const yLow = height - padY - (pt.low / maxVal) * (height - 2 * padY);

      pathD += (i === 0 ? "M " : "L ") + `${x.toFixed(1)} ${y.toFixed(1)} `;
      coneUpper += (i === 0 ? "M " : "L ") + `${x.toFixed(1)} ${yHigh.toFixed(1)} `;
      coneLower = `L ${x.toFixed(1)} ${yLow.toFixed(1)} ` + coneLower;

      nodesSvg += `
        <g class="trajectory-node" style="cursor:pointer;" data-tooltip="${pt.d} Forecast: ${formatMoney(pt.val)} • Compounding Threat Aging">
          <circle cx="${x}" cy="${y}" r="8" fill="${c.nodeRingFill}" stroke="${c.nodeRingStroke}" stroke-width="1"/>
          <circle cx="${x}" cy="${y}" r="4" fill="${c.nodeFill}" stroke="${c.nodeStroke}" stroke-width="1.5"/>
          <text x="${x}" y="${height - 10}" fill="${c.textColor}" font-size="10" font-weight="600" text-anchor="middle">${pt.d}</text>
        </g>
      `;
    });

    const coneD = coneUpper + coneLower + " Z";
    const coneStartOpacity = c.isLight ? 0.02 : 0.04;
    const coneEndOpacity = c.isLight ? 0.08 : 0.16;

    els.chartTrajectory.innerHTML = `
      <svg viewBox="0 0 ${width} ${height}" style="width:100%; height:100%; overflow:visible;">
        <defs>
          <linearGradient id="coneGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="${c.curveColor}" stop-opacity="${coneStartOpacity}" />
            <stop offset="100%" stop-color="${c.curveColor}" stop-opacity="${coneEndOpacity}" />
          </linearGradient>
        </defs>

        <line x1="${padX}" y1="${height - padY}" x2="${width - padX}" y2="${height - padY}" stroke="${c.gridColor}" stroke-width="1"/>
        <line x1="${padX}" y1="${padY}" x2="${padX}" y2="${height - padY}" stroke="${c.gridColor}" stroke-width="1"/>
        <line x1="${padX}" y1="${padY + (height - 2 * padY) * 0.5}" x2="${width - padX}" y2="${padY + (height - 2 * padY) * 0.5}" stroke="${c.gridSubtle}" stroke-dasharray="3,3"/>
        <text x="14" y="${padY + (height - 2 * padY) * 0.5}" fill="${c.textColor}" font-size="10" font-weight="600" text-anchor="middle" dominant-baseline="central" transform="rotate(-90 14 ${padY + (height - 2 * padY) * 0.5})">Loss Trajectory</text>

        <path d="${coneD}" fill="url(#coneGrad)" />
        <path d="${pathD}" fill="none" stroke="${c.curveColor}" stroke-width="2.5" stroke-dasharray="6,3" ${c.glowAttr} stroke-linecap="round"/>

        ${nodesSvg}
      </svg>
    `;
  }

  /**
   * Render Pareto Frontier Chart (True Convex Knapsack Frontier)
   */
  function renderFrontier(spend, mitigated) {
    if (!els.chartFrontier) return;
    const width = 480;
    const height = 180;
    const padX = 48;
    const padY = 25;
    const maxB = 10000000.0; // ₹1 Cr
    const maxR = 45000000.0; // ₹4.5 Cr
    const c = getThemeColors();

    // 1. Build the true Pareto efficient frontier milestones from the sorted controls
    const sorted = [...defaultData.controls].sort((a, b) => (b.eff / b.costInr) - (a.eff / a.costInr));
    const milestones = [{ s: 0.0, r: 0.0 }];
    let accS = 0.0;
    let accM = 0.0;
    sorted.forEach(ctrl => {
      accS += ctrl.costInr;
      accM += (defaultData.totalEalInr * 0.28) * ctrl.eff;
      milestones.push({ s: accS, r: Math.min(accM, defaultData.totalEalInr * 0.85) });
    });
    // Add plateau extension to maxB
    const maxMitigated = milestones[milestones.length - 1].r;
    milestones.push({ s: maxB, r: maxMitigated });

    // 2. Map milestones to screen coordinates
    const coords = milestones.map(m => ({
      x: padX + (Math.min(m.s, maxB) / maxB) * (width - 2 * padX),
      y: height - padY - (Math.min(m.r, maxR) / maxR) * (height - 2 * padY)
    }));

    // 3. Create smooth Catmull-Rom cubic bezier curve passing EXACTLY through every milestone
    let pathD = `M ${coords[0].x.toFixed(1)} ${coords[0].y.toFixed(1)}`;
    for (let i = 0; i < coords.length - 1; i++) {
      const p0 = coords[Math.max(i - 1, 0)];
      const p1 = coords[i];
      const p2 = coords[i + 1];
      const p3 = coords[Math.min(i + 2, coords.length - 1)];

      const cp1x = p1.x + (p2.x - p0.x) / 6;
      const cp1y = p1.y + (p2.y - p0.y) / 6;
      const cp2x = p2.x - (p3.x - p1.x) / 6;
      const cp2y = p2.y - (p3.y - p1.y) / 6;

      pathD += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
    }

    const first = coords[0];
    const last = coords[coords.length - 1];
    const areaD = pathD + ` L ${last.x.toFixed(1)} ${(height - padY).toFixed(1)} L ${first.x.toFixed(1)} ${(height - padY).toFixed(1)} Z`;

    const curX = padX + (Math.min(spend, maxB) / maxB) * (width - 2 * padX);
    const curY = height - padY - (Math.min(mitigated, maxR) / maxR) * (height - 2 * padY);
    const frontierGradOpacity = c.isLight ? 0.07 : 0.15;

    els.chartFrontier.innerHTML = `
      <svg viewBox="0 0 ${width} ${height}" style="width:100%; height:100%; overflow:visible;">
        <defs>
          <linearGradient id="frontierGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="${c.curveColor}" stop-opacity="${frontierGradOpacity}" />
            <stop offset="100%" stop-color="${c.curveColor}" stop-opacity="0" />
          </linearGradient>
        </defs>

        <line x1="${padX}" y1="${height - padY}" x2="${width - padX}" y2="${height - padY}" stroke="${c.gridColor}" stroke-width="1"/>
        <line x1="${padX}" y1="${padY}" x2="${padX}" y2="${height - padY}" stroke="${c.gridColor}" stroke-width="1"/>

        <path d="${areaD}" fill="url(#frontierGrad)" />
        <path d="${pathD}" fill="none" stroke="${c.frontierCurve}" stroke-width="2" stroke-linecap="round"/>

        <g class="frontier-node" style="cursor:pointer;" data-tooltip="Spend: ${formatMoney(spend)} • Risk Reduced: ${formatMoney(mitigated)}">
          <circle cx="${curX}" cy="${curY}" r="12" fill="${c.nodeRingFill}" stroke="${c.nodeRingStroke}" stroke-width="1"/>
          <circle cx="${curX}" cy="${curY}" r="5" fill="${c.nodeFill}" stroke="${c.nodeStroke}" stroke-width="1.5">
            <animate attributeName="r" values="4.5;6;4.5" dur="2.2s" repeatCount="indefinite"/>
          </circle>
        </g>

        <text x="${padX + (width - 2 * padX) * 0.5}" y="${height - 6}" fill="${c.textColor}" font-size="10" font-weight="600" text-anchor="middle">Capital Allocation</text>
        <text x="14" y="${padY + (height - 2 * padY) * 0.5}" fill="${c.textColor}" font-size="10" font-weight="600" text-anchor="middle" dominant-baseline="central" transform="rotate(-90 14 ${padY + (height - 2 * padY) * 0.5})">Mitigated Risk</text>
      </svg>
    `;
  }


  // =========================================================================
  // 5. Optimization Slider Calculations (SciPy HiGHS Solver Sync)
  // =========================================================================
  function updateOptimization() {
    if (!els.sliderBudget) return;
    const budget = parseFloat(els.sliderBudget.value);
    state.budget = budget;

    let spend = 0.0;
    let mitigated = 0.0;
    const sorted = [...defaultData.controls].sort((a, b) => (b.eff / b.costInr) - (a.eff / a.costInr));

    sorted.forEach(c => {
      if (spend + c.costInr <= budget) {
        spend += c.costInr;
        mitigated += (defaultData.totalEalInr * 0.28) * c.eff;
      }
    });

    mitigated = Math.min(mitigated, defaultData.totalEalInr * 0.85);
    const residual = Math.max(0.0, defaultData.totalEalInr - mitigated);
    const rosi = spend > 0 ? (((mitigated - spend) / spend) * 100.0) : 0.0;

    const totalControlCost = 3100000.0; // ₹31.0 Lakhs ($37.1K)
    if (els.budgetDisplay) {
      if (budget > totalControlCost) {
        const surplus = budget - spend;
        els.budgetDisplay.innerHTML = `${formatMoney(budget)} <span style="font-size:0.72rem; font-weight:600; margin-left:6px; color:var(--text-muted);">(Surplus: ${formatMoney(surplus)} • 100% Funded)</span>`;
      } else {
        els.budgetDisplay.textContent = formatMoney(budget);
      }
    }

    if (els.optSpend) els.optSpend.textContent = formatMoney(spend);
    if (els.optReduction) els.optReduction.textContent = formatMoney(mitigated);
    if (els.optResidual) els.optResidual.textContent = formatMoney(residual);
    if (els.optRosi) els.optRosi.textContent = `${rosi.toFixed(1)}%`;

    renderFrontier(spend, mitigated);
  }

  // =========================================================================
  // 6. What-If Counterfactual & Delay Cost Simulator
  // =========================================================================
  function updateWhatIf() {
    if (els.delayDisplay) els.delayDisplay.textContent = `${state.delayDays} Days`;

    let mitigated = 0.0;
    state.whatIfControls.forEach(cid => {
      const c = defaultData.controls.find(x => x.id === cid);
      if (c) {
        mitigated += (defaultData.totalEalInr * 0.25) * c.eff;
      }
    });
    mitigated = Math.min(mitigated, defaultData.totalEalInr * 0.85);

    const delayPenalty = defaultData.totalEalInr * (0.005 * state.delayDays + 0.0001 * Math.pow(state.delayDays, 1.5));
    const simEal = Math.max(0.0, defaultData.totalEalInr - mitigated + delayPenalty);

    if (els.wiDelta) els.wiDelta.textContent = formatMoney(mitigated);
    if (els.wiSimEal) els.wiSimEal.textContent = formatMoney(simEal);
    if (els.wiPenalty) els.wiPenalty.textContent = formatMoney(delayPenalty);
  }

  function initWhatIfToggles() {
    if (!els.whatIfToggles) return;
    els.whatIfToggles.innerHTML = "";

    const list = document.createElement("div");
    list.className = "whatif-control-list";

    defaultData.controls.forEach(c => {
      const row = document.createElement("div");
      row.className = "whatif-row";

      const left = document.createElement("div");
      left.className = "whatif-label-group";

      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "glass-checkbox";
      cb.checked = state.whatIfControls.has(c.id);
      cb.id = `wi-${c.id}`;

      cb.addEventListener("change", (e) => {
        if (e.target.checked) state.whatIfControls.add(c.id);
        else state.whatIfControls.delete(c.id);
        updateWhatIf();
      });

      const label = document.createElement("label");
      label.htmlFor = `wi-${c.id}`;
      label.textContent = c.name;
      label.style.cursor = "pointer";

      left.appendChild(cb);
      left.appendChild(label);

      const right = document.createElement("span");
      right.className = "whatif-cost";
      right.textContent = formatMoney(c.costInr);

      row.appendChild(left);
      row.appendChild(right);
      list.appendChild(row);
    });

    els.whatIfToggles.appendChild(list);
  }

  // =========================================================================
  // 7. Regulatory Framework Matrix & Technical Backlog
  // =========================================================================
  function renderCompliance() {
    if (!els.heatmapGrid) return;
    els.heatmapGrid.innerHTML = "";

    Object.entries(defaultData.frameworks).forEach(([key, fw]) => {
      const card = document.createElement("div");
      card.className = "framework-card";
      card.innerHTML = `
        <div class="fw-title">${fw.name}</div>
        <div style="display:flex; justify-content:space-between; font-size:0.78rem; color:var(--text-secondary); margin-bottom:0.25rem;">
          <span>Compliance Score</span>
          <strong style="color:var(--text-heading); font-weight:800;">${fw.score}%</strong>
        </div>
        <div class="progress-bar-bg">
          <div class="progress-bar-fill" style="width:${fw.score}%"></div>
        </div>
        <div style="font-size:0.72rem; color:var(--text-muted); display:flex; justify-content:space-between; margin-top:0.35rem;">
          <span>Passing: ${fw.passing} / ${fw.total} controls</span>
          <span>Deficiency Gap: ${fw.total - fw.passing}</span>
        </div>
      `;
      els.heatmapGrid.appendChild(card);
    });
  }

  function renderBacklog() {
    if (!els.tableBacklog) return;
    els.tableBacklog.innerHTML = "";

    defaultData.findings.forEach(f => {
      const tr = document.createElement("tr");
      const sevBadge = f.sev === "CRITICAL" ? "badge-crit" : "badge-high";
      tr.innerHTML = `
        <td><strong>${f.id}</strong></td>
        <td>${f.asset}</td>
        <td><span class="kpi-badge badge-med">${f.domain}</span></td>
        <td><span class="kpi-badge ${sevBadge}">${f.sev}</span></td>
        <td><strong>${f.cvss}</strong></td>
        <td><strong>${formatMoney(f.lossInr)}</strong></td>
        <td><code>${f.ctrl}</code></td>
      `;
      els.tableBacklog.appendChild(tr);
    });
  }

  // =========================================================================
  // 8. AI Decision Support & Natural Language Query (NLQ)
  // =========================================================================
  async function runNLQ() {
    if (!els.nlqInput || !els.nlqResult) return;
    const query = els.nlqInput.value.trim();
    if (!query) return;

    els.nlqResult.innerHTML = `<span style="color:var(--text-muted)">Querying continuous risk quantification models and analyzing telemetry graphs...</span>`;

    try {
      const resp = await fetch("/api/v1/decision/nlq", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query, currency: state.currency })
      });
      if (resp.ok) {
        const data = await resp.json();
        els.nlqResult.innerHTML = `
          <div style="margin-bottom:0.45rem;"><strong>Intent Detected:</strong> <span class="nlq-highlight">${data.intent}</span> (Confidence: ${(data.confidence * 100).toFixed(0)}%)</div>
          <div>${data.narrative_answer}</div>
        `;
        return;
      }
    } catch (e) {
      // Offline fallback
    }

    const qLower = query.toLowerCase();
    let text = "";
    if (qLower.includes("high") || qLower.includes("risk") || qLower.includes("loss")) {
      text = `Our highest financial cyber exposure resides in <strong>Core Banking PostgreSQL Primary (asset-core-db-01)</strong>, contributing <strong>${formatMoney(18500000.0)}</strong> in Expected Annual Loss due to critical vulnerability CVE-2023-34362. Prioritized patch deployment is urgently advised.`;
    } else if (qLower.includes("budget") || qLower.includes("allocat") || qLower.includes("spend")) {
      text = `For an allocated capital budget, funding <strong>Hardware MFA (CTRL-MFA)</strong> and <strong>Automated Vulnerability Patching (CTRL-PATCH)</strong> yields the highest risk reduction, delivering a <strong>222.2% Portfolio ROSI</strong>.`;
    } else if (qLower.includes("delay") || qLower.includes("postpone") || qLower.includes("cost")) {
      text = `Delaying remediation by 30 days incurs an estimated <strong>${formatMoney(defaultData.totalEalInr * 0.16)}</strong> in additional compounding risk exposure due to exploit weaponization velocity.`;
    } else {
      text = `Enterprise annualized financial cyber exposure stands at <strong>${formatMoney(defaultData.totalEalInr)}</strong> with 90% Value-at-Risk of <strong>${formatMoney(defaultData.var90Inr)}</strong>. Remediating critical findings across Core Banking and Cloud IAM provides immediate risk containment.`;
    }

    els.nlqResult.innerHTML = `
      <div style="margin-bottom:0.45rem;"><strong>Intent Detected:</strong> <span class="nlq-highlight">AI_RISK_INSIGHT</span> (Confidence: 96%)</div>
      <div>${text}</div>
    `;
  }

  // =========================================================================
  // 9. Master State Updater
  // =========================================================================
  function updateAllViews() {
    const currentEal = state.demoStats ? state.demoStats.ealInr : defaultData.totalEalInr;
    if (els.kpiEal) els.kpiEal.textContent = formatMoney(currentEal);
    if (els.kpiVar90) els.kpiVar90.textContent = formatMoney(defaultData.var90Inr);
    if (els.kpiVar95) els.kpiVar95.textContent = formatMoney(defaultData.var95Inr);
    if (els.kpiVar99) els.kpiVar99.textContent = formatMoney(defaultData.var99Inr);
    if (els.kpiCompliance) els.kpiCompliance.textContent = `${defaultData.compliancePct}%`;

    renderLEC();
    renderTrajectory();
    updateOptimization();
    updateWhatIf();
    initWhatIfToggles();
    renderCompliance();
    renderBacklog();
    updateDemoViews();
  }

  // =========================================================================
  // 9.5 Live Jury Demo, BharatCart Simulator & CEO Vendor Procurement (R1-R5)
  // =========================================================================

  // Update Dynamic Posture Dial SVG
  function updatePostureDial(score) {
    const clamped = Math.max(0, Math.min(100, score));
    if (state.demoStats) state.demoStats.posture = clamped;
    if (els.demoPostureVal) {
      els.demoPostureVal.textContent = clamped.toFixed(1);
    }
    if (els.postureMeterBar) {
      const circ = 2 * Math.PI * 50; // 314.159
      const offset = circ - (clamped / 100.0) * circ;
      els.postureMeterBar.style.strokeDashoffset = offset;
      if (clamped >= 80) {
        els.postureMeterBar.style.stroke = "#22c55e";
      } else if (clamped >= 60) {
        els.postureMeterBar.style.stroke = "#eab308";
      } else {
        els.postureMeterBar.style.stroke = "#ef4444";
      }
    }
    if (els.demoPostureBadge) {
      if (clamped >= 88) {
        els.demoPostureBadge.textContent = "Maximum Defense";
        els.demoPostureBadge.className = "kpi-badge badge-spec";
      } else if (clamped >= 75) {
        els.demoPostureBadge.textContent = "Resilient";
        els.demoPostureBadge.className = "kpi-badge badge-high";
      } else if (clamped >= 60) {
        els.demoPostureBadge.textContent = "Degraded";
        els.demoPostureBadge.className = "kpi-badge badge-med";
      } else {
        els.demoPostureBadge.textContent = "Critical Exposure";
        els.demoPostureBadge.className = "kpi-badge badge-crit";
      }
    }
  }

  // Update Dynamic Risk Factor Gauge (0.0 to 10.0)
  function updateRiskFactorGauge(rf) {
    const clamped = Math.max(0.0, Math.min(10.0, rf));
    if (state.demoStats) state.demoStats.riskFactor = clamped;
    if (els.demoRfVal) {
      els.demoRfVal.textContent = clamped.toFixed(1);
    }
    if (els.demoRfIndicator) {
      const pct = (clamped / 10.0) * 100;
      els.demoRfIndicator.style.width = `${pct}%`;
    }
    if (els.demoRiskBadge) {
      if (clamped < 3.0) {
        els.demoRiskBadge.textContent = `Low (${clamped.toFixed(1)})`;
        els.demoRiskBadge.className = "kpi-badge badge-med";
      } else if (clamped < 6.0) {
        els.demoRiskBadge.textContent = `Moderate (${clamped.toFixed(1)})`;
        els.demoRiskBadge.className = "kpi-badge badge-high";
      } else if (clamped < 8.0) {
        els.demoRiskBadge.textContent = `Elevated (${clamped.toFixed(1)})`;
        els.demoRiskBadge.className = "kpi-badge badge-high";
      } else {
        els.demoRiskBadge.textContent = `Critical (${clamped.toFixed(1)})`;
        els.demoRiskBadge.className = "kpi-badge badge-crit";
      }
    }
  }

  // Update Security Upgrade Percentage (SUP %)
  function updateSecurityUpgradePct(supPct, mitigatedInr, baselineEalInr) {
    if (state.demoStats) {
      state.demoStats.supPct = supPct;
      state.demoStats.riskMitigatedInr = mitigatedInr;
      state.demoStats.baselineEalInr = baselineEalInr;
    }

    if (els.demoSupVal) {
      els.demoSupVal.textContent = supPct > 0 ? `+${supPct.toFixed(1)}%` : `0.0%`;
    }
    if (els.demoSupBadge) {
      if (supPct > 0) {
        els.demoSupBadge.textContent = `+${supPct.toFixed(1)}% Gain`;
        els.demoSupBadge.className = "kpi-badge badge-crit";
      } else {
        els.demoSupBadge.textContent = "Baseline State";
        els.demoSupBadge.className = "kpi-badge badge-med";
      }
    }
    if (els.demoSupDetail) {
      if (supPct > 0) {
        els.demoSupDetail.textContent = `Mitigated ${formatMoney(mitigatedInr)} of ${formatMoney(baselineEalInr)} Baseline`;
      } else {
        els.demoSupDetail.textContent = "Invest in vendors below to unlock defense upgrade";
      }
    }
  }

  // Update Dynamic Loss Exposure (Live EAL)
  function updateDynamicEal(currentEalInr, baselineEalInr, isAttack) {
    if (state.demoStats) state.demoStats.ealInr = currentEalInr;
    if (els.demoEalVal) {
      els.demoEalVal.textContent = formatMoney(currentEalInr);
    }
    if (els.kpiEal) {
      els.kpiEal.textContent = formatMoney(currentEalInr);
    }
    if (els.demoEalBadge) {
      if (isAttack) {
        els.demoEalBadge.textContent = "ATTACK SURGE";
        els.demoEalBadge.className = "kpi-badge badge-crit";
      } else if (currentEalInr < baselineEalInr) {
        els.demoEalBadge.textContent = "RISK MITIGATED";
        els.demoEalBadge.className = "kpi-badge badge-high";
      } else {
        els.demoEalBadge.textContent = "Nominal State";
        els.demoEalBadge.className = "kpi-badge badge-med";
      }
    }
    if (els.demoEalDelta) {
      if (isAttack) {
        const diff = currentEalInr - baselineEalInr;
        els.demoEalDelta.textContent = `Surge Delta: +${formatMoney(diff)}`;
        els.demoEalDelta.style.color = "#ef4444";
      } else if (currentEalInr < baselineEalInr) {
        const diff = baselineEalInr - currentEalInr;
        els.demoEalDelta.textContent = `Capital Exposure Reduction: -${formatMoney(diff)}`;
        els.demoEalDelta.style.color = "#22c55e";
      } else {
        els.demoEalDelta.textContent = `Baseline: ${formatMoney(baselineEalInr)}`;
        els.demoEalDelta.style.color = "var(--text-muted)";
      }
    }
  }

  // Master Synchronizer for Demo Views
  function updateDemoViews() {
    if (!state.demoStats) return;
    updatePostureDial(state.demoStats.posture);
    updateRiskFactorGauge(state.demoStats.riskFactor);
    updateSecurityUpgradePct(state.demoStats.supPct, state.demoStats.riskMitigatedInr, state.demoStats.baselineEalInr);
    updateDynamicEal(state.demoStats.ealInr, state.demoStats.baselineEalInr, !!state.activeAttack);

    if (els.demoShieldsVal) {
      els.demoShieldsVal.textContent = `${state.demoStats.activeShields} Active`;
    }
    if (els.demoVendorsFunded) {
      els.demoVendorsFunded.textContent = `${state.purchasedVendors.size} Commercial Solutions Funded`;
    }
    if (els.vssTotalSpend) {
      els.vssTotalSpend.textContent = formatMoney(state.demoStats.totalSpendInr);
    }
    if (els.vssCount) {
      els.vssCount.textContent = `${state.purchasedVendors.size} / 5`;
    }
    if (els.vssCapitalSaved) {
      const netSaved = Math.max(0.0, state.demoStats.riskMitigatedInr - state.demoStats.totalSpendInr);
      els.vssCapitalSaved.textContent = formatMoney(netSaved);
    }
  }

  // Append entry to Incident Response Terminal Log
  function appendTerminalLog(text, type = "info") {
    if (!els.demoTerminalFeed) return;
    const now = new Date();
    const timeStr = now.toTimeString().slice(0, 8);
    const line = document.createElement("div");
    line.className = `terminal-line ${type === "attack" ? "attack-event" : type === "mitigation" ? "mitigation-event" : ""}`;
    line.textContent = `[${timeStr}] ${text}`;
    els.demoTerminalFeed.appendChild(line);
    els.demoTerminalFeed.scrollTop = els.demoTerminalFeed.scrollHeight;
  }

  // Update Dynamic cURL Snippet
  function updateCurlCommandSnippet(attackType = null) {
    if (!els.curlCommandDisplay) return;
    const type = attackType || (state.activeAttack || "DDOS_TRAFFIC_SURGE");
    const target = els.demoTargetNode ? els.demoTargetNode.value : "gateway-01";
    const host = window.location.host || "localhost:8000";
    const cmd = `curl -X POST http://${host}/api/v1/demo/inject-attack -H "Content-Type: application/json" -d '{"attack_type":"${type}","target_node":"${target}","source_device":"Jury-Laptop"}'`;
    els.curlCommandDisplay.textContent = cmd;
  }

  // Telemetry Ticker Polling (Every 2.5s for continuous non-hardcoded pulse)
  async function fetchTelemetryTicker() {
    try {
      const resp = await fetch("/api/v1/demo/telemetry-ticker");
      if (!resp.ok) return;
      const data = await resp.json();

      // Ingestion Velocity
      const epsStr = `${Math.round(data.events_per_second).toLocaleString()} events/sec`;
      if (els.tickerEps) els.tickerEps.textContent = epsStr;
      document.querySelectorAll(".ticker-eps-val").forEach(el => el.textContent = epsStr);

      // Threat Event Frequency
      const tefStr = `${data.threat_event_frequency.toFixed(2)} / yr`;
      if (els.tickerTef) els.tickerTef.textContent = tefStr;
      document.querySelectorAll(".ticker-tef-val").forEach(el => el.textContent = tefStr);

      // Active Alerts
      const alertsText = data.active_attack ? `${data.active_alerts_count} Critical Alert` : "0 Critical";
      const alertsClass = data.active_attack ? "tm-value badge-crit" : "tm-value badge-ticker-nominal";
      if (els.tickerAlerts) {
        els.tickerAlerts.textContent = alertsText;
        els.tickerAlerts.className = `${alertsClass} ticker-alerts-val`;
      }
      document.querySelectorAll(".ticker-alerts-val").forEach(el => {
        el.textContent = alertsText;
        el.className = `${alertsClass} ticker-alerts-val`;
      });

      // Quick Posture / Risk in ticker
      const postureStr = `${data.security_posture_score.toFixed(1)}% (RF: ${data.risk_factor_score.toFixed(1)})`;
      if (els.tickerPostureQuick) els.tickerPostureQuick.textContent = postureStr;
      document.querySelectorAll(".ticker-posture-val").forEach(el => el.textContent = postureStr);

      // Infrastructure Status
      if (els.tickerStatus && els.socTickerBanner) {
        if (data.active_attack) {
          const statusText = `CRITICAL ATTACK &bull; ${data.attack_type}`;
          els.tickerStatus.innerHTML = statusText;
          els.tickerStatus.className = "tm-value status-attack ticker-status-val";
          document.querySelectorAll(".ticker-status-val").forEach(el => {
            el.innerHTML = statusText;
            el.className = "tm-value status-attack ticker-status-val";
          });
          els.socTickerBanner.classList.add("attack-alert-active");

          // Keep alert banner visible
          if (els.attackAlertBanner && els.attackAlertBanner.style.display === "none") {
            els.attackAlertBanner.style.display = "flex";
            if (els.aabVector) els.aabVector.textContent = data.attack_type || "UNKNOWN";
            if (els.aabTarget) els.aabTarget.textContent = data.target_node || "gateway-01";
            if (els.aabLossSurge) els.aabLossSurge.textContent = `+₹ 4.58 Cr`;
          }
        } else {
          const statusText = `NOMINAL &bull; 99.98%`;
          els.tickerStatus.innerHTML = statusText;
          els.tickerStatus.className = "tm-value status-nominal ticker-status-val";
          document.querySelectorAll(".ticker-status-val").forEach(el => {
            el.innerHTML = statusText;
            el.className = "tm-value status-nominal ticker-status-val";
          });
          els.socTickerBanner.classList.remove("attack-alert-active");
        }
      }
      // Last Sync Timestamp
      const t = new Date().toISOString().slice(11, 19);
      const syncStr = `LIVE FEED • ${t} UTC • 2.5s HEARTBEAT`;
      if (els.tickerLastSync) els.tickerLastSync.textContent = syncStr;
      document.querySelectorAll(".ticker-last-sync-val").forEach(el => el.textContent = syncStr);

      // Sync active shields if not local override
      if (!state.activeAttack && state.demoStats) {
        state.demoStats.activeShields = data.total_threat_shields_active;
        if (els.demoShieldsVal) {
          els.demoShieldsVal.textContent = `${data.total_threat_shields_active} Active`;
        }
      }

      // Stream dynamic background telemetry events into SOC feed
      if (data.recent_events && Array.isArray(data.recent_events)) {
        state.processedEventKeys = state.processedEventKeys || new Set();
        data.recent_events.forEach(ev => {
          const key = `${ev.time}-${ev.msg}`;
          if (!state.processedEventKeys.has(key)) {
            state.processedEventKeys.add(key);
            const tag = ev.level === "CRITICAL" ? "attack" : (ev.level === "WARN" ? "warn" : "");
            appendTerminalLog(`[${ev.level}] ${ev.msg} (${ev.node || "NODE"})`, tag);
          }
        });
        if (state.processedEventKeys.size > 50) {
          state.processedEventKeys.clear();
        }
      }

      // Live update BharatCart Topology DAG badges
      if (data.nodes && Array.isArray(data.nodes)) {
        data.nodes.forEach(n => {
          const el = document.getElementById(`topo-${n.node}`);
          if (el) {
            const badge = el.querySelector(".topo-badge");
            if (badge) {
              badge.textContent = n.status;
              if (n.status === "ONLINE") {
                badge.style.color = "#22c55e";
                el.style.borderColor = "rgba(255,255,255,0.08)";
              } else {
                badge.style.color = "#ef4444";
                el.style.borderColor = "rgba(239, 68, 68, 0.6)";
              }
            }
          }
        });
      }

      // Live update Executive View KPI cards if present
      if (data.current_eal_inr !== undefined) {
        const elEal = document.getElementById("kpi-eal");
        if (elEal) elEal.textContent = formatMoney(data.current_eal_inr);
      }
      if (data.var_90_inr !== undefined) {
        const elV90 = document.getElementById("kpi-var90");
        if (elV90) elV90.textContent = formatMoney(data.var_90_inr);
      }
      if (data.var_95_inr !== undefined) {
        const elV95 = document.getElementById("kpi-var95");
        if (elV95) elV95.textContent = formatMoney(data.var_95_inr);
      }
      if (data.var_99_inr !== undefined) {
        const elV99 = document.getElementById("kpi-var99");
        if (elV99) elV99.textContent = formatMoney(data.var_99_inr);
      }
      if (data.security_posture_score !== undefined) {
        const elPost = document.getElementById("kpi-compliance");
        if (elPost) elPost.textContent = `${data.security_posture_score.toFixed(1)}%`;
      }

      // If attack state changed remotely from second laptop
      if (data.active_attack && !state.activeAttack) {
        state.activeAttack = data.attack_type;
        if (state.demoStats) {
          state.demoStats.ealInr = data.current_eal_inr;
          state.demoStats.posture = data.security_posture_score;
          state.demoStats.riskFactor = data.risk_factor_score;
        }
        updateDemoViews();
        appendTerminalLog(`[ALERT] REMOTE ATTACK DETECTED: Intrusion [${data.attack_type}] triggered against ${data.target_node}.`, "attack");
      } else if (!data.active_attack && state.activeAttack) {
        state.activeAttack = null;
        if (state.demoStats) {
          state.demoStats.ealInr = data.current_eal_inr;
          state.demoStats.posture = data.security_posture_score;
          state.demoStats.riskFactor = data.risk_factor_score;
        }
        if (els.attackAlertBanner) els.attackAlertBanner.style.display = "none";
        updateDemoViews();
        appendTerminalLog(`[RESOLVED] Attack state cleared remotely. Restored nominal baseline.`, "mitigation");
      }
    } catch (e) {
      // Local fallback ticker fluctuation
      const eps = 14200 + (Math.random() - 0.5) * 1200;
      const epsStr = `${Math.round(eps).toLocaleString()} events/sec`;
      if (els.tickerEps) els.tickerEps.textContent = epsStr;
      document.querySelectorAll(".ticker-eps-val").forEach(el => el.textContent = epsStr);
      const t = new Date().toISOString().slice(11, 19);
      const syncStr = `LIVE FEED • ${t} UTC • 2.5s HEARTBEAT`;
      if (els.tickerLastSync) els.tickerLastSync.textContent = syncStr;
      document.querySelectorAll(".ticker-last-sync-val").forEach(el => el.textContent = syncStr);
    }
  }

  // Inject Simulated Cyber Attack (R3 - Flipkart Demo)
  async function injectAttack(attackType, overrideTargetNode) {
    const targetNode = overrideTargetNode || (els.demoTargetNode ? els.demoTargetNode.value : "gateway-01");
    if (els.demoTargetNode && overrideTargetNode) {
      els.demoTargetNode.value = overrideTargetNode;
    }
    appendTerminalLog(`[TRANSMIT] Transmitting attack payload [${attackType}] targeted at [${targetNode}]...`);

    try {
      const resp = await fetch("/api/v1/demo/inject-attack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attack_type: attackType,
          target_node: targetNode,
          intensity: 5.0,
          source_device: "Jury-Dashboard-UI"
        })
      });

      if (resp.ok) {
        const res = await resp.json();
        state.activeAttack = attackType;
        state.activeAttackData = res;

        // Update stats
        if (state.demoStats) {
          state.demoStats.ealInr = res.spiked_eal_inr;
          state.demoStats.posture = res.posture_after;
          const rfSpike = Math.min(9.8, (res.spiked_eal_inr / res.baseline_eal_inr) * 4.8);
          state.demoStats.riskFactor = rfSpike;
        }

        // Show Attack Alert Banner
        if (els.attackAlertBanner) {
          els.attackAlertBanner.style.display = "flex";
          if (els.aabTimestamp) els.aabTimestamp.textContent = new Date().toTimeString().slice(0, 8);
          if (els.aabVector) els.aabVector.textContent = res.attack_type;
          if (els.aabTarget) els.aabTarget.textContent = res.target_node;
          if (els.aabTefSpike) els.aabTefSpike.textContent = `${res.tef_spike_multiplier}x`;
          if (els.aabLossSurge) els.aabLossSurge.textContent = `+${formatMoney(res.total_surge_inr)}`;
          if (els.aabCountermeasureText) els.aabCountermeasureText.textContent = res.recommended_countermeasure;
        }

        // Ticker alert status
        if (els.socTickerBanner) els.socTickerBanner.classList.add("attack-alert-active");
        const attackStatusHtml = `CRITICAL ATTACK &bull; ${res.attack_type}`;
        if (els.tickerStatus) {
          els.tickerStatus.innerHTML = attackStatusHtml;
          els.tickerStatus.className = "tm-value status-attack ticker-status-val";
        }
        document.querySelectorAll(".ticker-status-val").forEach(el => {
          el.innerHTML = attackStatusHtml;
          el.className = "tm-value status-attack ticker-status-val";
        });
        if (els.tickerAlerts) {
          els.tickerAlerts.textContent = "1 Critical Alert";
          els.tickerAlerts.className = "tm-value badge-crit ticker-alerts-val";
        }
        document.querySelectorAll(".ticker-alerts-val").forEach(el => {
          el.textContent = "1 Critical Alert";
          el.className = "tm-value badge-crit ticker-alerts-val";
        });

        updateDemoViews();
        appendTerminalLog(`[CONFIRMED] INTRUSION CONFIRMED: ${res.attack_type} on ${res.target_node}. Loss Surged: +${formatMoney(res.total_surge_inr)}. Posture degraded by -${res.posture_degradation_pts} pts.`, "attack");
        appendTerminalLog(`[AI-ADVISORY] AI Countermeasure: ${res.recommended_countermeasure}`);
        return;
      }
    } catch (e) {
      console.warn("Attack injection offline fallback:", e);
    }

    // Client fallback simulation
    state.activeAttack = attackType;
    const surge = 45800000.0;
    if (state.demoStats) {
      state.demoStats.ealInr = defaultData.totalEalInr + surge;
      state.demoStats.posture = 48.2;
      state.demoStats.riskFactor = 9.4;
    }

    if (els.attackAlertBanner) {
      els.attackAlertBanner.style.display = "flex";
      if (els.aabVector) els.aabVector.textContent = attackType;
      if (els.aabTarget) els.aabTarget.textContent = targetNode;
      if (els.aabTefSpike) els.aabTefSpike.textContent = "10.0x";
      if (els.aabLossSurge) els.aabLossSurge.textContent = `+${formatMoney(surge)}`;
      if (els.aabCountermeasureText) els.aabCountermeasureText.textContent = "Deploy enterprise perimeter WAF / EDR solution.";
    }
    updateDemoViews();
    appendTerminalLog(`[SIMULATION] INTRUSION SIMULATED: ${attackType} on ${targetNode}. Financial exposure surged by +${formatMoney(surge)}.`, "attack");
  }

  // Reset Attack Simulation
  async function resetAttack() {
    appendTerminalLog("[RESTORING] Restoring BharatCart infrastructure to nominal baseline...");

    try {
      const resp = await fetch("/api/v1/demo/reset-attack", { method: "POST" });
      if (resp.ok) {
        state.activeAttack = null;
        state.activeAttackData = null;
        if (state.demoStats) {
          state.demoStats.ealInr = state.demoStats.baselineEalInr - state.demoStats.riskMitigatedInr;
          state.demoStats.posture = state.purchasedVendors.size > 0 ? state.demoStats.posture : 84.6;
          state.demoStats.riskFactor = state.purchasedVendors.size > 0 ? state.demoStats.riskFactor : 4.8;
        }

        if (els.attackAlertBanner) els.attackAlertBanner.style.display = "none";
        if (els.socTickerBanner) els.socTickerBanner.classList.remove("attack-alert-active");
        const nominalStatusHtml = "NOMINAL &bull; 99.98%";
        if (els.tickerStatus) {
          els.tickerStatus.innerHTML = nominalStatusHtml;
          els.tickerStatus.className = "tm-value status-nominal ticker-status-val";
        }
        document.querySelectorAll(".ticker-status-val").forEach(el => {
          el.innerHTML = nominalStatusHtml;
          el.className = "tm-value status-nominal ticker-status-val";
        });
        if (els.tickerAlerts) {
          els.tickerAlerts.textContent = "0 Critical";
          els.tickerAlerts.className = "tm-value badge-ticker-nominal ticker-alerts-val";
        }
        document.querySelectorAll(".ticker-alerts-val").forEach(el => {
          el.textContent = "0 Critical";
          el.className = "tm-value badge-ticker-nominal ticker-alerts-val";
        });

        updateDemoViews();
        appendTerminalLog("[RESTORED] TOPOLOGY RESTORED: All active threat events terminated. Ingress rates nominal.", "mitigation");
        return;
      }
    } catch (e) {
      console.warn("Reset attack offline fallback:", e);
    }

    state.activeAttack = null;
    state.activeAttackData = null;
    if (state.demoStats) {
      state.demoStats.ealInr = defaultData.totalEalInr;
      state.demoStats.posture = 84.6;
      state.demoStats.riskFactor = 4.8;
    }
    if (els.attackAlertBanner) els.attackAlertBanner.style.display = "none";
    updateDemoViews();
    appendTerminalLog("[RESTORED] TOPOLOGY RESTORED: Nominal baseline re-established.", "mitigation");
  }

  // Fetch CEO Vendor Benchmarking Matrix (R5)
  async function fetchVendorCatalog() {
    try {
      const resp = await fetch(`/api/v1/vendor-benchmark/matrix?currency=${state.currency}`);
      if (resp.ok) {
        const data = await resp.json();
        state.vendorCatalog = data.vendors || [];
        (data.active_purchases || []).forEach(id => state.purchasedVendors.add(id));
        renderVendorCards();
        updateDemoViews();
        return;
      }
    } catch (e) {
      console.warn("Vendor catalog offline fallback:", e);
    }

    // Canonical Fallback Catalog
    state.vendorCatalog = [
      {
        vendor_id: "CROWDSTRIKE_FALCON",
        vendor_name: "CrowdStrike",
        product_name: "Falcon Complete XDR",
        category: "EDR",
        annual_cost: 850000.0,
        overall_coverage_rating: 94.5,
        recommendation_tags: ["Zero-Day Immunity", "Lateral Containment"],
        future_threat_shields: [
          { shield_id: "SHLD-CS-01", threat_vector: "Zero-Day Remote Code Execution (RCE)", description: "Kernel-level behavioral AI blocks unpatched memory corruption exploits.", neutralization_rate_pct: 96.0, proactive_defense_mechanism: "Behavioral heuristic sensor quarantine", coverage_tier: "ENTERPRISE_SHIELD" },
          { shield_id: "SHLD-CS-02", threat_vector: "Ransomware Lateral Movement", description: "Automated process-tree kill preventing SMB network propagation.", neutralization_rate_pct: 94.0, proactive_defense_mechanism: "Micro-segmented host network isolation", coverage_tier: "ENTERPRISE_SHIELD" }
        ],
        is_funded: state.purchasedVendors.has("CROWDSTRIKE_FALCON")
      },
      {
        vendor_id: "CLOUDFLARE_MAGIC_TRANSIT",
        vendor_name: "Cloudflare",
        product_name: "Magic Transit & Enterprise WAF",
        category: "WAF",
        annual_cost: 920000.0,
        overall_coverage_rating: 96.0,
        recommendation_tags: ["Volumetric DDoS Immunity", "API Shield"],
        future_threat_shields: [
          { shield_id: "SHLD-CF-01", threat_vector: "Volumetric DDoS Traffic Surge", description: "Anycast edge absorbs 300+ Tbps volumetric and L7 HTTP flood waves.", neutralization_rate_pct: 99.0, proactive_defense_mechanism: "Autonomous BGP Anycast scrubbing", coverage_tier: "ENTERPRISE_SHIELD" },
          { shield_id: "SHLD-CF-02", threat_vector: "Automated Credential Stuffing Wave", description: "Behavioral machine learning fingerprinting detects distributed botnets.", neutralization_rate_pct: 95.0, proactive_defense_mechanism: "Dynamic cryptographic challenge & bot scoring", coverage_tier: "ACTIVE_IMMUNITY" }
        ],
        is_funded: state.purchasedVendors.has("CLOUDFLARE_MAGIC_TRANSIT")
      },
      {
        vendor_id: "OKTA_WORKFORCE_IDENTITY",
        vendor_name: "Okta",
        product_name: "Workforce Identity Cloud",
        category: "IAM",
        annual_cost: 650000.0,
        overall_coverage_rating: 93.0,
        recommendation_tags: ["Phishing-Resistant MFA", "Zero Trust"],
        future_threat_shields: [
          { shield_id: "SHLD-OK-01", threat_vector: "Automated Credential Stuffing Wave", description: "FIDO2 WebAuthn eliminates password spray attack surfaces.", neutralization_rate_pct: 98.0, proactive_defense_mechanism: "Hardware-bound cryptographic keys", coverage_tier: "ENTERPRISE_SHIELD" },
          { shield_id: "SHLD-OK-02", threat_vector: "Session Hijacking & Token Replay", description: "Continuous session risk scoring revokes compromised OAuth tokens.", neutralization_rate_pct: 92.0, proactive_defense_mechanism: "Continuous access evaluation protocol (CAEP)", coverage_tier: "ACTIVE_IMMUNITY" }
        ],
        is_funded: state.purchasedVendors.has("OKTA_WORKFORCE_IDENTITY")
      },
      {
        vendor_id: "WIZ_CLOUD_SECURITY",
        vendor_name: "Wiz",
        product_name: "Cloud Security Platform CNAPP",
        category: "CSPM",
        annual_cost: 780000.0,
        overall_coverage_rating: 95.0,
        recommendation_tags: ["Agentless Graph DSPM", "Toxic Combos"],
        future_threat_shields: [
          { shield_id: "SHLD-WZ-01", threat_vector: "Public S3 Bucket Data Exfiltration", description: "Agentless graph correlation detects public exposure of cardholder stores.", neutralization_rate_pct: 97.0, proactive_defense_mechanism: "Automated CloudTrail policy guardrails", coverage_tier: "ENTERPRISE_SHIELD" },
          { shield_id: "SHLD-WZ-02", threat_vector: "Cloud IAM Privilege Escalation", description: "Maps toxic attack paths connecting public gateways to databases.", neutralization_rate_pct: 93.0, proactive_defense_mechanism: "Least-privilege permission rightsizing", coverage_tier: "ACTIVE_IMMUNITY" }
        ],
        is_funded: state.purchasedVendors.has("WIZ_CLOUD_SECURITY")
      },
      {
        vendor_id: "MICROSOFT_DEFENDER_SENTINEL",
        vendor_name: "Microsoft",
        product_name: "Defender for Cloud & Sentinel SIEM",
        category: "SOC",
        annual_cost: 1050000.0,
        overall_coverage_rating: 91.5,
        recommendation_tags: ["Cross-Cloud SOC", "SOAR Automated Playbooks"],
        future_threat_shields: [
          { shield_id: "SHLD-MS-01", threat_vector: "Zero-Day Remote Code Execution (RCE)", description: "Threat intelligence correlation across billions of cloud telemetry signals.", neutralization_rate_pct: 91.0, proactive_defense_mechanism: "Global threat intelligence cross-correlation", coverage_tier: "ENTERPRISE_SHIELD" },
          { shield_id: "SHLD-MS-02", threat_vector: "Volumetric DDoS Traffic Surge", description: "Automated Azure DDoS protection and routing divert hostile floods.", neutralization_rate_pct: 94.0, proactive_defense_mechanism: "Automated SOAR incident mitigation playbooks", coverage_tier: "ACTIVE_IMMUNITY" }
        ],
        is_funded: state.purchasedVendors.has("MICROSOFT_DEFENDER_SENTINEL")
      }
    ];
    renderVendorCards();
    updateDemoViews();
  }

  // Render Vendor Comparison Cards in CEO Benchmarking Grid
  function renderVendorCards() {
    if (!els.vendorBenchmarkCards) return;
    els.vendorBenchmarkCards.innerHTML = "";

    const icons = {
      "EDR": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
      "WAF": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>`,
      "IAM": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>`,
      "CSPM": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>`,
      "SOC": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>`
    };
    const defaultIcon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;

    state.vendorCatalog.forEach(v => {
      const isFunded = state.purchasedVendors.has(v.vendor_id);
      const card = document.createElement("div");
      card.className = `vendor-card ${isFunded ? "procured" : ""}`;

      const icon = icons[v.category] || defaultIcon;
      const tagsHtml = (v.recommendation_tags || []).map(t => `<span class="vc-tag">${t}</span>`).join("");

      card.innerHTML = `
        <div class="vc-left">
          <div class="vc-icon-box">${icon}</div>
          <div class="vc-meta">
            <div class="vc-title-row">
              <span class="vc-name">${v.vendor_name}</span>
              <span class="kpi-badge badge-med">${v.category}</span>
            </div>
            <div class="vc-product">${v.product_name}</div>
            <div class="vc-tags">${tagsHtml}</div>
          </div>
        </div>
        <div class="vc-middle">
          <div class="vc-coverage">${v.overall_coverage_rating}%</div>
          <div class="vc-cost">${formatMoney(v.annual_cost)} / yr</div>
        </div>
        <div class="vc-actions">
          <button class="btn-procure ${isFunded ? "btn-procured-done" : "btn-procure-active"}" data-vendor="${v.vendor_id}">
            ${isFunded ? "Procured & Active" : "Procure Solution"}
          </button>
          <button class="btn-shields-view" data-vendor="${v.vendor_id}">
            View Threat Shields (${(v.future_threat_shields || []).length})
          </button>
        </div>
      `;

      // Event listeners
      const btnProcure = card.querySelector(".btn-procure");
      if (btnProcure && !isFunded) {
        btnProcure.addEventListener("click", () => purchaseVendor(v.vendor_id));
      }

      const btnShields = card.querySelector(".btn-shields-view");
      if (btnShields) {
        btnShields.addEventListener("click", () => openThreatImmunityModal(v));
      }

      els.vendorBenchmarkCards.appendChild(card);
    });
  }

  // One-Click Virtual Vendor Procurement (R5 & R1/R4)
  async function purchaseVendor(vendorId) {
    const v = state.vendorCatalog.find(x => x.vendor_id === vendorId);
    const vendorName = v ? v.vendor_name : vendorId;
    appendTerminalLog(`[PENDING] Executing virtual procurement contract for ${vendorName}...`);

    try {
      const resp = await fetch("/api/v1/vendor-benchmark/purchase", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vendor_id: vendorId, currency: state.currency })
      });

      if (resp.ok) {
        const res = await resp.json();
        state.purchasedVendors.add(vendorId);

        // Update state with returned actuarial impact
        if (state.demoStats) {
          state.demoStats.supPct = res.security_upgrade_pct;
          state.demoStats.posture = res.posture_score;
          state.demoStats.riskFactor = res.risk_factor;
          state.demoStats.riskMitigatedInr = res.risk_mitigated;
          state.demoStats.totalSpendInr = res.allocated_spend;
          state.demoStats.ealInr = res.new_residual_eal;
          state.demoStats.activeShields += (res.future_shields_unlocked || 2);
        }

        renderVendorCards();
        updateDemoViews();
        appendTerminalLog(`[PROCURED] ${res.vendor_name} (${res.product_name}). Allocated Spend: ${formatMoney(res.allocated_spend)}. Security Upgrade: +${res.security_upgrade_pct.toFixed(1)}%. Residual EAL: ${formatMoney(res.new_residual_eal)}.`, "mitigation");

        // If attack banner is open and countermeasure matches, notify user
        if (state.activeAttack && els.aabCountermeasureText) {
          els.aabCountermeasureText.textContent = `Countermeasure successfully deployed via ${res.vendor_name}! Attack blast radius contained.`;
        }

        closeThreatImmunityModal();
        return;
      }
    } catch (e) {
      console.warn("Purchase offline fallback:", e);
    }

    // Client fallback
    state.purchasedVendors.add(vendorId);
    if (state.demoStats) {
      state.demoStats.totalSpendInr += (v ? v.annual_cost : 750000.0);
      const mitigated = 18500000.0;
      state.demoStats.riskMitigatedInr += mitigated;
      state.demoStats.supPct = Math.min(85.0, ((state.demoStats.riskMitigatedInr / defaultData.totalEalInr) * 100.0));
      state.demoStats.posture = Math.min(98.0, state.demoStats.posture + 6.5);
      state.demoStats.riskFactor = Math.max(1.5, state.demoStats.riskFactor - 0.8);
      state.demoStats.ealInr = Math.max(12000000.0, state.demoStats.ealInr - mitigated);
      state.demoStats.activeShields += 2;
    }

    renderVendorCards();
    updateDemoViews();
    appendTerminalLog(`[PROCURED] ${vendorName}. Security Posture upgraded to ${state.demoStats ? state.demoStats.posture.toFixed(1) : 90}%.`, "mitigation");
    closeThreatImmunityModal();
  }

  // Future Threat Immunity Modal (R2)
  function openThreatImmunityModal(vendor) {
    state.modalVendor = vendor;
    if (!els.modalThreatImmunity) return;

    if (els.modalVendorName) {
      els.modalVendorName.textContent = `${vendor.vendor_name} ${vendor.product_name} — Threat Immunity Arsenal`;
    }
    if (els.modalVendorDesc) {
      els.modalVendorDesc.textContent = `Category: ${vendor.category} • Annual Cost: ${formatMoney(vendor.annual_cost)} • Enterprise Defense Rating: ${vendor.overall_coverage_rating}%`;
    }

    if (els.modalShieldsGrid) {
      els.modalShieldsGrid.innerHTML = "";
      const shields = vendor.future_threat_shields || [];
      shields.forEach(s => {
        const sc = document.createElement("div");
        sc.className = "shield-card";
        sc.innerHTML = `
          <div>
            <div class="sc-header">
              <span class="sc-title"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:text-bottom; margin-right:4px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>${s.threat_vector}</span>
              <span class="sc-efficacy">${s.neutralization_rate_pct}% Reduction</span>
            </div>
            <div class="sc-desc" style="margin-top:0.4rem;">${s.description}</div>
          </div>
          <div class="sc-footer">
            <span><strong>Mechanism:</strong> ${s.proactive_defense_mechanism}</span>
            <span class="kpi-badge badge-med">${s.coverage_tier}</span>
          </div>
        `;
        els.modalShieldsGrid.appendChild(sc);
      });
    }

    if (els.btnModalProcure) {
      const isFunded = state.purchasedVendors.has(vendor.vendor_id);
      els.btnModalProcure.textContent = isFunded ? "Already Procured & Active" : `One-Click Procure (${formatMoney(vendor.annual_cost)} / yr)`;
      els.btnModalProcure.disabled = isFunded;
      els.btnModalProcure.onclick = () => purchaseVendor(vendor.vendor_id);
    }

    els.modalThreatImmunity.style.display = "flex";
  }

  function closeThreatImmunityModal() {
    if (els.modalThreatImmunity) {
      els.modalThreatImmunity.style.display = "none";
    }
  }

  // Setup Sandbox Event Handlers
  function initDemoSandbox() {
    // Attack Button Handlers
    if (els.attackBtns) {
      els.attackBtns.forEach(btn => {
        btn.addEventListener("click", () => {
          const attack = btn.dataset.attack;
          if (attack) {
            injectAttack(attack);
            updateCurlCommandSnippet(attack);
          }
        });
      });
    }

    // Target Node Change Handler
    if (els.demoTargetNode) {
      els.demoTargetNode.addEventListener("change", () => {
        updateCurlCommandSnippet();
      });
    }

    // Reset Simulation Buttons
    if (els.btnResetDemo) {
      els.btnResetDemo.addEventListener("click", resetAttack);
    }
    if (els.btnAlertReset) {
      els.btnAlertReset.addEventListener("click", resetAttack);
    }

    // Alert Banner Dismiss
    if (els.btnAlertDismiss) {
      els.btnAlertDismiss.addEventListener("click", () => {
        if (els.attackAlertBanner) els.attackAlertBanner.style.display = "none";
      });
    }

    // Alert Banner Deploy Countermeasure
    if (els.btnAlertMitigate) {
      els.btnAlertMitigate.addEventListener("click", () => {
        // If active attack has recommended product, purchase it!
        const recProd = state.activeAttackData ? state.activeAttackData.recommended_product_id : "CLOUDFLARE_MAGIC_TRANSIT";
        purchaseVendor(recProd || "CLOUDFLARE_MAGIC_TRANSIT");
      });
    }

    // Copy cURL Snippet
    if (els.btnCopyCurl && els.curlCommandDisplay) {
      els.btnCopyCurl.addEventListener("click", () => {
        const text = els.curlCommandDisplay.textContent;
        navigator.clipboard.writeText(text).then(() => {
          const original = els.btnCopyCurl.textContent;
          els.btnCopyCurl.textContent = "Copied to Clipboard";
          setTimeout(() => {
            els.btnCopyCurl.textContent = original;
          }, 2000);
        });
      });
    }

    // Modal Close
    if (els.btnCloseModal) {
      els.btnCloseModal.addEventListener("click", closeThreatImmunityModal);
    }
    if (els.btnModalCloseBottom) {
      els.btnModalCloseBottom.addEventListener("click", closeThreatImmunityModal);
    }
    if (els.modalThreatImmunity) {
      els.modalThreatImmunity.addEventListener("click", (e) => {
        if (e.target === els.modalThreatImmunity) {
          closeThreatImmunityModal();
        }
      });
    }

    // Initialize cURL snippet
    updateCurlCommandSnippet();

    // Initial fetch of vendors
    fetchVendorCatalog();

    // Initial Telemetry Ticker Pulse & Polling Loop (every 2.5 seconds)
    fetchTelemetryTicker();
    if (state.tickerTimer) clearInterval(state.tickerTimer);
    state.tickerTimer = setInterval(fetchTelemetryTicker, 2500);
  }

  // =========================================================================
  // 10. Initialization & Event Binding
  // =========================================================================
  function init() {
    // Initialize liquidGL WebGL Shader Engine
    LiquidGLEngine.init();

    // Tab Navigation
    els.tabBtns.forEach(btn => {
      btn.addEventListener("click", () => setTab(btn.dataset.tab));
    });
    setTab(state.activeTab);

    // Theme Switcher (Dark / Light)
    if (els.btnTheme) {
      els.btnTheme.innerHTML = state.theme === "dark"
        ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg> Dark`
        : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg> Light`;
      els.btnTheme.addEventListener("click", toggleTheme);
    }

    // Currency Switcher (INR / USD)
    if (els.btnCurrency) {
      els.btnCurrency.addEventListener("click", toggleCurrency);
    }

    // Export Report (Print / PDF)
    if (els.btnExport) {
      els.btnExport.addEventListener("click", () => {
        document.body.classList.add("printing");
        updateAllViews();
        setTimeout(() => {
          window.print();
          setTimeout(() => {
            document.body.classList.remove("printing");
            updateAllViews();
          }, 500);
        }, 60);
      });
    }

    window.addEventListener("beforeprint", () => {
      document.body.classList.add("printing");
      updateAllViews();
    });

    window.addEventListener("afterprint", () => {
      document.body.classList.remove("printing");
      updateAllViews();
    });

    // Sliders
    if (els.sliderBudget) {
      els.sliderBudget.addEventListener("input", updateOptimization);
    }

    if (els.sliderDelay) {
      els.sliderDelay.addEventListener("input", (e) => {
        state.delayDays = parseInt(e.target.value, 10);
        updateWhatIf();
      });
    }

    // NLQ
    if (els.btnNlq) {
      els.btnNlq.addEventListener("click", runNLQ);
    }

    if (els.nlqInput) {
      els.nlqInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") runNLQ();
      });
    }

    // Suggestion pills click
    document.querySelectorAll(".nlq-suggestions li").forEach(item => {
      item.addEventListener("click", () => {
        if (els.nlqInput) {
          els.nlqInput.value = item.textContent.replace(/[“”"]/g, "").trim();
          runNLQ();
        }
      });
    });

    // Initial render
    updateAllViews();

    // Initialize BharatCart Live Threat Defense Sandbox
    initDemoSandbox();

    // -------------------------------------------------------------------------
    // Liquid Glass Physical Card Optics & 3D Tilt (Apple VisionOS / liquidGL)
    // -------------------------------------------------------------------------
    initLiquidGlassCards();
    initGlassTooltip();
    initCopilot();
  }

  function initGlassTooltip() {
    let tooltipEl = document.getElementById("liquid-glass-tooltip");
    if (!tooltipEl) {
      tooltipEl = document.createElement("div");
      tooltipEl.id = "liquid-glass-tooltip";
      tooltipEl.className = "liquid-glass-tooltip";
      document.body.appendChild(tooltipEl);
    }

    document.addEventListener("mouseover", (e) => {
      const target = e.target.closest("[data-tooltip]");
      if (target) {
        const text = target.getAttribute("data-tooltip");
        if (text) {
          tooltipEl.textContent = text;
          tooltipEl.classList.add("visible");
          positionTooltip(e);
        }
      }
    });

    document.addEventListener("mousemove", (e) => {
      if (tooltipEl.classList.contains("visible")) {
        positionTooltip(e);
      }
    });

    document.addEventListener("mouseout", (e) => {
      const target = e.target.closest("[data-tooltip]");
      if (target) {
        tooltipEl.classList.remove("visible");
      }
    });

    function positionTooltip(e) {
      tooltipEl.style.left = `${e.clientX}px`;
      tooltipEl.style.top = `${e.clientY - 14}px`;
    }
  }

  function initLiquidGlassCards() {
    const glassElements = document.querySelectorAll(".glass-panel, .kpi-card, header.liquid-nav");
    glassElements.forEach(el => {
      el.addEventListener("mousemove", (e) => {
        const rect = el.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        el.style.setProperty("--mouse-x", `${x}px`);
        el.style.setProperty("--mouse-y", `${y}px`);

        // Physical Specular & Micro-Elevation Optics (Apple Enterprise Grade)
        if (el.classList.contains("glass-panel") || el.classList.contains("kpi-card")) {
          const normX = (x / rect.width - 0.5) * 2; // -1 to +1
          const normY = (y / rect.height - 0.5) * 2; // -1 to +1
          const tiltX = -normY * 0.8;
          const tiltY = normX * 0.8;
          el.style.transform = `perspective(1200px) rotateX(${tiltX.toFixed(2)}deg) rotateY(${tiltY.toFixed(2)}deg) translateY(-2.5px)`;
        }
      });

      el.addEventListener("mouseleave", () => {
        if (el.classList.contains("glass-panel") || el.classList.contains("kpi-card")) {
          el.style.transform = "";
        }
      });
    });
  }

  // =========================================================================
  // 11. Google Gemini 3.5 Flash Lite Slide-Out Copilot & Action Engine
  // =========================================================================
  const copilotState = {
    history: [],
    isStreaming: false,
  };

  function openCopilot() {
    if (els.copilotDrawer) els.copilotDrawer.classList.add("open");
    if (els.copilotBackdrop) els.copilotBackdrop.classList.add("open");
    if (els.copilotInput) {
      setTimeout(() => els.copilotInput.focus(), 150);
    }
  }

  function closeCopilot() {
    if (els.copilotDrawer) els.copilotDrawer.classList.remove("open");
    if (els.copilotBackdrop) els.copilotBackdrop.classList.remove("open");
  }

  function formatCopilotMarkdown(text) {
    if (!text) return "";
    let safe = text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

    // Bold
    safe = safe.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
    // Inline code
    safe = safe.replace(/`([^`]+)`/g, "<code>$1</code>");
    // Bullet points
    safe = safe.replace(/^[*-]\s+(.+)$/gm, "<li>$1</li>");
    safe = safe.replace(/(<li>.*<\/li>)/s, "<ul>$1</ul>");
    // Line breaks
    safe = safe.replace(/\n\n/g, "<br><br>");
    safe = safe.replace(/\n/g, "<br>");
    return safe;
  }

  function appendChatMessage(sender, text, role = "assistant", actionBadge = null, followups = []) {
    if (!els.copilotChatStream) return;

    const msgEl = document.createElement("div");
    msgEl.className = `chat-msg chat-msg-${role}`;

    const now = new Date();
    const timeStr = `${String(now.getUTCHours()).padStart(2, "0")}:${String(now.getUTCMinutes()).padStart(2, "0")}:${String(now.getUTCSeconds()).padStart(2, "0")} UTC`;

    let badgeHtml = "";
    if (actionBadge) {
      badgeHtml = `
        <div class="chat-action-badge">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
          ${actionBadge}
        </div>
      `;
    }

    let followupsHtml = "";
    if (followups && followups.length > 0) {
      const pills = followups.map(f => `<button class="copilot-chip followup-chip" style="margin-top:0.4rem; font-size:0.72rem;">${f}</button>`).join(" ");
      followupsHtml = `<div class="chat-followups" style="margin-top:0.6rem; display:flex; flex-wrap:wrap; gap:0.4rem;">${pills}</div>`;
    }

    msgEl.innerHTML = `
      <div class="chat-msg-header">
        <span class="chat-sender">${sender}</span>
        <span class="chat-time">${timeStr}</span>
      </div>
      <div class="chat-msg-body">
        ${formatCopilotMarkdown(text)}
        ${badgeHtml}
        ${followupsHtml}
      </div>
    `;

    // Add click listeners to followup chips
    if (followups && followups.length > 0) {
      msgEl.querySelectorAll(".followup-chip").forEach(chip => {
        chip.addEventListener("click", () => {
          if (els.copilotInput) {
            els.copilotInput.value = chip.textContent.trim();
            handleCopilotSubmit();
          }
        });
      });
    }

    els.copilotChatStream.appendChild(msgEl);
    els.copilotChatStream.scrollTop = els.copilotChatStream.scrollHeight;
  }

  // Structured ActionPayload Dispatcher (Client-side platform execution)
  function executePlatformAction(action) {
    if (!action) return null;

    const actionType = action.action_type || action.action;
    const targetTab = action.target_tab || action.target;
    const params = action.parameters || {};

    let feedback = null;

    switch (actionType) {
      case "switch_tab":
      case "tab_switch":
        if (targetTab === "executive" || targetTab === "technical" || targetTab === "demo") {
          setTab(targetTab);
          feedback = `Switched to ${targetTab.toUpperCase()} tab`;
        } else if (targetTab === "optimize" || targetTab === "frontier" || targetTab === "allocation") {
          setTab("executive");
          const optSec = document.getElementById("opt-controls-grid") || document.getElementById("chart-frontier");
          if (optSec) optSec.scrollIntoView({ behavior: "smooth" });
          feedback = `Focused Optimization Engine`;
        }
        break;

      case "set_slider":
      case "set_budget_and_optimize":
        if (params.name === "budget" || params.budget !== undefined || action.target_element === "#slider-budget") {
          const val = params.budget !== undefined ? params.budget : params.value;
          if (els.sliderBudget && val) {
            els.sliderBudget.value = val;
            updateOptimization();
            feedback = `Updated Capital Budget to ${formatMoney(parseFloat(val))} & Solved MILP`;
          }
        } else if (params.name === "delay" || params.delay !== undefined || action.target_element === "#slider-delay") {
          const val = params.delay !== undefined ? params.delay : params.value;
          if (els.sliderDelay && val) {
            els.sliderDelay.value = val;
            state.delayDays = parseInt(val, 10);
            updateWhatIf();
            feedback = `Set Remediation Delay to ${val} days`;
          }
        }
        break;

      case "inject_attack":
      case "simulate_attack":
        setTab("demo");
        const atkType = params.attack_type || action.target || "zero_day_cve";
        const tgtNode = params.target_node || "BC-FLASH-SALE-01";
        injectAttack(atkType, tgtNode);
        feedback = `Simulated attack [${atkType}] on [${tgtNode}]`;
        break;

      case "reset_simulation":
        resetAttack();
        feedback = `Reset Attack Simulation & Restored Nominal Telemetry`;
        break;

      case "toggle_currency":
        toggleCurrency();
        feedback = `Switched Currency to ${state.currency}`;
        break;

      case "open_drawer":
        openCopilot();
        feedback = `Copilot Drawer Opened`;
        break;

      default:
        console.log("Unrecognized action type:", actionType, action);
        break;
    }

    return feedback;
  }

  // Handle Copilot Submission
  async function handleCopilotSubmit(e) {
    if (e) e.preventDefault();
    if (!els.copilotInput) return;
    const query = els.copilotInput.value.trim();
    if (!query || copilotState.isStreaming) return;

    // Clear input
    els.copilotInput.value = "";

    // Append user message
    appendChatMessage("You", query, "user");
    copilotState.history.push({ role: "user", text: query });

    copilotState.isStreaming = true;

    // Append temporary assistant typing placeholder
    const typingId = `typing-${Date.now()}`;
    const typingEl = document.createElement("div");
    typingEl.id = typingId;
    typingEl.className = "chat-msg chat-msg-assistant";
    typingEl.innerHTML = `
      <div class="chat-msg-header">
        <span class="chat-sender">LossLogic Copilot</span>
        <span class="chat-time">Grounded Inference...</span>
      </div>
      <div class="chat-msg-body" style="font-style:italic; opacity:0.8;">
        Synthesizing telemetry and actuarial models...
      </div>
    `;
    els.copilotChatStream.appendChild(typingEl);
    els.copilotChatStream.scrollTop = els.copilotChatStream.scrollHeight;

    const cleanTyping = () => {
      const el = document.getElementById(typingId);
      if (el) el.remove();
    };

    try {
      // Check if command is an explicit navigation/action command
      const isNavCommand = /^(go to|switch to|navigate to|open|show|simulate|inject|optimize|run attack|set budget|reset)/i.test(query);

      let actionExecutedFeedback = null;
      let navResult = null;

      if (isNavCommand) {
        try {
          const navResp = await fetch("/api/v1/ai/navigate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ command: query, currency: state.currency })
          });
          if (navResp.ok) {
            navResult = await navResp.json();
            if (navResult.actions && navResult.actions.length > 0) {
              navResult.actions.forEach(act => {
                const fb = executePlatformAction(act);
                if (fb) actionExecutedFeedback = fb;
              });
            } else if (navResult.action) {
              actionExecutedFeedback = executePlatformAction(navResult.action);
            }
          }
        } catch (navErr) {
          console.warn("AI navigate non-fatal error:", navErr);
        }
      }

      // Call Grounded Conversational AI endpoint
      const chatResp = await fetch("/api/v1/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: query,
          currency: state.currency,
          history: copilotState.history.slice(-6),
          context: {
            activeTab: state.activeTab,
            posture: state.demoStats ? state.demoStats.posture : 84.6,
            currentEalInr: state.demoStats ? state.demoStats.ealInr : defaultData.totalEalInr,
            activeAttack: state.activeAttack,
          }
        })
      });

      cleanTyping();

      if (chatResp.ok) {
        const chatData = await chatResp.json();
        const reply = chatData.reply || chatData.response || (navResult ? navResult.explanation : "Action performed.");
        
        // If chat suggested actions and we haven't executed one yet, execute it
        if (!actionExecutedFeedback && chatData.suggested_actions && chatData.suggested_actions.length > 0) {
          actionExecutedFeedback = executePlatformAction(chatData.suggested_actions[0]);
        }

        appendChatMessage(
          "LossLogic Copilot",
          reply,
          "assistant",
          actionExecutedFeedback,
          chatData.suggested_followups || []
        );
        copilotState.history.push({ role: "model", text: reply });
      } else {
        // Fallback response if offline/rate-limited
        const fallbackText = navResult ? navResult.explanation : `Understood. Analyzing risk parameters for "${query}". Your current security posture is ${state.demoStats ? state.demoStats.posture.toFixed(1) : "84.6"}% with ₹${((state.demoStats ? state.demoStats.ealInr : defaultData.totalEalInr)/10000000).toFixed(2)} Cr residual loss exposure.`;
        appendChatMessage("LossLogic Copilot", fallbackText, "assistant", actionExecutedFeedback);
        copilotState.history.push({ role: "model", text: fallbackText });
      }
    } catch (err) {
      cleanTyping();
      console.warn("Copilot fetch fallback:", err);
      appendChatMessage(
        "LossLogic Copilot",
        `LossLogic local decision engine: Evaluated "${query}". Security posture active at ${state.demoStats ? state.demoStats.posture.toFixed(1) : "84.6"}%.`,
        "assistant"
      );
    } finally {
      copilotState.isStreaming = false;
    }
  }

  // Quick Action Chip Triggers
  async function triggerQuickAction(actionType) {
    openCopilot();

    if (actionType === "jury-pitch") {
      appendChatMessage("You", "Give me a 30-second jury pitch and executive summary of LossLogic.", "user");
      copilotState.isStreaming = true;

      const typingId = `typing-${Date.now()}`;
      const typingEl = document.createElement("div");
      typingEl.id = typingId;
      typingEl.className = "chat-msg chat-msg-assistant";
      typingEl.innerHTML = `<div class="chat-msg-header"><span class="chat-sender">LossLogic Copilot</span><span class="chat-time">Synthesizing Jury Pitch...</span></div><div class="chat-msg-body" style="font-style:italic;">Generating 30-second briefing from live telemetry...</div>`;
      els.copilotChatStream.appendChild(typingEl);
      els.copilotChatStream.scrollTop = els.copilotChatStream.scrollHeight;

      try {
        const resp = await fetch("/api/v1/ai/executive-summary", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target_audience: "jury", currency: state.currency })
        });
        const el = document.getElementById(typingId);
        if (el) el.remove();

        if (resp.ok) {
          const data = await resp.json();
          const headline = data.headline || data.board_headline || "LossLogic: Cyber Risk Quantified in Rupees";
          const pitch = data.elevator_pitch_30s || data.elevator_pitch || data.summary_30s || "";
          const bullets = (data.bulleted_insights || []).map(b => `* ${b}`).join("\n");
          const msg = `**${headline}**\n\n${pitch}\n\n**Executive Key Takeaways:**\n${bullets}`;
          appendChatMessage("LossLogic Copilot", msg, "assistant", "Jury Briefing Synthesized", [
            "What is our maximum probable loss (VaR 99%)?",
            "How does HiGHS MILP optimize our cybersecurity budget?",
            "Show live threat defense against zero-day exploits"
          ]);
        } else {
          appendChatMessage("LossLogic Copilot", "**LossLogic 30-Second Briefing**\n\nLossLogic replaces subjective red-amber-green risk heatmaps with actuarial Open FAIR Monte Carlo loss simulations and HiGHS MILP knapsack capital optimization. We prove real ROI per Rupee spent on enterprise defense.", "assistant", "Executive Pitch Loaded");
        }
      } catch (err) {
        const el = document.getElementById(typingId);
        if (el) el.remove();
        appendChatMessage("LossLogic Copilot", "**LossLogic 30-Second Briefing**\n\nLossLogic replaces subjective red-amber-green risk heatmaps with actuarial Open FAIR Monte Carlo loss simulations and HiGHS MILP knapsack capital optimization. We prove real ROI per Rupee spent on enterprise defense.", "assistant", "Executive Pitch Loaded");
      } finally {
        copilotState.isStreaming = false;
      }

    } else if (actionType === "blast-radius") {
      setTab("demo");
      appendChatMessage("You", "Analyze blast radius of critical vulnerabilities and multi-cloud attack propagation.", "user");
      copilotState.isStreaming = true;

      try {
        const resp = await fetch("/api/v1/ai/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            message: "Analyze blast radius of critical vulnerabilities and multi-cloud attack propagation across BharatCart.",
            currency: state.currency,
            context: { activeTab: "demo" }
          })
        });

        if (resp.ok) {
          const data = await resp.json();
          appendChatMessage("LossLogic Copilot", data.reply || data.response, "assistant", "Switched to BharatCart Topology DAG", [
            "Simulate DDoS surge on API Gateway",
            "Simulate Zero-Day exploit on Flash Sale node",
            "Procure Cloudflare Magic Transit to contain attack"
          ]);
        } else {
          appendChatMessage("LossLogic Copilot", "Switched to **BharatCart Threat Defense Sandbox**. Observe the 7-node NetworkX Directed Acyclic Graph (DAG): compromised edge nodes cascade into backend PII Vault and Core DB unless mitigated by zero-trust threat shields.", "assistant", "Switched to BharatCart Topology DAG");
        }
      } catch (err) {
        appendChatMessage("LossLogic Copilot", "Switched to **BharatCart Threat Defense Sandbox**. The multi-tier topology illustrates real-time blast radius across microservices.", "assistant", "Switched to BharatCart Topology DAG");
      } finally {
        copilotState.isStreaming = false;
      }

    } else if (actionType === "auto-optimize") {
      setTab("executive");
      appendChatMessage("You", "Auto-optimize security capital portfolio using HiGHS MILP solver.", "user");
      copilotState.isStreaming = true;

      try {
        const resp = await fetch("/api/v1/ai/navigate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            command: "Auto-optimize capital allocation for ₹45 Lakh budget and compute optimal frontier",
            currency: state.currency
          })
        });

        if (resp.ok) {
          const data = await resp.json();
          if (data.actions && data.actions.length > 0) {
            data.actions.forEach(a => executePlatformAction(a));
          } else if (data.action) {
            executePlatformAction(data.action);
          } else {
            updateOptimization();
          }
          const optSec = document.getElementById("opt-controls-grid") || document.getElementById("chart-frontier");
          if (optSec) optSec.scrollIntoView({ behavior: "smooth" });

          appendChatMessage("LossLogic Copilot", data.explanation || "HiGHS Mixed-Integer Linear Programming solver computed optimal control portfolio on efficient frontier, achieving maximal Return on Security Investment (ROSI).", "assistant", "Optimal Capital Frontier Solved", [
            "What if we increase budget to ₹75 Lakhs?",
            "Show delay penalty impact over 90 days",
            "Which control offers highest standalone marginal ROSI?"
          ]);
        } else {
          updateOptimization();
          appendChatMessage("LossLogic Copilot", "Optimized capital portfolio for ₹45 Lakhs. HiGHS MILP selected optimal control combination on the efficient frontier.", "assistant", "Optimal Capital Frontier Solved");
        }
      } catch (err) {
        updateOptimization();
        appendChatMessage("LossLogic Copilot", "Optimized capital portfolio for ₹45 Lakhs. HiGHS MILP selected optimal control combination on the efficient frontier.", "assistant", "Optimal Capital Frontier Solved");
      } finally {
        copilotState.isStreaming = false;
      }
    }
  }

  // Initialize Copilot Event Listeners
  function initCopilot() {
    // Header Open Button
    if (els.btnOpenCopilot) {
      els.btnOpenCopilot.addEventListener("click", openCopilot);
    }

    // FAB Open Button
    if (els.fabOpenCopilot) {
      els.fabOpenCopilot.addEventListener("click", openCopilot);
    }

    // Close Button
    if (els.btnCloseCopilot) {
      els.btnCloseCopilot.addEventListener("click", closeCopilot);
    }

    // Backdrop Click to Close
    if (els.copilotBackdrop) {
      els.copilotBackdrop.addEventListener("click", closeCopilot);
    }

    // ESC Key to Close
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && els.copilotDrawer && els.copilotDrawer.classList.contains("open")) {
        closeCopilot();
      }
    });

    // Form Submit
    if (els.copilotForm) {
      els.copilotForm.addEventListener("submit", handleCopilotSubmit);
    }

    // Quick-Action Chips
    document.querySelectorAll(".copilot-chip[data-action]").forEach(chip => {
      chip.addEventListener("click", () => {
        const act = chip.getAttribute("data-action");
        if (act) triggerQuickAction(act);
      });
    });

    // Auto-open via ?copilot=open URL param
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("copilot") === "open") {
      setTimeout(openCopilot, 200);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
