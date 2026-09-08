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
  const initialTab = (tabParam === "technical" || tabParam === "executive") ? tabParam : "executive";

  const state = {
    theme: savedTheme,
    currency: "INR",
    usdToInr: 83.5,
    budget: 4500000.0, // ₹45 Lakhs default
    whatIfControls: new Set(["CTRL-MFA", "CTRL-PATCH"]),
    delayDays: 0,
    activeTab: initialTab,
    data: null,
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
        float t = u_time * 0.85;

        // Base liquid height
        float h = liquidHeight(p, t);

        // Interactive mouse viscous wave (smooth organic fluid ripple)
        vec2 mPos = vec2(u_mouse.x * aspect, u_mouse.y) * 2.6;
        float d = distance(p, mPos);
        float mouseWave = sin(d * 14.0 - t * 4.5) * exp(-d * 2.2) * 0.16;
        h += mouseWave;

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

        // Fresnel contour & specular sheen
        float fresnel = clamp(length(norm) * 0.65, 0.0, 1.0);
        float spec = pow(clamp(1.0 - d * 0.7 + h * 0.35, 0.0, 1.0), 4.0) * 0.45;

        if (u_is_light > 0.5) {
          // Apple Light Studio: Refined liquid crystal with soft silver-titanium shadows
          vec3 baseLight = vec3(0.95, 0.965, 0.98);
          vec3 liquidShadow = vec3(0.80, 0.84, 0.90);
          float depthFactor = clamp(h * 0.55 + 0.5, 0.0, 1.0);
          vec3 fluidBody = mix(liquidShadow, baseLight, depthFactor);

          // Refractive valleys & edge contours
          fluidBody -= vec3(fresnel * 0.12);

          // Prismatic caustic crests
          float causticAvg = (causticR + causticG + causticB) * 0.3333;
          vec3 caustics = vec3(
            mix(causticAvg, causticR, 0.20),
            mix(causticAvg, causticG, 0.20),
            mix(causticAvg, causticB, 0.20)
          ) * 0.32;

          // Specular glint
          vec3 col = fluidBody + caustics + vec3(spec * 0.30);
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

          vec3 col = fluidBody + caustics * 1.25 + vec3(fresnel * 0.16) + vec3(spec * 0.45);
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
      this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.08;
      this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.08;

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
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: 160 + Math.random() * 200,
        intensity: 0.03 + Math.random() * 0.04,
      });
    }

    let time = 0;
    function renderFallback() {
      time += 0.008;
      ctx.clearRect(0, 0, width, height);
      const isLight = state.theme === "light";

      particles.forEach((p, idx) => {
        p.x += p.vx + Math.sin(time + idx) * 0.25;
        p.y += p.vy + Math.cos(time + idx * 0.8) * 0.25;

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
    if (els.kpiEal) els.kpiEal.textContent = formatMoney(defaultData.totalEalInr);
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

    // -------------------------------------------------------------------------
    // Liquid Glass Physical Card Optics & 3D Tilt (Apple VisionOS / liquidGL)
    // -------------------------------------------------------------------------
    initLiquidGlassCards();
    initGlassTooltip();
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

        // Physical 3D Tilt Optics (liquidGL tiltFactor)
        if (el.classList.contains("glass-panel") || el.classList.contains("kpi-card")) {
          const normX = (x / rect.width - 0.5) * 2; // -1 to +1
          const normY = (y / rect.height - 0.5) * 2; // -1 to +1
          const tiltX = -normY * 4.0;
          const tiltY = normX * 4.0;
          el.style.transform = `perspective(1000px) rotateX(${tiltX.toFixed(2)}deg) rotateY(${tiltY.toFixed(2)}deg) translateY(-2px)`;
        }
      });

      el.addEventListener("mouseleave", () => {
        if (el.classList.contains("glass-panel") || el.classList.contains("kpi-card")) {
          el.style.transform = "";
        }
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
