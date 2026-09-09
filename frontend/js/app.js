/**
 * ScamShield - Frontend Application Controller
 * Handles message input, character counting, sample prompt loading,
 * API communication, animated risk gauge, and dynamic indicator card rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const messageInput = document.getElementById("messageInput");
  const charCount = document.getElementById("charCount");
  const analyzerForm = document.getElementById("analyzerForm");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const btnText = document.getElementById("btnText");
  const btnSpinner = document.getElementById("btnSpinner");
  const clearBtn = document.getElementById("clearBtn");
  const errorAlert = document.getElementById("errorAlert");
  const errorMessage = document.getElementById("errorMessage");

  // Results Dashboard Elements
  const resultsDashboard = document.getElementById("resultsDashboard");
  const riskBadge = document.getElementById("riskBadge");
  const gaugeScoreValue = document.getElementById("gaugeScoreValue");
  const gaugeProgress = document.getElementById("gaugeProgress");
  const confidenceValue = document.getElementById("confidenceValue");
  const analysisSummary = document.getElementById("analysisSummary");
  const indicatorCount = document.getElementById("indicatorCount");
  const indicatorsGrid = document.getElementById("indicatorsGrid");
  const explanationText = document.getElementById("explanationText");
  const recommendationsList = document.getElementById("recommendationsList");
  const disclaimerText = document.getElementById("disclaimerText");

  // Mobile Navigation Toggle
  const mobileNavBtn = document.getElementById("mobileNavBtn");
  const navLinks = document.getElementById("navLinks");
  if (mobileNavBtn && navLinks) {
    mobileNavBtn.addEventListener("click", () => {
      navLinks.classList.toggle("nav-open");
    });
  }

  // Pre-configured Test Samples for College/Interview Demonstration
  const SAMPLES = {
    prize: "Congratulations! You won ?50,000 cash prize in our Diwali lucky draw! Claim immediately by clicking http://bit.ly/claim-prize50. Pay ?499 registration fee and send your OTP.",
    job: "Work from home part time job: Earn ?5,000 to ?10,000 daily by simply watching videos. No experience required. Pay ?750 refundable security deposit to start today.",
    kyc: "Dear Customer, your electricity power will be disconnected tonight at 9:30 PM due to pending KYC verification. Contact power officer immediately at http://192.168.4.12/bill",
    legit: "Dear Customer, Your OTP for transaction of Rs 500 at Amazon is 492102. NEVER share your OTP or password with anyone. Bank will never ask for your code."
  };

  // Sample prompt buttons
  document.querySelectorAll(".sample-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const sampleKey = btn.getAttribute("data-sample");
      if (SAMPLES[sampleKey]) {
        messageInput.value = SAMPLES[sampleKey];
        updateCharCount();
        hideError();
        messageInput.focus();
      }
    });
  });

  // Character Counter
  function updateCharCount() {
    const len = messageInput.value.length;
    charCount.textContent = `${len} / 5000`;
    if (len > 4500) {
      charCount.className = "char-counter limit-near";
    } else if (len > 5000) {
      charCount.className = "char-counter limit-exceeded";
    } else {
      charCount.className = "char-counter";
    }
  }
  messageInput.addEventListener("input", updateCharCount);

  // Clear button
  clearBtn.addEventListener("click", () => {
    messageInput.value = "";
    updateCharCount();
    hideError();
    resultsDashboard.style.display = "none";
    messageInput.focus();
  });

  // Show / Hide Error Helper
  function showError(msg) {
    errorMessage.textContent = msg;
    errorAlert.style.display = "flex";
  }

  function hideError() {
    errorAlert.style.display = "none";
  }

  // Set Loading State
  function setLoading(isLoading) {
    if (isLoading) {
      analyzeBtn.disabled = true;
      clearBtn.disabled = true;
      btnText.textContent = "Analyzing Indicators...";
      btnSpinner.style.display = "inline-block";
    } else {
      analyzeBtn.disabled = false;
      clearBtn.disabled = false;
      btnText.textContent = "??? Analyze Message";
      btnSpinner.style.display = "none";
    }
  }

  // Form Submission
  analyzerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError();

    const text = messageInput.value.trim();

    // Client-side Validation
    if (!text) {
      showError("Please enter a message to analyze.");
      return;
    }
    if (text.length < 10) {
      showError("Message is too short. Please enter at least 10 characters.");
      return;
    }
    if (text.length > 5000) {
      showError("Message exceeds 5,000 characters. Please shorten the text.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to analyze message.");
      }

      // Render Results
      renderResults(data);

      // Smooth scroll to results
      resultsDashboard.style.display = "block";
      resultsDashboard.scrollIntoView({ behavior: "smooth", block: "start" });

    } catch (err) {
      console.error("API Analysis Error:", err);
      showError(err.message || "Something went wrong while connecting to the detection server.");
    } finally {
      setLoading(false);
    }
  });

  /**
   * Render Analysis Result into the Dashboard
   */
  function renderResults(res) {
    const score = res.risk_score || 0;
    const level = res.risk_level || "Low Risk";
    const confidence = res.confidence ? Math.round(res.confidence * 100) : 80;

    // 1. Update Gauge & Badges
    animateGauge(score, level);
    confidenceValue.textContent = `${confidence}%`;
    analysisSummary.textContent = res.summary || "Analysis completed.";
    if (res.disclaimer) {
      disclaimerText.textContent = res.disclaimer;
    }

    // Risk Badge styling
    riskBadge.textContent = level;
    riskBadge.className = "risk-badge";
    if (score >= 76) {
      riskBadge.classList.add("badge-high");
    } else if (score >= 51) {
      riskBadge.classList.add("badge-suspicious");
    } else if (score >= 26) {
      riskBadge.classList.add("badge-attention");
    } else {
      riskBadge.classList.add("badge-low");
    }

    // 2. Indicators Cards
    const indicators = res.indicators || [];
    indicatorCount.textContent = indicators.length;
    indicatorsGrid.innerHTML = "";

    if (indicators.length === 0) {
      indicatorsGrid.innerHTML = `
        <div class="indicator-card sev-low" style="grid-column: 1 / -1;">
          <div class="indicator-card-header">
            <span class="indicator-name">? No Known Threats Found</span>
            <span class="indicator-badge sev-low">Clean</span>
          </div>
          <p class="indicator-desc">
            No high-risk keywords, predatory credential requests, or known obfuscated link structures were detected.
          </p>
        </div>
      `;
    } else {
      indicators.forEach(ind => {
        const card = document.createElement("div");
        const sevClass = ind.severity === "high" ? "sev-high" : (ind.severity === "medium" ? "sev-medium" : "sev-low");
        card.className = `indicator-card ${sevClass}`;

        let pillsHtml = "";
        if (ind.matched_terms && ind.matched_terms.length > 0) {
          pillsHtml = `<div class="matched-pills">${ind.matched_terms.map(t => `<span class="matched-pill">${escapeHtml(t)}</span>`).join("")}</div>`;
        }

        card.innerHTML = `
          <div class="indicator-card-header">
            <span class="indicator-name">${escapeHtml(ind.type)}</span>
            <span class="indicator-badge ${sevClass}">${escapeHtml(ind.severity)}</span>
          </div>
          <p class="indicator-desc">${escapeHtml(ind.description)}</p>
          ${pillsHtml}
        `;
        indicatorsGrid.appendChild(card);
      });
    }

    // 3. Plain-Language Explanation
    explanationText.textContent = res.explanation || "No explanation provided.";

    // 4. Actionable Recommendations
    recommendationsList.innerHTML = "";
    const recs = res.recommendations || [];
    if (recs.length === 0) {
      const li = document.createElement("li");
      li.textContent = "Continue following standard digital safety hygiene.";
      recommendationsList.appendChild(li);
    } else {
      recs.forEach(rec => {
        const li = document.createElement("li");
        li.textContent = rec;
        recommendationsList.appendChild(li);
      });
    }
  }

  /**
   * Animate the SVG circular meter
   */
  function animateGauge(targetScore, level) {
    const circumference = 2 * Math.PI * 70; // r=70 -> ~439.8
    const offset = circumference - (targetScore / 100) * circumference;

    // Pick stroke color
    let strokeColor = "#16a34a"; // Green
    if (targetScore >= 76) strokeColor = "#dc2626"; // Red
    else if (targetScore >= 51) strokeColor = "#ea580c"; // Orange
    else if (targetScore >= 26) strokeColor = "#d97706"; // Amber

    gaugeProgress.style.stroke = strokeColor;
    gaugeProgress.style.strokeDasharray = `${circumference}`;
    gaugeProgress.style.strokeDashoffset = `${offset}`;

    // Number counting animation
    let current = 0;
    const duration = 1000;
    const stepTime = 20;
    const steps = duration / stepTime;
    const increment = targetScore / steps;

    const timer = setInterval(() => {
      current += increment;
      if (current >= targetScore) {
        current = targetScore;
        clearInterval(timer);
      }
      gaugeScoreValue.textContent = Math.round(current);
    }, stepTime);
  }

  // Safe HTML Escaping Helper
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
