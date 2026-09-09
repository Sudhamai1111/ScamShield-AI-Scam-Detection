/**
 * ScamShield - Statistics & Threat Intelligence Controller
 * Fetches aggregated statistics from /api/statistics and renders
 * dynamic bar charts and sanitized incident lists.
 */

document.addEventListener("DOMContentLoaded", () => {
  const statTotalReports = document.getElementById("statTotalReports");
  const statTopCategory = document.getElementById("statTopCategory");
  const statTopPlatform = document.getElementById("statTopPlatform");
  const statDbMode = document.getElementById("statDbMode");

  const categoryChartContainer = document.getElementById("categoryChartContainer");
  const platformChartContainer = document.getElementById("platformChartContainer");
  const recentReportsContainer = document.getElementById("recentReportsContainer");

  // Mobile nav
  const mobileNavBtn = document.getElementById("mobileNavBtn");
  const navLinks = document.getElementById("navLinks");
  if (mobileNavBtn && navLinks) {
    mobileNavBtn.addEventListener("click", () => {
      navLinks.classList.toggle("nav-open");
    });
  }

  loadStatistics();

  async function loadStatistics() {
    try {
      const res = await fetch("/api/statistics");
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to load statistics.");
      }

      renderKPIs(data);
      renderBarChart(categoryChartContainer, data.categories_breakdown || {});
      renderBarChart(platformChartContainer, data.platforms_breakdown || {}, true);
      renderRecentReports(data.recent_reports || []);

    } catch (err) {
      console.error("Statistics Loading Error:", err);
      categoryChartContainer.innerHTML = `<p style="color: var(--risk-high);">Could not load live charts (${escapeHtml(err.message)})</p>`;
    }
  }

  function renderKPIs(data) {
    statTotalReports.textContent = data.total_reports ?? 0;
    statTopCategory.textContent = data.top_category || "None";
    statTopPlatform.textContent = data.top_platform || "None";
    
    if (data.database_mode === "firebase") {
      statDbMode.textContent = "Firestore (Live)";
      statDbMode.style.color = "var(--risk-low)";
    } else {
      statDbMode.textContent = "Local Resilient";
      statDbMode.style.color = "var(--primary-blue)";
    }
  }

  function renderBarChart(container, breakdownMap, isPlatform = false) {
    container.innerHTML = "";
    const entries = Object.entries(breakdownMap);

    if (entries.length === 0) {
      container.innerHTML = '<p style="color: var(--text-muted);">No report data available yet.</p>';
      return;
    }

    // Sort descending by count
    entries.sort((a, b) => b[1] - a[1]);
    const maxCount = Math.max(...entries.map(e => e[1]), 1);

    entries.forEach(([label, count]) => {
      const percentage = Math.round((count / maxCount) * 100);
      const row = document.createElement("div");
      row.className = "bar-row";

      row.innerHTML = `
        <div class="bar-labels">
          <span>${escapeHtml(label)}</span>
          <span style="color: var(--text-muted); font-size: 0.85rem;">${count} reports</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill" style="width: 0%; ${isPlatform ? 'background: linear-gradient(90deg, #0284c7, #38bdf8);' : ''}"></div>
        </div>
      `;

      container.appendChild(row);

      // Trigger transition animation
      setTimeout(() => {
        const fill = row.querySelector(".bar-fill");
        if (fill) fill.style.width = `${percentage}%`;
      }, 50);
    });
  }

  function renderRecentReports(reports) {
    recentReportsContainer.innerHTML = "";

    if (reports.length === 0) {
      recentReportsContainer.innerHTML = '<p style="color: var(--text-muted);">No reports logged yet.</p>';
      return;
    }

    reports.forEach(r => {
      const card = document.createElement("div");
      card.style.cssText = "padding: 1rem; border: 1px solid var(--border-light); border-radius: var(--radius-md); background: #f8fafc;";

      const dateStr = r.created_at ? new Date(r.created_at).toLocaleDateString() : "Recent";
      const senderText = r.sender ? escapeHtml(r.sender) : "Anonymous";

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 0.75rem; background: #e2e8f0; color: var(--primary-navy); padding: 2px 8px; border-radius: var(--radius-full); font-weight: 700;">
              ${escapeHtml(r.category)}
            </span>
            <span style="font-size: 0.75rem; color: var(--text-muted);">
              via ${escapeHtml(r.platform)}
            </span>
          </div>
          <span style="font-size: 0.8rem; color: var(--text-muted);">${dateStr}</span>
        </div>
        <p style="font-size: 0.9rem; font-family: monospace; color: var(--text-primary); margin-bottom: 0.4rem; background: #ffffff; padding: 0.5rem; border-radius: 4px; border: 1px solid var(--border-light);">
          "${escapeHtml(r.message)}"
        </p>
        <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-muted);">
          <span>Sender: ${senderText}</span>
          ${r.url ? `<span>URL: <span style="color: var(--risk-high);">${escapeHtml(r.url)}</span></span>` : ""}
        </div>
      `;

      recentReportsContainer.appendChild(card);
    });
  }

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
