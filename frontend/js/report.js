/**
 * ScamShield - Community Report Controller
 * Handles report validation, credential checking, and API submission.
 */

document.addEventListener("DOMContentLoaded", () => {
  const reportForm = document.getElementById("reportForm");
  const scamMessage = document.getElementById("scamMessage");
  const scamCategory = document.getElementById("scamCategory");
  const scamPlatform = document.getElementById("scamPlatform");
  const senderInfo = document.getElementById("senderInfo");
  const websiteUrl = document.getElementById("websiteUrl");
  const reportDescription = document.getElementById("reportDescription");
  const anonymousCheck = document.getElementById("anonymousCheck");

  const submitBtn = document.getElementById("submitReportBtn");
  const btnText = document.getElementById("reportBtnText");
  const btnSpinner = document.getElementById("reportBtnSpinner");

  const successAlert = document.getElementById("successAlert");
  const successDetails = document.getElementById("successDetails");
  const errorAlert = document.getElementById("errorAlert");
  const errorMessage = document.getElementById("errorMessage");

  // Mobile nav
  const mobileNavBtn = document.getElementById("mobileNavBtn");
  const navLinks = document.getElementById("navLinks");
  if (mobileNavBtn && navLinks) {
    mobileNavBtn.addEventListener("click", () => {
      navLinks.classList.toggle("nav-open");
    });
  }

  function showError(msg) {
    errorMessage.textContent = msg;
    errorAlert.style.display = "flex";
    successAlert.style.display = "none";
    errorAlert.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function showSuccess(msg, storageBackend) {
    successDetails.textContent = `${msg} [Logged via ${storageBackend === "firebase" ? "Firebase Firestore" : "Secure Local Storage"}]`;
    successAlert.style.display = "flex";
    errorAlert.style.display = "none";
    successAlert.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function hideAlerts() {
    errorAlert.style.display = "none";
    successAlert.style.display = "none";
  }

  function setLoading(isLoading) {
    if (isLoading) {
      submitBtn.disabled = true;
      btnText.textContent = "Submitting Report...";
      btnSpinner.style.display = "inline-block";
    } else {
      submitBtn.disabled = false;
      btnText.textContent = "??? Submit Scam Report";
      btnSpinner.style.display = "none";
    }
  }

  reportForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAlerts();

    const msg = scamMessage.value.trim();
    const desc = reportDescription.value.trim();

    // 1. Client-Side Sensitive Credential Protection Check
    const combined = (msg + " " + desc).toLowerCase();
    if (/(?:cvv|cvc)\s*[:=]?\s*\d{3,4}/.test(combined) || /(?:atm pin|card pin|upi pin)\s*[:=]?\s*\d{4,6}/.test(combined)) {
      showError("Critical Safety Warning: Detected potential card CVV or PIN numbers. Please remove personal financial credentials before submitting!");
      return;
    }

    if (msg.length < 5) {
      showError("Scam message text must be at least 5 characters.");
      return;
    }

    setLoading(true);

    const payload = {
      message: msg,
      category: scamCategory.value,
      platform: scamPlatform.value,
      sender: senderInfo.value.trim(),
      url: websiteUrl.value.trim(),
      description: desc,
      anonymous: anonymousCheck.checked
    };

    try {
      const response = await fetch("/api/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to submit report.");
      }

      showSuccess(data.message || "Report logged successfully.", data.storage || "database");
      reportForm.reset();
      anonymousCheck.checked = true;

    } catch (err) {
      console.error("Report Submission Error:", err);
      showError(err.message || "Network error. Please try again later.");
    } finally {
      setLoading(false);
    }
  });
});
