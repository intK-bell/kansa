(function () {
  var params = new URLSearchParams(window.location.search);
  var disableClarity = params.has("noclarity");

  if (!disableClarity) {
    var clarityId = "wiygdr6cwn";

    window.clarity =
      window.clarity ||
      function () {
        (window.clarity.q = window.clarity.q || []).push(arguments);
      };

    var clarityScript = document.createElement("script");
    clarityScript.async = true;
    clarityScript.src = "https://www.clarity.ms/tag/" + clarityId;

    var firstScript = document.getElementsByTagName("script")[0];
    firstScript.parentNode.insertBefore(clarityScript, firstScript);
  }

  // -------------------------
  // Clarity Event Tracking
  // -------------------------
  document.addEventListener("click", function (event) {
    var button = event.target.closest(".btn.btn-primary");

    if (!button || typeof window.clarity !== "function") {
      return;
    }

    // Hero CTA
    if (button.closest(".hero")) {
      window.clarity("event", "lp_click_hero_free");
    }

    // Bottom CTA
    else if (button.closest(".bottom-cta")) {
      window.clarity("event", "lp_click_bottom_free");
    }

    // Apply section
    else if (button.id === "to-app") {
      window.clarity("event", "lp_click_apply");
    }
  });

  var appButton = document.getElementById("to-app");
  var legalButton = document.getElementById("to-legal");
  var demoButtons = [
    document.getElementById("to-demo-top"),
    document.getElementById("to-demo-bottom"),
  ];

  if (appButton) {
    appButton.addEventListener("click", function () {
      window.location.href = "./index.html";
    });
  }

  if (legalButton) {
    legalButton.addEventListener("click", function () {
      window.location.href = "./legal.html";
    });
  }

  demoButtons.forEach(function (button) {
    if (button) {
      button.addEventListener("click", function () {
        window.location.href = "./demo.html";
      });
    }
  });
})();