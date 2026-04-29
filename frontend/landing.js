(function () {
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

  var appButton = document.getElementById("to-app");
  var legalButton = document.getElementById("to-legal");
  var demoButtons = [document.getElementById("to-demo-top"), document.getElementById("to-demo-bottom")];

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
