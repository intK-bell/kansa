(function () {
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
