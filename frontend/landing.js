(function () {
  var appButton = document.getElementById("to-app");
  var legalButton = document.getElementById("to-legal");
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
})();
