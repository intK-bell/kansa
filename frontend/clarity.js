(function () {
  var clarityProjectId = "vjnd5j5tbz";
  if (!clarityProjectId || window.clarity) return;
  window.clarity = window.clarity || function () {
    (window.clarity.q = window.clarity.q || []).push(arguments);
  };
  var script = document.createElement("script");
  script.async = true;
  script.src = "https://www.clarity.ms/tag/" + clarityProjectId;
  var firstScript = document.getElementsByTagName("script")[0];
  if (firstScript && firstScript.parentNode) {
    firstScript.parentNode.insertBefore(script, firstScript);
    return;
  }
  document.head.appendChild(script);
})();
