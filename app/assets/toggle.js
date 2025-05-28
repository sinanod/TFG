window.addEventListener("load", function () {
  const toggleButton = document.getElementById("toggle-button");
  const sidebar = document.querySelector(".sidebar");

  if (toggleButton && sidebar) {
    toggleButton.addEventListener("click", function () {
      sidebar.classList.toggle("collapsed");
    });
  }
});
