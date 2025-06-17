document.getElementById("logout-link").addEventListener("click", function (e) {
    e.preventDefault();
    document.getElementById("logout-modal").style.display = "flex";
  });
  
  document.getElementById("cancel-logout").addEventListener("click", function () {
    document.getElementById("logout-modal").style.display = "none";
  });
  
  document.getElementById("confirm-logout").addEventListener("click", function () {
    window.location.href = "/logout";
  });