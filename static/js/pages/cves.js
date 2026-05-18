(function () {
  document.addEventListener("DOMContentLoaded", function () {
    window.dojaaTable.init("#cvesTable", {
      order: [[3, "desc"]],
      pageLength: 15,
      columnDefs: [{ targets: [6, 7], orderable: false }],
    });
  });
})();
