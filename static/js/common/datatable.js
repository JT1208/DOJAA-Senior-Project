// Shared DataTables defaults so every table looks and behaves the same.

(function (global) {
  const DOM_LAYOUT =
    "<'dt-toolbar'<'dt-toolbar__left'l><'dt-toolbar__right'f>>" +
    "<'dt-body'tr>" +
    "<'dt-foot'<'dt-foot__left'i><'dt-foot__right'p>>";

  function init(selector, overrides = {}) {
    if (!global.jQuery || !global.jQuery.fn || !global.jQuery.fn.DataTable) {
      // DataTables not loaded — bail silently rather than throwing.
      return null;
    }
    return global.jQuery(selector).DataTable(Object.assign({
      paging: true,
      pageLength: 25,
      lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
      searching: true,
      ordering: true,
      autoWidth: false,
      dom: DOM_LAYOUT,
      pagingType: "simple_numbers",
      language: {
        emptyTable: "No data — try a rescan from this page or check API credentials.",
        zeroRecords: "No matching rows.",
        info: "Showing _START_–_END_ of _TOTAL_",
        infoEmpty: "Showing 0 of 0",
        infoFiltered: "(filtered from _MAX_)",
        lengthMenu: "Rows: _MENU_",
        search: "",
        searchPlaceholder: "Search",
        paginate: { previous: "Prev", next: "Next" },
      },
    }, overrides));
  }

  global.dojaaTable = { init };
})(window);
