// Reusable DataTable component with sorting, search, categorical filters, and pagination.
// Column definitions: { key, label, render?, sortable?, searchable? }
// Filters are added via addFilter(key, placeholder, options[]).

export class DataTable {
  constructor({ columns, pageSize = 15, onRowClick = null, emptyMessage = 'No items found.' }) {
    this.columns = columns;
    this.pageSize = pageSize;
    this.onRowClick = onRowClick;
    this.emptyMessage = emptyMessage;

    this._all = [];
    this._filtered = [];
    this._sort = { key: null, dir: 1 };
    this._page = 0;
    this._search = '';
    this._activeFilters = {};
    this._searchTimer = null;
    this._selectedRow = null;

    this.el = this._build();
  }

  setData(data) {
    this._all = Array.isArray(data) ? data : [];
    this._page = 0;
    this._process();
  }

  _build() {
    const wrap = document.createElement('div');
    wrap.className = 'dt-wrap';

    // Toolbar row
    const toolbar = document.createElement('div');
    toolbar.className = 'dt-toolbar';

    this._searchInput = document.createElement('input');
    this._searchInput.type = 'search';
    this._searchInput.placeholder = 'Search…';
    this._searchInput.className = 'dt-search';
    this._searchInput.addEventListener('input', () => {
      clearTimeout(this._searchTimer);
      this._searchTimer = setTimeout(() => {
        this._search = this._searchInput.value.toLowerCase();
        this._page = 0;
        this._process();
      }, 180);
    });

    this._filterRow = document.createElement('div');
    this._filterRow.className = 'dt-filters';

    this._countEl = document.createElement('span');
    this._countEl.className = 'dt-count';

    toolbar.appendChild(this._searchInput);
    toolbar.appendChild(this._filterRow);
    toolbar.appendChild(this._countEl);
    wrap.appendChild(toolbar);

    // Table
    const scroll = document.createElement('div');
    scroll.className = 'dt-scroll';

    this._table = document.createElement('table');
    this._table.className = 'dt';
    this._thead = document.createElement('thead');
    this._tbody = document.createElement('tbody');
    this._table.append(this._thead, this._tbody);
    scroll.appendChild(this._table);
    wrap.appendChild(scroll);

    // Pagination
    this._pager = document.createElement('div');
    this._pager.className = 'dt-pager';
    wrap.appendChild(this._pager);

    this._buildHeader();
    return wrap;
  }

  _buildHeader() {
    const tr = document.createElement('tr');
    for (const col of this.columns) {
      const th = document.createElement('th');
      th.className = col.sortable === false ? '' : 'sortable';
      th.dataset.key = col.key;
      th.innerHTML = `<span>${col.label}</span>`;
      if (col.sortable !== false) {
        const arrow = document.createElement('span');
        arrow.className = 'sort-arrow';
        th.appendChild(arrow);
        th.addEventListener('click', () => this._setSort(col.key));
      }
      tr.appendChild(th);
    }
    this._thead.appendChild(tr);
  }

  addFilter(key, placeholder, options) {
    const sel = document.createElement('select');
    sel.className = 'dt-filter-sel';
    const all = document.createElement('option');
    all.value = '';
    all.textContent = placeholder;
    sel.appendChild(all);
    for (const opt of options) {
      const el = document.createElement('option');
      el.value = opt.value;
      el.textContent = opt.label;
      sel.appendChild(el);
    }
    sel.addEventListener('change', () => {
      this._activeFilters[key] = sel.value;
      this._page = 0;
      this._process();
    });
    this._filterRow.appendChild(sel);
    return this;
  }

  _setSort(key) {
    this._sort = { key, dir: this._sort.key === key ? -this._sort.dir : 1 };
    this._thead.querySelectorAll('th[data-key]').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
      if (th.dataset.key === key) th.classList.add(this._sort.dir === 1 ? 'sort-asc' : 'sort-desc');
    });
    this._process();
  }

  _process() {
    let data = [...this._all];

    if (this._search) {
      data = data.filter(item =>
        this.columns.some(col => {
          if (col.searchable === false) return false;
          const v = item[col.key];
          if (v == null) return false;
          if (Array.isArray(v)) return v.some(x => String(x).toLowerCase().includes(this._search));
          return String(v).toLowerCase().includes(this._search);
        }),
      );
    }

    for (const [key, value] of Object.entries(this._activeFilters)) {
      if (!value) continue;
      data = data.filter(item => {
        const v = item[key];
        if (Array.isArray(v)) return v.some(x => String(x).toLowerCase() === value.toLowerCase());
        return String(v ?? '').toLowerCase() === value.toLowerCase();
      });
    }

    if (this._sort.key) {
      const { key, dir } = this._sort;
      data.sort((a, b) => {
        const va = a[key] ?? '';
        const vb = b[key] ?? '';
        if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
        return String(va).localeCompare(String(vb)) * dir;
      });
    }

    this._filtered = data;
    this._render();
  }

  _render() {
    this._tbody.innerHTML = '';

    const total = this._filtered.length;
    const pages = Math.max(1, Math.ceil(total / this.pageSize));
    this._page = Math.min(this._page, pages - 1);

    const start = this._page * this.pageSize;
    const slice = this._filtered.slice(start, start + this.pageSize);

    this._countEl.textContent = total === this._all.length
      ? `${total} item${total !== 1 ? 's' : ''}`
      : `${total} / ${this._all.length} items`;

    if (slice.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = this.columns.length;
      td.className = 'dt-empty';
      td.textContent = this.emptyMessage;
      tr.appendChild(td);
      this._tbody.appendChild(tr);
    } else {
      for (const item of slice) {
        const tr = document.createElement('tr');
        tr.className = 'dt-row';
        if (this.onRowClick) {
          tr.addEventListener('click', () => {
            this._tbody.querySelectorAll('tr.dt-row').forEach(r => r.classList.remove('dt-row-selected'));
            tr.classList.add('dt-row-selected');
            this.onRowClick(item);
          });
        }
        for (const col of this.columns) {
          const td = document.createElement('td');
          const val = item[col.key];
          if (col.render) {
            const out = col.render(val, item);
            if (out instanceof Node) td.appendChild(out);
            else td.innerHTML = out ?? '';
          } else {
            td.textContent = val ?? '—';
          }
          tr.appendChild(td);
        }
        this._tbody.appendChild(tr);
      }
    }

    this._renderPager(pages);
  }

  _renderPager(pages) {
    this._pager.innerHTML = '';
    if (pages <= 1) return;

    const mkBtn = (text, disabled, onClick) => {
      const btn = document.createElement('button');
      btn.className = 'pager-btn';
      btn.textContent = text;
      btn.disabled = disabled;
      btn.addEventListener('click', onClick);
      return btn;
    };

    this._pager.appendChild(mkBtn('← Prev', this._page === 0, () => { this._page--; this._render(); }));
    const info = document.createElement('span');
    info.className = 'pager-info';
    info.textContent = `${this._page + 1} / ${pages}`;
    this._pager.appendChild(info);
    this._pager.appendChild(mkBtn('Next →', this._page >= pages - 1, () => { this._page++; this._render(); }));
  }
}
