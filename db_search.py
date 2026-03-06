import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import os
import time
from cryptography.fernet import Fernet

VERSION = '2026.03.06.002'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, '.secret.key')
CONFIG_FILE = os.path.join(BASE_DIR, 'config.dat')
OLD_CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')


# ── 암호화 ──────────────────────────────────────────────

def _get_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key


def _encrypt(data: dict) -> bytes:
    f = Fernet(_get_key())
    return f.encrypt(json.dumps(data, ensure_ascii=False).encode('utf-8'))


def _decrypt(token: bytes) -> dict:
    f = Fernet(_get_key())
    return json.loads(f.decrypt(token).decode('utf-8'))


# ── 설정 관리 ──────────────────────────────────────────────

DEFAULT_CONFIG = {
    'databases': [
        {
            'label': '[MSSQL] MyDatabase',
            'type': 'mssql',
            'host': 'localhost',
            'port': 1433,
            'database': 'MyDatabase',
            'user': '',
            'password': '',
        },
        {
            'label': '[PG] MyDatabase',
            'type': 'postgresql',
            'host': 'localhost',
            'port': 5432,
            'database': 'mydb',
            'user': 'postgres',
            'password': '',
        },
    ]
}


def load_config():
    # 기존 config.json이 있으면 암호화로 마이그레이션
    if os.path.exists(OLD_CONFIG_FILE):
        with open(OLD_CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        save_config(cfg)
        os.remove(OLD_CONFIG_FILE)
        return cfg

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'rb') as f:
            return _decrypt(f.read())

    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG


def save_config(cfg):
    with open(CONFIG_FILE, 'wb') as f:
        f.write(_encrypt(cfg))


# ── DB 연결 ──────────────────────────────────────────────

def connect_mssql(cfg):
    import pyodbc
    driver = '{ODBC Driver 18 for SQL Server}'
    server = f"{cfg['host']},{cfg['port']}"
    conn_str = f"DRIVER={driver};SERVER={server};DATABASE={cfg['database']};TrustServerCertificate=yes;"
    if cfg.get('user'):
        conn_str += f"UID={cfg['user']};PWD={cfg['password']};"
    else:
        conn_str += "Trusted_Connection=yes;"
    conn = pyodbc.connect(conn_str, timeout=10)
    conn.timeout = 10
    return conn


def connect_pg(cfg):
    import psycopg2
    return psycopg2.connect(
        host=cfg['host'], port=cfg['port'],
        dbname=cfg['database'],
        user=cfg['user'], password=cfg['password']
    )


# ── 검색 로직 ──────────────────────────────────────────────

def escape_sql(value):
    return value.replace("'", "''")


def search_mssql(cfg, search_value, on_progress, on_found, on_done, on_error, stop_flag):
    try:
        conn = connect_mssql(cfg)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE DATA_TYPE IN (
                'char','nchar','varchar','nvarchar','text','ntext',
                'int','bigint','smallint','tinyint',
                'numeric','decimal','float','real'
            )
            AND TABLE_SCHEMA NOT IN ('sys','INFORMATION_SCHEMA')
            ORDER BY TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
        """)
        columns = cursor.fetchall()
        total = len(columns)
        start_time = time.time()

        for i, (schema, table, column) in enumerate(columns):
            if stop_flag():
                on_done(cancelled=True)
                conn.close()
                return

            elapsed = time.time() - start_time
            eta = (elapsed / (i + 1)) * (total - i - 1) if i > 0 else 0
            on_progress(i + 1, total, f'{schema}.{table}.{column}', elapsed, eta)

            sql = f"""
                SELECT COUNT(*) FROM [{schema}].[{table}]
                WHERE CAST([{column}] AS NVARCHAR(MAX)) LIKE ?
            """
            try:
                cursor.execute(sql, f'%{search_value}%')
                count = cursor.fetchone()[0]
                if count > 0:
                    on_found(schema, table, column, count)
            except Exception:
                pass

        conn.close()
        elapsed = time.time() - start_time
        on_done(elapsed=elapsed)
    except Exception as e:
        on_error(str(e))


def search_pg(cfg, search_value, on_progress, on_found, on_done, on_error, stop_flag):
    try:
        conn = connect_pg(cfg)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT table_schema, table_name, column_name
            FROM information_schema.columns
            WHERE table_schema NOT IN ('pg_catalog','information_schema')
              AND data_type IN (
                  'character varying','text','character',
                  'timestamp without time zone','timestamp with time zone',
                  'date','integer','bigint','smallint','numeric','real','double precision'
              )
            ORDER BY table_schema, table_name, column_name
        """)
        columns = cursor.fetchall()
        total = len(columns)
        start_time = time.time()
        safe_value = escape_sql(search_value)

        for i, (schema, table, column) in enumerate(columns):
            if stop_flag():
                on_done(cancelled=True)
                conn.close()
                return

            elapsed = time.time() - start_time
            eta = (elapsed / (i + 1)) * (total - i - 1) if i > 0 else 0
            on_progress(i + 1, total, f'{schema}.{table}.{column}', elapsed, eta)

            sql = f"""SELECT COUNT(*) FROM "{schema}"."{table}" WHERE ("{column}")::text LIKE '%{safe_value}%'"""
            try:
                cursor.execute(sql)
                count = cursor.fetchone()[0]
                if count > 0:
                    on_found(schema, table, column, count)
            except Exception:
                conn.rollback()

        conn.close()
        elapsed = time.time() - start_time
        on_done(elapsed=elapsed)
    except Exception as e:
        on_error(str(e))


# ── 테두리 버튼 헬퍼 ──────────────────────────────────────────

def bordered_button(parent, text, command, color, bg='#ffffff', font=('Segoe UI', 9), bold=False, state='normal'):
    border = tk.Frame(parent, bg=color, bd=0)
    f = (font[0], font[1], 'bold') if bold else font
    btn = tk.Button(border, text=text, command=command,
                    fg=color, bg=bg, relief='flat', font=f,
                    padx=10, pady=1, cursor='hand2', state=state,
                    activeforeground=color, activebackground=bg)
    btn.pack(padx=1, pady=1)
    return border, btn


# ── 설정 창 ──────────────────────────────────────────────

class SettingsDialog:
    def __init__(self, parent, config, on_save):
        self.config = config
        self.on_save = on_save

        self.win = tk.Toplevel(parent)
        self.win.title('DB 연결 설정')
        self.win.geometry('700x520')
        self.win.configure(bg='#f0f2f5')
        self.win.transient(parent)
        self.win.grab_set()

        self._build_ui()

    def _build_ui(self):
        list_frame = tk.Frame(self.win, bg='#f0f2f5')
        list_frame.pack(fill='x', padx=12, pady=(12, 0))

        tk.Label(list_frame, text='DB 연결 목록', bg='#f0f2f5',
                 font=('Segoe UI', 10, 'bold'), fg='#374151').pack(side='left')

        btn_frame = tk.Frame(list_frame, bg='#f0f2f5')
        btn_frame.pack(side='right')
        add_border, _ = bordered_button(btn_frame, '+ 추가', self._add_db, '#2563eb', bg='#f0f2f5')
        add_border.pack(side='left', padx=4)
        del_border, _ = bordered_button(btn_frame, '- 삭제', self._remove_db, '#dc2626', bg='#f0f2f5')
        del_border.pack(side='left')

        self.db_listbox = tk.Listbox(self.win, font=('Segoe UI', 10), height=6,
                                     selectmode='browse', activestyle='none')
        self.db_listbox.pack(fill='x', padx=12, pady=(6, 0))
        self.db_listbox.bind('<<ListboxSelect>>', self._on_select)

        for db in self.config['databases']:
            self.db_listbox.insert('end', db['label'])

        self.edit_frame = tk.LabelFrame(self.win, text='연결 정보', bg='#ffffff',
                                        font=('Segoe UI', 9), fg='#6b7280',
                                        padx=12, pady=8)
        self.edit_frame.pack(fill='both', expand=True, padx=12, pady=(8, 0))

        fields = [
            ('label', '표시명'),
            ('type', '타입 (mssql / postgresql)'),
            ('host', '호스트'),
            ('port', '포트'),
            ('database', '데이터베이스'),
            ('user', '사용자 (빈값=Windows인증)'),
            ('password', '비밀번호'),
        ]
        self.field_vars = {}
        for key, lbl in fields:
            row = tk.Frame(self.edit_frame, bg='#ffffff')
            row.pack(fill='x', pady=2)
            tk.Label(row, text=lbl, bg='#ffffff', font=('Segoe UI', 9),
                     fg='#374151', width=26, anchor='w').pack(side='left')
            var = tk.StringVar()
            show = '*' if key == 'password' else ''
            entry = tk.Entry(row, textvariable=var, font=('Segoe UI', 9),
                             width=40, show=show)
            entry.pack(side='left', fill='x', expand=True)
            self.field_vars[key] = var

        bottom = tk.Frame(self.win, bg='#f0f2f5')
        bottom.pack(fill='x', padx=12, pady=12)

        save_border, _ = bordered_button(bottom, '저장', self._save, '#2563eb', bg='#f0f2f5',
                                         font=('Segoe UI', 10), bold=True)
        save_border.pack(side='right', padx=(8, 0))
        cancel_border, _ = bordered_button(bottom, '취소', self.win.destroy, '#6b7280', bg='#f0f2f5',
                                            font=('Segoe UI', 10))
        cancel_border.pack(side='right')

        if self.config['databases']:
            self.db_listbox.selection_set(0)
            self._load_fields(0)

    def _on_select(self, event):
        sel = self.db_listbox.curselection()
        if sel:
            self._save_current_fields()
            self._load_fields(sel[0])

    def _load_fields(self, idx):
        self._current_idx = idx
        db = self.config['databases'][idx]
        for key, var in self.field_vars.items():
            var.set(str(db.get(key, '')))

    def _save_current_fields(self):
        if not hasattr(self, '_current_idx'):
            return
        idx = self._current_idx
        if idx >= len(self.config['databases']):
            return
        db = self.config['databases'][idx]
        for key, var in self.field_vars.items():
            val = var.get().strip()
            if key == 'port':
                try:
                    val = int(val)
                except ValueError:
                    val = 0
            db[key] = val
        self.db_listbox.delete(idx)
        self.db_listbox.insert(idx, db['label'])

    def _add_db(self):
        new_db = {
            'label': '[MSSQL] NewDB',
            'type': 'mssql',
            'host': 'localhost',
            'port': 1433,
            'database': '',
            'user': '',
            'password': '',
        }
        self.config['databases'].append(new_db)
        self.db_listbox.insert('end', new_db['label'])
        self.db_listbox.selection_clear(0, 'end')
        self.db_listbox.selection_set('end')
        self._load_fields(len(self.config['databases']) - 1)

    def _remove_db(self):
        sel = self.db_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        self.config['databases'].pop(idx)
        self.db_listbox.delete(idx)
        if self.config['databases']:
            new_idx = min(idx, len(self.config['databases']) - 1)
            self.db_listbox.selection_set(new_idx)
            self._load_fields(new_idx)

    def _save(self):
        self._save_current_fields()
        save_config(self.config)
        self.on_save(self.config)
        self.win.destroy()


# ── 메인 GUI ──────────────────────────────────────────────

class DBSearchApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f'DB 전체 데이터 검색  v{VERSION}')
        self.root.geometry('920x620')
        self.root.configure(bg='#f0f2f5')

        self.config = load_config()
        self.searching = False
        self._stop = False
        self.result_count = 0
        self._current_db_type = 'mssql'
        self._current_search_value = ''

        icon_path = os.path.join(BASE_DIR, 'icon.ico')
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)

        self._build_ui()

    def _build_ui(self):
        # ── 상단: 검색 영역 ──
        top = tk.Frame(self.root, bg='#ffffff', padx=12, pady=10)
        top.pack(fill='x', padx=10, pady=(10, 0))

        tk.Label(top, text='DB:', bg='#ffffff', font=('Segoe UI', 10)).pack(side='left')
        self.db_var = tk.StringVar()
        self.db_combo = ttk.Combobox(top, textvariable=self.db_var, state='readonly', width=30)
        self.db_combo.pack(side='left', padx=(4, 12))
        self._refresh_db_list()

        tk.Label(top, text='검색어:', bg='#ffffff', font=('Segoe UI', 10)).pack(side='left')
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(top, textvariable=self.search_var, width=30, font=('Segoe UI', 10))
        self.search_entry.pack(side='left', padx=(4, 12))
        self.search_entry.bind('<Return>', lambda e: self._start_search())
        self.search_entry.focus_set()

        search_border, self.search_btn = bordered_button(
            top, '검색', self._start_search, '#2563eb', bold=True)
        search_border.pack(side='left', padx=(0, 4))

        self.stop_border, self.stop_btn = bordered_button(
            top, '중단', self._stop_search, '#dc2626', bold=True, state='disabled')
        self.stop_border.pack(side='left', padx=(0, 8))

        settings_border, _ = bordered_button(
            top, '설정', self._open_settings, '#6b7280')
        settings_border.pack(side='right')

        # ── 진행률 ──
        status_frame = tk.Frame(self.root, bg='#f0f2f5')
        status_frame.pack(fill='x', padx=10, pady=(6, 0))

        status_top = tk.Frame(status_frame, bg='#f0f2f5')
        status_top.pack(fill='x')

        self.status_label = tk.Label(status_top, text='준비', bg='#f0f2f5',
                                     font=('Segoe UI', 9), fg='#6b7280', anchor='w')
        self.status_label.pack(side='left')

        self.time_label = tk.Label(status_top, text='', bg='#f0f2f5',
                                   font=('Segoe UI', 9), fg='#6b7280', anchor='e')
        self.time_label.pack(side='right')

        self.progress = ttk.Progressbar(status_frame, mode='determinate', length=400)
        self.progress.pack(fill='x', pady=(2, 0))

        # ── 결과 테이블 ──
        table_frame = tk.Frame(self.root, bg='#f0f2f5')
        table_frame.pack(fill='both', expand=True, padx=10, pady=(8, 10))

        cols = ('no', 'schema', 'table', 'column', 'count')
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings', selectmode='browse')

        self.tree.heading('no', text='#')
        self.tree.heading('schema', text='Schema')
        self.tree.heading('table', text='Table')
        self.tree.heading('column', text='Column')
        self.tree.heading('count', text='Count')

        self.tree.column('no', width=40, anchor='center', stretch=False)
        self.tree.column('schema', width=120)
        self.tree.column('table', width=280)
        self.tree.column('column', width=280)
        self.tree.column('count', width=80, anchor='e')

        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        self.tree.bind('<Double-1>', self._on_row_dblclick)
        self.tree.bind('<Button-3>', self._on_row_rightclick)

        # ── 하단 ──
        bottom = tk.Frame(self.root, bg='#f0f2f5')
        bottom.pack(fill='x', padx=10, pady=(0, 8))

        tk.Label(bottom, text=f'v{VERSION}  |  더블클릭: 셀 복사  |  우클릭: 쿼리 복사', bg='#f0f2f5',
                 font=('Segoe UI', 8), fg='#9ca3af').pack(side='left')
        self.count_label = tk.Label(bottom, text='결과: 0건', bg='#f0f2f5',
                                    font=('Segoe UI', 9, 'bold'), fg='#374151', anchor='e')
        self.count_label.pack(side='right')

    def _refresh_db_list(self):
        labels = [db['label'] for db in self.config['databases']]
        self.db_combo['values'] = labels
        if labels:
            self.db_combo.current(0)

    def _open_settings(self):
        import copy
        cfg_copy = copy.deepcopy(self.config)
        SettingsDialog(self.root, cfg_copy, self._on_settings_saved)

    def _on_settings_saved(self, new_config):
        self.config = new_config
        self._refresh_db_list()

    def _start_search(self):
        if self.searching:
            return

        search_value = self.search_var.get().strip()
        if not search_value:
            messagebox.showwarning('입력 필요', '검색어를 입력하세요')
            return

        db_label = self.db_var.get()
        cfg = next((c for c in self.config['databases'] if c['label'] == db_label), None)
        if not cfg:
            messagebox.showerror('오류', 'DB를 선택하세요')
            return

        self.tree.delete(*self.tree.get_children())
        self.result_count = 0
        self.count_label.config(text='결과: 0건')
        self.progress['value'] = 0
        self.searching = True
        self._stop = False
        self._current_db_type = cfg['type']
        self._current_search_value = search_value
        self.search_btn.config(state='disabled')
        self.stop_btn.config(state='normal')

        search_fn = search_mssql if cfg['type'] == 'mssql' else search_pg
        t = threading.Thread(target=search_fn, args=(
            cfg, search_value,
            self._on_progress, self._on_found, self._on_done, self._on_error,
            lambda: self._stop
        ), daemon=True)
        t.start()

    def _stop_search(self):
        self._stop = True

    def _on_progress(self, current, total, target, elapsed, eta):
        self.root.after(0, self._update_progress, current, total, target, elapsed, eta)

    def _format_time(self, seconds):
        m, s = divmod(int(seconds), 60)
        if m > 0:
            return f'{m}분 {s}초'
        return f'{s}초'

    def _update_progress(self, current, total, target, elapsed, eta):
        pct = (current / total) * 100
        self.progress['value'] = pct
        self.status_label.config(text=f'{current}/{total} ({pct:.0f}%) - {target}')
        self.time_label.config(text=f'경과: {self._format_time(elapsed)}  |  남은: ~{self._format_time(eta)}')

    def _on_found(self, schema, table, column, count):
        self.root.after(0, self._add_result, schema, table, column, count)

    def _add_result(self, schema, table, column, count):
        self.result_count += 1
        self.tree.insert('', 'end', values=(self.result_count, schema, table, column, f'{count:,}'))
        self.count_label.config(text=f'결과: {self.result_count}건')

    def _on_done(self, cancelled=False, elapsed=0):
        if cancelled:
            msg = '검색 중단됨'
        else:
            msg = f'검색 완료 (총 {self._format_time(elapsed)})'
        self.root.after(0, self._finish, msg)

    def _on_error(self, msg):
        self.root.after(0, self._finish, f'오류: {msg}')

    def _finish(self, msg):
        self.searching = False
        self.search_btn.config(state='normal')
        self.time_label.config(text='')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text=msg)
        self.progress['value'] = 100

    # ── 행 더블클릭 / 우클릭 ──

    def _get_row_data(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return None
        vals = self.tree.item(item, 'values')
        # vals: (no, schema, table, column, count)
        return {'schema': vals[1], 'table': vals[2], 'column': vals[3], 'count': vals[4]}

    def _build_query(self, row):
        schema, table, column = row['schema'], row['table'], row['column']
        sv = self._current_search_value
        if self._current_db_type == 'mssql':
            return f"SELECT * FROM [{schema}].[{table}] WHERE [{column}] LIKE N'%{sv}%'"
        else:
            return f"""SELECT * FROM "{schema}"."{table}" WHERE "{column}"::text LIKE '%{sv}%'"""

    def _copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_label.config(text=f'클립보드 복사됨: {text[:80]}...' if len(text) > 80 else f'클립보드 복사됨: {text}')

    def _on_row_dblclick(self, event):
        item = self.tree.identify_row(event.y)
        col_id = self.tree.identify_column(event.x)
        if not item or not col_id:
            return
        col_idx = int(col_id.replace('#', '')) - 1
        vals = self.tree.item(item, 'values')
        if 0 <= col_idx < len(vals):
            self._copy_to_clipboard(str(vals[col_idx]))

    def _on_row_rightclick(self, event):
        row = self._get_row_data(event)
        if not row:
            return

        # 해당 행 선택
        item = self.tree.identify_row(event.y)
        self.tree.selection_set(item)

        query = self._build_query(row)
        sv = self._current_search_value
        schema, table, column = row['schema'], row['table'], row['column']

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label='SELECT 쿼리 복사', command=lambda: self._copy_to_clipboard(query))
        menu.add_separator()
        menu.add_command(label=f'테이블명 복사: {schema}.{table}',
                         command=lambda: self._copy_to_clipboard(f'{schema}.{table}'))
        menu.add_command(label=f'컬럼명 복사: {column}',
                         command=lambda: self._copy_to_clipboard(column))
        menu.add_separator()
        if self._current_db_type == 'mssql':
            count_q = f"SELECT COUNT(*) FROM [{schema}].[{table}] WHERE [{column}] LIKE N'%{sv}%'"
        else:
            count_q = f"""SELECT COUNT(*) FROM "{schema}"."{table}" WHERE "{column}"::text LIKE '%{sv}%'"""
        menu.add_command(label='COUNT 쿼리 복사', command=lambda: self._copy_to_clipboard(count_q))
        menu.post(event.x_root, event.y_root)


if __name__ == '__main__':
    root = tk.Tk()
    app = DBSearchApp(root)
    root.mainloop()
