import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import os
import re
import sys
import time
from cryptography.fernet import Fernet

VERSION = '1.1.0'
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, '.secret.key')
CONFIG_FILE = os.path.join(BASE_DIR, 'config.dat')
OLD_CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')


def resource_path(name):
    if getattr(sys, 'frozen', False):
        bundled = os.path.join(getattr(sys, '_MEIPASS', BASE_DIR), name)
        if os.path.exists(bundled):
            return bundled
    return os.path.join(BASE_DIR, name)


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
            'comment': '',
            'type': 'mssql',
            'host': 'localhost',
            'port': 1433,
            'database': 'MyDatabase',
            'auth': 'windows',
            'user': '',
            'password': '',
            'oracle_sid': False,
        },
        {
            'label': '[PG] MyDatabase',
            'comment': '',
            'type': 'postgresql',
            'host': 'localhost',
            'port': 5432,
            'database': 'mydb',
            'auth': 'userpass',
            'user': 'postgres',
            'password': '',
            'oracle_sid': False,
        },
    ]
}


def normalize_config(cfg):
    defaults = {
        'label': '',
        'comment': '',
        'type': 'mssql',
        'host': '',
        'port': 1433,
        'database': '',
        'auth': 'userpass',
        'user': '',
        'password': '',
        'oracle_sid': False,
    }
    cfg.setdefault('databases', [])
    for db in cfg['databases']:
        old_has_auth = 'auth' in db
        for key, val in defaults.items():
            db.setdefault(key, val)
        try:
            db['port'] = int(db.get('port') or 0)
        except (TypeError, ValueError):
            db['port'] = 0
        db['oracle_sid'] = bool(db.get('oracle_sid'))
        if not old_has_auth:
            if db.get('type') == 'mssql' and not db.get('user'):
                db['auth'] = 'windows'
            else:
                db['auth'] = 'userpass'
    return cfg


def load_config():
    # 기존 config.json이 있으면 암호화로 마이그레이션
    if os.path.exists(OLD_CONFIG_FILE):
        with open(OLD_CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = normalize_config(json.load(f))
        save_config(cfg)
        os.remove(OLD_CONFIG_FILE)
        return normalize_config(cfg)

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'rb') as f:
            return normalize_config(_decrypt(f.read()))

    save_config(DEFAULT_CONFIG)
    return normalize_config(DEFAULT_CONFIG)


def save_config(cfg):
    with open(CONFIG_FILE, 'wb') as f:
        f.write(_encrypt(cfg))


# ── JDBC URL ──────────────────────────────────────────────

DEFAULT_PORTS = {
    'mssql': 1433,
    'postgresql': 5432,
    'oracle': 1521,
}


def build_jdbc_url(db: dict) -> str:
    db_type = db.get('type', 'mssql')
    host = db.get('host', '')
    port = db.get('port') or DEFAULT_PORTS.get(db_type, 0)
    database = db.get('database', '')
    if db_type == 'postgresql':
        return f'jdbc:postgresql://{host}:{port}/{database}'
    if db_type == 'oracle':
        if db.get('oracle_sid'):
            return f'jdbc:oracle:thin:@{host}:{port}:{database}'
        return f'jdbc:oracle:thin:@//{host}:{port}/{database}'
    return f'jdbc:sqlserver://{host}:{port};databaseName={database}'


def parse_jdbc_url(url: str) -> dict | None:
    try:
        text = (url or '').strip()
        if not text:
            return None
        if text.lower().startswith('jdbc:'):
            text = text[5:]

        m = re.match(r'^sqlserver://([^;/:]+)(?::(\d+))?(.*)$', text, re.I)
        if m:
            host, port, props = m.group(1), m.group(2), m.group(3) or ''
            database = ''
            for part in props.split(';'):
                if '=' not in part:
                    continue
                key, val = part.split('=', 1)
                if key.strip().lower() in ('databasename', 'database'):
                    database = val
                    break
            return {
                'type': 'mssql',
                'host': host,
                'port': int(port) if port else 1433,
                'database': database,
                'oracle_sid': False,
            }

        m = re.match(r'^postgresql://([^/:?]+)(?::(\d+))?(?:/([^?]*))?(?:\?.*)?$', text, re.I)
        if m:
            return {
                'type': 'postgresql',
                'host': m.group(1),
                'port': int(m.group(2)) if m.group(2) else 5432,
                'database': m.group(3) or '',
                'oracle_sid': False,
            }

        m = re.match(r'^oracle:thin:@//([^/:]+)(?::(\d+))?/([^?]+)$', text, re.I)
        if m:
            return {
                'type': 'oracle',
                'host': m.group(1),
                'port': int(m.group(2)) if m.group(2) else 1521,
                'database': m.group(3),
                'oracle_sid': False,
            }

        m = re.match(r'^oracle:thin:@([^/:]+)(?::(\d+))?:([^/?]+)$', text, re.I)
        if m:
            return {
                'type': 'oracle',
                'host': m.group(1),
                'port': int(m.group(2)) if m.group(2) else 1521,
                'database': m.group(3),
                'oracle_sid': True,
            }

        m = re.match(r'^oracle:thin:@([^/:]+)(?::(\d+))?/([^?]+)$', text, re.I)
        if m:
            return {
                'type': 'oracle',
                'host': m.group(1),
                'port': int(m.group(2)) if m.group(2) else 1521,
                'database': m.group(3),
                'oracle_sid': False,
            }
    except Exception:
        return None
    return None


# ── DB 연결 ──────────────────────────────────────────────

def connect_mssql(cfg):
    import pyodbc
    driver = '{ODBC Driver 18 for SQL Server}'
    server = f"{cfg['host']},{cfg['port']}"
    conn_str = f"DRIVER={driver};SERVER={server};DATABASE={cfg['database']};TrustServerCertificate=yes;"
    if cfg.get('auth') == 'windows' or not cfg.get('user'):
        conn_str += "Trusted_Connection=yes;"
    else:
        conn_str += f"UID={cfg['user']};PWD={cfg['password']};"
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


def connect_oracle(cfg):
    import oracledb
    if cfg.get('oracle_sid'):
        dsn = oracledb.makedsn(cfg['host'], cfg['port'], sid=cfg['database'])
    else:
        dsn = f"{cfg['host']}:{cfg['port']}/{cfg['database']}"
    return oracledb.connect(user=cfg['user'], password=cfg['password'], dsn=dsn)


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


def search_oracle(cfg, search_value, on_progress, on_found, on_done, on_error, stop_flag):
    try:
        conn = connect_oracle(cfg)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT OWNER, TABLE_NAME, COLUMN_NAME
            FROM ALL_TAB_COLUMNS
            WHERE DATA_TYPE IN (
                'CHAR','VARCHAR2','NCHAR','NVARCHAR2','CLOB','NCLOB',
                'NUMBER','FLOAT','BINARY_FLOAT','BINARY_DOUBLE','INTEGER',
                'DATE','TIMESTAMP(6)','TIMESTAMP(0)','TIMESTAMP'
            )
            AND OWNER NOT IN (
                'SYS','SYSTEM','XDB','MDSYS','CTXSYS','OUTLN','APPQOSSYS',
                'DBSNMP','GSMADMIN_INTERNAL','OJVMSYS','OLAPSYS','ORDDATA',
                'ORDPLUGINS','ORDSYS','SI_INFORMTN_SCHEMA','WMSYS','LBACSYS',
                'AUDSYS','REMOTE_SCHEDULER_AGENT','GSMUSER','GSMCATUSER',
                'SYSBACKUP','SYSDG','SYSKM','SYSRAC','XS$NULL','DIP',
                'ANONYMOUS','ORACLE_OCM','PUBLIC','FLOWS_FILES',
                'APEX_PUBLIC_USER','APEX_REST_PUBLIC_USER','APEX_LISTENER',
                'HR','SCOTT','PDBADMIN','DVF','DVSYS','GGSYS','MDDATA',
                'CTXAPP','EXFSYS','OWBSYS'
            )
            AND OWNER NOT LIKE 'APEX_%'
            AND OWNER NOT LIKE 'GG_%'
            ORDER BY OWNER, TABLE_NAME, COLUMN_NAME
        """)
        columns = cursor.fetchall()
        total = len(columns)
        start_time = time.time()
        pattern = f'%{search_value}%'

        for i, (schema, table, column) in enumerate(columns):
            if stop_flag():
                on_done(cancelled=True)
                conn.close()
                return

            elapsed = time.time() - start_time
            eta = (elapsed / (i + 1)) * (total - i - 1) if i > 0 else 0
            on_progress(i + 1, total, f'{schema}.{table}.{column}', elapsed, eta)

            sql = f'SELECT COUNT(*) FROM "{schema}"."{table}" WHERE TO_CHAR("{column}") LIKE :q'
            try:
                cursor.execute(sql, q=pattern)
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


def show_copyable_error(parent, title, msg):
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg='#f0f2f5')
    win.geometry('640x320')
    win.minsize(400, 200)

    text_frame = tk.Frame(win, bg='#f0f2f5')
    text_frame.pack(fill='both', expand=True, padx=10, pady=(10, 0))

    txt = tk.Text(text_frame, wrap='word', font=('Consolas', 10),
                  bg='white', fg='#b00020', borderwidth=1, relief='solid')
    yscroll = ttk.Scrollbar(text_frame, orient='vertical', command=txt.yview)
    txt.configure(yscrollcommand=yscroll.set)
    yscroll.pack(side='right', fill='y')
    txt.pack(side='left', fill='both', expand=True)
    txt.insert('1.0', msg)
    txt.config(state='disabled')
    # Text 위젯은 마우스 드래그로 선택 + Ctrl+C 기본 동작 가능

    btn_frame = tk.Frame(win, bg='#f0f2f5')
    btn_frame.pack(fill='x', padx=10, pady=10)

    def do_copy():
        parent.clipboard_clear()
        parent.clipboard_append(msg)
        copy_btn.config(text='복사됨!')
        win.after(1200, lambda: copy_btn.config(text='전체 복사'))

    copy_btn = tk.Button(btn_frame, text='전체 복사', command=do_copy, width=12)
    copy_btn.pack(side='left')
    tk.Button(btn_frame, text='닫기', command=win.destroy, width=12).pack(side='right')

    win.transient(parent)
    win.grab_set()
    win.focus_set()


# ── 설정 창 ──────────────────────────────────────────────

class SettingsDialog:
    def __init__(self, parent, config, on_save):
        self.config = config
        self.on_save = on_save
        self._current_idx = None
        self._syncing = False

        self.win = tk.Toplevel(parent)
        self.win.title('DB 연결 설정')
        self.win.geometry('880x560')
        self.win.configure(bg='#f0f2f5')
        self.win.transient(parent)
        self.win.grab_set()
        try:
            icon_path = resource_path('icon.ico')
            if os.path.exists(icon_path):
                self.win.iconbitmap(icon_path)
        except Exception:
            pass

        self._build_ui()

    def _build_ui(self):
        body = tk.Frame(self.win, bg='#f0f2f5')
        body.pack(fill='both', expand=True, padx=12, pady=(12, 0))

        left = tk.Frame(body, bg='#f0f2f5', width=240)
        left.pack(side='left', fill='y', padx=(0, 10))
        left.pack_propagate(False)

        tk.Label(left, text='데이터 소스', bg='#f0f2f5',
                 font=('Segoe UI', 10, 'bold'), fg='#374151').pack(anchor='w')

        btn_frame = tk.Frame(left, bg='#f0f2f5')
        btn_frame.pack(fill='x', pady=(6, 6))
        add_border, _ = bordered_button(btn_frame, '+ 추가', self._add_db, '#2563eb', bg='#f0f2f5')
        add_border.pack(side='left', padx=(0, 4))
        del_border, _ = bordered_button(btn_frame, '- 삭제', self._remove_db, '#dc2626', bg='#f0f2f5')
        del_border.pack(side='left', padx=(0, 4))
        copy_border, _ = bordered_button(btn_frame, '복제', self._duplicate_db, '#6b7280', bg='#f0f2f5')
        copy_border.pack(side='left')

        self.db_listbox = tk.Listbox(left, font=('Segoe UI', 10),
                                     selectmode='browse', activestyle='none')
        self.db_listbox.pack(fill='both', expand=True)
        self.db_listbox.bind('<<ListboxSelect>>', self._on_select)

        for db in self.config['databases']:
            self.db_listbox.insert('end', db['label'])

        self.edit_frame = tk.LabelFrame(body, text='연결 정보', bg='#ffffff',
                                        font=('Segoe UI', 9), fg='#6b7280',
                                        padx=14, pady=12)
        self.edit_frame.pack(side='left', fill='both', expand=True)

        self.field_vars = {
            'label': tk.StringVar(),
            'comment': tk.StringVar(),
            'type': tk.StringVar(),
            'host': tk.StringVar(),
            'port': tk.StringVar(),
            'database': tk.StringVar(),
            'oracle_sid': tk.StringVar(),
            'auth': tk.StringVar(),
            'user': tk.StringVar(),
            'password': tk.StringVar(),
            'url': tk.StringVar(),
        }
        self.driver_labels = {'mssql': 'MSSQL', 'postgresql': 'PostgreSQL', 'oracle': 'Oracle'}
        self.driver_values = {'MSSQL': 'mssql', 'PostgreSQL': 'postgresql', 'Oracle': 'oracle'}
        self.auth_labels = {'userpass': '사용자 및 비밀번호', 'windows': 'Windows 인증'}
        self.auth_values = {'사용자 및 비밀번호': 'userpass', 'Windows 인증': 'windows'}

        self._entry_row('label', '이름')
        self._entry_row('comment', '주석')
        self._combo_row('type', '드라이버', ['MSSQL', 'PostgreSQL', 'Oracle'], self._on_type_changed)
        self._host_port_row()
        self.database_label = self._entry_row('database', '데이터베이스')
        self.oracle_type_row = self._combo_row('oracle_sid', '연결 타입', ['Service Name', 'SID'], self._on_oracle_type_changed)
        self.auth_row = self._combo_row('auth', '인증', ['사용자 및 비밀번호', 'Windows 인증'], self._on_auth_changed)
        self.user_entry = self._entry_row('user', '사용자', return_entry=True)
        self.password_entry = self._entry_row('password', '비밀번호', show='*', return_entry=True)
        self._url_row()

        for key in ('host', 'port', 'database'):
            self.field_vars[key].trace_add('write', self._on_field_changed)
        self.field_vars['url'].trace_add('write', self._on_url_changed)

        bottom = tk.Frame(self.win, bg='#f0f2f5')
        bottom.pack(fill='x', padx=12, pady=12)

        test_border, self.test_btn = bordered_button(bottom, '연결 테스트', self._test_connection,
                                                     '#2563eb', bg='#f0f2f5', font=('Segoe UI', 10))
        test_border.pack(side='left', padx=(0, 8))
        self.test_status = tk.Label(bottom, text='', bg='#f0f2f5',
                                    font=('Segoe UI', 9), fg='#6b7280', anchor='w')
        self.test_status.pack(side='left', fill='x', expand=True)

        save_border, _ = bordered_button(bottom, '저장', self._save, '#2563eb', bg='#f0f2f5',
                                         font=('Segoe UI', 10), bold=True)
        save_border.pack(side='right', padx=(8, 0))
        cancel_border, _ = bordered_button(bottom, '취소', self.win.destroy, '#6b7280', bg='#f0f2f5',
                                            font=('Segoe UI', 10))
        cancel_border.pack(side='right')

        if self.config['databases']:
            self.db_listbox.selection_set(0)
            self._load_fields(0)

    def _entry_row(self, key, label, show='', return_entry=False):
        row = tk.Frame(self.edit_frame, bg='#ffffff')
        row.pack(fill='x', pady=4)
        lbl = tk.Label(row, text=label, bg='#ffffff', font=('Segoe UI', 9),
                       fg='#374151', width=18, anchor='w')
        lbl.pack(side='left')
        entry = tk.Entry(row, textvariable=self.field_vars[key], font=('Segoe UI', 9), show=show)
        entry.pack(side='left', fill='x', expand=True)
        return entry if return_entry else lbl

    def _combo_row(self, key, label, values, command):
        row = tk.Frame(self.edit_frame, bg='#ffffff')
        row.pack(fill='x', pady=4)
        tk.Label(row, text=label, bg='#ffffff', font=('Segoe UI', 9),
                 fg='#374151', width=18, anchor='w').pack(side='left')
        combo = ttk.Combobox(row, textvariable=self.field_vars[key], state='readonly',
                             values=values, font=('Segoe UI', 9))
        combo.pack(side='left', fill='x', expand=True)
        combo.bind('<<ComboboxSelected>>', command)
        setattr(self, f'{key}_combo', combo)
        return row

    def _host_port_row(self):
        row = tk.Frame(self.edit_frame, bg='#ffffff')
        row.pack(fill='x', pady=4)
        tk.Label(row, text='호스트', bg='#ffffff', font=('Segoe UI', 9),
                 fg='#374151', width=18, anchor='w').pack(side='left')
        tk.Entry(row, textvariable=self.field_vars['host'], font=('Segoe UI', 9)).pack(side='left', fill='x', expand=True)
        tk.Label(row, text='포트', bg='#ffffff', font=('Segoe UI', 9),
                 fg='#374151', padx=8).pack(side='left')
        tk.Entry(row, textvariable=self.field_vars['port'], font=('Segoe UI', 9), width=8).pack(side='left')

    def _url_row(self):
        row = tk.Frame(self.edit_frame, bg='#ffffff')
        row.pack(fill='x', pady=(12, 2))
        tk.Label(row, text='URL', bg='#ffffff', font=('Segoe UI', 9),
                 fg='#374151', width=18, anchor='w').pack(side='left')
        self.url_entry = tk.Entry(row, textvariable=self.field_vars['url'], font=('Segoe UI', 9))
        self.url_entry.pack(side='left', fill='x', expand=True)
        tk.Label(self.edit_frame, text='URL을 수정하면 위 필드에 반영됩니다',
                 bg='#ffffff', font=('Segoe UI', 8), fg='#6b7280').pack(anchor='w', padx=(126, 0))

    def _on_select(self, event):
        sel = self.db_listbox.curselection()
        if sel:
            self._save_current_fields()
            self._load_fields(sel[0])

    def _load_fields(self, idx):
        self._current_idx = idx
        db = self.config['databases'][idx]
        self._syncing = True
        self.field_vars['label'].set(str(db.get('label', '')))
        self.field_vars['comment'].set(str(db.get('comment', '')))
        self.field_vars['type'].set(self.driver_labels.get(db.get('type', 'mssql'), 'MSSQL'))
        self.field_vars['host'].set(str(db.get('host', '')))
        self.field_vars['port'].set(str(db.get('port', '')))
        self.field_vars['database'].set(str(db.get('database', '')))
        self.field_vars['oracle_sid'].set('SID' if db.get('oracle_sid') else 'Service Name')
        self.field_vars['auth'].set(self.auth_labels.get(db.get('auth', 'userpass'), '사용자 및 비밀번호'))
        self.field_vars['user'].set(str(db.get('user', '')))
        self.field_vars['password'].set(str(db.get('password', '')))
        self.field_vars['url'].set(build_jdbc_url(db))
        self._syncing = False
        self._update_dynamic_fields()

    def _save_current_fields(self):
        if self._current_idx is None:
            return
        idx = self._current_idx
        if idx >= len(self.config['databases']):
            return
        db = self.config['databases'][idx]
        db.update(self._fields_to_db())
        self.db_listbox.delete(idx)
        self.db_listbox.insert(idx, db['label'])

    def _fields_to_db(self):
        db_type = self.driver_values.get(self.field_vars['type'].get(), 'mssql')
        try:
            port = int(self.field_vars['port'].get().strip())
        except ValueError:
            port = 0
        auth = self.auth_values.get(self.field_vars['auth'].get(), 'userpass')
        if db_type != 'mssql':
            auth = 'userpass'
        return {
            'label': self.field_vars['label'].get().strip(),
            'comment': self.field_vars['comment'].get().strip(),
            'type': db_type,
            'host': self.field_vars['host'].get().strip(),
            'port': port,
            'database': self.field_vars['database'].get().strip(),
            'auth': auth,
            'user': self.field_vars['user'].get().strip(),
            'password': self.field_vars['password'].get(),
            'oracle_sid': self.field_vars['oracle_sid'].get() == 'SID',
        }

    def _add_db(self):
        new_db = {
            'label': '[MSSQL] NewDB',
            'comment': '',
            'type': 'mssql',
            'host': 'localhost',
            'port': 1433,
            'database': '',
            'auth': 'windows',
            'user': '',
            'password': '',
            'oracle_sid': False,
        }
        self._save_current_fields()
        self.config['databases'].append(new_db)
        self.db_listbox.insert('end', new_db['label'])
        self.db_listbox.selection_clear(0, 'end')
        self.db_listbox.selection_set('end')
        self._load_fields(len(self.config['databases']) - 1)

    def _duplicate_db(self):
        import copy
        sel = self.db_listbox.curselection()
        if not sel:
            return
        self._save_current_fields()
        idx = sel[0]
        new_db = copy.deepcopy(self.config['databases'][idx])
        new_db['label'] = f"{new_db.get('label', '')} 복사본"
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
        else:
            self._current_idx = None

    def _on_type_changed(self, event=None):
        old_port = self.field_vars['port'].get().strip()
        db_type = self.driver_values.get(self.field_vars['type'].get(), 'mssql')
        if old_port == '' or old_port in ('1433', '5432', '1521'):
            self.field_vars['port'].set(str(DEFAULT_PORTS[db_type]))
        self._update_dynamic_fields()
        self._update_url_from_fields()

    def _on_oracle_type_changed(self, event=None):
        self._update_dynamic_fields()
        self._update_url_from_fields()

    def _on_auth_changed(self, event=None):
        self._update_dynamic_fields()

    def _on_field_changed(self, *args):
        self._update_url_from_fields()

    def _on_url_changed(self, *args):
        if self._syncing:
            return
        parsed = parse_jdbc_url(self.field_vars['url'].get())
        if not parsed:
            self.url_entry.config(bg='#fdecea')
            return
        self._syncing = True
        self.field_vars['type'].set(self.driver_labels.get(parsed['type'], 'MSSQL'))
        self.field_vars['host'].set(parsed['host'])
        self.field_vars['port'].set(str(parsed['port']))
        self.field_vars['database'].set(parsed['database'])
        self.field_vars['oracle_sid'].set('SID' if parsed['oracle_sid'] else 'Service Name')
        self._syncing = False
        self.url_entry.config(bg='white')
        self._update_dynamic_fields()

    def _update_url_from_fields(self):
        if self._syncing:
            return
        self._syncing = True
        self.field_vars['url'].set(build_jdbc_url(self._fields_to_db()))
        self.url_entry.config(bg='white')
        self._syncing = False

    def _update_dynamic_fields(self):
        db_type = self.driver_values.get(self.field_vars['type'].get(), 'mssql')
        is_oracle = db_type == 'oracle'
        self.oracle_type_row.pack_forget()
        if is_oracle:
            self.oracle_type_row.pack(fill='x', pady=4, after=self.database_label.master)
            self.database_label.config(text='SID' if self.field_vars['oracle_sid'].get() == 'SID' else '서비스')
        else:
            self.database_label.config(text='데이터베이스')

        auth_values = ['사용자 및 비밀번호', 'Windows 인증'] if db_type == 'mssql' else ['사용자 및 비밀번호']
        self.auth_combo['values'] = auth_values
        if self.field_vars['auth'].get() not in auth_values:
            self.field_vars['auth'].set('사용자 및 비밀번호')
        state = 'disabled' if db_type == 'mssql' and self.field_vars['auth'].get() == 'Windows 인증' else 'normal'
        self.user_entry.config(state=state)
        self.password_entry.config(state=state)

    def _test_connection(self):
        cfg = self._fields_to_db()
        self.test_btn.config(state='disabled')
        self.test_status.config(text='테스트 중...', fg='#6b7280')

        def worker():
            conn = None
            try:
                if cfg['type'] == 'mssql':
                    conn = connect_mssql(cfg)
                    version_sql = 'SELECT @@VERSION'
                elif cfg['type'] == 'oracle':
                    conn = connect_oracle(cfg)
                    version_sql = 'SELECT banner FROM v$version WHERE ROWNUM=1'
                else:
                    conn = connect_pg(cfg)
                    version_sql = 'SELECT version()'
                version = ''
                try:
                    cur = conn.cursor()
                    cur.execute(version_sql)
                    row = cur.fetchone()
                    if row:
                        version = str(row[0]).splitlines()[0][:60]
                except Exception:
                    version = ''
                finally:
                    conn.close()
                self.win.after(0, self._test_success, version)
            except Exception as e:
                try:
                    if conn:
                        conn.close()
                except Exception:
                    pass
                self.win.after(0, self._test_failed, str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _test_success(self, version):
        self.test_btn.config(state='normal')
        msg = f'성공: {version}' if version else '연결 성공'
        self.test_status.config(text=msg, fg='#15803d')

    def _test_failed(self, msg):
        self.test_btn.config(state='normal')
        self.test_status.config(text='연결 실패', fg='#dc2626')
        show_copyable_error(self.win, '연결 실패', msg)

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

        try:
            icon_path = resource_path('icon.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

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

        if cfg['type'] == 'mssql':
            search_fn = search_mssql
        elif cfg['type'] == 'oracle':
            search_fn = search_oracle
        else:
            search_fn = search_pg
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
        self.root.after(0, self._show_copyable_error, '검색 오류', msg)

    def _show_copyable_error(self, title, msg):
        show_copyable_error(self.root, title, msg)

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
        elif self._current_db_type == 'oracle':
            return f"""SELECT * FROM "{schema}"."{table}" WHERE TO_CHAR("{column}") LIKE '%{sv}%'"""
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
        elif self._current_db_type == 'oracle':
            count_q = f"""SELECT COUNT(*) FROM "{schema}"."{table}" WHERE TO_CHAR("{column}") LIKE '%{sv}%'"""
        else:
            count_q = f"""SELECT COUNT(*) FROM "{schema}"."{table}" WHERE "{column}"::text LIKE '%{sv}%'"""
        menu.add_command(label='COUNT 쿼리 복사', command=lambda: self._copy_to_clipboard(count_q))
        menu.post(event.x_root, event.y_root)


if __name__ == '__main__':
    root = tk.Tk()
    app = DBSearchApp(root)
    root.mainloop()
