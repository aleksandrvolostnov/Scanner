from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from datetime import datetime
import os

# Для сетевого сканирования и сбора инфы
import socket
import platform
import psutil
import subprocess
import re
import threading
import ipaddress

# Настройки Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1111@localhost/network_admin'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Подключение базы данных
db = SQLAlchemy(app)
app.config['DEBUG'] = True
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.jinja_env.auto_reload = True
# Логин-менеджер
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модель User
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Модель Task
class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(50), nullable=False)  # Низкий, Средний, Высокий
    status = db.Column(db.String(50), nullable=False)  # Новая, В работе, Завершена
    difficulty = db.Column(db.String(50), nullable=False)  # Легко, Средне, Сложно
    due_date = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id], backref='created_tasks')
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id], backref='assigned_tasks')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Пароли не совпадают!', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Регистрация прошла успешно!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль!', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('welcome.html')


@app.route('/tasks/new', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description')
        priority = request.form['priority']
        status = request.form['status']
        difficulty = request.form['difficulty']
        due_date = datetime.strptime(request.form['due_date'], '%Y-%m-%d')
        assigned_to_id = request.form.get('assigned_to')

        new_task = Task(
            title=title,
            description=description,
            priority=priority,
            status=status,
            difficulty=difficulty,
            due_date=due_date,
            user_id=current_user.id,
            assigned_to_id=assigned_to_id if assigned_to_id else None
        )
        db.session.add(new_task)
        db.session.commit()
        flash('Задача создана', 'success')
        return redirect(url_for('tasks_list'))

    users = User.query.all()
    priorities = ['Низкий', 'Средний', 'Высокий']
    difficulties = ['Легкая', 'Средняя', 'Сложная']
    statuses = ['Новое', 'В работе', 'Завершено']

    return render_template('create_task.html', users=users, priorities=priorities, difficulties=difficulties, statuses=statuses)

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks_list():
    users = User.query.all()
    priorities = ['Низкий', 'Средний', 'Высокий']
    difficulties = ['Легкая', 'Средняя', 'Сложная']
    statuses = ['Новое', 'В работе', 'Завершено']

    filters = {}
    if request.method == 'POST':
        title = request.form.get('title')
        if title:
            filters['title'] = title
        assigned_to_id = request.form.get('assigned_to')
        if assigned_to_id and assigned_to_id != 'all':
            filters['assigned_to_id'] = int(assigned_to_id)
        priority = request.form.get('priority')
        if priority and priority != 'all':
            filters['priority'] = priority
        status = request.form.get('status')
        if status and status != 'all':
            filters['status'] = status
        difficulty = request.form.get('difficulty')
        if difficulty and difficulty != 'all':
            filters['difficulty'] = difficulty

    query = Task.query
    if 'title' in filters:
        query = query.filter(Task.title.ilike(f"%{filters['title']}%"))
    if 'assigned_to_id' in filters:
        query = query.filter(Task.assigned_to_id == filters['assigned_to_id'])
    if 'priority' in filters:
        query = query.filter(Task.priority == filters['priority'])
    if 'status' in filters:
        query = query.filter(Task.status == filters['status'])
    if 'difficulty' in filters:
        query = query.filter(Task.difficulty == filters['difficulty'])

    tasks = query.order_by(Task.due_date.asc()).all()

    return render_template('tasks_list.html', tasks=tasks, users=users, priorities=priorities, difficulties=difficulties, statuses=statuses)

@app.route('/tasks/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)

    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form.get('description')
        task.priority = request.form['priority']
        task.status = request.form['status']
        task.difficulty = request.form['difficulty']
        task.due_date = datetime.strptime(request.form['due_date'], '%Y-%m-%d')
        assigned_to_id = request.form.get('assigned_to')
        task.assigned_to_id = assigned_to_id if assigned_to_id else None

        db.session.commit()
        flash('Задача обновлена', 'success')
        return redirect(url_for('tasks_list'))

    users = User.query.all()
    priorities = ['Низкий', 'Средний', 'Высокий']
    difficulties = ['Легкая', 'Средняя', 'Сложная']
    statuses = ['Новое', 'В работе', 'Завершено']

    return render_template('edit_task.html', task=task, users=users, priorities=priorities, difficulties=difficulties, statuses=statuses)

@app.route('/tasks/delete/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash('Нет прав для удаления задачи', 'error')
        return redirect(url_for('tasks_list'))

    db.session.delete(task)
    db.session.commit()
    flash('Задача удалена', 'success')
    return redirect(url_for('tasks_list'))



@app.route('/task_board', methods=['GET'])
@login_required
def task_board():
    # Все пользователи видят все задачи
    tasks = Task.query.all()

    # Категоризация задач по статусу
    tasks_by_category = {
        'Новое': [task for task in tasks if task.status == 'Новое'],
        'В работе': [task for task in tasks if task.status == 'В работе'],
        'Завершено': [task for task in tasks if task.status == 'Завершено'],
    }

    return render_template(
        'task_board.html',
        tasks_by_category=tasks_by_category,
        board_type="Статус"
    )


@app.route('/task_board/priority', methods=['GET'])
@login_required
def task_board_priority():
    tasks = Task.query.all()

    # Категоризация по приоритету
    tasks_by_priority = {
        'Низкий': [task for task in tasks if task.priority == 'Низкий'],
        'Средний': [task for task in tasks if task.priority == 'Средний'],
        'Высокий': [task for task in tasks if task.priority == 'Высокий'],
    }

    return render_template(
        'task_board.html',
        tasks_by_category=tasks_by_priority,
        board_type="Приоритет"
    )


@app.route('/task_board/difficulty', methods=['GET'])
@login_required
def task_board_difficulty():
    tasks = Task.query.all()

    # Категоризация по сложности
    tasks_by_difficulty = {
        'Легкая': [task for task in tasks if task.difficulty == 'Легкая'],
        'Средняя': [task for task in tasks if task.difficulty == 'Средняя'],
        'Сложная': [task for task in tasks if task.difficulty == 'Сложная'],
    }

    return render_template(
        'task_board.html',
        tasks_by_category=tasks_by_difficulty,
        board_type="Сложность"
    )


@app.route('/update_task_category', methods=['POST'])
@login_required
def update_task_category():
    data = request.get_json()
    task_id = data.get('task_id')
    new_category = data.get('new_category')

    task = Task.query.filter_by(id=task_id).first()
    if not task:
        return jsonify({'error': 'Задача не найдена'}), 404

    try:
        ref = request.referrer or ''
        if ref.endswith('/task_board'):
            # Обновляем статус
            if new_category not in ['Новое', 'В работе', 'Завершено']:
                raise KeyError('Неверный статус')
            task.status = new_category

        elif ref.endswith('/task_board/priority'):
            # Обновляем приоритет
            if new_category not in ['Низкий', 'Средний', 'Высокий']:
                raise KeyError('Неверный приоритет')
            task.priority = new_category

        elif ref.endswith('/task_board/difficulty'):
            # Обновляем сложность
            if new_category not in ['Легкая', 'Средняя', 'Сложная']:
                raise KeyError('Неверная сложность')
            task.difficulty = new_category

        db.session.commit()
        return jsonify({'success': True})

    except KeyError as e:
        db.session.rollback()
        return jsonify({'error': f'Некорректная категория: {e}'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

import socket
import ipaddress
import subprocess
import platform
import threading
import re
import http.client
import psutil
import os

from flask import render_template
from flask_login import login_required
from app import app

OUI_DB = {}
if os.path.exists("oui.txt"):
    with open("oui.txt", "r", encoding="utf-8") as f:
        for line in f:
            if '\t' in line:
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    prefix = parts[0].strip().upper().replace('-', ':')[:8]
                    vendor = parts[-1].strip()
                    OUI_DB[prefix] = vendor

def get_local_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()

    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                try:
                    return str(ipaddress.IPv4Network(f"{local_ip}/{addr.netmask}", strict=False))
                except:
                    pass
    return str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))

def ping(ip):
    system = platform.system().lower()
    if system == 'windows':
        command = ['ping', '-n', '1', '-w', '1000', ip]
    else:
        command = ['ping', '-c', '1', '-W', '1', ip]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

def tcp_ping(ip, port=80, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def get_mac(ip):
    system = platform.system().lower()
    try:
        if system == 'windows':
            subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.DEVNULL)
            output = subprocess.check_output(f"arp -a {ip}", shell=True)
            output = output.decode('utf-8', errors='ignore')
        elif system == 'linux':
            subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.DEVNULL)
            try:
                output = subprocess.check_output(['ip', 'neigh', 'show', ip])
                output = output.decode('utf-8', errors='ignore')
            except subprocess.CalledProcessError:
                output = subprocess.check_output(['arp', '-n', ip])
                output = output.decode('utf-8', errors='ignore')
        else:
            return None

        mac_match = re.search(r'(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})', output)
        if mac_match:
            mac = mac_match.group(0).upper()
            mac = mac.replace('-', ':')
            return mac
        return None

    except Exception:
        return None

def get_vendor(mac):
    if not mac:
        return None
    prefix = mac.upper().replace("-", ":")[:8]
    return OUI_DB.get(prefix)

def get_ttl(ip):
    system = platform.system().lower()
    try:
        if system == 'windows':
            proc = subprocess.Popen(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, _ = proc.communicate()
            out_decoded = out.decode('utf-8', errors='ignore')
            ttl_match = re.search(r'TTL=(\d+)', out_decoded, re.IGNORECASE)
        else:
            proc = subprocess.Popen(["ping", "-c", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, _ = proc.communicate()
            out_decoded = out.decode('utf-8', errors='ignore')
            ttl_match = re.search(r'ttl=(\d+)', out_decoded, re.IGNORECASE)
        if ttl_match:
            return int(ttl_match.group(1))
    except:
        pass
    return None

def guess_os(ttl, ports, vendor=''):
    if vendor:
        v = vendor.lower()
        if 'apple' in v:
            return 'iOS/macOS'
        if 'samsung' in v:
            return 'Android (Samsung)'
        if 'huawei' in v:
            return 'Android (Huawei)'
        if 'intel' in v:
            return 'ПК/Сервер'
        if 'microsoft' in v:
            return 'Windows'
        if any(x in v for x in ['cisco', 'mikrotik', 'tp-link', 'zte', 'asustek', 'd-link', 'broadcom']):
            return 'Сетевое устройство'

    # Проверка портов для Windows
    if 139 in ports or 445 in ports:
        if ttl is None or ttl >= 64:
            return "Windows"

    if ttl is not None:
        if ttl >= 120:
            return "Windows"
        elif 60 <= ttl < 120:
            if 5353 in ports or 62078 in ports:
                return "Apple/Bonjour"
            return "Linux/Android/macOS"
        elif ttl < 60:
            return "Unix-like/Embedded"

    return "Неизвестно"

def scan_ports(ip, ports=None, timeout=0.3):
    if ports is None:
        ports = [22, 23, 53, 80, 88, 139, 443, 445, 3389, 8080, 5353, 62078]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            sock.close()
    return open_ports

def get_http_banner(ip, port=80):
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=1)
        conn.request("HEAD", "/")
        res = conn.getresponse()
        server = res.getheader("Server")
        return server
    except:
        return None

def get_ssdp_info(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST:239.255.255.250:1900',
            'MAN:"ssdp:discover"',
            'MX:1',
            'ST:ssdp:all',
            '', ''
        ])
        sock.sendto(msg.encode('utf-8'), (ip, 1900))
        data, addr = sock.recvfrom(1024)
        return data.decode('utf-8', errors='ignore')
    except:
        return None

def enhance_vendor(vendor, http_banner, ssdp_info):
    if vendor and vendor != "Неизвестно":
        return vendor

    # По HTTP banner пытаемся определить производителя
    if http_banner:
        http_banner_l = http_banner.lower()
        if "mikrotik" in http_banner_l:
            return "Mikrotik"
        if "cisco" in http_banner_l:
            return "Cisco"
        if "d-link" in http_banner_l or "dlink" in http_banner_l:
            return "D-Link"
        if "netgear" in http_banner_l:
            return "Netgear"
        if "asus" in http_banner_l:
            return "Asus"
        if "linksys" in http_banner_l:
            return "Linksys"
        if "tp-link" in http_banner_l:
            return "TP-Link"
        if "ubiquiti" in http_banner_l:
            return "Ubiquiti"
        if "huawei" in http_banner_l:
            return "Huawei"
        if "apple" in http_banner_l:
            return "Apple"
        if "windows" in http_banner_l:
            return "Microsoft"
        # Можно добавить еще

    # По SSDP info пытаемся определить производителя
    if ssdp_info:
        ssdp_l = ssdp_info.lower()
        if "mikrotik" in ssdp_l:
            return "Mikrotik"
        if "cisco" in ssdp_l:
            return "Cisco"
        if "d-link" in ssdp_l or "dlink" in ssdp_l:
            return "D-Link"
        if "netgear" in ssdp_l:
            return "Netgear"
        if "asus" in ssdp_l:
            return "Asus"
        if "linksys" in ssdp_l:
            return "Linksys"
        if "tp-link" in ssdp_l:
            return "TP-Link"
        if "ubiquiti" in ssdp_l:
            return "Ubiquiti"
        if "huawei" in ssdp_l:
            return "Huawei"
        if "apple" in ssdp_l:
            return "Apple"
        if "windows" in ssdp_l:
            return "Microsoft"
        # Можно добавить еще

    return "Неизвестно"

def scan_ip(ip, results):
    ip_str = str(ip)
    if not ping(ip_str):
        if not tcp_ping(ip_str, 80):
            return

    mac = get_mac(ip_str)
    vendor = get_vendor(mac)
    ttl = get_ttl(ip_str)
    open_ports = scan_ports(ip_str)
    http_banner = None
    if 80 in open_ports:
        http_banner = get_http_banner(ip_str, 80)
    ssdp_info = get_ssdp_info(ip_str)

    vendor = enhance_vendor(vendor, http_banner, ssdp_info)
    os_guess = guess_os(ttl, open_ports, vendor)

    results[ip_str] = {
        "ip": ip_str,
        "mac": mac,
        "vendor": vendor if vendor else "Неизвестно",
        "ttl": ttl,
        "os": os_guess,
        "open_ports": open_ports,
        "http_banner": http_banner,
        "ssdp_info": ssdp_info,
        "hostname": get_hostname(ip_str),
    }

from collections import Counter
from flask import render_template
from flask_login import login_required
from app import app
import ipaddress
import threading


CRITICAL_PORTS = {23, 445, 3389, 21, 110, 143}  # Telnet, SMB, RDP, FTP, POP3, IMAP

def detect_threats(devices):
    threats = []

    for d in devices:
        if not d.get('mac'):
            threats.append(f"{d['ip']} — не удалось определить MAC-адрес")
        if not d.get('vendor') or d['vendor'] == 'Неизвестно':
            threats.append(f"{d['ip']} — неизвестный производитель")
        if not d.get('os') or d['os'] == 'Неизвестно':
            threats.append(f"{d['ip']} — не удалось определить ОС")
        if any(port in CRITICAL_PORTS for port in d.get('open_ports', [])):
            threats.append(f"{d['ip']} — открыт критический порт: {d['open_ports']}")

        http = d.get("http_banner", "") or ""
        if "MiniServ" in http or "GoAhead" in http:
            threats.append(f"{d['ip']} — подозрительный HTTP-сервер: {http}")

    return threats

@app.route('/dashboard')
@login_required
def dashboard():
    network_cidr = get_local_network()
    net = ipaddress.ip_network(network_cidr, strict=False)
    results = {}

    threads = []
    for ip in net.hosts():
        t = threading.Thread(target=scan_ip, args=(ip, results))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    devices = list(results.values())

    # Генерация статистик
    os_stats = {}
    vendor_stats = {}
    threat_stats = {
        'Открытые SMB/NetBIOS': 0,
        'Неизвестные устройства': 0,
        'Без MAC-адреса': 0,
    }

    for device in devices:
        # ОС
        os_name = device.get('os') or 'Неизвестно'
        os_stats[os_name] = os_stats.get(os_name, 0) + 1

        # Производитель
        vendor = device.get('vendor') or 'Неизвестно'
        vendor_stats[vendor] = vendor_stats.get(vendor, 0) + 1

        # Угрозы
        ports = device.get('open_ports') or []
        if 139 in ports or 445 in ports:
            threat_stats['Открытые SMB/NetBIOS'] += 1
        if not device.get('mac'):
            threat_stats['Без MAC-адреса'] += 1
        if vendor == 'Неизвестно':
            threat_stats['Неизвестные устройства'] += 1

    return render_template(
        'dashboard.html',
        devices=devices,
        network=str(network_cidr),
        os_stats=os_stats,
        vendor_stats=vendor_stats,
        threat_stats=threat_stats
    )

@app.route('/device/<ip>')
@login_required
def device_detail(ip):
    alive = ping(ip)
    hostname = get_hostname(ip) if alive else None
    mac = get_mac(ip) if alive else None
    vendor = get_vendor(mac)
    ttl = get_ttl(ip) if alive else None
    ports = scan_ports(ip) if alive else []
    os_guess = guess_os(ttl, ports, vendor)
    http_info = get_http_banner(ip) if 80 in ports else None
    ssdp_info = get_ssdp_info(ip) if 1900 in ports else None

    device_info = {
        'ip': ip,
        'alive': alive,
        'hostname': hostname or '—',
        'mac': mac or '—',
        'vendor': vendor,
        'os': os_guess,
        'open_ports': ports,
        'http_info': http_info or '—',
        'ssdp_info': ssdp_info or '—'
    }
    return render_template('device_detail.html', device=device_info)


if __name__ == "__main__":
    app.run(debug=True)  # Включи debug=True
