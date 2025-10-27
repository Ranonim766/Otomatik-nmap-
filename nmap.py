import os
import json
import threading
import subprocess
import datetime
import time
import logging
import shutil
from flask import Flask, render_template_string, request, redirect, url_for, send_from_directory, jsonify

# --- TEMEL AYARLAR VE YAPILANDIRMA ---

SCAN_CATEGORIES = {
    "Temel Taramalar": [
        {"id": "scan_ping", "name": "Ping Taraması (Host canlı mı?)", "command": "nmap -sn {target}"},
        {"id": "scan_fast", "name": "Hızlı Tarama (En popüler 100 port)", "command": "nmap -F {target}"},
        {"id": "scan_default", "name": "Varsayılan Tarama (Varsayılan 1000 port)", "command": "nmap {target}"},
        {"id": "scan_tcp_top1000", "name": "TCP Port Taraması (Varsayılan 1000 port)", "command": "nmap -sT {target}"},
        {"id": "scan_udp_top1000", "name": "UDP Port Taraması (Varsayılan 1000 port)", "command": "sudo nmap -sU --top-ports 1000 {target}"},
        {"id": "scan_no_ping", "name": "Ping Atlama (Host keşfi yapma)", "command": "nmap -Pn {target}"},
    ],
    "Port Tarama Teknikleri": [
        {"id": "scan_syn", "name": "TCP SYN Taraması (Gizli)", "command": "sudo nmap -sS {target}"},
        {"id": "scan_connect", "name": "TCP Connect Taraması", "command": "nmap -sT {target}"},
        {"id": "scan_udp", "name": "UDP Taraması (Tüm UDP Portları)", "command": "sudo nmap -sU {target}"},
        {"id": "scan_fin", "name": "TCP FIN Taraması (Firewall atlatma)", "command": "sudo nmap -sF {target}"},
        {"id": "scan_xmas", "name": "Xmas Taraması (Firewall atlatma)", "command": "sudo nmap -sX {target}"},
        {"id": "scan_null", "name": "Null Taraması (Firewall atlatma)", "command": "sudo nmap -sN {target}"},
        {"id": "scan_ack", "name": "TCP ACK Taraması (Firewall kural tespiti)", "command": "sudo nmap -sA {target}"},
        {"id": "scan_all_ports", "name": "Tüm Portları Tara (65535 port)", "command": "nmap -p- {target}"},
    ],
    "Versiyon & OS Tespiti": [
        {"id": "scan_os", "name": "İşletim Sistemi Tespiti", "command": "sudo nmap -O {target}"},
        {"id": "scan_version", "name": "Servis / Versiyon Tespiti", "command": "nmap -sV {target}"},
        {"id": "scan_aggressive", "name": "Agresif Tarama (OS, Versiyon, Script, Traceroute)", "command": "nmap -A {target}"},
    ],
    "NSE Script Kategorileri (Güvenlik Açığı ve Keşif)": [
        {"id": "nse_safe", "name": "Güvenli Scriptler (safe)", "command": "nmap -sV --script=safe {target}"},
        {"id": "nse_discovery", "name": "Keşif Scriptleri (discovery)", "command": "nmap -sV --script=discovery {target}"},
        {"id": "nse_vuln", "name": "Güvenlik Açığı Scriptleri (vuln)", "command": "nmap -sV --script=vuln {target}"},
        {"id": "nse_auth", "name": "Yetkilendirme Scriptleri (auth)", "command": "nmap -sV --script=auth {target}"},
        {"id": "nse_brute", "name": "Brute Force Scriptleri (brute)", "command": "nmap -sV --script=brute {target}"},
        {"id": "nse_exploit", "name": "Exploit Scriptleri (exploit)", "command": "nmap -sV --script=exploit {target}"},
        {"id": "nse_external", "name": "Harici Kaynak Scriptleri (external)", "command": "nmap -sV --script=external {target}"},
        {"id": "nse_dos", "name": "DoS Scriptleri (dos)", "command": "nmap -sV --script=dos {target}"},
        {"id": "nse_intrusive", "name": "Müdahaleci Scriptler (intrusive)", "command": "nmap -sV --script=intrusive {target}"},
    ]
}

ALL_COMMANDS = {cmd['id']: cmd for category in SCAN_CATEGORIES.values() for cmd in category}


RESULTS_DIR = "scan_results"
DB_FILE = "scan_database.json"
app = Flask(__name__)
app.config['RESULTS_DIR'] = os.path.abspath(RESULTS_DIR)

db_lock = threading.Lock()
process_lock = threading.Lock()
ACTIVE_PROCESSES = {}

def load_database():
    with db_lock:
        if not os.path.exists(DB_FILE): return {}
        try:
            with open(DB_FILE, "r") as f: return json.load(f)
        except (json.JSONDecodeError, IOError): return {}

def save_database(db):
    with db_lock:
        with open(DB_FILE, "w") as f: json.dump(db, f, indent=4)

def scan_worker():
    logging.info("Tarama işçisi başlatıldı.")
    while True:
        db = load_database()
        scan_to_run = None
        for scan_id, scan_data in db.items():
            if scan_data["status"] == "Beklemede":
                scan_to_run = scan_id
                break
        if scan_to_run:
            target = db[scan_to_run]["target"]
            commands_to_run = db[scan_to_run]["commands"]
            logging.info(f"Yeni tarama bulundu: {target} (ID: {scan_to_run})")

            db[scan_to_run]["status"] = "Çalışıyor"
            db[scan_to_run]["start_time"] = datetime.datetime.now().isoformat()
            save_database(db)

            run_selected_scans(scan_to_run, target, commands_to_run)

            db = load_database()
            if scan_to_run in db and db[scan_to_run]["status"] == "Çalışıyor":
                db[scan_to_run]["status"] = "Tamamlandı"
                db[scan_to_run]["end_time"] = datetime.datetime.now().isoformat()
                save_database(db)
                logging.info(f"Tarama tamamlandı: {target} (ID: {scan_to_run})")
        time.sleep(5)

def run_selected_scans(scan_id, target, commands_to_run):
    scan_dir = os.path.join(RESULTS_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    for i, cmd_info in enumerate(commands_to_run):
        db = load_database()
        if not db.get(scan_id) or db.get(scan_id, {}).get("status") != "Çalışıyor":
            logging.warning(f"Tarama döngüsü durduruldu veya silindi: {scan_id}")
            break

        db[scan_id]["commands"][i]["status"] = "Çalışıyor"
        save_database(db)

        command = cmd_info["command"].format(target=target)
        safe_filename = "".join(c for c in cmd_info["name"] if c.isalnum() or c in (' ', '_')).rstrip()
        output_filename = f"{i+1:02d}_{safe_filename.replace(' ', '_')}.txt"
        output_path = os.path.join(scan_dir, output_filename)

        process = None
        try:
            logging.info(f"Komut çalıştırılıyor: {command}")
            command_parts = command.split()
            with open(output_path, "w", encoding='utf-8') as f:
                process = subprocess.Popen(command_parts, stdout=f, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
                with process_lock: ACTIVE_PROCESSES[scan_id] = process
            process.wait()
        except Exception as e:
            logging.error(f"Komut hatası: {command} - {e}")
            with open(output_path, "w", encoding='utf-8') as f:
                f.write(f"HATA OLUŞTU:\n{str(e)}\n\n")
                f.write("Komut 'sudo' gerektiriyor olabilir. Lütfen script'i 'sudo python3 oto_nmap.py' olarak çalıştırdığınızdan emin olun.")
            db = load_database()
            if scan_id in db:
                db[scan_id]["commands"][i]["status"] = "Hata"
                db[scan_id]["commands"][i]["error_message"] = str(e)
                save_database(db)
        finally:
            with process_lock: ACTIVE_PROCESSES.pop(scan_id, None)
            db = load_database()
            if scan_id in db and db.get(scan_id, {}).get("status") == "Çalışıyor":
                if db[scan_id]["commands"][i]["status"] != "Hata":
                    db[scan_id]["commands"][i]["status"] = "Tamamlandı"
                db[scan_id]["commands"][i]["output_file"] = os.path.join(scan_id, output_filename)
                save_database(db)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")
        selected_scans = request.form.getlist("scans")

        if target and selected_scans:
            db = load_database()
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_id = f"{target.replace('.', '_')}_{timestamp}"

            commands_to_run = []
            for scan_id_key in selected_scans:
                if scan_id_key in ALL_COMMANDS:
                    cmd = ALL_COMMANDS[scan_id_key]
                    commands_to_run.append({
                        "name": cmd["name"],
                        "command": cmd["command"],
                        "status": "Beklemede",
                        "output_file": None
                    })

            if commands_to_run:
                db[scan_id] = {
                    "id": scan_id, "target": target, "status": "Beklemede",
                    "submit_time": datetime.datetime.now().isoformat(),
                    "start_time": None, "end_time": None,
                    "commands": commands_to_run
                }
                save_database(db)
        return redirect(url_for("index"))

    scans_db = load_database()
    for scan_id, scan_data in scans_db.items():
        scan_data['has_completed_commands'] = any(cmd.get('status') == 'Tamamlandı' for cmd in scan_data.get('commands', []))

    sorted_scans = sorted(scans_db.values(), key=lambda x: x.get('submit_time', ''), reverse=True)
    return render_template_string(HTML_TEMPLATE, scans=sorted_scans, scan_categories=SCAN_CATEGORIES)

@app.route('/stop/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    logging.info(f"Durdurma isteği alındı: {scan_id}")
    with process_lock:
        process = ACTIVE_PROCESSES.get(scan_id)
        if process:
            try:
                os.kill(process.pid, 9)
                logging.info(f"Process {process.pid} sonlandırıldı.")
            except Exception as e:
                logging.error(f"Process sonlandırılamadı: {e}")
    db = load_database()
    if scan_id in db:
        db[scan_id]["status"] = "Durduruldu"
        db[scan_id]["end_time"] = datetime.datetime.now().isoformat()
        for cmd in db[scan_id]["commands"]:
            if cmd["status"] in ["Çalışıyor", "Beklemede"]:
                cmd["status"] = "Durduruldu"
        save_database(db)
    return redirect(url_for("index"))

@app.route('/delete_all', methods=['POST'])
def delete_all():
    logging.warning("TÜM TARAMA GEÇMİŞİNİ SİLME İSTEĞİ ALINDI!")
    with process_lock:
        running_scans = list(ACTIVE_PROCESSES.items())
        for scan_id, process in running_scans:
            try:
                os.kill(process.pid, 9)
                logging.info(f"Çalışan tarama durduruldu: {scan_id}")
            except Exception:
                pass
        ACTIVE_PROCESSES.clear()
    with db_lock:
        try:
            if os.path.isdir(RESULTS_DIR):
                shutil.rmtree(RESULTS_DIR)
                logging.info(f"'{RESULTS_DIR}' klasörü başarıyla silindi.")
        except Exception as e:
            logging.error(f"'{RESULTS_DIR}' silinirken hata: {e}")
        try:
            if os.path.exists(DB_FILE):
                os.remove(DB_FILE)
                logging.info(f"'{DB_FILE}' dosyası başarıyla silindi.")
        except Exception as e:
            logging.error(f"'{DB_FILE}' silinirken hata: {e}")
        os.makedirs(RESULTS_DIR, exist_ok=True)
    return redirect(url_for("index"))

@app.route('/results/<path:filepath>')
def serve_result_file(filepath):
    return send_from_directory(app.config['RESULTS_DIR'], filepath)

@app.route('/api/scan_files/<scan_id>')
def get_scan_files(scan_id):
    db = load_database()
    scan_info = db.get(scan_id)
    if not scan_info: return jsonify({"error": "Tarama bulunamadı"}), 404
    files_content = []
    for command in scan_info["commands"]:
        if command["status"] in ["Tamamlandı", "Hata"] and command["output_file"]:
            try:
                filepath = os.path.join(app.config['RESULTS_DIR'], command["output_file"])
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
                files_content.append({"filename": os.path.basename(command["output_file"]), "content": content})
            except FileNotFoundError:
                files_content.append({"filename": os.path.basename(command["output_file"]), "content": "HATA: Dosya bulunamadı."})
    return jsonify(files_content)

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Oto-Nmap Akıllı Analiz Aracı</title>
    <script src="https://js.puter.com/v2/"></script>
    <style>
        :root {
            --background-color: #121212;
            --text-color: #e0e0e0;
            --container-bg: #1e1e1e;
            --input-bg: #2a2a2a;
            --button-bg: #0e639c;
            --button-stop-bg: #c94040;
            --button-summarize-bg: #5a3c94;
            --button-clear-bg: #6c757d;
            --prompt-color: #4ec9b0;
            --glow-color: rgba(78, 201, 176, 0.5);
            --error-color: #f44747;
            --border-radius: 12px;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --info-color: #17a2b8;
        }
        body {
            font-family: 'Consolas', 'Monaco', monospace;
            background-color: var(--background-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        header { text-align: center; margin-bottom: 20px; position: relative; }
        header h1 { color: var(--prompt-color); text-shadow: 0 0 10px var(--glow-color); margin-bottom: 5px; }
        .delete-all-container { text-align: right; margin-bottom: 20px; }
        .delete-all-button { background-color: var(--button-clear-bg); color: white; border: none; padding: 8px 15px; border-radius: var(--border-radius); cursor: pointer; font-weight: bold; transition: all 0.3s ease; }
        .delete-all-button:hover { background-color: var(--button-stop-bg); }
        .main-form-container { background-color: var(--container-bg); padding: 25px; border-radius: var(--border-radius); border: 1px solid #333; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        .scan-form { display: flex; flex-direction: column; gap: 20px; }
        .target-input-group { display: flex; gap: 15px; }
        .target-input-group input[type="text"] { flex-grow: 1; padding: 12px; border: 1px solid #333; border-radius: var(--border-radius); background-color: var(--input-bg); color: var(--text-color); font-size: 1rem; font-family: inherit; }
        .scan-form button { padding: 12px 25px; border: none; border-radius: var(--border-radius); background-color: var(--button-bg); color: white; font-size: 16px; font-weight: bold; cursor: pointer; }
        @media (max-width: 600px) { .target-input-group { flex-direction: column; } }
        .scan-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 20px; }
        .scan-category { background-color: #2a2a2b; border: 1px solid #333; border-radius: var(--border-radius); padding: 15px; }
        .category-title { margin-top: 0; color: #569cd6; border-bottom: 1px solid #444; padding-bottom: 10px; cursor: pointer; position: relative; user-select: none; }
        .category-title::after { content: '▶'; position: absolute; right: 5px; font-size: 0.8em; transition: transform 0.2s ease-in-out; }
        .category-title:not(.collapsed)::after { transform: rotate(90deg); }
        .collapsible-content { padding-top: 10px; display: none; }
        .checkbox-group { display: flex; flex-direction: column; gap: 10px; }
        .checkbox-item { display: flex; align-items: center; justify-content: space-between; }
        .checkbox-item label { cursor: pointer; flex-grow: 1; }
        .checkbox-item input { margin-right: 10px; accent-color: var(--prompt-color); width: 16px; height: 16px;}
        .ai-info-btn { background: none; border: none; cursor: pointer; font-size: 12px; padding: 0 5px; line-height: 1; vertical-align: middle; color: var(--button-summarize-bg); transition: transform 0.2s ease; }
        .ai-info-btn:hover { transform: scale(1.2); color: var(--prompt-color); }
        .scan-list { margin-top: 30px; }
        .scan-card { background-color: var(--container-bg); border: 1px solid #333; border-left-width: 5px; border-radius: var(--border-radius); margin-bottom: 20px; overflow: hidden; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2); }
        .scan-card-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; background-color: #2a2a2a; flex-wrap: wrap; gap: 10px; }
        .header-left { flex-grow: 1; min-width: 200px; }
        .header-right { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
        .scan-target { font-size: 1.2em; font-weight: bold; color: var(--prompt-color); }
        .status { padding: 5px 12px; border-radius: 20px; font-size: 0.9em; font-weight: bold; color: white; white-space: nowrap; }
        .status.beklemede { background-color: var(--warning-color); color: #121212; }
        .status.calisiyor { background-color: var(--info-color); animation: pulse 1.5s infinite; }
        .status.tamamlandi { background-color: var(--success-color); }
        .status.durduruldu { background-color: var(--button-clear-bg); }
        .scan-card.status-beklemede { border-left-color: var(--warning-color); }
        .scan-card.status-calisiyor { border-left-color: var(--info-color); }
        .scan-card.status-tamamlandi { border-left-color: var(--success-color); }
        .scan-card.status-durduruldu { border-left-color: var(--button-clear-bg); }
        .action-button { padding: 6px 12px; color: white; border: none; border-radius: var(--border-radius); cursor: pointer; font-weight: bold; transition: opacity 0.3s; font-size: 14px; }
        .stop-button { background-color: var(--button-stop-bg); }
        .ai-button { background-color: var(--button-summarize-bg); }
        .scan-card-body { padding: 20px; display: none; background-color: #121212; }
        .command-list { list-style: none; padding: 0; }
        .command-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #333; flex-wrap: wrap; gap: 10px;}
        .command-item:last-child { border-bottom: none; }
        .command-name { flex-grow: 1; }
        .command-status { margin-left: 20px; min-width: 100px; text-align: right; }
        .command-status a { color: var(--prompt-color); text-decoration: none; font-weight: bold; }
        .ai-result-container { margin-top: 20px; padding: 15px; background-color: #0d0d0d; border-radius: var(--border-radius); border: 1px solid #333; }
        .ai-result-container h4 { margin-top: 0; color: #569cd6; }
        .ai-result-content { white-space: pre-wrap; word-wrap: break-word; font-family: inherit; font-size: 0.9em; color: var(--text-color); }
        .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3); border-radius: 50%; border-top-color: #fff; animation: spin 1s ease-in-out infinite; margin-right: 5px; }
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.7); display: flex; justify-content: center; align-items: center; z-index: 1000; transition: opacity 0.3s ease; }
        .modal-content { background-color: var(--container-bg); padding: 25px; border-radius: var(--border-radius); box-shadow: 0 5px 25px rgba(0,0,0,0.4); width: 90%; max-width: 600px; position: relative; border-top: 4px solid var(--prompt-color); border: 1px solid #333; }
        .modal-close-btn { position: absolute; top: 10px; right: 15px; background: none; border: none; color: var(--text-color); font-size: 2em; cursor: pointer; line-height: 1; }
        #modal-title { margin-top: 0; color: #569cd6; }
        .chat-container { height: 300px; max-height: 50vh; overflow-y: auto; border: 1px solid #333; border-radius: var(--border-radius); padding: 10px; margin-bottom: 15px; background-color: var(--background-color); }
        .chat-message { margin-bottom: 10px; padding: 8px
