import os
import platform
import subprocess
import psutil
import json
import stat
from datetime import datetime

def ensure_directory_exists(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_system_info():
    return {
        "System": platform.system(),
        "Node": platform.node(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "Architecture": platform.architecture(),
        "Boot Time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    }

def get_installed_software():
    software_list = []
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(['wmic', 'product', 'get', 'name,version'], shell=True)
            lines = output.decode().split('\n')[1:]
            for line in lines:
                if line.strip():
                    software_list.append(line.strip())
    except Exception as e:
        software_list.append(f"Error: {e}")
    return software_list

def get_running_processes():
    processes = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'status', 'create_time', 'memory_info']):
        try:
            proc_info = proc.info
            proc_info['create_time'] = datetime.fromtimestamp(proc_info['create_time']).strftime("%Y-%m-%d %H:%M:%S")
            proc_info['memory_info'] = proc_info['memory_info']._asdict()
            processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def get_network_info():
    network_info = psutil.net_if_addrs()
    net_io_counters = psutil.net_io_counters(pernic=True)
    return {
        "Interfaces": {iface: [snic._asdict() for snic in snics] for iface, snics in network_info.items()},
        "IO Counters": {iface: counters._asdict() for iface, counters in net_io_counters.items()}
    }

def get_users():
    users = []
    try:
        users = psutil.users()
    except Exception as e:
        users.append(f"Error: {e}")
    return [user._asdict() for user in users]

def get_scheduled_tasks():
    tasks = []
    try:
        output = subprocess.check_output(['schtasks'], shell=True)
        tasks = output.decode().split('\n')
    except Exception as e:
        tasks.append(f"Error: {e}")
    return tasks

def get_environment_variables():
    return dict(os.environ)

def get_disk_info():
    disk_partitions = psutil.disk_partitions()
    disk_info = {}
    for partition in disk_partitions:
        usage = psutil.disk_usage(partition.mountpoint)._asdict()
        disk_info[partition.device] = {
            "mountpoint": partition.mountpoint,
            "fstype": partition.fstype,
            "opts": partition.opts,
            "usage": usage
        }
    return disk_info

def get_memory_info():
    virtual_memory = psutil.virtual_memory()._asdict()
    swap_memory = psutil.swap_memory()._asdict()
    return {
        "Virtual Memory": virtual_memory,
        "Swap Memory": swap_memory
    }

def get_cpu_info():
    return {
        "Physical Cores": psutil.cpu_count(logical=False),
        "Total Cores": psutil.cpu_count(logical=True),
        "Max Frequency": psutil.cpu_freq().max,
        "Min Frequency": psutil.cpu_freq().min,
        "Current Frequency": psutil.cpu_freq().current,
        "CPU Usage": psutil.cpu_percent(interval=1, percpu=True)
    }

def get_network_connections():
    connections = psutil.net_connections()
    return [conn._asdict() for conn in connections]

def get_firewall_rules():
    firewall_rules = []
    try:
        output = subprocess.check_output(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], shell=True)
        firewall_rules = output.decode().split('\n')
    except Exception as e:
        firewall_rules.append(f"Error: {e}")
    return firewall_rules

def get_services_info():
    services = []
    try:
        output = subprocess.check_output(['sc', 'query', 'type=', 'service', 'state=', 'all'], shell=True)
        services = output.decode().split('\n')
    except Exception as e:
        services.append(f"Error: {e}")
    return services

def get_security_policies():
    security_policies = []
    try:
        output = subprocess.check_output(['secedit', '/export', '/cfg', 'secconfig.inf', '/areas', 'SECURITYPOLICY'], shell=True)
        with open('secconfig.inf', 'r') as file:
            security_policies = file.readlines()
        os.remove('secconfig.inf')
    except Exception as e:
        security_policies.append(f"Error: {e}")
    return security_policies

def get_audit_policies():
    audit_policies = []
    try:
        output = subprocess.check_output(['auditpol', '/get', '/category:*'], shell=True)
        audit_policies = output.decode().split('\n')
    except Exception as e:
        audit_policies.append(f"Error: {e}")
    return audit_policies

def check_permissions(path, output_file):
    try:
        st = os.stat(path)
        if bool(st.st_mode & stat.S_IWGRP) or bool(st.st_mode & stat.S_IWOTH):
            output_file.write(f"[VULNERABLE] {path} is writable by group or others.\n")
        else:
            output_file.write(f"[SAFE] {path} has safe permissions.\n")
    except Exception as e:
        output_file.write(f"Error checking {path}: {e}\n")

def scan_directories(directories, output_file_path):
    ensure_directory_exists(output_file_path)  # Ensure the directory exists
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        for directory in directories:
            for root, dirs, files in os.walk(directory):
                for name in dirs + files:
                    check_permissions(os.path.join(root, name), output_file)

def save_to_file(data, folder, filename):
    file_path = os.path.join(folder, filename)
    ensure_directory_exists(file_path)
    with open(file_path, 'w', encoding='utf-8') as f:
        if isinstance(data, dict):
            json.dump(data, f, indent=4)
        elif isinstance(data, list):
            for item in data:
                f.write(f"{item}\n")
        else:
            f.write(str(data))

def main():
    base_dir = 'Audit'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # System Information
    system_info = get_system_info()
    save_to_file(system_info, os.path.join(base_dir, 'System'), f'system_info_{timestamp}.json')

    # Installed Software
    installed_software = get_installed_software()
    save_to_file(installed_software, os.path.join(base_dir, 'Software'), f'installed_software_{timestamp}.txt')

    # Running Processes
    running_processes = get_running_processes()
    save_to_file(running_processes, os.path.join(base_dir, 'Processes'), f'running_processes_{timestamp}.json')

    # Network Information
    network_info = get_network_info()
    save_to_file(network_info, os.path.join(base_dir, 'Network'), f'network_info_{timestamp}.json')

    # Users
    users = get_users()
    save_to_file(users, os.path.join(base_dir, 'Users'), f'users_{timestamp}.json')

    # Scheduled Tasks
    scheduled_tasks = get_scheduled_tasks()
    save_to_file(scheduled_tasks, os.path.join(base_dir, 'Tasks'), f'scheduled_tasks_{timestamp}.txt')

    # Environment Variables
    environment_variables = get_environment_variables()
    save_to_file(environment_variables, os.path.join(base_dir, 'Environment'), f'environment_variables_{timestamp}.json')

    # Disk Information
    disk_info = get_disk_info()
    save_to_file(disk_info, os.path.join(base_dir, 'Disk'), f'disk_info_{timestamp}.json')

    # Memory Information
    memory_info = get_memory_info()
    save_to_file(memory_info, os.path.join(base_dir, 'Memory'), f'memory_info_{timestamp}.json')

    # CPU Information
    cpu_info = get_cpu_info()
    save_to_file(cpu_info, os.path.join(base_dir, 'CPU'), f'cpu_info_{timestamp}.json')

    # Network Connections
    network_connections = get_network_connections()
    save_to_file(network_connections, os.path.join(base_dir, 'Network'), f'network_connections_{timestamp}.json')

    # Firewall Rules
    firewall_rules = get_firewall_rules()
    save_to_file(firewall_rules, os.path.join(base_dir, 'Firewall'), f'firewall_rules_{timestamp}.txt')

    # Services Information
    services_info = get_services_info()
    save_to_file(services_info, os.path.join(base_dir, 'Services'), f'services_info_{timestamp}.txt')

    # Security Policies
    security_policies = get_security_policies()
    save_to_file(security_policies, os.path.join(base_dir, 'Policies'), f'security_policies_{timestamp}.txt')

    # Audit Policies
    audit_policies = get_audit_policies()
    save_to_file(audit_policies, os.path.join(base_dir, 'Policies'), f'audit_policies_{timestamp}.txt')

    # Permission Checks
    directories_to_scan = ["C:\\Program Files", "C:\\Program Files (x86)"]
    output_file_path = os.path.join(base_dir, 'Permissions', f'permissions_check_results_{timestamp}.txt')
    scan_directories(directories_to_scan, output_file_path)

if __name__ == "__main__":
    main()
