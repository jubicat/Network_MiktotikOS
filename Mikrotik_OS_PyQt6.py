import sys
from time import sleep
import netmiko
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QLabel,
    QLineEdit, QTextEdit, QMainWindow, QInputDialog
)

CREDS = {
    "device_type": "mikrotik_routeros",
    "ip": "192.168.37.2",
    "username": "admin",
    "password": "admin",
    "port": "28",
}

class MikrotikSimulator(QMainWindow):
    def __init__(self):
        super().__init__()

        self.init_ui()
        self.connection = None

    def init_ui(self):
        self.setWindowTitle('MikroTik Simulator')
        self.setGeometry(100, 100, 1000, 600)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)

        ip_label = QLabel("Enter IP:")
        self.ip_input = QLineEdit(CREDS['ip'])

        username_label = QLabel("Enter Username:")
        self.username_input = QLineEdit(CREDS['username'])

        password_label = QLabel("Enter Password:")
        self.password_input = QLineEdit(CREDS['password'])

        port_label = QLabel("Enter Port:")
        self.port_input = QLineEdit(CREDS['port'])

        connect_button = QPushButton("Connect")
        connect_button.clicked.connect(self.connect)

        show_ip_button = QPushButton("Show IP")
        show_ip_button.clicked.connect(self.show_ip)

        change_ip_button = QPushButton("Change IP")
        change_ip_button.clicked.connect(self.change_ip)

        add_ip_button = QPushButton("Add IP")
        add_ip_button.clicked.connect(self.add_ip)

        remove_ip_button = QPushButton("Remove IP")
        remove_ip_button.clicked.connect(self.remove_ip)
        show_services_button = QPushButton("Show services and ports")
        show_services_button.clicked.connect(self.show_services)

        change_service_port_button = QPushButton("Change service port")
        change_service_port_button.clicked.connect(self.change_service_port)

        show_firewall_rules_button = QPushButton("Show firewall rules")
        show_firewall_rules_button.clicked.connect(self.show_firewall_rules)

        add_new_firewall_rules_button = QPushButton("Add new firewall rules")
        add_new_firewall_rules_button.clicked.connect(self.add_new_firewall_rules)

        remove_firewall_rule_button = QPushButton("Remove firewall rule")
        remove_firewall_rule_button.clicked.connect(self.remove_firewall_rule)

        enable_firewall_rule_button = QPushButton("Enable Firewall Rule")
        enable_firewall_rule_button.clicked.connect(self.enable_firewall_rule)

        connect_internet_button = QPushButton("Connect to Internet")
        connect_internet_button.clicked.connect(self.connect_internet)

        disconnect_internet_button = QPushButton("Disconnect from Internet")
        disconnect_internet_button.clicked.connect(self.disconnect_internet_button)
        
        layout = QVBoxLayout()
        
        layout = QVBoxLayout()
        layout.addWidget(ip_label)
        layout.addWidget(self.ip_input)
        layout.addWidget(username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(connect_button)
        layout.addWidget(show_ip_button)
        layout.addWidget(change_ip_button)
        layout.addWidget(add_ip_button)
        layout.addWidget(remove_ip_button)
        layout.addWidget(connect_button)
        layout.addWidget(show_services_button)
        layout.addWidget(change_service_port_button)
        layout.addWidget(show_firewall_rules_button)
        layout.addWidget(add_new_firewall_rules_button)
        layout.addWidget(remove_firewall_rule_button)
        layout.addWidget(enable_firewall_rule_button)
        layout.addWidget(connect_internet_button)
        layout.addWidget(disconnect_internet_button)
        layout.addWidget(self.output_text)

        central_widget.setLayout(layout)

    def clean_output(self):
        self.output_text.clear()

    def connect(self):
        if self.connection is not None:
            self.connection.disconnect()
        creds = {
            "device_type": "mikrotik_routeros",
            "ip": self.ip_input.text(),
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "port": self.port_input.text(),
        }
        for _ in range(3):  # 3 times retry
            try:
                self.connection = netmiko.ConnectHandler(**creds)
                self.output_text.append("Connected")
                return
            except Exception as e:
                self.output_text.append(f'Login failed: {str(e)}. Retrying...')
                sleep(10)
                continue

    def show_ip(self):
        if self.connection is not None:
            self.clean_output()
            output = self.connection.send_command("ip address print", cmd_verify=False)
            self.output_text.append(output)

    def change_ip(self):
        if self.connection is not None:
            self.clean_output()
            text, ok1 = QInputDialog.getText(self, "Enter IP", "IP Address")
            interface, ok2 = QInputDialog.getText(self, "Enter Interface", "Interface (ether1, ether2, ether3)")
            if ok1 and ok2 and interface.lower() in ['ether1', 'ether2', 'ether3']:
                self.ip_input.setText(text)
                output = self.connection.send_command(f"ip address set [find interface={interface}] address={text}", cmd_verify=False)
                self.output_text.append(output)
            elif not ok1 or not ok2:
                self.output_text.append('Enter IP and Interface correctly')
            elif not text:
                self.output_text.append('Enter IP correctly')
            elif interface.lower() not in ['ether1', 'ether2', 'ether3']:
                self.output_text.append('Enter Interface correctly')
    def add_ip(self):
        if self.connection is not None:
            self.clean_output()
            text, ok1 = QInputDialog.getText(self, "Enter IP", "IP Address")
            interface, ok2 = QInputDialog.getText(self, "Enter Interface", "Interface (ether1, ether2, ether3)")

            if ok1 and ok2 and interface.lower() in ['ether1', 'ether2', 'ether3']:
                output = self.connection.send_command(f"ip address add address={text} interface={interface}", cmd_verify=False)
                self.output_text.append(output)
            elif not ok1 or not ok2:
                self.output_text.append('Enter IP and Interface correctly')
            elif not text:
                self.output_text.append('Enter IP correctly')
            elif interface.lower() not in ['ether1', 'ether2', 'ether3']:
                self.output_text.append('Enter Interface correctly')
    def remove_ip(self):
        if self.connection is not None:
            self.clean_output()
            interface, ok = QInputDialog.getText(self, "Enter Interface", "Interface (ether1, ether2, ether3)")

            if ok and interface.lower() in ['ether1', 'ether2', 'ether3']:
                output = self.connection.send_command(f"ip address remove [find interface={interface}]", cmd_verify=False)
                self.output_text.append(output)
            elif not ok:
                self.output_text.append('Enter Interface correctly')
            else:
                self.output_text.append('Enter a valid Interface (ether1, ether2, ether3)')
    def change_service_port(self):
        if self.connection is not None:
            self.clean_output()
            service_list = ['telnet', 'ftp', 'www', 'ssh', 'www-ssl', 'api', 'winbox', 'api-ssl']
            service, ok = QInputDialog.getText(self, "Enter Service Name", "Service Name (ssh or ftp):")

            if ok and service.lower() in service_list:
                port, ok = QInputDialog.getText(self, "Enter Port Number", "Port Number:")
                if ok:
                    output = self.connection.send_command(f"/ip service set [find name={service}] port={port}")
                    self.output_text.append(output)
            else:
                self.output_text.append("Enter correct service name")

    def show_services(self):
        if self.connection is not None:
            self.clean_output()
            output = self.connection.send_command('ip service print', cmd_verify=False)
            self.output_text.append(output)

    def add_new_firewall_rules(self):
        if self.connection is not None:
            self.clean_output()
            chains = ['forward', 'input', 'output']
            chain, ok = QInputDialog.getText(self, "Enter Chain", "Chain (forward, input or output):")

            if ok and chain in chains:
                actions = ['accept', 'drop']
                action, ok = QInputDialog.getText(self, "Enter Action", "Action (accept or drop):")

                if ok and action in actions:
                    output = self.connection.send_command(f'ip firewall filter add chain={chain} action={action}')
                    self.output_text.append(output)
                else:
                    self.output_text.append("Enter correct action type")
            else:
                self.output_text.append("Enter correct chain type")

    def remove_firewall_rule(self):
        if self.connection is not None:
            self.clean_output()
            rule_number, ok = QInputDialog.getText(self, "Enter Rule Number", "Firewall Rule Number:")

            if ok:
                output = self.connection.send_command(f"ip firewall filter remove {rule_number}")
                self.output_text.append(output)

    def enable_firewall_rule(self):
        if self.connection is not None:
            self.clean_output()
            rule_number, ok = QInputDialog.getText(self, "Enter Rule Number", "Firewall Rule Number:")

            if ok:
                output = self.connection.send_command(f"ip firewall filter enable {rule_number}")
                self.output_text.append(output)

    def show_firewall_rules(self):
        if self.connection is not None:
            self.clean_output()
            output = self.connection.send_command('ip firewall filter print', cmd_verify=False)
            self.output_text.append(output)
    
    def connect_internet(self):
        if self.connection is not None:
            self.clean_output()
            output = self.connection.send_command('interface ethernet enable [find name!=ether2]')
            self.output_text.append(output)
    
    def disconnect_internet_button(self):
        if self.connection is not None:
            self.clean_output()
            output = self.connection.send_command('interface ethernet disable [find name!=ether2]')
            self.output_text.append(output)
            

def run_app():
    app = QApplication(sys.argv)
    widget = MikrotikSimulator()
    widget.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    run_app()
