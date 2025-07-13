import sys
import os
import json
import base64
import hashlib
import sqlite3
import smtplib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox, QTableWidget,
    QTableWidgetItem, QTabWidget, QComboBox, QGroupBox,
    QListWidget, QScrollArea, QTextEdit, QDialog, QFileDialog,
    QFormLayout, QSizePolicy, QSpacerItem, QStackedWidget, QFrame,
    QDateEdit, QHeaderView, QInputDialog, QListWidgetItem
)
from PySide6.QtCore import Qt, QSize, QTimer, QDateTime, QDate
from PySide6.QtGui import QIntValidator, QFont, QIcon, QPixmap, QColor, QTextCursor

class SecurityUtils:
    @staticmethod
    def generate_salt(size=16):
        return os.urandom(size)
    
    @staticmethod
    def aes_encrypt(data: str, key: bytes) -> dict:
        salt = SecurityUtils.generate_salt()
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return {
            'encrypted': base64.b64encode(encrypted).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }
    
    @staticmethod
    def aes_decrypt(encrypted_data: dict, key: bytes) -> str:
        encrypted = base64.b64decode(encrypted_data['encrypted'])
        iv = base64.b64decode(encrypted_data['iv'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode('utf-8')
    
    @staticmethod
    def pbkdf2_hash(password: str, salt: bytes, iterations=100000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def generate_fernet_key(password: str, salt: bytes) -> bytes:
        key_material = SecurityUtils.pbkdf2_hash(password, salt)
        return base64.urlsafe_b64encode(key_material)
    
    @staticmethod
    def encrypt_data(data: str, password: str) -> dict:
        salt = SecurityUtils.generate_salt()
        key = SecurityUtils.pbkdf2_hash(password, salt)
        encrypted_data = SecurityUtils.aes_encrypt(data, key)
        return {
            'encrypted_data': encrypted_data,
            'salt': base64.b64encode(salt).decode('utf-8')
        }
    
    @staticmethod
    def decrypt_data(encrypted_package: dict, password: str) -> str:
        salt = base64.b64decode(encrypted_package['salt'])
        key = SecurityUtils.pbkdf2_hash(password, salt)
        return SecurityUtils.aes_decrypt(encrypted_package['encrypted_data'], key)
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None, iterations=100000) -> dict:
        if salt is None:
            salt = SecurityUtils.generate_salt()
        hashed = SecurityUtils.pbkdf2_hash(password, salt, iterations)
        return {
            'hashed': base64.b64encode(hashed).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iterations': iterations
        }

class DatabaseManager:
    def __init__(self, db_name="hr_database.db"):
        self.db_name = db_name
        self.connection = sqlite3.connect(db_name)
        self.create_tables()
        self.create_indexes()
        self.create_default_users()
    
    def create_tables(self):
        cursor = self.connection.cursor()
        
        # Employees table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            iterations INTEGER NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            salary REAL NOT NULL,
            contact TEXT NOT NULL,
            contact_iv TEXT,
            contact_salt TEXT NOT NULL,
            hire_date TEXT NOT NULL,
            hire_reason TEXT,
            last_login TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """)
        
        # Leave applications table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS leave_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            leave_type TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            approver_id INTEGER,
            comments TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (employee_id) REFERENCES employees (id),
            FOREIGN KEY (approver_id) REFERENCES employees (id)
        )
        """)
        
        # System logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES employees (id)
        )
        """)
        
        # Terminations table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS terminations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            termination_type TEXT NOT NULL,
            termination_date TEXT NOT NULL,
            reason TEXT NOT NULL,
            processed_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (employee_id) REFERENCES employees (id),
            FOREIGN KEY (processed_by) REFERENCES employees (id)
        )
        """)
        
        self.connection.commit()
    
    def create_indexes(self):
        cursor = self.connection.cursor()
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_employees_role ON employees(role)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_employees_department ON employees(department)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_leave_applications_employee_id ON leave_applications(employee_id)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_leave_applications_status ON leave_applications(status)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_terminations_employee_id ON terminations(employee_id)")
        self.connection.commit()
    
    def create_default_users(self):
        default_users = [
            ("root1", "root123", "System Root", "root",
             "Management", 0, "root@company.com"),
            ("boss1", "boss123", "Company Boss", "boss",
             "Management", 100000, "boss@company.com"),
            ("admin1", "admin123", "System Admin",
             "admin", "IT", 80000, "admin@company.com"),
            ("moderator1", "moderator123", "Department Moderator",
             "moderator", "HR", 60000, "moderator@company.com")
        ]
        
        cursor = self.connection.cursor()
        for user in default_users:
            cursor.execute(
                "SELECT id FROM employees WHERE username=?", (user[0],))
            if not cursor.fetchone():
                password_data = SecurityUtils.hash_password(user[1])
                encrypted_contact = SecurityUtils.encrypt_data(
                    user[6], "secure_master_key_placeholder")
                current_time = datetime.now().isoformat()
                cursor.execute("""
                INSERT INTO employees (
                    username, password, salt, iterations, name, role, department, salary,
                    contact, contact_iv, contact_salt, hire_date, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user[0],
                    password_data['hashed'],
                    password_data['salt'],
                    password_data['iterations'],
                    user[2],
                    user[3],
                    user[4],
                    user[5],
                    encrypted_contact['encrypted_data']['encrypted'],
                    encrypted_contact['encrypted_data']['iv'],
                    encrypted_contact['encrypted_data']['salt'],
                    current_time,
                    current_time,
                    current_time
                ))
        self.connection.commit()
    
    def log_activity(self, user_id, action, details=None, ip_address=None):
        cursor = self.connection.cursor()
        cursor.execute("""
        INSERT INTO system_logs (user_id, action, details, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            action,
            details,
            ip_address,
            datetime.now().isoformat()
        ))
        self.connection.commit()
    
    def close(self):
        self.connection.close()

class StyledButton(QPushButton):
    def __init__(self, text, parent=None, color="#4CAF50", hover_color="#45a049", pressed_color="#3e8e41"):
        super().__init__(text, parent)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                padding: 8px 16px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px 2px;
                border-radius: 4px;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
            }}
            QPushButton:pressed {{
                background-color: {pressed_color};
            }}
            QPushButton:disabled {{
                background-color: #cccccc;
                color: #666666;
            }}
        """)

class StyledLineEdit(QLineEdit):
    def __init__(self, parent=None, placeholder="", password=False):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        if password:
            self.setEchoMode(QLineEdit.Password)
        self.setStyleSheet("""
            QLineEdit {
                padding: 6px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #4CAF50;
            }
        """)

class StyledComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QComboBox {
                padding: 6px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 14px;
            }
            QComboBox:focus {
                border: 1px solid #4CAF50;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left-width: 1px;
                border-left-color: #ccc;
                border-left-style: solid;
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
            }
        """)

class StyledTableWidget(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QTableWidget {
                border: 1px solid #ddd;
                font-size: 14px;
                selection-background-color: #e6f3ff;
                selection-color: black;
            }
            QHeaderView::section {
                background-color: #f2f2f2;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 6px;
            }
        """)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

class StyledListWidget(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QListWidget {
                border: 1px solid #ddd;
                font-size: 14px;
                selection-background-color: #e6f3ff;
                selection-color: black;
            }
        """)

class HRManagementSystem(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HR Management System")
        self.setMinimumSize(QSize(1200, 800))
        
        # Create necessary directories if they don't exist
        if not os.path.exists("candidates"):
            os.makedirs("candidates")
        
        # Security configuration
        # In production, use proper key management
        self.master_key = "secure_master_key_placeholder"
        
        # Initialize database
        self.db = DatabaseManager()
        
        # System configuration
        self.roles = ["root", "boss", "admin", "moderator",
                      "senior", "engineer", "assistant", "intern"]
        self.departments = [
            "Management", "IT", "HR", "Finance", "Marketing",
            "Sales", "Operations", "Cybersecurity", "R&D"
        ]
        self.leave_types = ["Annual", "Sick",
                            "Maternity", "Paternity", "Unpaid", "Other"]
        self.termination_types = ["Resignation",
                                  "Termination", "Dismissal", "Retirement"]
        
        # Current user
        self.current_user = None
        
        # SMTP configuration
        self.smtp_config = {
            'server': 'smtp.example.com',
            'port': 587,
            'username': 'hr@example.com',
            'password': 'email_password',
            'from_email': 'hr@example.com'
        }
        
        # Create login screen
        self.init_login_ui()
        
        # Status bar
        self.statusBar().showMessage("Ready")
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status_bar)
        self.timer.start(1000)
    
    def update_status_bar(self):
        current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        user_info = f"Not logged in" if not self.current_user else f"User: {self.current_user['name']} ({self.current_user['role']})"
        self.statusBar().showMessage(
            f"{user_info} | System Status: Operational | {current_time}")
    
    def init_login_ui(self):
        self.login_widget = QWidget()
        self.setCentralWidget(self.login_widget)
        
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        self.login_widget.setLayout(layout)
        
        # Logo/Title
        title_label = QLabel("HR Management System")
        title_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-bottom: 30px;
        """)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Login Form
        form_container = QWidget()
        form_container.setMaximumWidth(400)
        form_container.setStyleSheet("""
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            border: 1px solid #ddd;
        """)
        form_layout = QVBoxLayout(form_container)
        form_layout.setSpacing(20)
        
        # Username
        self.username_input = StyledLineEdit(placeholder="Enter your username")
        form_layout.addWidget(QLabel("Username:"))
        form_layout.addWidget(self.username_input)
        
        # Password
        self.password_input = StyledLineEdit(
            placeholder="Enter your password", password=True)
        form_layout.addWidget(QLabel("Password:"))
        form_layout.addWidget(self.password_input)
        
        # Login button
        login_button = StyledButton("Login")
        login_button.clicked.connect(self.login)
        form_layout.addWidget(login_button)
        
        # Pressing Enter triggers login
        self.password_input.returnPressed.connect(self.login)
        
        layout.addWidget(form_container)
        
        # Footer
        footer_label = QLabel("© 2024 HR Management System")
        footer_label.setStyleSheet("color: #666; margin-top: 30px;")
        footer_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(footer_label)
    
    def login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(
                self, "Warning", "Please enter both username and password")
            return
        
        cursor = self.db.connection.cursor()
        cursor.execute("""
        SELECT id, username, password, salt, iterations, name, role, department, salary,
               contact, contact_iv, contact_salt, is_active
        FROM employees WHERE username=?
        """, (username,))
        
        user_data = cursor.fetchone()
        
        if user_data:
            if not user_data[12]:  # is_active check
                QMessageBox.warning(
                    self, "Account Disabled", "Your account is disabled. Please contact HR.")
                return
            
            # Verify password
            salt = base64.b64decode(user_data[3])
            iterations = user_data[4]
            hashed_password = SecurityUtils.hash_password(
                password, salt, iterations)['hashed']
            
            if hashed_password == user_data[2]:
                # Decrypt contact information
                encrypted_contact = {
                    'encrypted': user_data[9],
                    'iv': user_data[10],
                    'salt': user_data[11]
                }
                try:
                    contact = SecurityUtils.decrypt_data(
                        {'encrypted_data': encrypted_contact}, self.master_key)
                except:
                    contact = "Encrypted"
                
                self.current_user = {
                    "id": user_data[0],
                    "username": user_data[1],
                    "password": hashed_password,
                    "salt": user_data[3],
                    "iterations": iterations,
                    "name": user_data[5],
                    "role": user_data[6],
                    "department": user_data[7],
                    "salary": user_data[8],
                    "contact": contact,
                    "is_active": user_data[12]
                }
                
                # Update last login
                cursor.execute("""
                UPDATE employees SET last_login=? WHERE id=?
                """, (datetime.now().isoformat(), self.current_user["id"]))
                self.db.connection.commit()
                
                # Log login activity
                self.db.log_activity(
                    self.current_user["id"], "login", f"User logged in from {self.get_ip_address()}")
                
                self.init_main_ui()
            else:
                QMessageBox.critical(self, "Login Failed",
                                     "Invalid username or password")
        else:
            QMessageBox.critical(self, "Login Failed",
                                 "Invalid username or password")
    
    def get_ip_address(self):
        """Simplified method to get IP (in real app, use proper method)"""
        return "127.0.0.1"  # Placeholder
    
    def init_main_ui(self):
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        self.main_widget.setLayout(layout)
        
        # Header
        header = QWidget()
        header.setStyleSheet(
            "background-color: #4CAF50; color: white; padding: 10px; border-radius: 4px;")
        header_layout = QHBoxLayout(header)
        
        user_info = QLabel(
            f"Welcome, {self.current_user['name']} ({self.current_user['role']})")
        user_info.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(user_info)
        
        logout_button = StyledButton(
            "Logout", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
        logout_button.clicked.connect(self.logout)
        header_layout.addWidget(logout_button)
        
        layout.addWidget(header)
        
        # Create tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Employee Management Tab
        self.emp_management_tab = QWidget()
        self.setup_employee_management_tab()
        self.tabs.addTab(self.emp_management_tab, "👥 Employee Management")
        
        # Personal Tab
        self.personal_tab = QWidget()
        self.setup_personal_tab()
        self.tabs.addTab(self.personal_tab, "👤 Personal")
        
        # Leave Management Tab
        self.leave_tab = QWidget()
        self.setup_leave_management_tab()
        self.tabs.addTab(self.leave_tab, "📅 Leave Management")
        
        # Recruitment Tab (for authorized roles)
        if self.check_permission("manage_recruitment"):
            self.recruitment_tab = QWidget()
            self.setup_recruitment_tab()
            self.tabs.addTab(self.recruitment_tab, "📝 Recruitment")
        
        # Reports Tab (for authorized roles)
        if self.check_permission("view_reports"):
            self.reports_tab = QWidget()
            self.setup_reports_tab()
            self.tabs.addTab(self.reports_tab, "📊 Reports")
        
        # Admin Tab (for admin+ roles)
        if self.check_permission("admin_access"):
            self.admin_tab = QWidget()
            self.setup_admin_tab()
            self.tabs.addTab(self.admin_tab, "⚙️ Admin")
        
        self.refresh_employee_list()
    
    def check_permission(self, permission):
        """Check if current user has the required permission"""
        role_permissions = {
            'root': ['all'],
            'boss': ['manage_employees', 'view_reports', 'approve_leave', 'admin_access', 'terminate_employee'],
            'admin': ['manage_employees', 'view_reports', 'manage_recruitment', 'admin_access', 'terminate_employee'],
            'moderator': ['manage_recruitment', 'view_team_reports', 'terminate_employee'],
            'senior': ['view_team_reports', 'request_leave'],
            'engineer': ['request_leave'],
            'assistant': ['request_leave'],
            'intern': ['request_leave']
        }
        
        user_role = self.current_user['role']
        if 'all' in role_permissions.get(user_role, []):
            return True
        return permission in role_permissions.get(user_role, [])
    
    def can_terminate_employee(self, target_role):
        """Check if current user can terminate employee with given role"""
        current_role = self.current_user['role']
        target_role_index = self.roles.index(target_role)
        
        # Only these roles can terminate employees
        if current_role not in ['root', 'boss', 'admin', 'moderator']:
            return False
        
        # Boss can terminate anyone (including other bosses)
        if current_role == 'boss':
            return True
        
        # Root can terminate anyone except other roots
        if current_role == 'root':
            return target_role != 'root'
        
        # Admin can terminate moderator and below
        if current_role == 'admin':
            return target_role_index >= self.roles.index('moderator')
        
        # Moderator can only terminate senior and below
        if current_role == 'moderator':
            return target_role_index >= self.roles.index('senior')
        
        return False
    
    def get_available_roles_for_creation(self):
        """Determine which roles current user can assign"""
        current_role = self.current_user['role']
        if current_role == "root":
            return self.roles[1:]  # Can create any role except root
        elif current_role == "boss":
            return self.roles[2:]  # Can create admin and below
        elif current_role == "admin":
            return self.roles[3:]  # Can create moderator and below
        elif current_role == "moderator":
            return self.roles[4:]  # Can create senior and below
        else:
            return []  # No permission to create users
    
    def get_available_departments_for_role(self, role):
        """Determine which departments are available for the selected role"""
        if role in ["root", "boss"]:
            return ["Management"]  # Only Management for root and boss
        else:
            return self.departments  # All departments for other roles
    
    def setup_employee_management_tab(self):
        layout = QVBoxLayout()
        self.emp_management_tab.setLayout(layout)
        
        # Filter controls
        filter_group = QGroupBox("Employee Filter")
        filter_layout = QHBoxLayout()
        
        self.employee_filter_input = StyledLineEdit(
            placeholder="Search by name...")
        self.employee_filter_input.textChanged.connect(self.filter_employees)
        
        self.department_filter_combo = StyledComboBox()
        self.department_filter_combo.addItem("All Departments")
        self.department_filter_combo.addItems(self.departments)
        self.department_filter_combo.currentTextChanged.connect(
            self.filter_employees)
        
        self.status_filter_combo = StyledComboBox()
        self.status_filter_combo.addItem("All Statuses")
        self.status_filter_combo.addItems(["Active", "Inactive"])
        self.status_filter_combo.currentTextChanged.connect(
            self.filter_employees)
        
        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.employee_filter_input)
        filter_layout.addWidget(QLabel("Department:"))
        filter_layout.addWidget(self.department_filter_combo)
        filter_layout.addWidget(QLabel("Status:"))
        filter_layout.addWidget(self.status_filter_combo)
        
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        refresh_button = StyledButton("Refresh")
        refresh_button.clicked.connect(self.refresh_employee_list)
        button_layout.addWidget(refresh_button)
        
        if self.check_permission("manage_employees"):
            add_button = StyledButton("Add Employee")
            add_button.clicked.connect(self.show_add_employee_dialog)
            button_layout.addWidget(add_button)
            
            edit_button = StyledButton("Edit Employee")
            edit_button.clicked.connect(self.show_edit_employee_dialog)
            button_layout.addWidget(edit_button)
            
            delete_button = StyledButton(
                "Delete Employee", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
            delete_button.clicked.connect(self.delete_employee)
            button_layout.addWidget(delete_button)
            
            if self.check_permission("terminate_employee"):
                terminate_button = StyledButton(
                    "Terminate Employee", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
                terminate_button.clicked.connect(
                    self.show_terminate_employee_dialog)
                button_layout.addWidget(terminate_button)
        
        layout.addLayout(button_layout)
        
        # Employee Table
        self.employee_table = StyledTableWidget()
        self.employee_table.setColumnCount(6)
        self.employee_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Role", "Department", "Salary", "Status"])
        self.employee_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.employee_table.cellDoubleClicked.connect(
            self.show_employee_details)
        layout.addWidget(self.employee_table)
    
    def show_add_employee_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Employee")
        dialog.setMinimumSize(500, 500)
        layout = QVBoxLayout()
        form = QFormLayout()

        self.new_emp_username = StyledLineEdit()
        self.new_emp_password = StyledLineEdit(password=True)
        self.new_emp_name = StyledLineEdit()
        
        self.new_emp_role = StyledComboBox()
        available_roles = self.get_available_roles_for_creation()
        self.new_emp_role.addItems(available_roles)
        
        self.new_emp_department = StyledComboBox()
        # Initially populate with all departments
        self.new_emp_department.addItems(self.departments)
        
        # Connect role change to department update
        self.new_emp_role.currentTextChanged.connect(self.update_department_options)
        
        # Set initial department options based on first role
        if available_roles:
            self.update_department_options(available_roles[0])
        
        self.new_emp_salary = StyledLineEdit()
        self.new_emp_salary.setValidator(QIntValidator(0, 999999))
        self.new_emp_contact = StyledLineEdit()

        form.addRow("Username:", self.new_emp_username)
        form.addRow("Password:", self.new_emp_password)
        form.addRow("Full Name:", self.new_emp_name)
        form.addRow("Role:", self.new_emp_role)
        form.addRow("Department:", self.new_emp_department)
        form.addRow("Salary:", self.new_emp_salary)
        form.addRow("Contact Info:", self.new_emp_contact)

        # Hiring information
        hire_group = QGroupBox("Hiring Information")
        hire_layout = QFormLayout()
        self.new_emp_hire_date = QDateEdit()
        self.new_emp_hire_date.setDate(QDate.currentDate())
        self.new_emp_hire_date.setCalendarPopup(True)
        self.new_emp_hire_reason = QTextEdit()
        self.new_emp_hire_reason.setMaximumHeight(60)
        hire_layout.addRow("Hire Date:", self.new_emp_hire_date)
        hire_layout.addRow("Hire Reason:", self.new_emp_hire_reason)
        hire_group.setLayout(hire_layout)

        button_box = QHBoxLayout()
        cancel_button = StyledButton(
            "Cancel", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
        cancel_button.clicked.connect(dialog.reject)
        save_button = StyledButton("Save")
        save_button.clicked.connect(lambda: self.save_new_employee(dialog))

        button_box.addWidget(cancel_button)
        button_box.addWidget(save_button)

        layout.addLayout(form)
        layout.addWidget(hire_group)
        layout.addLayout(button_box)
        dialog.setLayout(layout)
        dialog.exec()
    
    def update_department_options(self, selected_role):
        """Update department options based on selected role"""
        if hasattr(self, 'new_emp_department'):
            current_selection = self.new_emp_department.currentText()
            self.new_emp_department.clear()
            
            available_departments = self.get_available_departments_for_role(selected_role)
            self.new_emp_department.addItems(available_departments)
            
            # Try to maintain previous selection if valid
            if current_selection in available_departments:
                self.new_emp_department.setCurrentText(current_selection)
            else:
                # Set default department based on role
                if selected_role in ["root", "boss"]:
                    self.new_emp_department.setCurrentText("Management")
    
    def save_new_employee(self, dialog):
        # Validate inputs
        if not all([
            self.new_emp_username.text(),
            self.new_emp_password.text(),
            self.new_emp_name.text(),
            self.new_emp_salary.text()
        ]):
            QMessageBox.warning(self, "Validation Error",
                                "All fields are required")
            return
        
        try:
            salary = float(self.new_emp_salary.text())
        except ValueError:
            QMessageBox.warning(self, "Validation Error",
                                "Invalid salary amount")
            return
        
        # Check if username exists
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT id FROM employees WHERE username=?",
                       (self.new_emp_username.text(),))
        if cursor.fetchone():
            QMessageBox.warning(self, "Error", "Username already exists")
            return
        
        # Hash password and encrypt contact
        password_data = SecurityUtils.hash_password(
            self.new_emp_password.text())
        encrypted_contact = SecurityUtils.encrypt_data(
            self.new_emp_contact.text(), self.master_key)
        
        hire_date = self.new_emp_hire_date.date().toString("yyyy-MM-dd")
        hire_reason = self.new_emp_hire_reason.toPlainText()
        current_time = datetime.now().isoformat()
        
        try:
            cursor.execute("""
            INSERT INTO employees (
                username, password, salt, iterations, name, role, department, salary,
                contact, contact_iv, contact_salt, hire_date, hire_reason, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.new_emp_username.text(),
                password_data['hashed'],
                password_data['salt'],
                password_data['iterations'],
                self.new_emp_name.text(),
                self.new_emp_role.currentText(),
                self.new_emp_department.currentText(),
                salary,
                encrypted_contact['encrypted_data']['encrypted'],
                encrypted_contact['encrypted_data']['iv'],
                encrypted_contact['encrypted_data']['salt'],
                hire_date,
                hire_reason,
                current_time,
                current_time
            ))
            self.db.connection.commit()
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "employee_create",
                f"Created employee {self.new_emp_username.text()}"
            )
            
            QMessageBox.information(
                self, "Success", "Employee added successfully")
            self.refresh_employee_list()
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to add employee: {str(e)}")
    
    def show_edit_employee_dialog(self):
        selected = self.employee_table.selectedItems()
        if not selected:
            QMessageBox.warning(
                self, "Warning", "Please select an employee to edit")
            return

        emp_id = int(self.employee_table.item(selected[0].row(), 0).text())
        cursor = self.db.connection.cursor()
        cursor.execute("""
        SELECT id, username, name, role, department, salary, contact, is_active, hire_date, hire_reason
        FROM employees WHERE id=?
        """, (emp_id,))
        emp_data = cursor.fetchone()

        if not emp_data:
            QMessageBox.critical(self, "Error", "Employee not found")
            return

        # Check permissions
        if not self.can_modify_employee(emp_data[3]):
            QMessageBox.warning(self, "Permission Denied",
                                "You don't have permission to edit this employee")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit Employee: {emp_data[2]}")
        dialog.setMinimumSize(500, 500)
        layout = QVBoxLayout()
        form = QFormLayout()

        self.edit_emp_id = emp_data[0]
        self.edit_emp_username = StyledLineEdit()
        self.edit_emp_username.setText(emp_data[1])
        self.edit_emp_username.setReadOnly(True)

        self.edit_emp_name = StyledLineEdit()
        self.edit_emp_name.setText(emp_data[2])

        self.edit_emp_role = StyledComboBox()
        self.edit_emp_role.addItems(self.get_available_roles_for_creation())
        self.edit_emp_role.setCurrentText(emp_data[3])

        self.edit_emp_department = StyledComboBox()
        # Set departments based on current role
        available_departments = self.get_available_departments_for_role(emp_data[3])
        self.edit_emp_department.addItems(available_departments)
        self.edit_emp_department.setCurrentText(emp_data[4])
        
        # Connect role change to department update for edit dialog
        self.edit_emp_role.currentTextChanged.connect(self.update_edit_department_options)

        self.edit_emp_salary = StyledLineEdit()
        self.edit_emp_salary.setValidator(QIntValidator(0, 999999))
        self.edit_emp_salary.setText(str(emp_data[5]))

        self.edit_emp_contact = StyledLineEdit()
        self.edit_emp_contact.setText(emp_data[6])

        self.edit_emp_active = QComboBox()
        self.edit_emp_active.addItems(["Active", "Inactive"])
        self.edit_emp_active.setCurrentIndex(0 if emp_data[7] else 1)

        form.addRow("Username:", self.edit_emp_username)
        form.addRow("Full Name:", self.edit_emp_name)
        form.addRow("Role:", self.edit_emp_role)
        form.addRow("Department:", self.edit_emp_department)
        form.addRow("Salary:", self.edit_emp_salary)
        form.addRow("Contact Info:", self.edit_emp_contact)
        form.addRow("Status:", self.edit_emp_active)

        # Hiring information
        hire_group = QGroupBox("Hiring Information")
        hire_layout = QFormLayout()
        self.edit_emp_hire_date = QDateEdit()
        hire_date = QDate.fromString(
            emp_data[8], "yyyy-MM-dd") if emp_data[8] else QDate.currentDate()
        self.edit_emp_hire_date.setDate(hire_date)
        self.edit_emp_hire_date.setCalendarPopup(True)

        self.edit_emp_hire_reason = QTextEdit()
        self.edit_emp_hire_reason.setPlainText(
            emp_data[9] if emp_data[9] else "")
        self.edit_emp_hire_reason.setMaximumHeight(60)

        hire_layout.addRow("Hire Date:", self.edit_emp_hire_date)
        hire_layout.addRow("Hire Reason:", self.edit_emp_hire_reason)
        hire_group.setLayout(hire_layout)

        button_box = QHBoxLayout()
        cancel_button = StyledButton(
            "Cancel", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
        cancel_button.clicked.connect(dialog.reject)
        save_button = StyledButton("Save Changes")
        save_button.clicked.connect(lambda: self.save_employee_changes(dialog))

        button_box.addWidget(cancel_button)
        button_box.addWidget(save_button)

        layout.addLayout(form)
        layout.addWidget(hire_group)
        layout.addLayout(button_box)
        dialog.setLayout(layout)
        dialog.exec()
    
    def update_edit_department_options(self, selected_role):
        """Update department options based on selected role in edit dialog"""
        if hasattr(self, 'edit_emp_department'):
            current_selection = self.edit_emp_department.currentText()
            self.edit_emp_department.clear()
            
            available_departments = self.get_available_departments_for_role(selected_role)
            self.edit_emp_department.addItems(available_departments)
            
            # Try to maintain previous selection if valid
            if current_selection in available_departments:
                self.edit_emp_department.setCurrentText(current_selection)
            else:
                # Set default department based on role
                if selected_role in ["root", "boss"]:
                    self.edit_emp_department.setCurrentText("Management")
    
    def can_modify_employee(self, target_role):
        """Check if current user can modify employee with given role"""
        current_role_index = self.roles.index(self.current_user['role'])
        target_role_index = self.roles.index(target_role)
        return current_role_index <= target_role_index
    
    def save_employee_changes(self, dialog):
        try:
            salary = float(self.edit_emp_salary.text())
        except ValueError:
            QMessageBox.warning(self, "Validation Error",
                                "Invalid salary amount")
            return
        
        # Encrypt contact
        encrypted_contact = SecurityUtils.encrypt_data(
            self.edit_emp_contact.text(), self.master_key)
        
        hire_date = self.edit_emp_hire_date.date().toString("yyyy-MM-dd")
        hire_reason = self.edit_emp_hire_reason.toPlainText()
        
        try:
            cursor = self.db.connection.cursor()
            cursor.execute("""
            UPDATE employees SET
                name=?,
                role=?,
                department=?,
                salary=?,
                contact=?,
                contact_iv=?,
                contact_salt=?,
                is_active=?,
                hire_date=?,
                hire_reason=?,
                updated_at=?
            WHERE id=?
            """, (
                self.edit_emp_name.text(),
                self.edit_emp_role.currentText(),
                self.edit_emp_department.currentText(),
                salary,
                encrypted_contact['encrypted_data']['encrypted'],
                encrypted_contact['encrypted_data']['iv'],
                encrypted_contact['encrypted_data']['salt'],
                self.edit_emp_active.currentIndex() == 0,
                hire_date,
                hire_reason,
                datetime.now().isoformat(),
                self.edit_emp_id
            ))
            self.db.connection.commit()
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "employee_update",
                f"Updated employee {self.edit_emp_username.text()}"
            )
            
            QMessageBox.information(
                self, "Success", "Employee updated successfully")
            self.refresh_employee_list()
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to update employee: {str(e)}")
    
    def delete_employee(self):
        selected = self.employee_table.selectedItems()
        if not selected:
            QMessageBox.warning(
                self, "Warning", "Please select an employee to delete")
            return
        
        emp_id = int(self.employee_table.item(selected[0].row(), 0).text())
        emp_name = self.employee_table.item(selected[0].row(), 1).text()
        
        # Check if trying to delete self
        if emp_id == self.current_user['id']:
            QMessageBox.warning(self, "Error", "You cannot delete yourself")
            return
        
        # Get employee role to check permissions
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT role FROM employees WHERE id=?", (emp_id,))
        emp_role = cursor.fetchone()[0]
        
        if not self.can_modify_employee(emp_role):
            QMessageBox.warning(
                self, "Permission Denied", "You don't have permission to delete this employee")
            return
        
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete {emp_name}? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                cursor.execute("DELETE FROM employees WHERE id=?", (emp_id,))
                self.db.connection.commit()
                
                # Log activity
                self.db.log_activity(
                    self.current_user['id'],
                    "employee_delete",
                    f"Deleted employee {emp_name}"
                )
                
                QMessageBox.information(
                    self, "Success", "Employee deleted successfully")
                self.refresh_employee_list()
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to delete employee: {str(e)}")
    
    def show_terminate_employee_dialog(self):
        selected = self.employee_table.selectedItems()
        if not selected:
            QMessageBox.warning(
                self, "Warning", "Please select an employee to terminate")
            return
        
        emp_id = int(self.employee_table.item(selected[0].row(), 0).text())
        emp_name = self.employee_table.item(selected[0].row(), 1).text()
        
        # Get employee role to check permissions
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT role FROM employees WHERE id=?", (emp_id,))
        emp_role = cursor.fetchone()[0]
        
        if not self.can_terminate_employee(emp_role):
            QMessageBox.warning(self, "Permission Denied",
                                "You don't have permission to terminate this employee")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Terminate Employee: {emp_name}")
        dialog.setMinimumSize(400, 300)
        layout = QVBoxLayout()
        form = QFormLayout()
        
        self.terminate_type = StyledComboBox()
        self.terminate_type.addItems(self.termination_types)
        
        self.terminate_date = QDateEdit()
        self.terminate_date.setDate(QDate.currentDate())
        self.terminate_date.setCalendarPopup(True)
        
        self.terminate_reason = QTextEdit()
        self.terminate_reason.setMaximumHeight(100)
        
        form.addRow("Termination Type:", self.terminate_type)
        form.addRow("Effective Date:", self.terminate_date)
        form.addRow("Reason:", self.terminate_reason)
        
        button_box = QHBoxLayout()
        cancel_button = StyledButton(
            "Cancel", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
        cancel_button.clicked.connect(dialog.reject)
        confirm_button = StyledButton("Confirm Termination")
        confirm_button.clicked.connect(
            lambda: self.process_termination(emp_id, emp_name, dialog))
        
        button_box.addWidget(cancel_button)
        button_box.addWidget(confirm_button)
        
        layout.addLayout(form)
        layout.addLayout(button_box)
        dialog.setLayout(layout)
        dialog.exec()
    
    def process_termination(self, emp_id, emp_name, dialog):
        term_type = self.terminate_type.currentText()
        term_date = self.terminate_date.date().toString("yyyy-MM-dd")
        term_reason = self.terminate_reason.toPlainText().strip()
        
        if not term_reason:
            QMessageBox.warning(self, "Validation Error",
                                "Please provide a reason for termination")
            return
        
        try:
            cursor = self.db.connection.cursor()
            
            # 1. Update employee status to inactive
            cursor.execute("""
            UPDATE employees SET
                is_active=?,
                updated_at=?
            WHERE id=?
            """, (
                0,
                datetime.now().isoformat(),
                emp_id
            ))
            
            # 2. Create termination record
            cursor.execute("""
            INSERT INTO terminations (
                employee_id, termination_type, termination_date, reason,
                processed_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                emp_id,
                term_type,
                term_date,
                term_reason,
                self.current_user['id'],
                datetime.now().isoformat()
            ))
            
            self.db.connection.commit()
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "employee_termination",
                f"Terminated employee {emp_name} ({term_type})"
            )
            
            # Notify employee (simulated)
            self.notify_employee_about_termination(
                emp_id, term_type, term_date, term_reason)
            
            QMessageBox.information(
                self, "Success", "Employee termination processed successfully")
            self.refresh_employee_list()
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to process termination: {str(e)}")
    
    def notify_employee_about_termination(self, emp_id, term_type, term_date, reason):
        """Send email notification to employee about termination"""
        cursor = self.db.connection.cursor()
        cursor.execute(
            "SELECT name, contact FROM employees WHERE id=?", (emp_id,))
        emp_data = cursor.fetchone()
        
        if not emp_data:
            return
        
        subject = f"Employment Termination Notification: {term_type}"
        body = f"""
        Dear {emp_data[0]},

        This is to inform you that your employment has been terminated.

        Type: {term_type}
        Effective Date: {term_date}
        Reason: {reason}

        Please contact HR if you have any questions.

        Sincerely,
        {self.current_user['name']}
        HR Department
        """
        
        # In a real app, you would send this email
        print(f"Would send email to {emp_data[1]}: {subject}\n{body}")
        # self.send_email(emp_data[1], subject, body)
    
    def refresh_employee_list(self):
        cursor = self.db.connection.cursor()
        cursor.execute("""
        SELECT id, name, role, department, salary,
               CASE WHEN is_active THEN 'Active' ELSE 'Inactive' END as status
        FROM employees
        ORDER BY name
        """)
        employees = cursor.fetchall()
        
        self.employee_table.setRowCount(0)
        for emp in employees:
            row = self.employee_table.rowCount()
            self.employee_table.insertRow(row)
            for col, value in enumerate(emp):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.employee_table.setItem(row, col, item)
                # Color inactive employees differently
                if col == 5 and value == "Inactive":
                    for i in range(6):
                        self.employee_table.item(row, i).setBackground(
                            QColor(255, 220, 220))
    
    def filter_employees(self):
        name_filter = self.employee_filter_input.text().lower()
        dept_filter = self.department_filter_combo.currentText()
        status_filter = self.status_filter_combo.currentText()
        
        query = """
        SELECT id, name, role, department, salary,
               CASE WHEN is_active THEN 'Active' ELSE 'Inactive' END as status
        FROM employees
        WHERE LOWER(name) LIKE ?
        """
        params = [f"%{name_filter}%"]
        
        if dept_filter != "All Departments":
            query += " AND department = ?"
            params.append(dept_filter)
        
        if status_filter != "All Statuses":
            query += " AND is_active = ?"
            params.append(1 if status_filter == "Active" else 0)
        
        query += " ORDER BY name"
        
        cursor = self.db.connection.cursor()
        cursor.execute(query, params)
        employees = cursor.fetchall()
        
        self.employee_table.setRowCount(0)
        for emp in employees:
            row = self.employee_table.rowCount()
            self.employee_table.insertRow(row)
            for col, value in enumerate(emp):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.employee_table.setItem(row, col, item)
                # Color inactive employees differently
                if col == 5 and value == "Inactive":
                    for i in range(6):
                        self.employee_table.item(row, i).setBackground(
                            QColor(255, 220, 220))
    
    def show_employee_details(self, row, col):
        emp_id = int(self.employee_table.item(row, 0).text())
        cursor = self.db.connection.cursor()
        cursor.execute("""
        SELECT id, username, name, role, department, salary, contact, hire_date, hire_reason, last_login, is_active
        FROM employees WHERE id=?
        """, (emp_id,))
        emp_data = cursor.fetchone()
        
        if not emp_data:
            return
        
        details_dialog = QDialog(self)
        details_dialog.setWindowTitle(f"Employee Details: {emp_data[2]}")
        details_dialog.setMinimumSize(400, 400)
        layout = QVBoxLayout()
        
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        details_text.setHtml(f"""
        <h2>{emp_data[2]}</h2>
        <table border='0' cellpadding='5'>
            <tr><td width='150'><b>Employee ID:</b></td><td>{emp_data[0]}</td></tr>
            <tr><td><b>Username:</b></td><td>{emp_data[1]}</td></tr>
            <tr><td><b>Role:</b></td><td>{emp_data[3]}</td></tr>
            <tr><td><b>Department:</b></td><td>{emp_data[4]}</td></tr>
            <tr><td><b>Salary:</b></td><td>${emp_data[5]:,.2f}</td></tr>
            <tr><td><b>Contact:</b></td><td>{emp_data[6]}</td></tr>
            <tr><td><b>Hire Date:</b></td><td>{emp_data[7]}</td></tr>
            <tr><td><b>Hire Reason:</b></td><td>{emp_data[8] if emp_data[8] else 'Not specified'}</td></tr>
            <tr><td><b>Last Login:</b></td><td>{emp_data[9] if emp_data[9] else 'Never'}</td></tr>
            <tr><td><b>Status:</b></td><td>{'Active' if emp_data[10] else 'Inactive'}</td></tr>
        </table>
        """)
        
        # Add termination history if exists
        cursor.execute("""
        SELECT termination_type, termination_date, reason, created_at
        FROM terminations
        WHERE employee_id=?
        ORDER BY termination_date DESC
        """, (emp_id,))
        terminations = cursor.fetchall()
        
        if terminations:
            details_text.append("\nTermination History:")
            for term in terminations:
                details_text.append(
                    f"\nType: {term[0]}\nDate: {term[1]}\nReason: {term[2]}\nProcessed: {term[3][:19]}")
        
        close_button = StyledButton("Close")
        close_button.clicked.connect(details_dialog.accept)
        
        layout.addWidget(details_text)
        layout.addWidget(close_button)
        details_dialog.setLayout(layout)
        details_dialog.exec()
    
    def setup_personal_tab(self):
        layout = QVBoxLayout()
        self.personal_tab.setLayout(layout)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        scroll_layout = QVBoxLayout(content)
        
        # Personal Information
        info_group = QGroupBox("Personal Information")
        info_layout = QFormLayout()
        
        self.personal_name = StyledLineEdit()
        self.personal_name.setText(self.current_user['name'])
        
        self.personal_username = StyledLineEdit()
        self.personal_username.setText(self.current_user['username'])
        self.personal_username.setReadOnly(True)
        
        self.personal_role = StyledLineEdit()
        self.personal_role.setText(self.current_user['role'])
        self.personal_role.setReadOnly(True)
        
        self.personal_department = StyledComboBox()
        self.personal_department.addItems(self.departments)
        self.personal_department.setCurrentText(
            self.current_user['department'])
        
        self.personal_salary = StyledLineEdit()
        self.personal_salary.setText(str(self.current_user['salary']))
        self.personal_salary.setReadOnly(True)
        
        self.personal_contact = StyledLineEdit()
        self.personal_contact.setText(self.current_user['contact'])
        
        info_layout.addRow("Name:", self.personal_name)
        info_layout.addRow("Username:", self.personal_username)
        info_layout.addRow("Role:", self.personal_role)
        info_layout.addRow("Department:", self.personal_department)
        info_layout.addRow("Salary:", self.personal_salary)
        info_layout.addRow("Contact:", self.personal_contact)
        
        info_group.setLayout(info_layout)
        scroll_layout.addWidget(info_group)
        
        # Password Change
        pass_group = QGroupBox("Change Password")
        pass_layout = QFormLayout()
        
        self.current_password = StyledLineEdit(password=True)
        self.new_password = StyledLineEdit(password=True)
        self.confirm_password = StyledLineEdit(password=True)
        
        pass_layout.addRow("Current Password:", self.current_password)
        pass_layout.addRow("New Password:", self.new_password)
        pass_layout.addRow("Confirm Password:", self.confirm_password)
        
        pass_group.setLayout(pass_layout)
        scroll_layout.addWidget(pass_group)
        
        # Buttons
        button_box = QHBoxLayout()
        save_info_button = StyledButton("Save Personal Info")
        save_info_button.clicked.connect(self.save_personal_info)
        change_pass_button = StyledButton("Change Password")
        change_pass_button.clicked.connect(self.change_password)
        
        button_box.addWidget(save_info_button)
        button_box.addWidget(change_pass_button)
        
        scroll_layout.addLayout(button_box)
        
        scroll.setWidget(content)
        layout.addWidget(scroll)
    
    def save_personal_info(self):
        new_name = self.personal_name.text().strip()
        new_dept = self.personal_department.currentText()
        new_contact = self.personal_contact.text().strip()
        
        if not all([new_name, new_contact]):
            QMessageBox.warning(self, "Validation Error",
                                "Name and contact information are required")
            return
        
        # Encrypt contact
        encrypted_contact = SecurityUtils.encrypt_data(
            new_contact, self.master_key)
        
        try:
            cursor = self.db.connection.cursor()
            cursor.execute("""
            UPDATE employees SET
                name=?,
                department=?,
                contact=?,
                contact_iv=?,
                contact_salt=?,
                updated_at=?
            WHERE id=?
            """, (
                new_name,
                new_dept,
                encrypted_contact['encrypted_data']['encrypted'],
                encrypted_contact['encrypted_data']['iv'],
                encrypted_contact['encrypted_data']['salt'],
                datetime.now().isoformat(),
                self.current_user['id']
            ))
            self.db.connection.commit()
            
            # Update current user data
            self.current_user['name'] = new_name
            self.current_user['department'] = new_dept
            self.current_user['contact'] = new_contact
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "personal_info_update",
                "Updated personal information"
            )
            
            QMessageBox.information(
                self, "Success", "Personal information updated successfully")
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to update information: {str(e)}")
    
    def change_password(self):
        current_pass = self.current_password.text()
        new_pass = self.new_password.text()
        confirm_pass = self.confirm_password.text()
        
        if not all([current_pass, new_pass, confirm_pass]):
            QMessageBox.warning(self, "Validation Error",
                                "All password fields are required")
            return
        
        if new_pass != confirm_pass:
            QMessageBox.warning(self, "Validation Error",
                                "New passwords do not match")
            return
        
        # Verify current password
        salt = base64.b64decode(self.current_user['salt'])
        iterations = self.current_user['iterations']
        current_hashed = SecurityUtils.hash_password(
            current_pass, salt, iterations)['hashed']
        
        if current_hashed != self.current_user['password']:
            QMessageBox.warning(self, "Validation Error",
                                "Current password is incorrect")
            return
        
        # Hash new password
        new_password_data = SecurityUtils.hash_password(new_pass)
        
        try:
            cursor = self.db.connection.cursor()
            cursor.execute("""
            UPDATE employees SET
                password=?,
                salt=?,
                iterations=?,
                updated_at=?
            WHERE id=?
            """, (
                new_password_data['hashed'],
                new_password_data['salt'],
                new_password_data['iterations'],
                datetime.now().isoformat(),
                self.current_user['id']
            ))
            self.db.connection.commit()
            
            # Update current user data
            self.current_user['password'] = new_password_data['hashed']
            self.current_user['salt'] = new_password_data['salt']
            self.current_user['iterations'] = new_password_data['iterations']
            
            # Clear password fields
            self.current_password.clear()
            self.new_password.clear()
            self.confirm_password.clear()
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "password_change",
                "Changed password"
            )
            
            QMessageBox.information(
                self, "Success", "Password changed successfully")
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to change password: {str(e)}")
    
    def setup_leave_management_tab(self):
        layout = QVBoxLayout()
        self.leave_tab.setLayout(layout)
        
        # Leave Application Button
        if self.check_permission("request_leave"):
            new_leave_button = StyledButton("New Leave Application")
            new_leave_button.clicked.connect(self.show_new_leave_dialog)
            layout.addWidget(new_leave_button)
        
        # Leave List
        self.leave_table = StyledTableWidget()
        self.leave_table.setColumnCount(6)
        self.leave_table.setHorizontalHeaderLabels([
            "ID", "Type", "Start Date", "End Date", "Status", "Days"
        ])
        self.leave_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.refresh_leave_list()
        layout.addWidget(self.leave_table)
        
        # For managers: Approval buttons
        if self.check_permission("approve_leave"):
            approval_box = QHBoxLayout()
            approve_button = StyledButton("Approve Selected")
            approve_button.clicked.connect(self.approve_leave)
            reject_button = StyledButton(
                "Reject Selected", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
            reject_button.clicked.connect(self.reject_leave)
            
            approval_box.addWidget(approve_button)
            approval_box.addWidget(reject_button)
            layout.addLayout(approval_box)
    
    def show_new_leave_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("New Leave Application")
        dialog.setMinimumSize(400, 300)
        layout = QVBoxLayout()
        form = QFormLayout()
        
        self.leave_type = StyledComboBox()
        self.leave_type.addItems(self.leave_types)
        
        self.leave_start = QDateEdit()
        self.leave_start.setDate(QDate.currentDate())
        self.leave_start.setCalendarPopup(True)
        
        self.leave_end = QDateEdit()
        self.leave_end.setDate(QDate.currentDate().addDays(1))
        self.leave_end.setCalendarPopup(True)
        
        self.leave_reason = QTextEdit()
        self.leave_reason.setMaximumHeight(100)
        
        form.addRow("Leave Type:", self.leave_type)
        form.addRow("Start Date:", self.leave_start)
        form.addRow("End Date:", self.leave_end)
        form.addRow("Reason:", self.leave_reason)
        
        button_box = QHBoxLayout()
        cancel_button = StyledButton(
            "Cancel", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
        cancel_button.clicked.connect(dialog.reject)
        submit_button = StyledButton("Submit Application")
        submit_button.clicked.connect(
            lambda: self.submit_leave_application(dialog))
        
        button_box.addWidget(cancel_button)
        button_box.addWidget(submit_button)
        
        layout.addLayout(form)
        layout.addLayout(button_box)
        dialog.setLayout(layout)
        dialog.exec()
    
    def submit_leave_application(self, dialog):
        leave_type = self.leave_type.currentText()
        start_date = self.leave_start.date().toString("yyyy-MM-dd")
        end_date = self.leave_end.date().toString("yyyy-MM-dd")
        reason = self.leave_reason.toPlainText().strip()
        
        if not reason:
            QMessageBox.warning(self, "Validation Error",
                                "Please provide a reason for your leave")
            return
        
        # Calculate number of days
        start = self.leave_start.date()
        end = self.leave_end.date()
        days = start.daysTo(end) + 1  # Inclusive
        
        if days <= 0:
            QMessageBox.warning(self, "Validation Error",
                                "End date must be after start date")
            return
        
        try:
            cursor = self.db.connection.cursor()
            cursor.execute("""
            INSERT INTO leave_applications (
                employee_id, leave_type, start_date, end_date, reason, status,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.current_user['id'],
                leave_type,
                start_date,
                end_date,
                reason,
                "Pending",
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            self.db.connection.commit()
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "leave_submit",
                f"Submitted {leave_type} leave for {days} days"
            )
            
            # Send notification to manager
            self.notify_manager_about_leave(
                leave_type, days, start_date, end_date)
            
            QMessageBox.information(
                self, "Success", "Leave application submitted successfully")
            self.refresh_leave_list()
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to submit leave application: {str(e)}")
    
    def notify_manager_about_leave(self, leave_type, days, start_date, end_date):
        """Send email notification to manager about new leave request"""
        subject = f"New Leave Request: {self.current_user['name']}"
        body = f"""
        You have a new leave request to review:

        Employee: {self.current_user['name']}
        Type: {leave_type}
        Duration: {days} days ({start_date} to {end_date})
        Department: {self.current_user['department']}

        Please review this request in the HR Management System.
        """
        
        # In a real app, you would send this email
        print(f"Would send email to manager: {subject}\n{body}")
        # self.send_email(manager_email, subject, body)
    
    def refresh_leave_list(self):
        cursor = self.db.connection.cursor()
        
        if self.check_permission("approve_leave"):
            # Managers see all leave in their department
            cursor.execute("""
            SELECT l.id, l.leave_type, l.start_date, l.end_date, l.status,
                   e.name, julianday(l.end_date) - julianday(l.start_date) + 1
            FROM leave_applications l
            JOIN employees e ON l.employee_id = e.id
            WHERE e.department = ? AND l.status = 'Pending'
            ORDER BY l.start_date
            """, (self.current_user['department'],))
        else:
            # Employees see only their own leave
            cursor.execute("""
            SELECT id, leave_type, start_date, end_date, status,
                   NULL, julianday(end_date) - julianday(start_date) + 1
            FROM leave_applications
            WHERE employee_id = ?
            ORDER BY start_date
            """, (self.current_user['id'],))
        
        leaves = cursor.fetchall()
        
        self.leave_table.setRowCount(0)
        for leave in leaves:
            row = self.leave_table.rowCount()
            self.leave_table.insertRow(row)
            for col in range(5):  # First 5 columns
                item = QTableWidgetItem(str(leave[col]))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.leave_table.setItem(row, col, item)
            
            # Days column
            days_item = QTableWidgetItem(str(int(leave[6])))
            days_item.setFlags(days_item.flags() & ~Qt.ItemIsEditable)
            self.leave_table.setItem(row, 5, days_item)
            
            # Color coding based on status
            if leave[4] == "Approved":
                for col in range(6):
                    self.leave_table.item(row, col).setBackground(
                        QColor(220, 255, 220))
            elif leave[4] == "Rejected":
                for col in range(6):
                    self.leave_table.item(row, col).setBackground(
                        QColor(255, 220, 220))
    
    def approve_leave(self):
        if not self.check_permission("approve_leave"):
            QMessageBox.warning(self, "Permission Denied",
                                "You don't have permission to approve leave")
            return
        
        selected = self.leave_table.selectedItems()
        if not selected:
            QMessageBox.warning(
                self, "Warning", "Please select a leave request to approve")
            return
        
        leave_id = int(self.leave_table.item(selected[0].row(), 0).text())
        
        try:
            cursor = self.db.connection.cursor()
            cursor.execute("""
            UPDATE leave_applications SET
                status=?,
                approver_id=?,
                updated_at=?
            WHERE id=?
            """, (
                "Approved",
                self.current_user['id'],
                datetime.now().isoformat(),
                leave_id
            ))
            self.db.connection.commit()
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "leave_approve",
                f"Approved leave request {leave_id}"
            )
            
            # Notify employee
            self.notify_employee_about_leave_decision(leave_id, True)
            
            QMessageBox.information(self, "Success", "Leave request approved")
            self.refresh_leave_list()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to approve leave: {str(e)}")
    
    def reject_leave(self):
        if not self.check_permission("approve_leave"):
            QMessageBox.warning(self, "Permission Denied",
                                "You don't have permission to reject leave")
            return
        
        selected = self.leave_table.selectedItems()
        if not selected:
            QMessageBox.warning(
                self, "Warning", "Please select a leave request to reject")
            return
        
        leave_id = int(self.leave_table.item(selected[0].row(), 0).text())
        
        # Get reason for rejection
        reason, ok = QInputDialog.getText(
            self,
            "Reason for Rejection",
            "Please enter the reason for rejecting this leave request:"
        )
        
        if not ok or not reason.strip():
            return
        
        try:
            cursor = self.db.connection.cursor()
            cursor.execute("""
            UPDATE leave_applications SET
                status=?,
                approver_id=?,
                comments=?,
                updated_at=?
            WHERE id=?
            """, (
                "Rejected",
                self.current_user['id'],
                reason.strip(),
                datetime.now().isoformat(),
                leave_id
            ))
            self.db.connection.commit()
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "leave_reject",
                f"Rejected leave request {leave_id}"
            )
            
            # Notify employee
            self.notify_employee_about_leave_decision(leave_id, False, reason)
            
            QMessageBox.information(self, "Success", "Leave request rejected")
            self.refresh_leave_list()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to reject leave: {str(e)}")
    
    def notify_employee_about_leave_decision(self, leave_id, approved, reason=None):
        """Send email notification to employee about leave decision"""
        cursor = self.db.connection.cursor()
        cursor.execute("""
        SELECT e.name, e.contact, l.leave_type, l.start_date, l.end_date
        FROM leave_applications l
        JOIN employees e ON l.employee_id = e.id
        WHERE l.id = ?
        """, (leave_id,))
        leave_data = cursor.fetchone()
        
        if not leave_data:
            return
        
        status = "APPROVED" if approved else "REJECTED"
        subject = f"Your Leave Request Has Been {status}"
        body = f"""
        Dear {leave_data[0]},

        Your {leave_data[2]} leave request for {leave_data[3]} to {leave_data[4]} has been {status.lower()}.
        """
        
        if not approved and reason:
            body += f"\nReason: {reason}\n"
        
        body += "\nThank you,\nHR Department"
        
        # In a real app, you would send this email
        print(f"Would send email to {leave_data[1]}: {subject}\n{body}")
        # self.send_email(leave_data[1], subject, body)
    
    def setup_recruitment_tab(self):
        layout = QVBoxLayout()
        self.recruitment_tab.setLayout(layout)
        
        # Recruitment controls
        control_box = QHBoxLayout()
        new_candidate_button = StyledButton("New Candidate")
        new_candidate_button.clicked.connect(self.show_new_candidate_dialog)
        view_candidate_button = StyledButton("View Candidate")
        view_candidate_button.clicked.connect(self.view_candidate_details)
        delete_candidate_button = StyledButton(
            "Delete Candidate", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
        delete_candidate_button.clicked.connect(self.delete_candidate)
        
        control_box.addWidget(new_candidate_button)
        control_box.addWidget(view_candidate_button)
        control_box.addWidget(delete_candidate_button)
        layout.addLayout(control_box)
        
        # Candidate list
        self.candidate_list = StyledListWidget()
        self.refresh_candidate_list()
        layout.addWidget(self.candidate_list)
    
    def show_new_candidate_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("New Candidate")
        dialog.setMinimumSize(800, 600)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        
        # Personal Information
        personal_group = QGroupBox("Personal Information")
        personal_layout = QFormLayout()
        
        self.candidate_name = StyledLineEdit()
        self.candidate_email = StyledLineEdit()
        self.candidate_phone = StyledLineEdit()
        self.candidate_address = StyledLineEdit()
        
        personal_layout.addRow("Full Name:", self.candidate_name)
        personal_layout.addRow("Email:", self.candidate_email)
        personal_layout.addRow("Phone:", self.candidate_phone)
        personal_layout.addRow("Address:", self.candidate_address)
        
        personal_group.setLayout(personal_layout)
        layout.addWidget(personal_group)
        
        # Professional Information
        professional_group = QGroupBox("Professional Information")
        professional_layout = QFormLayout()
        
        self.candidate_position = StyledComboBox()
        self.candidate_position.addItems(self.departments)
        
        self.candidate_experience = StyledLineEdit()
        self.candidate_experience.setValidator(QIntValidator(0, 50))
        
        self.candidate_skills = QTextEdit()
        self.candidate_skills.setMaximumHeight(100)
        
        professional_layout.addRow(
            "Position Applied:", self.candidate_position)
        professional_layout.addRow(
            "Years of Experience:", self.candidate_experience)
        professional_layout.addRow("Key Skills:", self.candidate_skills)
        
        professional_group.setLayout(professional_layout)
        layout.addWidget(professional_group)
        
        # Education Information
        education_group = QGroupBox("Education Information")
        education_layout = QFormLayout()
        
        self.candidate_degree = StyledLineEdit()
        self.candidate_university = StyledLineEdit()
        self.candidate_graduation = QDateEdit()
        self.candidate_graduation.setDate(QDate.currentDate().addYears(-1))
        
        education_layout.addRow("Degree:", self.candidate_degree)
        education_layout.addRow("University:", self.candidate_university)
        education_layout.addRow("Graduation Year:", self.candidate_graduation)
        
        education_group.setLayout(education_layout)
        layout.addWidget(education_group)
        
        # Buttons
        button_box = QHBoxLayout()
        cancel_button = StyledButton(
            "Cancel", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
        cancel_button.clicked.connect(dialog.reject)
        save_button = StyledButton("Save Candidate")
        save_button.clicked.connect(lambda: self.save_candidate(dialog))
        
        button_box.addWidget(cancel_button)
        button_box.addWidget(save_button)
        
        layout.addLayout(button_box)
        
        scroll.setWidget(content)
        dialog_layout = QVBoxLayout(dialog)
        dialog_layout.addWidget(scroll)
        dialog.exec()
    
    def save_candidate(self, dialog):
        # Validate inputs
        if not all([
            self.candidate_name.text().strip(),
            self.candidate_email.text().strip(),
            self.candidate_position.currentText()
        ]):
            QMessageBox.warning(self, "Validation Error",
                                "Name, email and position are required")
            return
        
        # Create candidate directory if it doesn't exist
        if not os.path.exists("candidates"):
            os.makedirs("candidates")
        
        # Prepare candidate data
        candidate_data = {
            "personal_info": {
                "name": self.candidate_name.text().strip(),
                "email": self.candidate_email.text().strip(),
                "phone": self.candidate_phone.text().strip(),
                "address": self.candidate_address.text().strip()
            },
            "professional_info": {
                "position": self.candidate_position.currentText(),
                "experience": self.candidate_experience.text().strip(),
                "skills": self.candidate_skills.toPlainText().strip()
            },
            "education_info": {
                "degree": self.candidate_degree.text().strip(),
                "university": self.candidate_university.text().strip(),
                "graduation": self.candidate_graduation.date().toString("yyyy")
            },
            "status": "New",
            "created_by": self.current_user['username'],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Generate filename
        safe_name = "".join(
            c for c in candidate_data["personal_info"]["name"]
            if c.isalnum() or c in " _-")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"candidates/{safe_name}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(candidate_data, f, indent=4, ensure_ascii=False)
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "candidate_add",
                f"Added candidate {candidate_data['personal_info']['name']}"
            )
            
            QMessageBox.information(
                self, "Success", "Candidate saved successfully")
            self.refresh_candidate_list()
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to save candidate: {str(e)}")
    
    def refresh_candidate_list(self):
        self.candidate_list.clear()
        if not os.path.exists("candidates"):
            return
        
        for filename in sorted(os.listdir("candidates"), reverse=True):
            if filename.endswith(".json"):
                try:
                    with open(os.path.join("candidates", filename), 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        name = data["personal_info"]["name"]
                        position = data["professional_info"]["position"]
                        status = data.get("status", "New")
                        date = datetime.fromisoformat(
                            data["created_at"]).strftime("%Y-%m-%d")
                        self.candidate_list.addItem(
                            f"{name} | {position} | {status} | {date} | {filename}")
                except:
                    continue
    
    def view_candidate_details(self):
        selected = self.candidate_list.selectedItems()
        if not selected:
            QMessageBox.warning(
                self, "Warning", "Please select a candidate to view")
            return
        
        filename = selected[0].text().split(" | ")[-1]
        filepath = os.path.join("candidates", filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                candidate_data = json.load(f)
            
            dialog = QDialog(self)
            dialog.setWindowTitle(
                f"Candidate: {candidate_data['personal_info']['name']}")
            dialog.setMinimumSize(800, 600)
            
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            content = QWidget()
            layout = QVBoxLayout(content)
            
            # Personal Information
            personal_group = QGroupBox("Personal Information")
            personal_layout = QFormLayout()
            personal_layout.addRow("Name:", QLabel(
                candidate_data["personal_info"]["name"]))
            personal_layout.addRow("Email:", QLabel(
                candidate_data["personal_info"]["email"]))
            personal_layout.addRow("Phone:", QLabel(
                candidate_data["personal_info"]["phone"]))
            personal_layout.addRow("Address:", QLabel(
                candidate_data["personal_info"]["address"]))
            personal_group.setLayout(personal_layout)
            layout.addWidget(personal_group)
            
            # Professional Information
            professional_group = QGroupBox("Professional Information")
            professional_layout = QFormLayout()
            professional_layout.addRow("Position:", QLabel(
                candidate_data["professional_info"]["position"]))
            professional_layout.addRow("Experience:", QLabel(
                f"{candidate_data['professional_info']['experience']} years"))
            skills = QTextEdit()
            skills.setPlainText(candidate_data["professional_info"]["skills"])
            skills.setReadOnly(True)
            professional_layout.addRow("Skills:", skills)
            professional_group.setLayout(professional_layout)
            layout.addWidget(professional_group)
            
            # Education Information
            education_group = QGroupBox("Education Information")
            education_layout = QFormLayout()
            education_layout.addRow("Degree:", QLabel(
                candidate_data["education_info"]["degree"]))
            education_layout.addRow("University:", QLabel(
                candidate_data["education_info"]["university"]))
            education_layout.addRow("Graduation Year:", QLabel(
                candidate_data["education_info"]["graduation"]))
            education_group.setLayout(education_layout)
            layout.addWidget(education_group)
            
            # Status and Actions (for HR)
            status_group = QGroupBox("Status and Actions")
            status_layout = QFormLayout()
            self.candidate_status = StyledComboBox()
            self.candidate_status.addItems(
                ["New", "Reviewed", "Interview Scheduled", "Hired", "Rejected"])
            self.candidate_status.setCurrentText(
                candidate_data.get("status", "New"))
            self.candidate_notes = QTextEdit()
            self.candidate_notes.setPlainText(candidate_data.get("notes", ""))
            self.candidate_notes.setMaximumHeight(100)
            status_layout.addRow("Status:", self.candidate_status)
            status_layout.addRow("Notes:", self.candidate_notes)
            status_group.setLayout(status_layout)
            layout.addWidget(status_group)
            
            # Buttons
            button_box = QHBoxLayout()
            close_button = StyledButton("Close")
            close_button.clicked.connect(dialog.reject)
            if self.check_permission("manage_recruitment"):
                save_button = StyledButton("Save Changes")
                save_button.clicked.connect(
                    lambda: self.save_candidate_changes(filename, dialog))
                button_box.addWidget(save_button)
            button_box.addWidget(close_button)
            
            layout.addLayout(button_box)
            
            scroll.setWidget(content)
            dialog_layout = QVBoxLayout(dialog)
            dialog_layout.addWidget(scroll)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to load candidate: {str(e)}")
    
    def save_candidate_changes(self, filename, dialog):
        filepath = os.path.join("candidates", filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                candidate_data = json.load(f)
            
            # Update status and notes
            candidate_data["status"] = self.candidate_status.currentText()
            candidate_data["notes"] = self.candidate_notes.toPlainText()
            candidate_data["updated_at"] = datetime.now().isoformat()
            candidate_data["updated_by"] = self.current_user['username']
            
            # Save back to file
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(candidate_data, f, indent=4, ensure_ascii=False)
            
            # Log activity
            self.db.log_activity(
                self.current_user['id'],
                "candidate_update",
                f"Updated candidate {candidate_data['personal_info']['name']}"
            )
            
            QMessageBox.information(
                self, "Success", "Candidate updated successfully")
            self.refresh_candidate_list()
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to update candidate: {str(e)}")
    
    def delete_candidate(self):
        selected = self.candidate_list.selectedItems()
        if not selected:
            QMessageBox.warning(
                self, "Warning", "Please select a candidate to delete")
            return
        
        filename = selected[0].text().split(" | ")[-1]
        filepath = os.path.join("candidates", filename)
        
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            "Are you sure you want to delete this candidate?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                os.remove(filepath)
                # Log activity
                self.db.log_activity(
                    self.current_user['id'],
                    "candidate_delete",
                    f"Deleted candidate {selected[0].text().split(' | ')[0]}"
                )
                QMessageBox.information(
                    self, "Success", "Candidate deleted successfully")
                self.refresh_candidate_list()
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to delete candidate: {str(e)}")
    
    def setup_reports_tab(self):
        layout = QVBoxLayout()
        self.reports_tab.setLayout(layout)
        
        # Report types
        report_group = QGroupBox("Generate Report")
        report_layout = QHBoxLayout()
        
        self.report_type = StyledComboBox()
        self.report_type.addItems([
            "Employee List by Department",
            "Salary Summary by Role",
            "Department Headcount",
            "Leave Report",
            "Recruitment Status",
            "Termination Report"
        ])
        
        generate_button = StyledButton("Generate")
        generate_button.clicked.connect(self.generate_report)
        
        report_layout.addWidget(self.report_type)
        report_layout.addWidget(generate_button)
        report_group.setLayout(report_layout)
        layout.addWidget(report_group)
        
        # Report display
        self.report_display = QTextEdit()
        self.report_display.setReadOnly(True)
        layout.addWidget(self.report_display)
        
        # Export buttons
        export_group = QGroupBox("Export Options")
        export_layout = QHBoxLayout()
        
        export_pdf_button = StyledButton("Export to PDF")
        export_csv_button = StyledButton("Export to CSV")
        export_text_button = StyledButton("Export to Text")
        
        export_pdf_button.clicked.connect(lambda: self.export_report("PDF"))
        export_csv_button.clicked.connect(lambda: self.export_report("CSV"))
        export_text_button.clicked.connect(lambda: self.export_report("TXT"))
        
        export_layout.addWidget(export_pdf_button)
        export_layout.addWidget(export_csv_button)
        export_layout.addWidget(export_text_button)
        
        export_group.setLayout(export_layout)
        layout.addWidget(export_group)
    
    def generate_report(self):
        report_type = self.report_type.currentText()
        cursor = self.db.connection.cursor()
        
        if report_type == "Employee List by Department":
            cursor.execute("""
            SELECT name, role, department, salary, hire_date,
                   CASE WHEN is_active THEN 'Active' ELSE 'Inactive' END as status
            FROM employees
            ORDER BY department, name
            """)
            employees = cursor.fetchall()
            
            report_text = "EMPLOYEE LIST BY DEPARTMENT\n"
            report_text += "=" * 50 + "\n\n"
            
            current_dept = None
            for emp in employees:
                if emp[2] != current_dept:
                    current_dept = emp[2]
                    report_text += f"\nDEPARTMENT: {current_dept}\n"
                    report_text += "-" * 50 + "\n"
                report_text += f"{emp[0]} ({emp[1]}) - ${emp[3]:,.2f} - Hired: {emp[4][:10]} - Status: {emp[5]}\n"
            
            self.report_display.setPlainText(report_text)
            
        elif report_type == "Salary Summary by Role":
            cursor.execute("""
            SELECT role, COUNT(*), AVG(salary), MIN(salary), MAX(salary), SUM(salary)
            FROM employees
            WHERE is_active = 1
            GROUP BY role
            ORDER BY SUM(salary) DESC
            """)
            roles = cursor.fetchall()
            
            report_text = "SALARY SUMMARY BY ROLE\n"
            report_text += "=" * 50 + "\n\n"
            
            for role in roles:
                report_text += (
                    f"{role[0]}:\n"
                    f"  Employees: {role[1]}\n"
                    f"  Avg Salary: ${role[2]:,.2f}\n"
                    f"  Min Salary: ${role[3]:,.2f}\n"
                    f"  Max Salary: ${role[4]:,.2f}\n"
                    f"  Total Salary: ${role[5]:,.2f}\n\n"
                )
            
            self.report_display.setPlainText(report_text)
            
        elif report_type == "Department Headcount":
            cursor.execute("""
            SELECT department, COUNT(*)
            FROM employees
            WHERE is_active = 1
            GROUP BY department
            ORDER BY COUNT(*) DESC
            """)
            depts = cursor.fetchall()
            
            report_text = "DEPARTMENT HEADCOUNT\n"
            report_text += "=" * 50 + "\n\n"
            
            for dept in depts:
                report_text += f"{dept[0]}: {dept[1]} employees\n"
            
            self.report_display.setPlainText(report_text)
            
        elif report_type == "Leave Report":
            cursor.execute("""
            SELECT e.name, l.leave_type, l.start_date, l.end_date, l.status,
                   julianday(l.end_date) - julianday(l.start_date) + 1
            FROM leave_applications l
            JOIN employees e ON l.employee_id = e.id
            ORDER BY l.start_date DESC
            """)
            leaves = cursor.fetchall()
            
            report_text = "LEAVE REPORT\n"
            report_text += "=" * 50 + "\n\n"
            
            for leave in leaves:
                report_text += (
                    f"{leave[0]} - {leave[1]} Leave\n"
                    f"  Dates: {leave[2]} to {leave[3]} ({int(leave[5])} days)\n"
                    f"  Status: {leave[4]}\n\n"
                )
            
            self.report_display.setPlainText(report_text)
            
        elif report_type == "Recruitment Status":
            if not os.path.exists("candidates"):
                self.report_display.setPlainText("No candidate data available")
                return
            
            report_text = "RECRUITMENT STATUS REPORT\n"
            report_text += "=" * 50 + "\n\n"
            
            status_counts = {}
            total = 0
            
            for filename in os.listdir("candidates"):
                if filename.endswith(".json"):
                    try:
                        with open(os.path.join("candidates", filename), 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            status = data.get("status", "New")
                            status_counts[status] = status_counts.get(
                                status, 0) + 1
                            total += 1
                    except:
                        continue
            
            for status, count in status_counts.items():
                report_text += f"{status}: {count} candidates ({count/total:.1%})\n"
            
            self.report_display.setPlainText(report_text)
            
        elif report_type == "Termination Report":
            cursor.execute("""
            SELECT e.name, t.termination_type, t.termination_date, t.reason,
                   p.name as processed_by, t.created_at
            FROM terminations t
            JOIN employees e ON t.employee_id = e.id
            JOIN employees p ON t.processed_by = p.id
            ORDER BY t.termination_date DESC
            """)
            terminations = cursor.fetchall()
            
            report_text = "TERMINATION REPORT\n"
            report_text += "=" * 50 + "\n\n"
            
            for term in terminations:
                report_text += (
                    f"{term[0]}\n"
                    f"  Type: {term[1]}\n"
                    f"  Date: {term[2]}\n"
                    f"  Reason: {term[3]}\n"
                    f"  Processed by: {term[4]}\n"
                    f"  Recorded: {term[5][:19]}\n\n"
                )
            
            self.report_display.setPlainText(report_text)
    
    def export_report(self, format):
        if not self.report_display.toPlainText():
            QMessageBox.warning(self, "Warning", "No report to export")
            return
        
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            f"Export Report as {format}",
            "",
            f"{format} Files (*.{format.lower()});;All Files (*)",
            options=options
        )
        
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.report_display.toPlainText())
                
                # Log activity
                self.db.log_activity(
                    self.current_user['id'],
                    "report_export",
                    f"Exported {format} report"
                )
                
                QMessageBox.information(
                    self, "Success", "Report exported successfully")
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to export report: {str(e)}")
    
    def setup_admin_tab(self):
        layout = QVBoxLayout()
        self.admin_tab.setLayout(layout)
        
        # Database Backup/Restore
        db_group = QGroupBox("Database Management")
        db_layout = QHBoxLayout()
        
        backup_button = StyledButton("Backup Database")
        backup_button.clicked.connect(self.backup_database)
        restore_button = StyledButton("Restore Database")
        restore_button.clicked.connect(self.restore_database)
        
        db_layout.addWidget(backup_button)
        db_layout.addWidget(restore_button)
        db_group.setLayout(db_layout)
        layout.addWidget(db_group)
        
        # System Logs
        logs_group = QGroupBox("System Logs")
        logs_layout = QVBoxLayout()
        
        self.logs_display = QTextEdit()
        self.logs_display.setReadOnly(True)
        self.refresh_logs()
        
        logs_layout.addWidget(self.logs_display)
        logs_group.setLayout(logs_layout)
        layout.addWidget(logs_group)
        
        # Only for root/admin
        if self.current_user['role'] in ['root', 'admin']:
            system_group = QGroupBox("System Administration")
            system_layout = QHBoxLayout()
            
            if self.current_user['role'] == 'root':
                init_button = StyledButton(
                    "Initialize System", color="#f44336", hover_color="#d32f2f", pressed_color="#b71c1c")
                init_button.clicked.connect(self.initialize_system)
                system_layout.addWidget(init_button)
            
            update_button = StyledButton("Check for Updates")
            update_button.clicked.connect(self.check_for_updates)
            system_layout.addWidget(update_button)
            
            system_group.setLayout(system_layout)
            layout.addWidget(system_group)
    
    def backup_database(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Backup Database",
            "",
            "JSON Files (*.json);;All Files (*)",
            options=options
        )
        
        if file_name:
            try:
                cursor = self.db.connection.cursor()
                cursor.execute("SELECT * FROM employees")
                employees = cursor.fetchall()
                columns = [column[0] for column in cursor.description]
                employees_data = [dict(zip(columns, row)) for row in employees]
                
                with open(file_name, 'w') as f:
                    json.dump(employees_data, f, indent=4)
                
                # Log activity
                self.db.log_activity(
                    self.current_user['id'],
                    "database_backup",
                    "Created database backup"
                )
                
                QMessageBox.information(
                    self, "Success", "Database backed up successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Backup failed: {str(e)}")
    
    def restore_database(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Restore Database",
            "",
            "JSON Files (*.json);;All Files (*)",
            options=options
        )
        
        if file_name:
            reply = QMessageBox.question(
                self,
                "Confirm Restore",
                "This will overwrite current data. Continue?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                try:
                    with open(file_name, 'r') as f:
                        employees_data = json.load(f)
                    
                    cursor = self.db.connection.cursor()
                    
                    # Clear current data (except root user)
                    cursor.execute(
                        "DELETE FROM employees WHERE role != 'root'")
                    
                    # Insert new data
                    for emp in employees_data:
                        if emp["role"] == "root":  # Skip root users from backup
                            continue
                        cursor.execute("""
                        INSERT INTO employees (
                            username, password, salt, iterations, name, role, department, salary,
                            contact, contact_iv, contact_salt, hire_date, created_at, updated_at, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            emp["username"],
                            emp["password"],
                            emp["salt"],
                            emp.get("iterations", 100000),
                            emp["name"],
                            emp["role"],
                            emp["department"],
                            emp["salary"],
                            emp["contact"],
                            emp.get("contact_iv", ""),
                            emp["contact_salt"],
                            emp.get("hire_date", datetime.now().isoformat()),
                            emp.get("created_at", datetime.now().isoformat()),
                            datetime.now().isoformat(),
                            emp.get("is_active", 1)
                        ))
                    
                    self.db.connection.commit()
                    
                    # Log activity
                    self.db.log_activity(
                        self.current_user['id'],
                        "database_restore",
                        "Restored database from backup"
                    )
                    
                    QMessageBox.information(
                        self, "Success", "Database restored successfully")
                    self.refresh_employee_list()
                except Exception as e:
                    QMessageBox.critical(
                        self, "Error", f"Restore failed: {str(e)}")
    
    def refresh_logs(self):
        cursor = self.db.connection.cursor()
        cursor.execute("""
        SELECT l.created_at, e.name, l.action, l.details
        FROM system_logs l
        JOIN employees e ON l.user_id = e.id
        ORDER BY l.created_at DESC
        LIMIT 100
        """)
        logs = cursor.fetchall()
        
        log_text = "SYSTEM LOGS (Last 100 entries)\n"
        log_text += "=" * 50 + "\n\n"
        
        for log in logs:
            log_text += f"{log[0][:19]} - {log[1]} - {log[2]}\n"
            if log[3]:
                log_text += f"   Details: {log[3]}\n"
            log_text += "\n"
        
        self.logs_display.setPlainText(log_text)
    
    def initialize_system(self):
        reply = QMessageBox.question(
            self,
            "Confirm Initialization",
            "This will reset the system to default state. Continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Clear all data except root user
                cursor = self.db.connection.cursor()
                cursor.execute("DELETE FROM employees WHERE role != 'root'")
                cursor.execute("DELETE FROM leave_applications")
                cursor.execute("DELETE FROM system_logs")
                cursor.execute("DELETE FROM terminations")
                
                # Recreate default users
                self.db.create_default_users()
                
                # Log activity
                self.db.log_activity(
                    self.current_user['id'],
                    "system_initialize",
                    "Initialized system to default state"
                )
                
                QMessageBox.information(
                    self, "Success", "System initialized to default state")
                self.refresh_employee_list()
                self.refresh_logs()
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Initialization failed: {str(e)}")
    
    def check_for_updates(self):
        # In a real application, this would check for updates from a server
        QMessageBox.information(
            self, "Check for Updates", "This feature would check for system updates in a real implementation")
    
    def logout(self):
        # Log logout activity
        self.db.log_activity(
            self.current_user['id'],
            "logout",
            "User logged out"
        )
        self.current_user = None
        self.init_login_ui()
    
    def closeEvent(self, event):
        if self.current_user:
            self.db.log_activity(
                self.current_user['id'],
                "system_exit",
                "Application closed"
            )
        self.db.close()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style and font
    app.setStyle("Fusion")
    font = QFont()
    font.setFamily("Segoe UI")
    font.setPointSize(10)
    app.setFont(font)
    
    window = HRManagementSystem()
    window.show()
    
    sys.exit(app.exec())