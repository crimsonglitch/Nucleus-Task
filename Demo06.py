import sys
import os
import json
import base64
import hashlib
import sqlite3
from datetime import datetime
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
    QListWidget, QScrollArea, QTextEdit, QDialog, QFileDialog
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIntValidator


class SecurityUtils:
    @staticmethod
    def generate_salt():
        return os.urandom(16)

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
    def pbkdf2_hash(password: str, salt: bytes) -> str:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode('utf-8'))
        return base64.b64encode(key).decode('utf-8')

    @staticmethod
    def fernet_encrypt(data: str, key: bytes) -> str:
        f = Fernet(key)
        return f.encrypt(data.encode('utf-8')).decode('utf-8')

    @staticmethod
    def fernet_decrypt(encrypted_data: str, key: bytes) -> str:
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

    @staticmethod
    def triple_encrypt(data: str, master_key: str) -> dict:
        salt = SecurityUtils.generate_salt()
        derived_key = SecurityUtils.pbkdf2_hash(master_key, salt)
        aes_result = SecurityUtils.aes_encrypt(data, base64.b64decode(derived_key))
        fernet_key = base64.urlsafe_b64encode(base64.b64decode(derived_key)[:32])
        fernet_encrypted = SecurityUtils.fernet_encrypt(
            json.dumps(aes_result), 
            fernet_key
        )
        return {
            'triple_encrypted': fernet_encrypted,
            'salt': base64.b64encode(salt).decode('utf-8')
        }

    @staticmethod
    def triple_decrypt(encrypted_data: dict, master_key: str) -> str:
        salt = base64.b64decode(encrypted_data['salt'])
        derived_key = SecurityUtils.pbkdf2_hash(master_key, salt)
        fernet_key = base64.urlsafe_b64encode(base64.b64decode(derived_key)[:32])
        fernet_decrypted = SecurityUtils.fernet_decrypt(
            encrypted_data['triple_encrypted'],
            fernet_key
        )
        aes_data = json.loads(fernet_decrypted)
        return SecurityUtils.aes_decrypt(aes_data, base64.b64decode(derived_key))


class HRManagementSystem(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HR Management System")
        self.setMinimumSize(QSize(1000, 800))
        
        # Security configuration
        self.master_key = self.secure_master_key()
        
        # Roles hierarchy
        self.roles = ["root", "boss", "admin", "moderator", "senior", "engineer", "assistant", "intern"]
        
        # Departments
        self.departments = [
            "Management", "IT", "HR", "Finance",
            "Marketing", "Sales", "Operations",
            "Cybersecurity", "R&D"
        ]
        
        # Initialize database
        self.db_connection = sqlite3.connect("hr_database.db")
        self.create_tables()
        
        # Current user
        self.current_user = None
        
        # Create default users if they don't exist
        self.create_default_users()
        
        # Create login screen
        self.init_login_ui()
    
    def secure_master_key(self):
        """Secure method to get master key (in production, use proper key management)"""
        # In a real application, this should come from a secure key management system
        return "secure_master_key_placeholder"  # Replace with proper key management
    
    def encrypt_user_data(self, data: str) -> dict:
        """Encrypt sensitive user data using triple encryption"""
        return SecurityUtils.triple_encrypt(data, self.master_key)
    
    def decrypt_user_data(self, encrypted_data: dict) -> str:
        """Decrypt triple-encrypted user data"""
        return SecurityUtils.triple_decrypt(encrypted_data, self.master_key)
    
    def hash_password(self, password: str, salt: bytes = None) -> dict:
        """Hash password with salt using PBKDF2"""
        if salt is None:
            salt = SecurityUtils.generate_salt()
        hashed = SecurityUtils.pbkdf2_hash(password, salt)
        return {
            'hashed': hashed,
            'salt': base64.b64encode(salt).decode('utf-8')
        }
    
    def create_tables(self):
        cursor = self.db_connection.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            salary REAL NOT NULL,
            contact TEXT NOT NULL,
            contact_iv TEXT,
            contact_salt TEXT NOT NULL
        )
        """)
        self.db_connection.commit()
    
    def create_default_users(self):
        default_users = [
            ("root", "toor", "System Root", "root", "Management", 0, "root@company.com"),
            ("boss", "boss123", "Company Boss", "boss", "Management", 100000, "boss@company.com"),
            ("admin", "admin123", "System Admin", "admin", "IT", 80000, "admin@company.com")
        ]
        
        cursor = self.db_connection.cursor()
        for user in default_users:
            cursor.execute("SELECT id FROM employees WHERE username=?", (user[0],))
            if not cursor.fetchone():
                # Encrypt the password and contact info
                password_data = self.hash_password(user[1])
                encrypted_contact = self.encrypt_user_data(user[6])
                
                cursor.execute("""
                INSERT INTO employees (username, password, salt, name, role, department, salary, 
                                     contact, contact_iv, contact_salt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user[0],
                    password_data['hashed'],
                    password_data['salt'],
                    user[2],
                    user[3],
                    user[4],
                    user[5],
                    encrypted_contact['triple_encrypted'],
                    encrypted_contact.get('iv', ''),
                    encrypted_contact['salt']
                ))
        self.db_connection.commit()
    
    def init_login_ui(self):
        self.login_widget = QWidget()
        self.setCentralWidget(self.login_widget)
        
        layout = QVBoxLayout()
        self.login_widget.setLayout(layout)
        
        # Username
        username_layout = QHBoxLayout()
        username_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        username_layout.addWidget(self.username_input)
        layout.addLayout(username_layout)
        
        # Password
        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        # Login button
        login_button = QPushButton("Login")
        login_button.clicked.connect(self.login)
        layout.addWidget(login_button)
        
        # Pressing Enter in password field also triggers login
        self.password_input.returnPressed.connect(self.login)
    
    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        cursor = self.db_connection.cursor()
        cursor.execute("""
        SELECT id, username, password, salt, name, role, department, salary, 
               contact, contact_iv, contact_salt 
        FROM employees WHERE username=?
        """, (username,))
        
        user_data = cursor.fetchone()
        
        if user_data:
            # Verify password
            salt = base64.b64decode(user_data[3])
            hashed_password = self.hash_password(password, salt)['hashed']
            
            if hashed_password == user_data[2]:  # Compare hashes
                # Decrypt contact information
                encrypted_contact = {
                    'triple_encrypted': user_data[8],
                    'iv': user_data[9],
                    'salt': user_data[10]
                }
                try:
                    contact = self.decrypt_user_data(encrypted_contact)
                except:
                    contact = "Encrypted"  # Fallback if decryption fails
                    
                self.current_user = {
                    "id": user_data[0],
                    "username": user_data[1],
                    "password": hashed_password,
                    "salt": user_data[3],
                    "name": user_data[4],
                    "role": user_data[5],
                    "department": user_data[6],
                    "salary": user_data[7],
                    "contact": contact
                }
                self.init_main_ui()
            else:
                QMessageBox.critical(self, "Login Failed", "Invalid username or password")
        else:
            QMessageBox.critical(self, "Login Failed", "Invalid username or password")
    
    def init_main_ui(self):
        # Create main widget with tabs
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        
        main_layout = QVBoxLayout()
        self.main_widget.setLayout(main_layout)
        
        # Status bar
        self.status_label = QLabel(f"Logged in as: {self.current_user['name']} ({self.current_user['role']})")
        main_layout.addWidget(self.status_label)
        
        # Create tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Employee Management Tab
        self.emp_management_tab = QWidget()
        self.setup_employee_management_tab()
        self.tabs.addTab(self.emp_management_tab, "Employee Management")
        
        # Personal Tab
        self.personal_tab = QWidget()
        self.setup_personal_tab()
        self.tabs.addTab(self.personal_tab, "Personal Information")
        
        # Recruitment Tab
        self.setup_recruitment_tab()
        
        # Reports Tab (only for certain roles)
        current_role_index = self.roles.index(self.current_user["role"])
        if current_role_index <= self.roles.index("senior"):
            self.reports_tab = QWidget()
            self.setup_reports_tab()
            self.tabs.addTab(self.reports_tab, "Reports")
        
        # Admin Tab (only for admin+ roles)
        if current_role_index <= self.roles.index("admin"):
            self.admin_tab = QWidget()
            self.setup_admin_tab()
            self.tabs.addTab(self.admin_tab, "Admin Tools")
        
        self.refresh_employee_list()
    
    def setup_employee_management_tab(self):
        layout = QVBoxLayout()
        self.emp_management_tab.setLayout(layout)
        
        # Filter controls
        filter_group = QGroupBox("Employee Filter")
        filter_layout = QHBoxLayout()
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Filter by name
        filter_layout.addWidget(QLabel("Search by Name:"))
        self.employee_filter_input = QLineEdit()
        self.employee_filter_input.setPlaceholderText("Enter employee name...")
        self.employee_filter_input.textChanged.connect(self.filter_employees)
        filter_layout.addWidget(self.employee_filter_input)
        
        # Filter by department
        filter_layout.addWidget(QLabel("Department:"))
        self.department_filter_combo = QComboBox()
        self.department_filter_combo.addItem("All Departments")
        self.department_filter_combo.addItems(self.departments)
        self.department_filter_combo.currentTextChanged.connect(self.filter_employees)
        filter_layout.addWidget(self.department_filter_combo)
        
        # Buttons
        button_layout = QHBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_employee_list)
        button_layout.addWidget(refresh_button)
        
        current_role_index = self.roles.index(self.current_user["role"])
        
        if current_role_index <= self.roles.index("admin"):
            add_button = QPushButton("Add Employee")
            add_button.clicked.connect(self.add_employee_dialog)
            button_layout.addWidget(add_button)
        
        if current_role_index <= self.roles.index("moderator"):
            edit_button = QPushButton("Edit Employee")
            edit_button.clicked.connect(self.edit_employee_dialog)
            button_layout.addWidget(edit_button)
        
        if current_role_index <= self.roles.index("admin"):
            delete_button = QPushButton("Delete Employee")
            delete_button.clicked.connect(self.delete_employee)
            button_layout.addWidget(delete_button)
        
        layout.addLayout(button_layout)
        
        # Employee Table
        self.employee_table = QTableWidget()
        self.employee_table.setColumnCount(4)
        self.employee_table.setHorizontalHeaderLabels(["Name", "Role", "Department", "Salary"])
        self.employee_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.employee_table.setSelectionMode(QTableWidget.SingleSelection)
        self.employee_table.cellDoubleClicked.connect(self.show_employee_details)
        layout.addWidget(self.employee_table)
        
        # Employee Details Panel
        self.employee_details_group = QGroupBox("Employee Details")
        self.employee_details_group.setVisible(False)
        details_layout = QVBoxLayout()
        self.employee_details_group.setLayout(details_layout)
        
        self.employee_details_text = QTextEdit()
        self.employee_details_text.setReadOnly(True)
        details_layout.addWidget(self.employee_details_text)
        
        close_details_button = QPushButton("Close Details")
        close_details_button.clicked.connect(self.hide_employee_details)
        details_layout.addWidget(close_details_button)
        
        layout.addWidget(self.employee_details_group)
    
    def filter_employees(self):
        """Filter employees based on name and department selection"""
        name_filter = self.employee_filter_input.text().lower()
        department_filter = self.department_filter_combo.currentText()
        
        cursor = self.db_connection.cursor()
        query = """
        SELECT name, role, department, salary, contact, username
        FROM employees
        WHERE LOWER(name) LIKE ? 
        """
        params = [f"%{name_filter}%"]
        
        if department_filter != "All Departments":
            query += " AND department = ?"
            params.append(department_filter)
        
        cursor.execute(query, params)
        employees = cursor.fetchall()
        
        self.employee_table.setRowCount(0)
        
        current_role_index = self.roles.index(self.current_user["role"])
        
        for emp in employees:
            emp_role_index = self.roles.index(emp[1])
            if current_role_index <= emp_role_index or emp[0] == self.current_user["name"]:
                row = self.employee_table.rowCount()
                self.employee_table.insertRow(row)
                for col, value in enumerate(emp[:4]):  # Only show first 4 columns in table
                    item = QTableWidgetItem(str(value))
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self.employee_table.setItem(row, col, item)
    
    def show_employee_details(self, row, column):
        """Show detailed information for the selected employee"""
        employee_name = self.employee_table.item(row, 0).text()
        
        cursor = self.db_connection.cursor()
        cursor.execute("""
        SELECT name, role, department, salary, contact, username
        FROM employees WHERE name=?
        """, (employee_name,))
        
        employee_data = cursor.fetchone()
        
        if employee_data:
            details = f"""
            <h2>{employee_data[0]}</h2>
            <table border='0' cellpadding='5'>
                <tr><td width='150'><b>Username:</b></td><td>{employee_data[5]}</td></tr>
                <tr><td><b>Role:</b></td><td>{employee_data[1]}</td></tr>
                <tr><td><b>Department:</b></td><td>{employee_data[2]}</td></tr>
                <tr><td><b>Salary:</b></td><td>${float(employee_data[3]):,.2f}</td></tr>
                <tr><td><b>Contact:</b></td><td>{employee_data[4]}</td></tr>
            </table>
            """
            
            self.employee_details_text.setHtml(details)
            self.employee_details_group.setVisible(True)
    
    def hide_employee_details(self):
        """Hide the employee details panel"""
        self.employee_details_group.setVisible(False)
    
    def refresh_employee_list(self):
        """Refresh employee list applying current filters"""
        self.filter_employees()
    
    def setup_personal_tab(self):
        layout = QVBoxLayout()
        self.personal_tab.setLayout(layout)
        
        scroll_area = QScrollArea()
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout()
        scroll_content.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_content)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)
        
        # Personal Information Section
        info_group = QGroupBox("Personal Information")
        info_layout = QVBoxLayout()
        info_group.setLayout(info_layout)
        scroll_layout.addWidget(info_group)
        
        fields = [
            ("Name:", "name", False),
            ("Username:", "username", True),
            ("Role:", "role", True),
            ("Department:", "department", False),
            ("Salary:", "salary", False),
            ("Contact:", "contact", False)
        ]
        
        self.personal_info_inputs = {}
        
        for label, field, readonly in fields:
            field_layout = QHBoxLayout()
            field_layout.addWidget(QLabel(label))
            
            input_widget = QLineEdit(str(self.current_user[field]))
            if readonly:
                input_widget.setReadOnly(True)
            self.personal_info_inputs[field] = input_widget
            field_layout.addWidget(input_widget)
            
            info_layout.addLayout(field_layout)
        
        # Password Change Section
        pass_group = QGroupBox("Change Password")
        pass_layout = QVBoxLayout()
        pass_group.setLayout(pass_layout)
        scroll_layout.addWidget(pass_group)
        
        self.current_pass_input = QLineEdit()
        self.current_pass_input.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(QLabel("Current Password:"))
        pass_layout.addWidget(self.current_pass_input)
        
        self.new_pass_input = QLineEdit()
        self.new_pass_input.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(QLabel("New Password:"))
        pass_layout.addWidget(self.new_pass_input)
        
        self.confirm_pass_input = QLineEdit()
        self.confirm_pass_input.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(QLabel("Confirm New Password:"))
        pass_layout.addWidget(self.confirm_pass_input)
        
        # Update Buttons
        button_layout = QHBoxLayout()
        update_pass_button = QPushButton("Update Password")
        update_pass_button.clicked.connect(self.update_password)
        button_layout.addWidget(update_pass_button)
        
        update_info_button = QPushButton("Update Personal Information")
        update_info_button.clicked.connect(self.update_personal_info)
        button_layout.addWidget(update_info_button)
        
        scroll_layout.addLayout(button_layout)
    
    def setup_recruitment_tab(self):
        """Setup the recruitment tab for candidate management"""
        self.recruitment_tab = QWidget()
        
        # Only show to authorized roles
        current_role_index = self.roles.index(self.current_user["role"])
        if current_role_index <= self.roles.index("moderator"):
            self.tabs.addTab(self.recruitment_tab, "Recruitment")
        
        layout = QVBoxLayout()
        self.recruitment_tab.setLayout(layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        new_candidate_button = QPushButton("New Candidate")
        new_candidate_button.clicked.connect(self.new_candidate_dialog)
        button_layout.addWidget(new_candidate_button)
        
        view_candidate_button = QPushButton("View Candidate")
        view_candidate_button.clicked.connect(self.view_candidate_info)
        button_layout.addWidget(view_candidate_button)
        
        delete_candidate_button = QPushButton("Delete Candidate")
        delete_candidate_button.clicked.connect(self.delete_candidate)
        button_layout.addWidget(delete_candidate_button)
        
        layout.addLayout(button_layout)
        
        # Candidate list
        self.candidate_list = QListWidget()
        self.refresh_candidate_list()
        layout.addWidget(self.candidate_list)
    
    def new_candidate_dialog(self):
        """Dialog for entering new candidate information"""
        dialog = QDialog(self)
        dialog.setWindowTitle("New Candidate Information")
        dialog.setMinimumSize(800, 900)
        
        scroll = QScrollArea()
        content = QWidget()
        layout = QVBoxLayout()
        content.setLayout(layout)
        scroll.setWidget(content)
        scroll.setWidgetResizable(True)
        
        dialog_layout = QVBoxLayout()
        dialog_layout.addWidget(scroll)
        dialog.setLayout(dialog_layout)
        
        # Personal Information
        personal_group = QGroupBox("Personal Information")
        personal_layout = QVBoxLayout()
        personal_group.setLayout(personal_layout)
        layout.addWidget(personal_group)
        
        personal_fields = [
            ("Full Name:", "full_name"),
            ("Email:", "email"),
            ("Phone:", "phone"),
            ("Address:", "address"),
            ("Date of Birth:", "birth_date"),
            ("Nationality:", "nationality"),
            ("ID/Passport Number:", "id_number")
        ]
        
        self.candidate_inputs = {}
        
        for label, field in personal_fields:
            field_layout = QHBoxLayout()
            field_layout.addWidget(QLabel(label))
            input_widget = QLineEdit()
            self.candidate_inputs[field] = input_widget
            field_layout.addWidget(input_widget)
            personal_layout.addLayout(field_layout)
        
        # Education Information
        education_group = QGroupBox("Education Information")
        education_layout = QVBoxLayout()
        education_group.setLayout(education_layout)
        layout.addWidget(education_group)
        
        education_fields = [
            ("University:", "university"),
            ("Department:", "education_department"),
            ("Degree:", "degree"),
            ("Graduation Year:", "graduation_year"),
            ("GPA:", "gpa")
        ]
        
        for label, field in education_fields:
            field_layout = QHBoxLayout()
            field_layout.addWidget(QLabel(label))
            input_widget = QLineEdit()
            self.candidate_inputs[field] = input_widget
            field_layout.addWidget(input_widget)
            education_layout.addLayout(field_layout)
        
        # Health Information
        health_group = QGroupBox("Health Information")
        health_layout = QVBoxLayout()
        health_group.setLayout(health_layout)
        layout.addWidget(health_group)
        
        # Blood Type
        blood_layout = QHBoxLayout()
        blood_layout.addWidget(QLabel("Blood Type:"))
        self.blood_type_combo = QComboBox()
        self.blood_type_combo.addItems(["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"])
        blood_layout.addWidget(self.blood_type_combo)
        health_layout.addLayout(blood_layout)
        
        # Allergies
        health_layout.addWidget(QLabel("Allergies (comma separated):"))
        self.allergies_input = QLineEdit()
        health_layout.addWidget(self.allergies_input)
        
        # Chronic Diseases
        health_layout.addWidget(QLabel("Chronic Diseases:"))
        self.chronic_diseases_input = QTextEdit()
        self.chronic_diseases_input.setMaximumHeight(100)
        health_layout.addWidget(self.chronic_diseases_input)
        
        # Medications
        self.medications = []
        medication_group = QGroupBox("Medications")
        medication_layout = QVBoxLayout()
        medication_group.setLayout(medication_layout)
        health_layout.addWidget(medication_group)
        
        self.medication_scroll = QScrollArea()
        self.medication_content = QWidget()
        self.medication_inner_layout = QVBoxLayout()
        self.medication_content.setLayout(self.medication_inner_layout)
        self.medication_scroll.setWidget(self.medication_content)
        self.medication_scroll.setWidgetResizable(True)
        medication_layout.addWidget(self.medication_scroll)
        
        add_med_button = QPushButton("Add Medication")
        add_med_button.clicked.connect(self.add_medication_field)
        medication_layout.addWidget(add_med_button)
        
        # Additional Information
        additional_group = QGroupBox("Additional Information")
        additional_layout = QVBoxLayout()
        additional_group.setLayout(additional_layout)
        layout.addWidget(additional_group)
        
        # Emergency Contact
        additional_layout.addWidget(QLabel("Emergency Contact Name:"))
        self.emergency_contact_name = QLineEdit()
        additional_layout.addWidget(self.emergency_contact_name)
        
        additional_layout.addWidget(QLabel("Emergency Contact Phone:"))
        self.emergency_contact_phone = QLineEdit()
        additional_layout.addWidget(self.emergency_contact_phone)
        
        # Additional Notes
        additional_layout.addWidget(QLabel("Additional Notes:"))
        self.additional_notes = QTextEdit()
        additional_layout.addWidget(self.additional_notes)
        
        # Applied Department
        dept_layout = QHBoxLayout()
        dept_layout.addWidget(QLabel("Applied Department:"))
        self.department_combo = QComboBox()
        self.department_combo.addItems(self.departments)
        dept_layout.addWidget(self.department_combo)
        layout.addLayout(dept_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)
        
        save_button = QPushButton("Save Candidate")
        save_button.clicked.connect(lambda: self.save_candidate_info(dialog))
        button_layout.addWidget(save_button)
        
        layout.addLayout(button_layout)
        
        dialog.exec()
    
    def add_medication_field(self):
        """Add a new medication field to the form"""
        medication_widget = QWidget()
        med_layout = QHBoxLayout()
        medication_widget.setLayout(med_layout)
        
        med_name = QLineEdit()
        med_name.setPlaceholderText("Medication Name")
        med_layout.addWidget(med_name)
        
        med_dosage = QLineEdit()
        med_dosage.setPlaceholderText("Dosage")
        med_layout.addWidget(med_dosage)
        
        med_frequency = QLineEdit()
        med_frequency.setPlaceholderText("Frequency (e.g., 2x daily)")
        med_layout.addWidget(med_frequency)
        
        remove_button = QPushButton("X")
        remove_button.setFixedWidth(30)
        remove_button.clicked.connect(lambda: self.remove_medication_field(medication_widget))
        med_layout.addWidget(remove_button)
        
        self.medications.append({
            "widget": medication_widget,
            "name": med_name,
            "dosage": med_dosage,
            "frequency": med_frequency
        })
        
        self.medication_inner_layout.addWidget(medication_widget)
    
    def remove_medication_field(self, widget):
        """Remove a medication field from the form"""
        for med in self.medications[:]:
            if med["widget"] == widget:
                self.medications.remove(med)
                widget.deleteLater()
                break
    
    def save_candidate_info(self, dialog):
        """Save candidate information to a JSON file"""
        # Collect all data
        candidate_data = {
            "timestamp": datetime.now().isoformat(),
            "personal_info": {},
            "education": {},
            "health": {
                "blood_type": self.blood_type_combo.currentText(),
                "allergies": [a.strip() for a in self.allergies_input.text().split(",") if a.strip()],
                "chronic_diseases": self.chronic_diseases_input.toPlainText(),
                "medications": []
            },
            "additional_info": {
                "emergency_contact": {
                    "name": self.emergency_contact_name.text(),
                    "phone": self.emergency_contact_phone.text()
                },
                "notes": self.additional_notes.toPlainText()
            },
            "applied_department": self.department_combo.currentText()
        }
        
        # Personal info
        for field in ["full_name", "email", "phone", "address", "birth_date", "nationality", "id_number"]:
            candidate_data["personal_info"][field] = self.candidate_inputs[field].text()
        
        # Education info
        for field in ["university", "education_department", "degree", "graduation_year", "gpa"]:
            candidate_data["education"][field] = self.candidate_inputs[field].text()
        
        # Medications
        for med in self.medications:
            if med["name"].text().strip():
                candidate_data["health"]["medications"].append({
                    "name": med["name"].text(),
                    "dosage": med["dosage"].text(),
                    "frequency": med["frequency"].text()
                })
        
        # Validation
        if not candidate_data["personal_info"]["full_name"]:
            QMessageBox.critical(self, "Error", "Full name is required!")
            return
        
        # Save to JSON file
        try:
            # Create candidates directory if it doesn't exist
            if not os.path.exists("candidates"):
                os.makedirs("candidates")
            
            # Create filename (safe name + timestamp)
            safe_name = "".join(c for c in candidate_data["personal_info"]["full_name"] if c.isalnum() or c in " _-")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"candidates/{safe_name}_{timestamp}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(candidate_data, f, indent=4, ensure_ascii=False)
            
            self.refresh_candidate_list()
            dialog.accept()
            QMessageBox.information(self, "Success", "Candidate information saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save candidate: {str(e)}")
    
    def refresh_candidate_list(self):
        """Refresh the list of candidates from JSON files"""
        self.candidate_list.clear()
        
        if not os.path.exists("candidates"):
            return
        
        for filename in sorted(os.listdir("candidates"), reverse=True):
            if filename.endswith(".json"):
                try:
                    with open(os.path.join("candidates", filename), 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        name = data["personal_info"]["full_name"]
                        department = data.get("applied_department", "Unknown")
                        date = datetime.fromisoformat(data["timestamp"]).strftime("%Y-%m-%d")
                        self.candidate_list.addItem(f"{name} | {department} | {date} | {filename}")
                except:
                    continue
    
    def view_candidate_info(self):
        """View detailed information about a selected candidate"""
        selected_items = self.candidate_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a candidate")
            return
        
        filename = selected_items[0].text().split(" | ")[-1]
        filepath = os.path.join("candidates", filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                candidate_data = json.load(f)
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Candidate: {candidate_data['personal_info']['full_name']}")
            dialog.setMinimumSize(800, 900)
            
            scroll = QScrollArea()
            content = QWidget()
            layout = QVBoxLayout()
            content.setLayout(layout)
            scroll.setWidget(content)
            scroll.setWidgetResizable(True)
            
            dialog_layout = QVBoxLayout()
            dialog_layout.addWidget(scroll)
            dialog.setLayout(dialog_layout)
            
            # Helper function to add sections
            def add_section(title, data, parent_layout):
                group = QGroupBox(title)
                group_layout = QVBoxLayout()
                group.setLayout(group_layout)
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, (dict, list)):
                            group_layout.addWidget(QLabel(f"{key}:"))
                            text_edit = QTextEdit()
                            text_edit.setPlainText(json.dumps(value, indent=2, ensure_ascii=False))
                            text_edit.setReadOnly(True)
                            group_layout.addWidget(text_edit)
                        else:
                            group_layout.addWidget(QLabel(f"{key}: {value}"))
                else:
                    group_layout.addWidget(QLabel(str(data)))
                
                parent_layout.addWidget(group)
            
            # Add all sections
            add_section("Personal Information", candidate_data["personal_info"], layout)
            add_section("Education", candidate_data["education"], layout)
            add_section("Health Information", candidate_data["health"], layout)
            add_section("Additional Information", candidate_data["additional_info"], layout)
            add_section("Applied Department", candidate_data["applied_department"], layout)
            
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load candidate info: {str(e)}")
    
    def delete_candidate(self):
        """Delete selected candidate file"""
        selected_items = self.candidate_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a candidate to delete")
            return
        
        filename = selected_items[0].text().split(" | ")[-1]
        filepath = os.path.join("candidates", filename)
        
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete candidate {selected_items[0].text().split(' | ')[0]}?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                os.remove(filepath)
                self.refresh_candidate_list()
                QMessageBox.information(self, "Success", "Candidate deleted successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete candidate: {str(e)}")
    
    def setup_reports_tab(self):
        layout = QVBoxLayout()
        self.reports_tab.setLayout(layout)
        
        # Report buttons
        button_layout = QHBoxLayout()
        report_types = [
            "Employee List by Department",
            "Salary Summary by Role",
            "Department Headcount",
            "Contact List",
            "Candidate Report"
        ]
        
        for report in report_types:
            button = QPushButton(report)
            button.clicked.connect(lambda _, r=report: self.generate_report(r))
            button_layout.addWidget(button)
        
        layout.addLayout(button_layout)
        
        # Report display area
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        layout.addWidget(self.report_text)
        
        # Export button
        export_button = QPushButton("Export Report")
        export_button.clicked.connect(self.export_report)
        layout.addWidget(export_button)
        
        # Clear button
        clear_button = QPushButton("Clear Report")
        clear_button.clicked.connect(lambda: self.report_text.clear())
        layout.addWidget(clear_button)
    
    def generate_report(self, report_type):
        """Generate various reports"""
        self.report_text.clear()
        
        cursor = self.db_connection.cursor()
        
        if report_type == "Employee List by Department":
            cursor.execute("""
            SELECT department, name, role, salary 
            FROM employees 
            ORDER BY department, name
            """)
            employees = cursor.fetchall()
            
            current_dept = None
            for emp in employees:
                if emp[0] != current_dept:
                    current_dept = emp[0]
                    self.report_text.append(f"\nDepartment: {current_dept}")
                    self.report_text.append("-" * 50)
                self.report_text.append(f"{emp[1]} ({emp[2]}) - ${emp[3]:,.2f}")
        
        elif report_type == "Salary Summary by Role":
            cursor.execute("""
            SELECT role, COUNT(*), AVG(salary), SUM(salary) 
            FROM employees 
            GROUP BY role
            """)
            roles = cursor.fetchall()
            
            self.report_text.append("Salary Summary by Role")
            self.report_text.append("-" * 50)
            for role in roles:
                self.report_text.append(
                    f"{role[0]}: {role[1]} employees, "
                    f"Total: ${role[3]:,.2f}, "
                    f"Avg: ${role[2]:,.2f}"
                )
        
        elif report_type == "Department Headcount":
            cursor.execute("""
            SELECT department, COUNT(*) 
            FROM employees 
            GROUP BY department
            ORDER BY COUNT(*) DESC
            """)
            depts = cursor.fetchall()
            
            self.report_text.append("Department Headcount")
            self.report_text.append("-" * 50)
            for dept in depts:
                self.report_text.append(f"{dept[0]}: {dept[1]} employees")
        
        elif report_type == "Contact List":
            cursor.execute("""
            SELECT name, contact 
            FROM employees 
            ORDER BY name
            """)
            contacts = cursor.fetchall()
            
            self.report_text.append("Employee Contact List")
            self.report_text.append("-" * 50)
            for contact in contacts:
                self.report_text.append(f"{contact[0]}: {contact[1]}")
        
        elif report_type == "Candidate Report":
            if not os.path.exists("candidates"):
                self.report_text.append("No candidates found")
                return
            
            self.report_text.append("Candidate Report")
            self.report_text.append("-" * 50)
            
            for filename in sorted(os.listdir("candidates")):
                if filename.endswith(".json"):
                    try:
                        with open(os.path.join("candidates", filename), 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            name = data["personal_info"]["full_name"]
                            dept = data.get("applied_department", "Unknown")
                            date = datetime.fromisoformat(data["timestamp"]).strftime("%Y-%m-%d")
                            self.report_text.append(f"{name} | {dept} | {date}")
                    except:
                        continue
    
    def export_report(self):
        """Export the current report to a file"""
        if not self.report_text.toPlainText():
            QMessageBox.warning(self, "Warning", "No report to export")
            return
        
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            "",
            "Text Files (*.txt);;All Files (*)",
            options=options
        )
        
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.report_text.toPlainText())
                QMessageBox.information(self, "Success", "Report exported successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")
    
    def setup_admin_tab(self):
        layout = QVBoxLayout()
        self.admin_tab.setLayout(layout)
        
        # Admin tools buttons
        backup_button = QPushButton("Backup Database")
        backup_button.clicked.connect(self.backup_database)
        layout.addWidget(backup_button)
        
        restore_button = QPushButton("Restore Database")
        restore_button.clicked.connect(self.restore_database)
        layout.addWidget(restore_button)
        
        logs_button = QPushButton("System Logs")
        logs_button.clicked.connect(self.view_system_logs)
        layout.addWidget(logs_button)
        
        # Only root can access these
        if self.current_user["role"] == "root":
            init_button = QPushButton("Initialize System")
            init_button.clicked.connect(self.initialize_system)
            layout.addWidget(init_button)
            
            priv_button = QPushButton("Privilege Escalation")
            priv_button.clicked.connect(self.privilege_escalation)
            layout.addWidget(priv_button)
        
        # Role management for admin
        if self.current_user["role"] == "admin":
            manage_roles_button = QPushButton("Manage Roles")
            manage_roles_button.clicked.connect(self.manage_roles)
            layout.addWidget(manage_roles_button)
    
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
                cursor = self.db_connection.cursor()
                cursor.execute("SELECT * FROM employees")
                employees = cursor.fetchall()
                
                # Convert to list of dictionaries
                columns = [column[0] for column in cursor.description]
                employees_data = [dict(zip(columns, row)) for row in employees]
                
                with open(file_name, 'w') as f:
                    json.dump(employees_data, f, indent=4)
                
                QMessageBox.information(self, "Success", "Database backed up successfully!")
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
                "Restore will overwrite current data. Continue?", 
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                try:
                    with open(file_name, 'r') as f:
                        employees_data = json.load(f)
                    
                    cursor = self.db_connection.cursor()
                    
                    # Clear current data (except root user)
                    cursor.execute("DELETE FROM employees WHERE role != 'root'")
                    
                    # Insert new data
                    for emp in employees_data:
                        # Skip root users from backup to prevent privilege escalation
                        if emp["role"] == "root":
                            continue
                            
                        cursor.execute("""
                        INSERT INTO employees (username, password, salt, name, role, department, salary, 
                                             contact, contact_iv, contact_salt)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            emp["username"],
                            emp["password"],
                            emp["salt"],
                            emp["name"],
                            emp["role"],
                            emp["department"],
                            emp["salary"],
                            emp["contact"],
                            emp.get("contact_iv", ""),
                            emp["contact_salt"]
                        ))
                    
                    self.db_connection.commit()
                    self.refresh_employee_list()
                    QMessageBox.information(self, "Success", "Database restored successfully!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Restore failed: {str(e)}")
    
    def view_system_logs(self):
        QMessageBox.information(self, "System Logs", "Log viewing functionality would be implemented here")
    
    def initialize_system(self):
        reply = QMessageBox.question(
            self, 
            "Confirm Initialization", 
            "This will reset the system to default. Continue?", 
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                cursor = self.db_connection.cursor()
                
                # Clear all data
                cursor.execute("DELETE FROM employees")
                
                # Recreate default users
                self.create_default_users()
                
                self.refresh_employee_list()
                QMessageBox.information(self, "Success", "System initialized to default state")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Initialization failed: {str(e)}")
    
    def privilege_escalation(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Privilege Escalation")
        dialog.setMinimumSize(400, 300)
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Employee list
        layout.addWidget(QLabel("Select an employee to escalate privileges:"))
        
        self.priv_emp_list = QListWidget()
        layout.addWidget(self.priv_emp_list)
        
        # Populate list with employees (except root)
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT name, role FROM employees WHERE role != 'root'")
        employees = cursor.fetchall()
        
        for emp in employees:
            self.priv_emp_list.addItem(f"{emp[0]} ({emp[1]})")
        
        # Role selection
        role_layout = QHBoxLayout()
        role_layout.addWidget(QLabel("New Role:"))
        
        self.priv_role_combo = QComboBox()
        self.priv_role_combo.addItems(self.roles)
        role_layout.addWidget(self.priv_role_combo)
        
        layout.addLayout(role_layout)
        
        # Update button
        update_button = QPushButton("Update Privilege")
        update_button.clicked.connect(lambda: self.update_privilege(dialog))
        layout.addWidget(update_button)
        
        dialog.exec()
    
    def update_privilege(self, dialog):
        selected_items = self.priv_emp_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select an employee")
            return
            
        new_role = self.priv_role_combo.currentText()
        if not new_role:
            QMessageBox.warning(self, "Warning", "Please select a role")
            return
            
        emp_name = selected_items[0].text().split(" (")[0]
        
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
            UPDATE employees SET role=? WHERE name=?
            """, (new_role, emp_name))
            self.db_connection.commit()
            
            self.refresh_employee_list()
            dialog.accept()
            QMessageBox.information(self, "Success", "Privilege updated successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update privilege: {str(e)}")
    
    def manage_roles(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Manage Roles")
        dialog.setMinimumSize(400, 300)
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Employee list
        layout.addWidget(QLabel("Select an employee to change their role:"))
        
        self.role_emp_list = QListWidget()
        layout.addWidget(self.role_emp_list)
        
        # Populate list with employees (except root and boss)
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT name, role FROM employees WHERE role NOT IN ('root', 'boss')")
        employees = cursor.fetchall()
        
        for emp in employees:
            self.role_emp_list.addItem(f"{emp[0]} ({emp[1]})")
        
        # Role selection
        role_layout = QHBoxLayout()
        role_layout.addWidget(QLabel("New Role:"))
        
        self.role_combo = QComboBox()
        # Only allow setting roles from admin down
        self.role_combo.addItems(self.roles[self.roles.index("admin"):])
        role_layout.addWidget(self.role_combo)
        
        layout.addLayout(role_layout)
        
        # Update button
        update_button = QPushButton("Update Role")
        update_button.clicked.connect(lambda: self.update_role(dialog))
        layout.addWidget(update_button)
        
        dialog.exec()
    
    def update_role(self, dialog):
        selected_items = self.role_emp_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select an employee")
            return
            
        new_role = self.role_combo.currentText()
        if not new_role:
            QMessageBox.warning(self, "Warning", "Please select a role")
            return
            
        emp_name = selected_items[0].text().split(" (")[0]
        
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
            UPDATE employees SET role=? WHERE name=?
            """, (new_role, emp_name))
            self.db_connection.commit()
            
            self.refresh_employee_list()
            dialog.accept()
            QMessageBox.information(self, "Success", "Role updated successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update role: {str(e)}")
    
    def add_employee_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Employee")
        dialog.setMinimumSize(400, 400)
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Form fields
        fields = [
            ("Username:", "username", False),
            ("Password:", "password", True),  # password field
            ("Full Name:", "name", False),
            ("Role:", "role", False),
            ("Department:", "department", False),
            ("Salary:", "salary", False),
            ("Contact Info:", "contact", False)
        ]
        
        self.new_emp_inputs = {}
        
        for label, field, is_password in fields:
            field_layout = QHBoxLayout()
            field_layout.addWidget(QLabel(label))
            
            if field == "role":
                # Create a dropdown for role selection
                current_role_index = self.roles.index(self.current_user["role"])
                
                # Determine available roles based on current user's role
                if self.current_user["role"] == "root":
                    available_roles = self.roles[1:]  # Root can create any role except another root
                elif self.current_user["role"] == "boss":
                    available_roles = self.roles[2:]  # Boss can create admin and below
                else:  # admin
                    available_roles = self.roles[3:]  # Admin can create moderator and below
                
                combo = QComboBox()
                combo.addItems(available_roles)
                self.new_emp_inputs[field] = combo
                field_layout.addWidget(combo)
            elif field == "department":
                combo = QComboBox()
                combo.addItems(self.departments)
                self.new_emp_inputs[field] = combo
                field_layout.addWidget(combo)
            else:
                input_widget = QLineEdit()
                if is_password:
                    input_widget.setEchoMode(QLineEdit.Password)
                self.new_emp_inputs[field] = input_widget
                field_layout.addWidget(input_widget)
            
            layout.addLayout(field_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)
        
        save_button = QPushButton("Save")
        save_button.clicked.connect(lambda: self.save_new_employee(dialog))
        button_layout.addWidget(save_button)
        
        layout.addLayout(button_layout)
        
        dialog.exec()
    
    def save_new_employee(self, dialog):
        # Get data from inputs
        username = self.new_emp_inputs["username"].text()
        password = self.new_emp_inputs["password"].text()
        name = self.new_emp_inputs["name"].text()
        role = self.new_emp_inputs["role"].currentText() if isinstance(self.new_emp_inputs["role"], QComboBox) else self.new_emp_inputs["role"].text()
        department = self.new_emp_inputs["department"].currentText() if isinstance(self.new_emp_inputs["department"], QComboBox) else self.new_emp_inputs["department"].text()
        salary = self.new_emp_inputs["salary"].text()
        contact = self.new_emp_inputs["contact"].text()

        # Validate
        if not all([username, password, name, role, department, salary, contact]):
            QMessageBox.critical(self, "Error", "All fields are required!")
            return
            
        try:
            salary = float(salary)
        except ValueError:
            QMessageBox.critical(self, "Error", "Salary must be a number!")
            return
        
        # Check if username exists
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT id FROM employees WHERE username=?", (username,))
        if cursor.fetchone():
            QMessageBox.critical(self, "Error", "Username already exists!")
            return
            
        # Hash password and encrypt contact
        password_data = self.hash_password(password)
        encrypted_contact = self.encrypt_user_data(contact)
        
        # Insert new employee
        try:
            cursor.execute("""
            INSERT INTO employees (username, password, salt, name, role, department, salary, 
                                 contact, contact_iv, contact_salt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                username,
                password_data['hashed'],
                password_data['salt'],
                name,
                role,
                department,
                salary,
                encrypted_contact['triple_encrypted'],
                encrypted_contact.get('iv', ''),
                encrypted_contact['salt']
            ))
            self.db_connection.commit()
            
            self.refresh_employee_list()
            dialog.accept()
            QMessageBox.information(self, "Success", "Employee added successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add employee: {str(e)}")
    
    def edit_employee_dialog(self):
        selected_items = self.employee_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select an employee to edit")
            return
            
        # Get selected employee name
        selected_row = selected_items[0].row()
        emp_name = self.employee_table.item(selected_row, 0).text()
        
        # Get employee data from database
        cursor = self.db_connection.cursor()
        cursor.execute("""
        SELECT id, username, name, role, department, salary, contact 
        FROM employees WHERE name=?
        """, (emp_name,))
        employee_data = cursor.fetchone()
        
        if not employee_data:
            QMessageBox.critical(self, "Error", "Employee not found")
            return
            
        employee = {
            "id": employee_data[0],
            "username": employee_data[1],
            "name": employee_data[2],
            "role": employee_data[3],
            "department": employee_data[4],
            "salary": employee_data[5],
            "contact": employee_data[6]
        }
        
        # Check permissions
        current_role_index = self.roles.index(self.current_user["role"])
        emp_role_index = self.roles.index(employee["role"])
        
        if current_role_index > emp_role_index and employee["username"] != self.current_user["username"]:
            QMessageBox.critical(self, "Permission Denied", "You don't have permission to edit this employee")
            return
            
        # Create edit dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Employee")
        dialog.setMinimumSize(400, 400)
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Form fields
        fields = [
            ("Username:", "username", True),  # readonly
            ("Full Name:", "name", False),
            ("Role:", "role", True),  # readonly
            ("Department:", "department", False),
            ("Salary:", "salary", False),
            ("Contact Info:", "contact", False)
        ]
        
        self.edit_emp_inputs = {}
        
        for label, field, readonly in fields:
            field_layout = QHBoxLayout()
            field_layout.addWidget(QLabel(label))
            
            if field == "department":
                combo = QComboBox()
                combo.addItems(self.departments)
                combo.setCurrentText(employee[field])
                self.edit_emp_inputs[field] = combo
                field_layout.addWidget(combo)
            else:
                input_widget = QLineEdit(str(employee[field]))
                if readonly:
                    input_widget.setReadOnly(True)
                self.edit_emp_inputs[field] = input_widget
                field_layout.addWidget(input_widget)
            
            layout.addLayout(field_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)
        
        save_button = QPushButton("Save Changes")
        save_button.clicked.connect(lambda: self.save_employee_changes(employee["id"], dialog))
        button_layout.addWidget(save_button)
        
        layout.addLayout(button_layout)
        
        dialog.exec()
    
    def save_employee_changes(self, emp_id, dialog):
        # Get updated data
        updated_data = {
            "name": self.edit_emp_inputs["name"].text(),
            "department": self.edit_emp_inputs["department"].currentText() if isinstance(self.edit_emp_inputs["department"], QComboBox) else self.edit_emp_inputs["department"].text(),
            "salary": self.edit_emp_inputs["salary"].text(),
            "contact": self.edit_emp_inputs["contact"].text()
        }
        
        # Validate
        if not all(updated_data.values()):
            QMessageBox.critical(self, "Error", "All fields are required!")
            return
            
        try:
            salary = float(updated_data["salary"])
        except ValueError:
            QMessageBox.critical(self, "Error", "Salary must be a number!")
            return
        
        # Encrypt contact if changed
        encrypted_contact = self.encrypt_user_data(updated_data["contact"])
        
        # Update database
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
            UPDATE employees 
            SET name=?, department=?, salary=?, contact=?, contact_iv=?, contact_salt=?
            WHERE id=?
            """, (
                updated_data["name"],
                updated_data["department"],
                salary,
                encrypted_contact['triple_encrypted'],
                encrypted_contact.get('iv', ''),
                encrypted_contact['salt'],
                emp_id
            ))
            self.db_connection.commit()
            
            # Update current user data if editing self
            if emp_id == self.current_user["id"]:
                self.current_user.update(updated_data)
                self.current_user["contact"] = updated_data["contact"]
                self.status_label.setText(f"Logged in as: {self.current_user['name']} ({self.current_user['role']})")
                self.setup_personal_tab()  # Refresh personal tab
            
            self.refresh_employee_list()
            dialog.accept()
            QMessageBox.information(self, "Success", "Employee updated successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update employee: {str(e)}")
    
    def delete_employee(self):
        selected_items = self.employee_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select an employee to delete")
            return
            
        # Get selected employee name
        selected_row = selected_items[0].row()
        emp_name = self.employee_table.item(selected_row, 0).text()
        
        # Get employee data from database
        cursor = self.db_connection.cursor()
        cursor.execute("""
        SELECT id, username, role FROM employees WHERE name=?
        """, (emp_name,))
        employee_data = cursor.fetchone()
        
        if not employee_data:
            QMessageBox.critical(self, "Error", "Employee not found")
            return
            
        emp_id, emp_username, emp_role = employee_data
        
        # Check permissions
        current_role_index = self.roles.index(self.current_user["role"])
        emp_role_index = self.roles.index(emp_role)
        
        if current_role_index > emp_role_index:
            QMessageBox.critical(self, "Permission Denied", "You don't have permission to delete this employee")
            return
            
        if emp_username == self.current_user["username"]:
            QMessageBox.critical(self, "Error", "You cannot delete yourself!")
            return
            
        # Confirm deletion
        reply = QMessageBox.question(
            self, 
            "Confirm Delete", 
            f"Are you sure you want to delete {emp_name}?", 
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                cursor.execute("DELETE FROM employees WHERE id=?", (emp_id,))
                self.db_connection.commit()
                self.refresh_employee_list()
                QMessageBox.information(self, "Success", "Employee deleted successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete employee: {str(e)}")
    
    def update_password(self):
        current = self.current_pass_input.text()
        new = self.new_pass_input.text()
        confirm = self.confirm_pass_input.text()
        
        # Verify current password
        current_salt = base64.b64decode(self.current_user["salt"])
        current_hashed = self.hash_password(current, current_salt)['hashed']
        
        if current_hashed != self.current_user["password"]:
            QMessageBox.critical(self, "Error", "Current password is incorrect")
            return
            
        if new != confirm:
            QMessageBox.critical(self, "Error", "New passwords don't match")
            return
            
        if not new:
            QMessageBox.critical(self, "Error", "Password cannot be empty")
            return
            
        # Update database
        try:
            # Generate new hash
            password_data = self.hash_password(new)
            
            cursor = self.db_connection.cursor()
            cursor.execute("""
            UPDATE employees SET password=?, salt=? WHERE id=?
            """, (
                password_data['hashed'],
                password_data['salt'],
                self.current_user["id"]
            ))
            self.db_connection.commit()
            
            # Update current user data
            self.current_user["password"] = password_data['hashed']
            self.current_user["salt"] = password_data['salt']
            
            # Clear fields
            self.current_pass_input.clear()
            self.new_pass_input.clear()
            self.confirm_pass_input.clear()
            
            QMessageBox.information(self, "Success", "Password updated successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update password: {str(e)}")
    
    def update_personal_info(self):
        updated_data = {
            "name": self.personal_info_inputs["name"].text(),
            "department": self.personal_info_inputs["department"].text(),
            "salary": self.personal_info_inputs["salary"].text(),
            "contact": self.personal_info_inputs["contact"].text()
        }
        
        # Validate
        if not all(updated_data.values()):
            QMessageBox.critical(self, "Error", "All fields are required!")
            return
            
        try:
            salary = float(updated_data["salary"])
        except ValueError:
            QMessageBox.critical(self, "Error", "Salary must be a number!")
            return
        
        # Encrypt contact information
        encrypted_contact = self.encrypt_user_data(updated_data["contact"])
        
        # Update database
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
            UPDATE employees 
            SET name=?, department=?, salary=?, contact=?, contact_iv=?, contact_salt=?
            WHERE id=?
            """, (
                updated_data["name"],
                updated_data["department"],
                salary,
                encrypted_contact['triple_encrypted'],
                encrypted_contact.get('iv', ''),
                encrypted_contact['salt'],
                self.current_user["id"]
            ))
            self.db_connection.commit()
            
            # Update current user data
            self.current_user.update(updated_data)
            self.status_label.setText(f"Logged in as: {self.current_user['name']} ({self.current_user['role']})")
            
            # Refresh employee list to show updated info
            self.refresh_employee_list()
            
            QMessageBox.information(self, "Success", "Personal information updated!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update information: {str(e)}")
    
    def closeEvent(self, event):
        # Close database connection when application closes
        self.db_connection.close()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HRManagementSystem()
    window.show()
    sys.exit(app.exec())