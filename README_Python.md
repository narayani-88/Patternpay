# Bank Application - Python Version

A complete Python-based bank application with Tkinter GUI and JSON data storage, featuring all the functionality of the original Java version.

## 🐍 Features

- **User Authentication**: Login and registration system with JSON data persistence
- **Account Management**: Add new bank accounts (Savings, Current, Fixed Deposit)
- **Bank Transfer**: Transfer money between accounts with balance validation
- **UPI Payment**: Make UPI payments to other users
- **Transaction History**: View all transactions in a table format
- **User Profile**: View and manage personal information
- **Account IFSC**: View bank details and account information
- **Settings**: Configure application preferences
- **3-Dot Menu Navigation**: Modern collapsible navigation panel

## 📋 Requirements

- **Python 3.6 or higher**
- **Tkinter** (usually comes with Python installation)
- **No external packages required** - uses only Python standard library

## 🚀 Installation & Setup

### Option 1: Direct Run
```bash
python bank_application.py
```

### Option 2: Using Python Launcher
```bash
python3 bank_application.py
```

### Option 3: Windows
```bash
# Double-click bank_application.py or run:
py bank_application.py
```

## 🔑 Default Login Credentials

- **Username**: `user`
- **Password**: `password`

## 📁 File Structure

```
bank/
├── bank_application.py      # Main application file
├── requirements.txt         # Dependencies (none required)
├── README_Python.md        # This file
├── users.json              # User data (created automatically)
├── accounts.json           # Account data (created automatically)
└── transactions.json       # Transaction data (created automatically)
```

## 🎨 Design Features

- **Color Theme**: Orange (#FF8C00) and white throughout
- **Modern UI**: Clean, professional interface
- **Responsive Layout**: Fixed window size (1200x800)
- **3-Dot Menu**: Collapsible navigation with ⋮ icon
- **Hover Effects**: Interactive navigation buttons
- **Data Persistence**: JSON-based data storage

## 🔧 Key Features

### User Management
- **Registration**: New user account creation
- **Login**: Secure authentication
- **Profile Management**: View and update user information

### Banking Operations
- **Account Creation**: Multiple account types support
- **Money Transfer**: Inter-account transfers
- **UPI Payments**: Digital payment system
- **Transaction Tracking**: Complete transaction history

### Data Storage
- **JSON Files**: Persistent data storage
- **Automatic Backup**: Data saved after each operation
- **Sample Data**: Pre-loaded for testing

## 🖥️ GUI Components

### Main Interface
- **Login/Register**: Authentication screens
- **Dashboard**: Home page with statistics
- **Navigation Panel**: Collapsible menu system
- **Content Areas**: Dynamic page switching

### Navigation System
- **3-Dot Menu**: ⋮ button for menu access
- **Auto-Close**: Navigation closes after selection
- **Hover Effects**: Visual feedback on buttons
- **Smooth Transitions**: Instant panel show/hide

## 📊 Data Models

### User Class
```python
class User:
    - username: str
    - password: str
    - full_name: str
    - email: str
```

### BankAccount Class
```python
class BankAccount:
    - account_number: str
    - account_type: str
    - balance: float
    - user: User
```

### Transaction Class
```python
class Transaction:
    - account_number: str
    - transaction_type: str
    - amount: float
    - description: str
    - date: datetime
```

## 🔄 Data Flow

1. **Application Start**: Load existing data from JSON files
2. **User Actions**: Perform banking operations
3. **Data Updates**: Modify in-memory data structures
4. **Auto-Save**: Persist changes to JSON files
5. **Data Integrity**: Maintain consistency across operations

## 🛡️ Security Features

- **Password Validation**: Secure login system
- **Balance Verification**: Prevent overdrafts
- **Transaction Logging**: Complete audit trail
- **Data Validation**: Input sanitization and verification

## 🎯 Usage Guide

### Getting Started
1. Run the application: `python bank_application.py`
2. Login with default credentials or register new account
3. Use 3-dot menu (⋮) to access navigation
4. Explore different banking features

### Navigation
- **3-Dot Menu**: Click ⋮ to show/hide navigation
- **Auto-Close**: Navigation closes after selecting option
- **Quick Access**: Menu available on all pages

### Banking Operations
- **Add Account**: Create new bank accounts
- **Transfer Money**: Move funds between accounts
- **UPI Payment**: Make digital payments
- **View History**: Check transaction records

## 🔧 Customization

### Colors
```python
self.orange_color = "#FF8C00"  # Main theme color
self.white_color = "#FFFFFF"   # Background color
```

### Window Size
```python
self.root.geometry("1200x800")  # Application window size
```

### Data Files
- `users.json`: User account information
- `accounts.json`: Bank account details
- `transactions.json`: Transaction history

## 🐛 Troubleshooting

### Common Issues

1. **Tkinter Not Found**
   ```bash
   # Install tkinter (Ubuntu/Debian)
   sudo apt-get install python3-tk
   
   # Install tkinter (macOS)
   brew install python-tk
   ```

2. **Permission Errors**
   ```bash
   # Make file executable
   chmod +x bank_application.py
   ```

3. **Data File Issues**
   - Delete JSON files to reset to default data
   - Application will recreate sample data automatically

### Performance Tips
- Close unused applications for better performance
- Ensure sufficient disk space for data files
- Use SSD storage for faster file operations

## 🔮 Future Enhancements

- **Database Integration**: SQLite/PostgreSQL support
- **Encryption**: Enhanced data security
- **API Integration**: Real banking services
- **Mobile App**: Cross-platform development
- **Advanced Analytics**: Financial reporting
- **Multi-Currency**: International banking support

## 📝 License

This project is open source and available under the MIT License.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For issues and questions:
- Check the troubleshooting section
- Review the code comments
- Test with default credentials
- Verify Python version compatibility

---

**Note**: This is a demonstration application. For real banking applications, additional security measures and compliance requirements would be necessary. 