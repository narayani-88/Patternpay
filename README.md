# PatternPay - Modern Banking Application

A modern, real-time banking application built with Flask and MongoDB, featuring user authentication, account management, and real-time transaction updates.

## Features

- User authentication (login/register)
- Account management
- Real-time balance updates
- Transaction history
- Secure money transfers
- Responsive design

## Prerequisites

- Python 3.8+
- MongoDB
- pip

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/patternpay-bank.git
   cd patternpay-bank
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the root directory with:
   ```
   MONGO_URI=your_mongodb_connection_string
   SECRET_KEY=your_secret_key
   ```

## Running the Application

```bash
python patternpay_web.py
```

Visit `http://localhost:5000` in your browser.

## Default Credentials

- Username: `user`
- Password: `password`

## License

This project is licensed under the MIT License.
