import os
import json
import random
import bcrypt
import qrcode
import requests
from datetime import datetime
from io import BytesIO
from colorama import Fore, Back, Style, init
from supabase import create_client, Client
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from Crypto.Hash import RIPEMD160
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

# Initialize colorama
init(autoreset=True)

# Constants
COOKIES_PATH = os.path.join(os.path.expanduser('~'), 'crypto_app_cookies.json')

# Supabase setup
SUPABASE_URL = 'https://mcsqjznczjhjstkpquxa.supabase.co'
SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1jc3Fqem5jempoanN0a3BxdXhhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzgzNDU1MDksImV4cCI6MjA1MzkyMTUwOX0.Lv9SbVrngs6flfS0yBHFShOIAvECdiwHzaSddcHDXB4'
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Constants
CREDIT_AMOUNT = 2.32
BANK_ADDRESS = "123-3816330217/0100"

# Helper functions
def encrypt_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_wallet():
    random_bytes = os.urandom(32)
    h = RIPEMD160.new()
    h.update(random_bytes)
    return h.hexdigest()

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_data(data, key):
    data = b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def generate_pdf_statement(user):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.drawString(100, height - 100, f"Výpis transakcí pro {user['pseudonym']}")
    c.drawString(100, height - 120, f"Peněženka: {user['wallet']}")
    c.drawString(100, height - 140, f"Zůstatek: {user['balance']}")

    transactions = user.get('transactions', [])
    y = height - 160
    for transaction in transactions:
        c.drawString(100, y, f"{transaction['date']}: {transaction['type']} {transaction['amount']} - {transaction['description']}")
        y -= 20
        if y < 40:
            c.showPage()
            y = height - 40

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer

def save_cookies(data):
    with open(COOKIES_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f)

def load_cookies():
    if os.path.exists(COOKIES_PATH):
        with open(COOKIES_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

class CryptoApp(toga.App):
    def startup(self):
        self.main_window = toga.MainWindow(title=self.name)

        self.login_screen = self.build_login_screen()
        self.dashboard_screen = self.build_dashboard_screen()
        self.transfer_screen = self.build_transfer_screen()
        self.transactions_screen = self.build_transactions_screen()
        self.buycrypto_screen = self.build_buycrypto_screen()
        self.scanqr_screen = self.build_scanqr_screen()

        self.main_box = toga.Box(style=Pack(direction=COLUMN))
        self.main_box.add(self.login_screen)

        self.main_window.content = self.main_box
        self.main_window.show()

    def build_login_screen(self):
        box = toga.Box(style=Pack(direction=COLUMN, padding=20, spacing=10))

        self.pseudonym_input = toga.TextInput(placeholder='Přezdívka')
        box.add(self.pseudonym_input)

        self.password_input = toga.PasswordInput(placeholder='Heslo')
        box.add(self.password_input)

        login_button = toga.Button('PŘIHLÁSIT SE', on_press=self.login)
        box.add(login_button)

        self.message = toga.Label('')
        box.add(self.message)

        cookies = load_cookies()
        if 'pseudonym' in cookies:
            self.pseudonym_input.value = cookies['pseudonym']

        return box

    def login(self, widget):
        pseudonym = self.pseudonym_input.value
        password = self.password_input.value

        user = supabase.table('users').select("*").eq('pseudonym', pseudonym).execute()
        if user.data and verify_password(password, user.data[0]['password']):
            self.user = user.data[0]
            print(Fore.GREEN + "Přihlášení úspěšné")
            save_cookies({'pseudonym': pseudonym})
            self.main_box.remove(self.login_screen)
            self.main_box.add(self.dashboard_screen)
            self.on_pre_enter_dashboard()
        else:
            self.message.text = 'Přihlášení selhalo'
            print(Fore.RED + "Přihlášení selhalo")

    def build_dashboard_screen(self):
        box = toga.Box(style=Pack(direction=COLUMN, padding=20, spacing=10))

        self.pseudonym_label = toga.Label('')
        box.add(self.pseudonym_label)

        self.wallet_label = toga.Label('')
        box.add(self.wallet_label)

        self.balance_label = toga.Label('')
        box.add(self.balance_label)

        generate_qr_button = toga.Button('Pay me', on_press=self.generate_qr_code)
        box.add(generate_qr_button)

        scan_qr_button = toga.Button('QR platba', on_press=self.scan_qr_code)
        box.add(scan_qr_button)

        transfer_button = toga.Button('Převod', on_press=self.transfer)
        box.add(transfer_button)

        transactions_button = toga.Button('Historie', on_press=self.transactions)
        box.add(transactions_button)

        buy_crypto_button = toga.Button('Koupit', on_press=self.buy_crypto)
        box.add(buy_crypto_button)

        download_statement_button = toga.Button('Download Statement', on_press=self.download_statement)
        box.add(download_statement_button)

        logout_button = toga.Button('Logout', on_press=self.logout)
        box.add(logout_button)

        return box

    def on_pre_enter_dashboard(self):
        user_id = self.user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]
        self.pseudonym_label.text = f"Pseudonym: {user['pseudonym']}"
        self.wallet_label.text = f"Wallet: {user['wallet']}"
        self.balance_label.text = f"Balance: {user['balance']}"

    def generate_qr_code(self, widget):
        amount = '10'
        user_id = self.user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]

        qr_data = {
            'wallet': user['wallet'],
            'amount': amount
        }
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(qr_data)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')

        buffer = BytesIO()
        img.save(buffer, 'PNG')
        buffer.seek(0)

        popup = toga.Window(title='QR Code')
        popup.content = toga.Image(data=buffer)
        popup.show()

    def scan_qr_code(self, widget):
        self.main_box.remove(self.dashboard_screen)
        self.main_box.add(self.scanqr_screen)

    def transfer(self, widget):
        self.main_box.remove(self.dashboard_screen)
        self.main_box.add(self.transfer_screen)

    def transactions(self, widget):
        self.main_box.remove(self.dashboard_screen)
        self.main_box.add(self.transactions_screen)

    def buy_crypto(self, widget):
        self.main_box.remove(self.dashboard_screen)
        self.main_box.add(self.buycrypto_screen)

    def download_statement(self, widget):
        user_id = self.user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]
        buffer = generate_pdf_statement(user)

        save_path = os.path.join(os.path.expanduser('~'), 'Documents', 'statement.pdf')
        with open(save_path, 'wb') as f:
            f.write(buffer.getvalue())

        popup = toga.Window(title='STÁHNOUT')
        popup.content = toga.Label(f'Výpis účtu ve formátu PDF byl stažen do: {save_path}')
        popup.show()

    def logout(self, widget):
        self.main_box.remove(self.dashboard_screen)
        self.main_box.add(self.login_screen)

    def build_transfer_screen(self):
        box = toga.Box(style=Pack(direction=COLUMN, padding=20, spacing=10))

        self.recipient_wallet_input = toga.TextInput(placeholder='Recipient Wallet')
        box.add(self.recipient_wallet_input)

        self.amount_input = toga.TextInput(placeholder='Amount')
        box.add(self.amount_input)

        self.description_input = toga.TextInput(placeholder='Description')
        box.add(self.description_input)

        transfer_button = toga.Button('Transfer', on_press=self.perform_transfer)
        box.add(transfer_button)

        return box

    def perform_transfer(self, widget):
        recipient_wallet = self.recipient_wallet_input.value
        amount = float(self.amount_input.value)
        description = self.description_input.value

        user_id = self.user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]

        if recipient_wallet == user['wallet']:
            popup = toga.Window(title='Error')
            popup.content = toga.Label('Nemůžete posílat krypoměnu na váš vlastní účet.')
            popup.show()
            return

        if user['balance'] < amount:
            popup = toga.Window(title='Error')
            popup.content = toga.Label('Nedostatečný zůstatek')
            popup.show()
            return

        recipient_query = supabase.table('users').select("*").eq('wallet', recipient_wallet).execute()
        if not recipient_query.data:
            popup = toga.Window(title='Error')
            popup.content = toga.Label('Uživatelský účet neexistuje.')
            popup.show()
            return

        recipient = recipient_query.data[0]

        new_balance = user['balance'] - amount
        transactions = user.get('transactions', [])
        transactions.append({
            'type': 'expense',
            'amount': amount,
            'date': datetime.utcnow().isoformat(),
            'description': description
        })
        supabase.table('users').update({'balance': new_balance, 'transactions': transactions}).eq('user_id', user_id).execute()

        recipient_transactions = recipient.get('transactions', [])
        recipient_transactions.append({
            'type': 'revenue',
            'amount': amount,
            'date': datetime.utcnow().isoformat(),
            'description': description
        })
        supabase.table('users').update({'balance': recipient['balance'] + amount, 'transactions': recipient_transactions}).eq('wallet', recipient_wallet).execute()

        popup = toga.Window(title='Success')
        popup.content = toga.Label('Transfer Successful')
        popup.show()

        self.main_box.remove(self.transfer_screen)
        self.main_box.add(self.dashboard_screen)

    def build_transactions_screen(self):
        box = toga.Box(style=Pack(direction=COLUMN, padding=20, spacing=10))

        self.transactions_label = toga.Label('')
        box.add(self.transactions_label)

        return box

    def on_pre_enter_transactions(self):
        user_id = self.user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]
        transactions = user.get('transactions', [])
        transactions_text = ""
        for transaction in transactions:
            transactions_text += f"{transaction['date']}: {transaction['type']} of {transaction['amount']} - {transaction['description']}\n"
        self.transactions_label.text = transactions_text

    def build_buycrypto_screen(self):
        box = toga.Box(style=Pack(direction=COLUMN, padding=20, spacing=10))

        self.bank_address_label = toga.Label(f"Bankovní účet: {BANK_ADDRESS}")
        box.add(self.bank_address_label)

        self.variable_symbol_label = toga.Label('')
        box.add(self.variable_symbol_label)

        return box

    def on_pre_enter_buycrypto(self):
        user_id = self.user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]
        self.variable_symbol_label.text = f"Variabilní symbol: {user.get('variable_symbol', 'default_variable_symbol')}"

    def build_scanqr_screen(self):
        box = toga.Box(style=Pack(direction=COLUMN, padding=20, spacing=10))

        self.camera_label = toga.Label('QR Code Scanner')
        box.add(self.camera_label)

        self.camera_input = toga.TextInput(placeholder='Scan QR Code Here')
        box.add(self.camera_input)

        scan_button = toga.Button('Scan', on_press=self.scan_qr_code_action)
        box.add(scan_button)

        return box

    def scan_qr_code_action(self, widget):
        # Implement QR Code scanning logic
        qr_code_data = self.camera_input.value
        if qr_code_data:
            try:
                qr_data = json.loads(qr_code_data)
                self.process_qr_code(qr_data)
            except json.JSONDecodeError:
                popup = toga.Window(title='Error')
                popup.content = toga.Label('Invalid QR Code')
                popup.show()

    def process_qr_code(self, qr_data):
        wallet = qr_data.get('wallet')
        amount = qr_data.get('amount')
        if wallet and amount:
            self.recipient_wallet_input.value = wallet
            self.amount_input.value = amount
            self.main_box.remove(self.scanqr_screen)
            self.main_box.add(self.transfer_screen)
        else:
            popup = toga.Window(title='Error')
            popup.content = toga.Label('Invalid QR Code Data')
            popup.show()

def main():
    return CryptoApp()

if __name__ == '__main__':
    main().main_loop()
