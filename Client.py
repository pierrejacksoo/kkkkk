import os
import json
import random
import bcrypt
import qrcode
import requests
from datetime import datetime
from io import BytesIO
from colorama import Fore, Back, Style, init
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.image import Image
from kivy.uix.popup import Popup
from kivy.core.window import Window
from kivy.uix.camera import Camera
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.graphics.texture import Texture
from supabase import create_client, Client
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from Crypto.Hash import RIPEMD160
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

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

# Helper functions
def save_cookies(data):
    with open(COOKIES_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f)

def load_cookies():
    if os.path.exists(COOKIES_PATH):
        with open(COOKIES_PATH, 'r', encoding='utf-8') as f):
            return json.load(f)
    return {}

class LoginScreen(BoxLayout):
    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 20
        self.spacing = 10
        self.background_color = [255/255, 224/255, 130/255, 1]  # Light yellow background

        self.pseudonym_input = TextInput(hint_text='Přezdívka', multiline=False)
        self.add_widget(self.pseudonym_input)

        self.password_input = TextInput(hint_text='Heslo', multiline=False, password=True)
        self.add_widget(self.password_input)

        self.login_button = Button(text='PŘIHLÁSIT SE', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.login_button.bind(on_press=self.login)
        self.add_widget(self.login_button)

        self.message = Label(color=[255/255, 0/255, 0/255, 1])  # Red text
        self.add_widget(self.message)
        # Load cookies and autofill pseudonym if available
        cookies = load_cookies()
        if 'pseudonym' in cookies:
            self.pseudonym_input.text = cookies['pseudonym']

    def login(self, instance):
        pseudonym = self.pseudonym_input.text
        password = self.password_input.text

        user = supabase.table('users').select("*").eq('pseudonym', pseudonym).execute()
        if user.data and verify_password(password, user.data[0]['password']):
            self.user = user.data[0]
            print(Fore.GREEN + "Přihlášení úspěšné")
            save_cookies({'pseudonym': pseudonym})
            self.manager.current = 'dashboard'
        else:
            self.message.text = 'Přihlášení selhalo'
            print(Fore.RED + "Přihlášení selhalo")

class DashboardScreen(BoxLayout):
    def __init__(self, **kwargs):
        super(DashboardScreen, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 20
        self.spacing = 10
        self.background_color = [224/255, 255/255, 255/255, 1]  # Light cyan background

        self.pseudonym_label = Label()
        self.add_widget(self.pseudonym_label)

        self.wallet_label = Label()
        self.add_widget(self.wallet_label)

        self.balance_label = Label()
        self.add_widget(self.balance_label)

        
        self.generate_qr_button = Button(text='Pay me' # Blue button
        self.generate_qr_button.bind(on_press=self.generate_qr_code)
        self.add_widget(self.generate_qr_button)

        self.scan_qr_button = Button(text='QR platba', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.scan_qr_button.bind(on_press=self.scan_qr_code)
        self.add_widget(self.scan_qr_button)

        self.transfer_button = Button(text='Převod', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.transfer_button.bind(on_press=self.transfer)
        self.add_widget(self.transfer_button)

        self.transactions_button = Button(text='Historie', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.transactions_button.bind(on_press=self.transactions)
        self.add_widget(self.transactions_button)

        self.buy_crypto_button = Button(text='Koupit', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.buy_crypto_button.bind(on_press=self.buy_crypto)
        self.add_widget(self.buy_crypto_button)

        self.download_statement_button = Button(text='Download Statement', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.download_statement_button.bind(on_press=self.download_statement)
        self.add_widget(self.download_statement_button)

        self.logout_button = Button(text='Logout', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.logout_button.bind(on_press=self.logout)
        self.add_widget(self.logout_button)

    def on_pre_enter(self):
        user_id = self.manager.get_screen('login').user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]
        self.pseudonym_label.text = f"Pseudonym: {user['pseudonym']}"
        self.wallet_label.text = f"Wallet: {user['wallet']}"
        self.balance_label.text = f"Balance: {user['balance']}"

    def generate_qr_code(self, instance):
        amount = '10'  # Example amount
        user_id = self.manager.get_screen('login').user['user_id']
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

        popup = Popup(title='QR Code', content=Image(texture=Texture.create(size=img.size, colorfmt='rgb', buffer=buffer.read())), size_hint=(0.8, 0.8))
        popup.open()

    def scan_qr_code(self, instance):
        self.manager.current = 'scanqr'

    def transfer(self, instance):
        self.manager.current = 'transfer'

    def transactions(self, instance):
        self.manager.current = 'transactions'

    def buy_crypto(self, instance):
        self.manager.current = 'buycrypto'

    def download_statement(self, instance):
        user_id = self.manager.get_screen('login').user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]
        buffer = generate_pdf_statement(user)

        # Save PDF to a real directory
        save_path = os.path.join(os.path.expanduser('~'), 'Documents', 'statement.pdf')
        with open(save_path, 'wb') as f:
            f.write(buffer.getvalue())

        popup = Popup(title='STÁHNOUT', content=Label(text=f'Výpis účtu ve formátu PDF byl stažen do: {save_path}'), size_hint=(0.8, 0.8))
        popup.open()

    def logout(self, instance):
        self.manager.current = 'login'

class TransferScreen(BoxLayout):
    def __init__(self, **kwargs):
        super(TransferScreen, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 20
        self.spacing = 10
        self.background_color = [255/255, 224/255, 224/255, 1]  # Light pink background

        self.recipient_wallet_input = TextInput(hint_text='Recipient Wallet', multiline=False)
        self.add_widget(self.recipient_wallet_input)

        self.amount_input = TextInput(hint_text='Amount', multiline=False)
        self.add_widget(self.amount_input)

        self.description_input = TextInput(hint_text='Description', multiline=False)
        self.add_widget(self.description_input)

        self.transfer_button = Button(text='Transfer', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.transfer_button.bind(on_press=self.transfer)
        self.add_widget(self.transfer_button)

    def transfer(self, instance):
        recipient_wallet = self.recipient_wallet_input.text
        amount = float(self.amount_input.text)
        description = self.description_input.text

        user_id = self.manager.get_screen('login').user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]

        if recipient_wallet == user['wallet']:
            popup = Popup(title='Error', content=Label(text='Nemůžete posílat krypoměnu na váš vlastní účet.'), size_hint=(0.8, 0.8))
            popup.open()
            return

        if user['balance'] < amount:
            popup = Popup(title='Error', content=Label(text='Nedostatečný zůstatek'), size_hint=(0.8, 0.8))
            popup.open()
            return

        recipient_query = supabase.table('users').select("*").eq('wallet', recipient_wallet).execute()
        if not recipient_query.data:
            popup = Popup(title='Error', content=Label(text='Uživatelský účet neexistuje.'), size_hint=(0.8, 0.8))
            popup.open()
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

        popup = Popup(title='Success', content=Label(text='Transfer Successful'), size_hint=(0.8, 0.8))
        popup.open()

        self.manager.current = 'dashboard'

class TransactionsScreen(BoxLayout):
    def __init__(self, **kwargs):
        super(TransactionsScreen, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 20
        self.spacing = 10
        self.background_color = [255/255, 255/255, 224/255, 1]  # Light yellow background

        self.transactions_label = Label()
        self.add_widget(self.transactions_label)

    def on_pre_enter(self):
        user_id = self.manager.get_screen('login').user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]
        transactions = user.get('transactions', [])
        transactions_text = ""
        for transaction in transactions:
            transactions_text += f"{transaction['date']}: {transaction['type']} of {transaction['amount']} - {transaction['description']}\n"
        self.transactions_label.text = transactions_text

class BuyCryptoScreen(BoxLayout):
    def __init__(self, **kwargs):
        super(BuyCryptoScreen, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 20
        self.spacing = 10
        self.background_color = [224/255, 255/255, 224/255, 1]  # Light green background

        self.bank_address_label = Label(text=f"Bankovní účet: {BANK_ADDRESS}")
        self.add_widget(self.bank_address_label)

        self.variable_symbol_label = Label()
        self.add_widget(self.variable_symbol_label)

    def on_pre_enter(self):
        user_id = self.manager.get_screen('login').user['user_id']
        user = supabase.table('users').select("*").eq('user_id', user_id).execute().data[0]
        self.variable_symbol_label.text = f"Variabilní symbol: {user.get('variable_symbol', 'default_variable_symbol')}"

class ScanQRScreen(BoxLayout):
    def __init__(self, **kwargs):
        super(ScanQRScreen, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 20
        self.spacing = 10
        self.background_color = [255/255, 224/255, 255/255, 1]  # Light purple background

        self.camera = Camera(play=True)
        self.add_widget(self.camera)

        self.scan_button = Button(text='Scan', background_color=[0/255, 122/255, 255/255, 1])  # Blue button
        self.scan_button.bind(on_press=self.scan)
        self.add_widget(self.scan_button)

    def scan(self, instance):
        # Implement QR Code scanning logic
        pass

class CryptoAppApp(App):
    def build(self):
        self.sm = ScreenManager()

        self.sm.add_widget(Screen(name='login', content=LoginScreen()))
        self.sm.add_widget(Screen(name='dashboard', content=DashboardScreen()))
        self.sm.add_widget(Screen(name='transfer', content=TransferScreen()))
        self.sm.add_widget(Screen(name='transactions', content=TransactionsScreen()))
        self.sm.add_widget(Screen(name='buycrypto', content=BuyCryptoScreen()))
        self.sm.add_widget(Screen(name='scanqr', content=ScanQRScreen()))

        return self.sm

if __name__ == '__main__':
    CryptoAppApp().run()
