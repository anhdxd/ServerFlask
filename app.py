from flask import Flask, url_for, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import json
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
import base64
import re
import pyotp
import my_otp
import time
from flask_migrate import Migrate
import secrets
import requests
import random
import math
import os 

# Tắt xác thực chứng chỉ SSL/TLS
os.environ['PYTHONHTTPSVERIFY'] = '0'

g_time_token = 3600 * 24 # 24h

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class PCUser(db.Model):
    pc_id = db.Column(db.Integer, primary_key=True)
    pc_serial = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    public_key = db.Column(db.Text)
    pc_user = db.relationship('Connect', backref='pc_user', lazy=True)
    #pcname = db.Column(db.String(100), nullable=False)

    #sync_data = db.relationship('SyncData', backref='pc_user', lazy=True)

    def __init__(self, pc_serial, public_key, phone):
        self.pc_serial = pc_serial
        self.public_key = public_key
        self.phone = phone

class MobileUser(db.Model):
    mb_id = db.Column(db.Integer, primary_key=True)
    mobile_serial = db.Column(db.String(255), nullable=False, unique=True)
    phone = db.Column(db.String(20))
    public_key = db.Column(db.Text)
    mobile_user = db.relationship('Connect', backref='mobile_user', lazy=True)
    #sync_data = db.relationship('SyncData', backref='mobile_user', lazy=True)
    #token = db.Column(db.String(256), nullable=False)
    #time_create_token = db.Column(db.REAL, nullable=False)
    # pc_user = db.relationship('PCUser', backref='pc_user', lazy=True)

    def __init__(self, mobile_serial, public_key, phone):
        self.mobile_serial = mobile_serial
        self.public_key = public_key
        self.phone = phone

class Connect(db.Model):
    connect_id = db.Column(db.Integer, primary_key=True)
    mb_id = db.Column(db.Integer, db.ForeignKey("mobile_user.mb_id"), nullable=False)
    pc_id = db.Column(db.Integer, db.ForeignKey("pc_user.pc_id"), nullable=False)

    connect = db.relationship('SyncData', backref='connect', lazy=True)

    def __init__(self, mb_id, pc_id):
        self.mb_id = mb_id
        self.pc_id = pc_id

class SyncData(db.Model):
    sync_id = db.Column(db.Integer, primary_key=True)
    connect_id = db.Column(db.Integer, db.ForeignKey("connect.connect_id"), nullable=False)
    data_enc = db.Column(db.Text, nullable=False)
    time_sync = db.Column(db.REAL, nullable=False)

    def __init__(self, connect_id, data_enc, time_sync):
        self.connect_id = connect_id
        self.data_enc = data_enc
        self.time_sync = time_sync

dct_otp = {} # dict chứa phone và otp

#Login email


# Thiết lập API để xác thực số điện thoại của người dùng và gửi mã OTP
@app.route('/verify_phone_number', methods=['POST'])
def verify_phone_number():
    try:
        # Chưa có gửi cho nhiều sdt và time 1p/lần
        phone_number = request.get_json()['phone']
        
        # Test với 1 số điện thoại
        # if phone_number != '0836206984' and phone_number != '84836206984':
        #     return 'Phone number not found', 400

        # Get otp timeout 5p
        r_otp = pyotp.random_base32()
        dct_otp[phone_number] = pyotp.TOTP(r_otp, interval=300)
        otp = dct_otp[phone_number].now()

        # Gửi mã OTP đến số điện thoại của người dùng
        message = f'Your OTP is: {otp}'
        my_otp.send_text_phone(message, phone_number)
        print(message)

        return 'oke', 200
    except Exception as e:
        print(e)
        return 'server error', 500
    
# Thiết lập API để kiểm tra mã OTP và cho phép người dùng truy cập
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    global dct_otp
    phone_number = request.get_json()['phone']
    otp = request.get_json()['otp']
    if phone_number not in dct_otp:
        # Nếu số điện thoại không tồn tại trong cơ sở dữ liệu, trả về thông báo lỗi
        return 'Phone number not found', 400
    elif not dct_otp[phone_number].verify(otp):
        # Nếu mã OTP không hợp lệ, trả về thông báo lỗi
        return 'OTP not valid', 400
    else:
        # create token
        token = secrets.token_hex(32)

        # Nếu mã OTP hợp lệ, trả về thông báo thành công va remove otp
        # Ở đây sau này sẽ thêm luôn cả phone và serial, hiện tại đang làm thủ công theo cách khác
        del dct_otp[phone_number]
        return token, 200

@app.route('/change_config/', methods=['GET', 'POST'])
def change_config():
    if request.method == 'POST':
        try:
            print(request.form["adult"])
        except Exception as e:
            print(e)
            return ""
    return ""

@app.route('/delete_all_diary', methods=['POST'])
def delete_all_diary():
    try:
        json_response = request.get_json()
        phone = request.get_json()['phone']
        token = request.get_json()['token']
        query_syncdata = MobileUser.query.filter_by(token=token, phone=phone).first()
        if query_syncdata is None:
            return 'Phone number not found', 400
        elif (query_syncdata.time_create_token + g_time_token) < time.time():
            json_response['status'] = 'error'
            json_response['message'] = 'timetoken'
            return json.dumps(json_response)
        
        query_syncdata = SyncData.query.filter_by(phone=phone).first()
        if query_syncdata is None:
            return 'Do not have diary', 400
        else:
            query_syncdata.data_enc = ""
            query_syncdata.timesync = 0
            db.session.commit()
            return 'oke', 200
    except Exception as e:
        print(e)
        return 'server error', 500
# *********************** Sync ******************

@app.route('/sync/upload', methods=['POST'])
def sync_upload():
    try:
        json_response = request.get_json()
        enc_data = json_response['data']
        phone = json_response['phone']
        serial = json_response['serial']

        # Insert data to SyncData. If exists, update
        query_syncdata = SyncData.query.filter_by(serial=serial, phone=phone).first()
        if query_syncdata is None:
            db.session.add(SyncData(phone=phone, serial = serial, data_enc=enc_data, timesync=0))
        else:
            #query_syncdata = SyncData.query.filter_by(phone=phone).first()
            query_syncdata.data_enc = enc_data
            query_syncdata.serial = serial
            query_syncdata.timesync = time.time()
        db.session.commit()

        json_response['status']= 'success'
        json_response['message'] = ''
        print("add db oke!")
        return json.dumps(json_response)

    except Exception as e:
        json_response['status'] = 'server_error'
        json_response['message'] = "upload: " + str(e)
        json_response = json.dumps(json_response)
        return json_response

@app.route('/sync/download', methods=['POST'])
def sync_download():
    try:
        json_response = request.get_json()
        phone = json_response['phone']
        phone_token = json_response['token']

        # Check token
        query_mobileuser = MobileUser.query.filter_by(phone=phone, token = phone_token).first()
        if query_mobileuser is None:
            json_response['status'] = 'error'
            json_response['message'] = 'Token not match'
            return json.dumps(json_response)
        elif (query_mobileuser.time_create_token + g_time_token) < time.time():
            json_response['status'] = 'error'
            json_response['message'] = 'timetoken'
            return json.dumps(json_response)
        
        # Get data from SyncData
        query_syncdata = SyncData.query.filter_by(phone=phone).first()
        if query_syncdata is None:
            json_response['status'] = 'error'
            json_response['message'] = 'No data'
            return json.dumps(json_response)
        else:
            json_response['status'] = 'success'
            json_response['message'] = ''
            json_response['serial'] = query_syncdata.serial
            json_response['data'] = query_syncdata.data_enc
            return json.dumps(json_response)

    except Exception as e:
        json_response['status'] = 'server_error'
        json_response['message'] = "download: " + str(e)
        json_response = json.dumps(json_response)
        return json_response

@app.route('/sync/uploadpublickey', methods=['POST'])
def uploadpublickey():
    try:
        json_response = request.get_json()
        phone = json_response['phone']
        publickey = json_response['publickey']
        token = json_response['token']

        # insert to User, if exists, update
        query_user = MobileUser.query.filter_by(phone=phone).first()
        if query_user is None:
            db.session.add(MobileUser(phone=phone, public_key=publickey, token=token, time_create_token=time.time()))
        else:
            query_user.public_key = publickey
            query_user.token = token
            query_user.time_create_token = time.time()
        db.session.commit()
        # Tới đây là xong rồi
        # Đoạn này mã hóa bằng public
        key_enc = encrypt_data_rsa(phone)

        data = {
    "phone":str(phone),
    "serial":"pc-serial-" + str(phone),
    "data":"{\"aes\":\"" + key_enc + "\",\"data_enc\":\"YVcd1VudMGKjBviDSWVyPb7qhqWO8tUNKML09EIShmSrpFHKZNMsmIZizNvl3whhunnR60HgATUn8yejlTjRcEYvO9mY6gJy8HenI9bMoY0cIXYwbnG+9UzufkDokItQo5C/y3OiKOpVxMRRpf0BEaHpYq+v0211YvdEVt4RMZ7Ns0oCJJ1RdjZ+3nJU2JN2XoRDoJZ2xkSm4nxIOPFrhXu1UUN0ayFKTOMUy35fVVdyUDEaHEuwlxhMYMC2rFGoNNFCTsVDeQBi8jkNDuSmh+458TY6dJ9S7EpbWskjWYVngv1oNC2HThM5I1SMXX4qW11f2WpXt0Uw22lKFRn1oMdTW2kMtCzePG/83pl9+utlKYgqu4ufDzd+tqg1AlCzhdyXIE5E3Yc0Wr4jpseQIhPyy/Lc70KUIyVwVR4MyEyKblg8RdGhwWlw4vXTWLHcY79Y6wK1cBZpyqqoF1HhV/QDRN/dEsGtEXduRDZyBB8yEz1D091GEp4kcy0sljYRpTiK+C61FsybfrxUd93G/YcTXPIpg3Ed+bsRZegdbNfCR1My143mgankbgwBAuaGWsUD4/ic7Ex0cqQk0Z/xqyb+7HDn0r+guV+SdJ7ywnlk8FVr1T4Ze+Z3AFr+5dbQkOL/khTopE+I7IhWa//S1IwluAFS1hfspHye1llefhiubxxstSmtWMCIiP+xxzftL89ypr+WPIdoJF6YXg9oIPfqpQIuogW0hPEDL2HIGT/Jsn4xi8w3dBlEHqtAkrBRTdqrOcCCJV8w5C6WR2Oeav0x1Wl9rzxxDOHxLvW3ViR0GiVYeI+IzAXIYrbdpC2/KvV5fTfSiO6+em6crDT4kJ2diB97bJE82wEW9NlfhuWJ6VmEoZXlM04nd6eKgbrUQfZxp0kFBQ9kISLpEaSheK1dAOyma5NaQTf3G7pLsbWO0JoKCsc7MxBoDPXy8RFx1kMXm26tm7h6iLR5V3VKWe7x72zEyCFXUvH6saUpTPFmi47WmEVK1QbwclhYop7cRKBJ3f8ge0NDrsJJSO72imONOWKYnec8loQxAfUBRZ+YaEQL5EM6scikw0gLqkRABgIsmh4Ms8LuDdOIEphM/c7QGA1Rtck6/FmXxEeFqGuyovjAFDsaHwalOByQVt46ZU+cw+X1FzZp4tr4vqeReiFt5zgBadLYJIhV0JQlpoVuZpwqI0Px5k+flLZ3U426+lfmcMSDL+JeRgyCXlfYHFH7hcbewLIzWEt6y8lUSPJoEATyspRm90Scdp+/BWrqzl3yEURyjUSFfy4PPrMreAHyArEwVDw7OU5/xxwEVSvDkd4pPhCompHv/Zfo4KmtfMr248pDjgJEozr6mpJmgWeOh/0V604Ds4euu0SeJiHr70hEFGEq2iRpGYAO0KavEdji3yP9co4+eMQfj1s+c+xkYi8c23CDM7R/uIFReSXqxWhVjBaL0PCwz/8g6uF8LXd+jKcqPfZ3UUeIR+7gvjwlIy0XU9Js1aaDNOOKQ5pj08TV/X2bK+PthnyyEfMCi5dvDwNvJmMNhC1EGo1C/aJtHT5zdjfpolRb4mDxEXKAoW8TqwswUZDdrH5J5/6TKuRxY7iN+nPKja+cnfaHasEDUi69hQddU1w+U5GZPB51obYwn3Vc9ZFajND4bvrRPfVy7FD9EG+Ym0mi6ifknmV07q0/ZqjyV4zqJ7TyEXs=\"}"
}
        requests.post("http://127.0.0.1:5000/sync/upload", json=data)
        return "1", 200

    except Exception as e:
        return {"status": "error", "publickey": str(e)}

@app.route('/sync/getpublickey', methods=['GET'])
def getpublickey():
    try:
        phone = request.args.get('phone')
        query_user = MobileUser.query.filter_by(phone=phone).first()
        if query_user is None:
            return "0", 200 # No phone number
        else:
            return query_user.public_key, 200

    except Exception as e:
        return {"status": "error", "getpublickey": str(e)}


# ********************* PC API *******************
@app.route('/info/addpcuserinfo', methods=['POST'])
def addpcuserinfo():
    try:
        json_response = request.get_json()
        phone = json_response['phone']
        serial = json_response['serial']
        pcname = json_response['pcname']

        # insert to User, if exists, update
        query_user = PCUser.query.filter_by(serial=serial).first()
        if query_user is None:
            db.session.add(PCUser(serial=serial, phone=phone, pcname=pcname))
        else:
            query_user.phone = phone
        db.session.commit()
        return "1", 200

    except Exception as e:
        return {"status": "error", "uploadpcuser": str(e)}
# generate rsa key
def generate_rsa_key():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key().decode('utf-8')
    private_key = key.export_key().decode('utf-8')
    return public_key, private_key


# import websockets
# async def hello():
#     uri = "ws://localhost:789"
#     async with websockets.connect(uri) as websocket:
#         name = input("What's your name? ")
#         await websocket.send(name)
#         print(f"> {name}")

#         greeting = await websocket.recv()
#         print(f"< {greeting}")

#encrypt data
def encrypt_data_rsa(phone):
    #Query public key with phone
    try:
        key = MobileUser.query.filter_by(phone=phone).first()
        if key is None:
            return ""

        data = "12345678123456781234567812345678"
        public_key = RSA.import_key(key.public_key)
        cipher_rsa = PKCS1_v1_5.new(public_key)
        encrypted_data = base64.b64encode(cipher_rsa.encrypt(data.encode("utf-8"))).decode("utf-8")
        return encrypted_data
    except Exception as e:
        print(e)
        return ""

if (__name__ == '__main__'):
    
   
    app.secret_key = "ThisIsNotASecret:p"
    app.app_context().push()

    #encrypt_data_rsa('0836206984')
    
    # # gen_key = generate_rsa_key()
    # # print(gen_key[1].encode('utf-8'))

    # key = getpublickey()
    # print(Utils.RemovePaddingRSA(key['publickey']))
    # print("*******************")
    # key = PublicKey.query.order_by(PublicKey.id.desc()).first()
    # print(Utils.RemovePaddingRSA( key.private_key))
    db.create_all()
    app.run(host='0.0.0.0', port=5000) #ssl_context=('certificate.pem', 'private_key.pem'),
    




# #decrypt data
# def decrypt_data_rsa(data):
#     #Query last public key
#     try:
#         key = MobilePubKey.query.order_by(MobilePubKey.id.desc()).first()
#         if key is None:
#             return None
#         else:
#             private_key = RSA.import_key(key.private_key)
#             cipher_rsa = PKCS1_OAEP.new(private_key)
#             decrypted_data = cipher_rsa.decrypt(base64.b64decode(data))
#             return decrypted_data
#     except Exception as e:
#         print(e)
#         return None
# def decrypt_data_aes(data = '', key=''):
#     cipher = AES.new(key, AES.MODE_ECB)
#     b64data = base64.standard_b64decode(data)
#     data_dec = cipher.decrypt(b64data).decode('UTF8')#[:-1]
#     data_dec = data_dec[0:data_dec.rfind('}')+1] 
#     return data_dec


# import asyncio
# import websockets
# from websockets.server import serve

# async def echo(websocket):
#     try:
#         async for message in websocket:
#             await websocket.send(message)
#     except websockets.exceptions.ConnectionClosedError:
#         print("ConnectionClosed")
#         pass

# async def on_close(websocket, close_code):
#     # code to handle a client closing the connection goes here
#     pass


# async def main():
#     async with serve(echo, "localhost", 789, process_request=on_close):
#         await asyncio.Future()  # run forever



# if __name__ == "__main__":
#     #websocket.enableTrace(True)
#     #asyncio.run(main())

