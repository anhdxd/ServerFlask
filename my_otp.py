# Download the helper library from https://www.twilio.com/docs/python/install

from twilio.rest import Client

import telegram

url_tele = "https://api.telegram.org/bot6179912911:AAGMg3od1lNvVQunmpyWRkUOe77mkjNWa1s/sendMessage" #sendMessage
telebot_token = '6179912911:AAGMg3od1lNvVQunmpyWRkUOe77mkjNWa1s'
# Send message to bot telegram
def send_text_bot(text):
    #telegram bot python version 13.15
    lst_id = [916485452, 1042979764, 5176914547]
    bot = telegram.Bot(token=telebot_token)
    for chat_id in lst_id:
      bot.send_message(chat_id=chat_id, text=text)

def send_text_phone(text, phone_number):
    # test send with telegram
    send_text_bot(text)
    return
    # end test telegram

    account_sid = ""
    auth_token = ""
    client = Client(account_sid, auth_token)
    message = client.messages.create(
      body=text,
      from_="+13184966970",
      to="+84836206984"
    )
    print(message.sid)

#send_text_phone('1234', '0836206984')
# def send_text_phone(text, phone_number):
#     access_token = 'eVA2GW0VRuQomn8W2a4PmKAzkmF-zipU'
#     # url = f'https://api.speedsms.vn/index.php/user/info?access-token={access_token}'

#     headers = {
#         'Content-Type': 'application/x-www-form-urlencoded',
#     }

#     # response = requests.request('GET', url, headers=headers)
#     # print(response.text)

#     print('----------------------- Send OTP-----------------------')
#     # /** API gửi SMS */
#     #
#     sms_url = f'https://api.speedsms.vn/index.php/sms/send?access-token={access_token}&to={phone_number}&content=OTP android của bạn là {text}&type=2&sender=0866726001'
#     response = requests.request('GET', sms_url, headers=headers)
#     print(response.text)

# def send_text_phone(text, phone_number):
#     access_token = 'eVA2GW0VRuQomn8W2a4PmKAzkmF-zipU'
#     url = f'http://rest.esms.vn/MainService.svc/json/SendMultipleMessage_V4_post_json/'

#     headers = {
#         'Content-Type': 'application/json',
#         'Cookie':'ASP.NET_SessionId=4zhxi2iaxcyqrlooff2u3vj1',
#     }
#     # random id
#     id = random.randint(100, 1000000)

#     data_json = {
#         "ApiKey": "9404B4FC8D123CDFC32C9EA68EF09E",
#         "Content": f'OTP android app:{text}',
#         "Phone": f'{phone_number}',
#         "SecretKey": "6EB02E3EE9658A76D93742FA1C9157",
#         "SmsType": "8",
#         "SandBox":0,
#         "RequestId":id,
#         "CallbackUrl":0
#     }

#     response = requests.request('POST', url, headers=headers, json=data_json)
#     print(response.text)



#send_text_phone('1234', '0836206984')
