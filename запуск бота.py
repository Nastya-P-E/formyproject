import telebot

bot = telebot.TeleBot("8803552394:AAE7kTtp7B9usOHYPi_HiYUv9uDXnnEzmLc")

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Привет! Я бот, который помогает распознать мошенников. Чем я могу тебе помочь?")

@bot.message_handler(commands=['scanmessage'])
def scan_work(message):
    bot.reply_to(message, "Пришлите свое сообщение, пожалуйста")

@bot.message_handler(commands=['help'])
def send_help(message):
    bot.reply_to(message, "Напиши /start для начала работы.")

bot.infinity_polling()
