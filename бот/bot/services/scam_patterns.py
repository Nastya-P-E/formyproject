from dataclasses import dataclass


@dataclass(frozen=True)
class ScamTemplate:
    id: str
    category: str
    weight: float
    text: str
    keywords: tuple[str, ...] = ()


TEMPLATES: list[ScamTemplate] = [
    ScamTemplate(
        id="prize_win",
        category="Приз/выигрыш",
        weight=0.9,
        text="Поздравляем вы выиграли приз перейдите по ссылке чтобы получить деньги",
        keywords=("выиграли", "приз", "поздравляем"),
    ),
    ScamTemplate(
        id="prize_lottery",
        category="Приз/выигрыш",
        weight=0.9,
        text="Ваш номер стал победителем в розыгрыше лотереи заберите выигрыш срочно",
        keywords=("победител", "розыгрыш", "лотере"),
    ),
    ScamTemplate(
        id="free_money",
        category="Приз/выигрыш",
        weight=0.85,
        text="Получите бесплатные деньги на карту просто заполните форму",
        keywords=("бесплатн", "деньги", "карт"),
    ),

    ScamTemplate(
        id="acc_blocked",
        category="Блокировка аккаунта",
        weight=0.85,
        text="Ваш аккаунт заблокирован подтвердите данные чтобы восстановить доступ",
        keywords=("заблокирован", "подтверд", "восстанов"),
    ),
    ScamTemplate(
        id="acc_suspend",
        category="Блокировка аккаунта",
        weight=0.85,
        text="Подозрительная активность в вашем аккаунте войдите по ссылке для проверки",
        keywords=("подозрительн", "активност", "войд"),
    ),
    ScamTemplate(
        id="bank_block",
        category="Блокировка аккаунта",
        weight=0.9,
        text="Ваша банковская карта заблокирована позвоните по номеру для разблокировки",
        keywords=("карт", "заблокирован", "позвон"),
    ),

    ScamTemplate(
        id="urgent_transfer",
        category="Срочный перевод",
        weight=0.9,
        text="Срочно переведите деньги на этот счёт иначе будет плохо",
        keywords=("срочно", "перевед", "счёт"),
    ),
    ScamTemplate(
        id="relative_trouble",
        category="Срочный перевод",
        weight=0.95,
        text="Мама я попал в беду срочно переведи денег на этот номер",
        keywords=("мама", "папа", "попал", "перевед", "денег"),
    ),
    ScamTemplate(
        id="help_friend",
        category="Срочный перевод",
        weight=0.85,
        text="Привет это я у меня проблема нужно срочно занять денег переведи на карту",
        keywords=("занять", "перевед", "карт", "срочно"),
    ),

    ScamTemplate(
        id="crypto_invest",
        category="Инвестиции",
        weight=0.8,
        text="Инвестируйте в криптовалюту и получайте гарантированный доход каждый день",
        keywords=("инвест", "крипт", "гарантирован", "доход"),
    ),
    ScamTemplate(
        id="fast_profit",
        category="Инвестиции",
        weight=0.85,
        text="Заработайте в два раза больше за неделю без риска вложите средства",
        keywords=("заработ", "без риск", "влож"),
    ),

    ScamTemplate(
        id="card_verify",
        category="Кража данных",
        weight=0.95,
        text="Для подтверждения личности введите номер карты срок действия и cvv код",
        keywords=("cv", "карт", "подтверд", "срок"),
    ),
    ScamTemplate(
        id="sms_code",
        category="Кража данных",
        weight=0.95,
        text="Сообщите код из смс который пришёл вам для подтверждения операции",
        keywords=("код", "смс", "сообщ"),
    ),
    ScamTemplate(
        id="passport_scan",
        category="Кража данных",
        weight=0.8,
        text="Отправьте скан паспорта для верификации личности",
        keywords=("скан", "паспорт", "верификац"),
    ),

    ScamTemplate(
        id="easy_job",
        category="Фейковая работа",
        weight=0.75,
        text="Работа из дома без опыта два часа в день высокая оплата каждый день",
        keywords=("работ", "дом", "опыт", "оплат"),
    ),
    ScamTemplate(
        id="job_deposit",
        category="Фейковая работа",
        weight=0.9,
        text="Для начала работы внесите небольшой депозит он вернётся с первой зарплатой",
        keywords=("депозит", "работ", "зарплат"),
    ),

    ScamTemplate(
        id="romance",
        category="Романтический скам",
        weight=0.8,
        text="Я познакомился с вами и влюбился пришлите денег на билет чтобы приехать",
        keywords=("влюб", "билет", "приеха", "денег"),
    ),
]


import re

REGEX_RULES = [
    (
        "url_shortener_redirect",
        "Подозрительная ссылка",
        0.6,
        re.compile(r"https?://(?:bit\.ly|tinyurl\.com|t\.me/\+|goo\.gl|is\.gd)/", re.I),
        "Сокращённая ссылка — часто скрывает фишинг",
    ),
    (
        "crypto_wallet",
        "Крипта",
        0.7,
        re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
        "Адрес крипто-кошелька в сообщении",
    ),
    (
        "card_number",
        "Кража данных",
        0.75,
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "Похоже на номер банковской карты",
    ),
    (
        "phone_ru",
        "Реквизиты",
        0.3,
        re.compile(r"(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"),
        "Телефонный номер",
    ),
    (
        "urgency_word",
        "Срочность",
        0.4,
        re.compile(r"\b(?:срочно|немедленно|сейчас же|только сегодня|последний шанс)\b", re.I),
        "Слово-маркер срочности",
    ),
]