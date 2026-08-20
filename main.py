"""
Telegram-бот для уведомлений о выводах средств с аккаунтов Bybit.

Бот периодически опрашивает Bybit API (эндпоинт "Get Withdrawal Records")
для каждого из настроенных аккаунтов и присылает сообщение в Telegram,
как только появляется новая запись о выводе.

Настройка через переменные окружения — см. .env.example и README.md.
"""

import os
import sys
import time
import json
import hmac
import hashlib
import logging
import threading
import http.server
from urllib.parse import urlencode
from dataclasses import dataclass
from typing import Optional

import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("bybit-withdraw-bot")

BYBIT_BASE_URL = os.environ.get("BYBIT_BASE_URL", "https://api.bybit.com")
WITHDRAW_ENDPOINT = "/v5/asset/withdraw/query-record"

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "60"))
STATE_FILE = os.environ.get("STATE_FILE", "/data/state.json")
RECV_WINDOW = "5000"

# сколько последних withdrawId по каждому аккаунту хранить для дедупликации
MAX_SEEN_IDS_PER_ACCOUNT = 200


@dataclass
class BybitAccount:
    key: str
    name: str
    api_key: str
    api_secret: str


def load_accounts() -> list[BybitAccount]:
    accounts = []
    i = 1
    while True:
        api_key = os.environ.get(f"BYBIT_API_KEY_{i}")
        api_secret = os.environ.get(f"BYBIT_API_SECRET_{i}")
        if not api_key or not api_secret:
            break
        name = os.environ.get(f"ACCOUNT_{i}_NAME", f"Аккаунт {i}")
        accounts.append(
            BybitAccount(key=f"account_{i}", name=name, api_key=api_key, api_secret=api_secret)
        )
        i += 1
    return accounts


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Не удалось прочитать файл состояния %s: %s", STATE_FILE, e)
    return {}


def save_state(state: dict) -> None:
    try:
        os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
        tmp_path = STATE_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, STATE_FILE)
    except OSError as e:
        log.error("Не удалось сохранить файл состояния %s: %s", STATE_FILE, e)


def bybit_signed_get(api_key: str, api_secret: str, endpoint: str, params: dict) -> dict:
    ts = str(int(time.time() * 1000))
    query_string = urlencode(params)
    sign_payload = ts + api_key + RECV_WINDOW + query_string
    signature = hmac.new(
        api_secret.encode("utf-8"), sign_payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    headers = {
        "X-BAPI-API-KEY": api_key,
        "X-BAPI-SIGN": signature,
        "X-BAPI-SIGN-TYPE": "2",
        "X-BAPI-TIMESTAMP": ts,
        "X-BAPI-RECV-WINDOW": RECV_WINDOW,
        # Bybit's CDN (CloudFront/WAF) blocks requests whose User-Agent
        # identifies them as a generic scripting library (e.g. the default
        # "python-requests/x.y.z"). A browser-like User-Agent avoids that
        # bot-detection block, which otherwise returns a bare 403 Forbidden
        # before the request ever reaches Bybit's backend.
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json",
    }
    url = f"{BYBIT_BASE_URL}{endpoint}"
    if query_string:
        url += f"?{query_string}"
    resp = requests.get(url, headers=headers, timeout=20)
    if resp.status_code >= 400:
        # Diagnostic detail so we can tell a CDN/WAF block (CloudFront, etc.)
        # apart from a real Bybit API error, instead of just seeing a bare
        # "403 Forbidden" with no context.
        diag_headers = {
            k: v
            for k, v in resp.headers.items()
            if k.lower() in ("server", "via", "x-cache", "x-amz-cf-id", "x-amz-cf-pop", "cf-ray", "content-type")
        }
        log.error(
            "Bybit HTTP %s for %s | resp_headers=%s | body=%r",
            resp.status_code, url, diag_headers, resp.text[:500],
        )
    resp.raise_for_status()
    return resp.json()


def fetch_withdrawals(account: BybitAccount, limit: int = 20) -> list[dict]:
    data = bybit_signed_get(
        account.api_key,
        account.api_secret,
        WITHDRAW_ENDPOINT,
        {"limit": str(limit), "withdrawType": "2"},
    )
    ret_code = data.get("retCode")
    if ret_code != 0:
        raise RuntimeError(f"Bybit API error ({account.name}): retCode={ret_code} msg={data.get('retMsg')}")
    return data.get("result", {}).get("rows", []) or []


def format_withdrawal_message(account_name: str, row: dict) -> str:
    coin = row.get("coin", "?")
    chain = row.get("chain", "-")
    amount = row.get("amount", "?")
    status = row.get("status", "?")
    address = row.get("toAddress") or row.get("address") or "-"
    tag = row.get("tag")
    create_time_ms = row.get("createTime")
    withdraw_id = row.get("withdrawId", "?")
    tx_id = row.get("txID") or "-"

    time_str = "-"
    if create_time_ms:
        try:
            time_str = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(create_time_ms) / 1000)
            )
        except (ValueError, TypeError):
            pass

    lines = [
        f"🔔 <b>Вывод средств — {account_name}</b>",
        f"Сумма: <b>{amount} {coin}</b>",
        f"Сеть: {chain}",
        f"Статус: {status}",
        f"Адрес: <code>{address}</code>",
    ]
    if tag:
        lines.append(f"Тег/memo: <code>{tag}</code>")
    lines.append(f"Время: {time_str}")
    lines.append(f"Withdraw ID: <code>{withdraw_id}</code>")
    if tx_id and tx_id != "-":
        lines.append(f"TxID: <code>{tx_id}</code>")
    return "\n".join(lines)


async def check_withdrawals(context: ContextTypes.DEFAULT_TYPE) -> None:
    accounts: list[BybitAccount] = context.bot_data["accounts"]
    state: dict = context.bot_data["state"]
    chat_id = context.bot_data.get("chat_id")

    if not chat_id:
        log.warning("TELEGRAM_CHAT_ID не задан — пришлите /start боту, чтобы узнать chat_id.")
        return

    state_changed = False

    for account in accounts:
        try:
            rows = fetch_withdrawals(account)
        except Exception as e:
            log.error("Ошибка запроса к Bybit для %s: %s", account.name, e)
            continue

        acc_state = state.setdefault(account.key, {"seen_ids": []})
        seen_ids = set(acc_state.get("seen_ids", []))
        is_first_run = acc_state.get("initialized", False) is False

        new_rows = [r for r in rows if r.get("withdrawId") and r.get("withdrawId") not in seen_ids]

        if is_first_run:
            # При первом запуске просто запоминаем текущие записи, чтобы не
            # засыпать пользователя историей старых выводов.
            for r in rows:
                if r.get("withdrawId"):
                    seen_ids.add(r["withdrawId"])
            acc_state["initialized"] = True
            state_changed = True
            log.info(
                "%s: первичная инициализация, запомнено %d записей.",
                account.name,
                len(seen_ids),
            )
        elif new_rows:
            # Отправляем от старых к новым
            for row in reversed(new_rows):
                message = format_withdrawal_message(account.name, row)
                try:
                    await context.bot.send_message(
                        chat_id=chat_id, text=message, parse_mode="HTML"
                    )
                except Exception as e:
                    log.error("Не удалось отправить сообщение в Telegram: %s", e)
                seen_ids.add(row["withdrawId"])
            state_changed = True
            log.info("%s: отправлено %d новых уведомлений о выводе.", account.name, len(new_rows))

        # ограничиваем размер списка виденных id
        if len(seen_ids) > MAX_SEEN_IDS_PER_ACCOUNT:
            seen_ids = set(list(seen_ids)[-MAX_SEEN_IDS_PER_ACCOUNT:])
        acc_state["seen_ids"] = list(seen_ids)

    if state_changed:
        save_state(state)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    context.bot_data["chat_id"] = chat_id
    context.bot_data.setdefault("chat_ids_seen", set()).add(chat_id)
    accounts: list[BybitAccount] = context.bot_data["accounts"]
    names = "\n".join(f"• {a.name}" for a in accounts) if accounts else "(аккаунты не настроены)"
    await update.message.reply_text(
        "Бот запущен. Этот чат (id={}) выбран для уведомлений о выводах.\n\n"
        "Отслеживаемые аккаунты Bybit:\n{}\n\n"
        "Команда /status — проверить состояние.".format(chat_id, names)
    )
    if not TELEGRAM_CHAT_ID:
        log.info(
            "TELEGRAM_CHAT_ID не был задан в переменных окружения. "
            "Используется chat_id=%s из последнего /start. "
            "Рекомендуется зафиксировать его в переменной TELEGRAM_CHAT_ID.",
            chat_id,
        )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    accounts: list[BybitAccount] = context.bot_data["accounts"]
    chat_id = context.bot_data.get("chat_id")
    lines = [
        f"Отслеживается аккаунтов: {len(accounts)}",
        f"Интервал проверки: {POLL_INTERVAL_SECONDS} сек.",
        f"Уведомления идут в chat_id: {chat_id or 'не задан — отправьте /start'}",
    ]
    await update.message.reply_text("\n".join(lines))


def start_health_server() -> None:
    """Простой HTTP-сервер для health-check (нужен некоторым платформам,
    например Railway, чтобы считать сервис живым)."""
    port = os.environ.get("PORT")
    if not port:
        return

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    def run():
        server = http.server.HTTPServer(("0.0.0.0", int(port)), Handler)
        server.serve_forever()

    threading.Thread(target=run, daemon=True).start()
    log.info("Health-check сервер запущен на порту %s", port)


def main() -> None:
    if not TELEGRAM_BOT_TOKEN:
        log.error("Не задана переменная окружения TELEGRAM_BOT_TOKEN. Завершение работы.")
        sys.exit(1)

    accounts = load_accounts()
    if not accounts:
        log.error(
            "Не найдено ни одного аккаунта Bybit. "
            "Задайте BYBIT_API_KEY_1 / BYBIT_API_SECRET_1 и т.д. Завершение работы."
        )
        sys.exit(1)

    log.info("Настроено аккаунтов Bybit: %d", len(accounts))
    for a in accounts:
        log.info(" - %s (%s)", a.name, a.key)

    start_health_server()

    state = load_state()

    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    application.bot_data["accounts"] = accounts
    application.bot_data["state"] = state
    application.bot_data["chat_id"] = int(TELEGRAM_CHAT_ID) if TELEGRAM_CHAT_ID else None

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("status", cmd_status))

    application.job_queue.run_repeating(
        check_withdrawals, interval=POLL_INTERVAL_SECONDS, first=5
    )

    log.info("Бот запущен, интервал проверки %d сек.", POLL_INTERVAL_SECONDS)
    application.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
