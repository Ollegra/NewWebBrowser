import json
import logging.config
import os
import re
import sqlite3
import sys
from datetime import datetime
from urllib.parse import urlparse
import requests
from PyQt6.QtCore import (
    QUrl,
    QTimer,
    pyqtSignal,
    QThread,
    QStandardPaths,
    QByteArray,
    QBuffer,
    Qt,
    QSize,
)
from PyQt6.QtGui import QAction, QPixmap, QIcon, QColor, QPainter, QFont, QBrush
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile,
    QWebEngineUrlRequestInterceptor,
    QWebEngineUrlRequestInfo,
    QWebEngineScript,
    QWebEngineSettings,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage
from PyQt6.QtPrintSupport import QPrintDialog, QPrinter
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QTabWidget,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QToolBar,
    QStatusBar,
    QLineEdit,
    QFileDialog,
    QMenu,
    QListWidget,
    QInputDialog,
    QLabel,
    QDialog,
    QProgressBar,
    QTextEdit,
    QMessageBox,
    QListWidgetItem,
    QProgressDialog,
    QFormLayout,
    QComboBox,
    QGroupBox,
    QCheckBox,
    QScrollArea,
)
from config_loggin import logger_conf

logging.config.dictConfig(logger_conf)
logger = logging.getLogger("my_py_logger")
blocked_urls = []


class AdBlockRule:
    def __init__(self, rule_text):
        self.raw_rule = rule_text.strip()
        self.is_exception = self.raw_rule.startswith("@@")
        self.is_comment = self.raw_rule.startswith("!")
        self.is_html = "##" in self.raw_rule or "#@#" in self.raw_rule
        self.domain = None
        self.patterns = None
        self.options = {}
        self.safe_extensions = {
            ".ico",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".css",
            ".ttf",
            ".woff",
            ".woff2",
        }
        if not self.is_comment and self.raw_rule:
            self.parse_rule()

    def matches_url(self, url, source_url=""):
        if self.is_comment or self.is_html:
            return False
        url_parts = urlparse(url)
        # Проверяем расширение файла
        path = url_parts.path.lower()
        if any(path.endswith(ext) for ext in self.safe_extensions):
            return False
        # Проверяем домен
        if self.domain:
            domain_match = (
                url_parts.netloc.endswith(self.domain)
                or url_parts.netloc == self.domain
            )
            # Для рекламных доменов блокируем все
            if domain_match and self.is_advertising_domain():
                return True
            # Для обычных доменов проверяем путь
            elif domain_match:
                return self.matches_path(url_parts.path)
            return False

        return self.matches_path(url_parts.path)

    def is_advertising_domain(self):
        """Проверяет, является ли домен рекламным"""
        ad_domains = {
            "doubleclick.net",
            "googlesyndication.com",
            "adnxs.com",
            "advertising.com",
            "admob.com",
            "ads.yahoo.com",
        }
        return self.domain in ad_domains

    def matches_path(self, path):
        if not self.pattern:
            return False
        # Игнорируем запросы к корню сайта
        if path in ("/", ""):
            return False
        pattern = re.escape(self.pattern)
        pattern = pattern.replace(r"\\\*", ".*")
        pattern = pattern.replace(r"\\^", r"[^a-zA-Z0-9._-]")
        try:
            return bool(re.search(pattern, path))
        except re.error:
            return False

    def parse_rule(self):
        # Удаляем исключения
        rule = self.raw_rule[2:] if self.is_exception else self.raw_rule
        # Разбираем опции
        if "$" in rule:
            rule, options = rule.split("$", 1)
            self.parse_options(options)
        # Разбираем HTML-правила
        if self.is_html:
            if "##" in rule:
                self.domain, self.pattern = rule.split("##", 1)
            elif "#@#" in rule:
                self.domain, self.pattern = rule.split("#@#", 1)
                self.is_exception = True
        else:
            # Разбираем обычные правила
            self.pattern = rule
            # Извлекаем домен, если указан
            if self.pattern.startswith("||"):
                self.pattern = self.pattern[2:]
                domain_end = self.pattern.find("/")
                if domain_end == -1:
                    domain_end = len(self.pattern)
                self.domain = self.pattern[:domain_end]
                self.pattern = self.pattern[domain_end:]
            elif self.pattern.startswith("|"):
                self.pattern = self.pattern[1:]

    def parse_options(self, options_text):
        for option in options_text.split(","):
            if "=" in option:
                key, value = option.split("=", 1)
                self.options[key] = value
            else:
                self.options[option] = True


class AdBlockInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []
        # self.blocked_urls = []  # Для отладки
        self.load_default_rules()
        self.safe_domains = {
            "google.com",
            "googleapis.com",
            "gstatic.com",
            "github.com",
            "githubusercontent.com",
            "cdn.jsdelivr.net",
            "cloudflare.com",
            "jquery.com",
            "bootstrap.com",
        }
        logger.info("✅ AdBlock инициализирован с базовыми правилами")

    def load_default_rules(self):
        # МЯГКИЕ правила для блокировки только явной рекламы
        basic_rules = [
            # Только самые очевидные рекламные сети
            "||doubleclick.net/ads/",
            "||googlesyndication.com/pagead/",
            "||adnxs.com^$third-party",
            "||advertising.com^$third-party",
            # Явные рекламные пути
            "/ads/",
            "/advertisements/",
            "/banner/",
            "/popup/",
        ]
        # РАСШИРЕННЫЕ исключения для предотвращения блокировки контента
        exceptions = [
            # Основные сервисы
            "@@||google.com^",
            "@@||googleapis.com^",
            "@@||gstatic.com^",
            "@@||googleusercontent.com^",
            "@@||youtube.com^",
            "@@||ytimg.com^",
            "@@||github.com^",
            "@@||githubusercontent.com^",
            "@@||cdn.jsdelivr.net^",
            "@@||cdnjs.cloudflare.com^",
            "@@||cloudflare.com^",
            "@@||jquery.com^",
            "@@||bootstrap.com^",
            "@@||fontawesome.com^",
            "@@||fonts.googleapis.com^",
            "@@||fonts.gstatic.com^",
            "@@||ru2.elvenar.com^",
            "@@||ru0.elvenar.com^",
            "@@||ru15.forgeofempires.com^",
            "@@||ru0.forgeofempires.com^",
            # Ресурсы
            "@@/favicon.",
            "@@.css",
            "@@.js",
            "@@.png",
            "@@.jpg",
            "@@.jpeg",
            "@@.svg",
            "@@.gif",
            "@@.ico",
            "@@.woff",
            "@@.woff2",
            "@@.ttf",
            "@@.eot",
            # Популярные домены
            "@@||wikipedia.org^",
            "@@||stackoverflow.com^",
            "@@||reddit.com^",
            "@@||twitter.com^",
            "@@||facebook.com^",
            "@@||instagram.com^",
            "@@||linkedin.com^",
            "@@||discord.com^",
            "@@||telegram.org^",
            "@@||whatsapp.com^",
            "@@||ru2.elvenar.com^",
            "@@||ru0.elvenar.com^",
            "@@||ru15.forgeofempires.com^",
            "@@||ru0.forgeofempires.com^",
        ]
        self.parse_rules("\n".join(basic_rules + exceptions))
        # print("EasyList отключен для предотвращения блокировки контента")
        try:
            response = requests.get(
                "https://easylist.to/easylist/easylist.txt", timeout=5
            )
            if response.status_code == 200:
                self.parse_rules(response.text)
                # print("EasyList загружен успешно")
                logger.info("✅ EasyList загружен успешно")
        except Exception as e:
            # print(f"Ошибка загрузки EasyList: {e}")
            logger.error(f"🆘 Ошибка загрузки EasyList: {e}")

    def parse_rules(self, rules_text):
        for line in rules_text.splitlines():
            line = line.strip()
            if line and not line.startswith("!"):
                rule = AdBlockRule(line)
                if not rule.is_comment:
                    self.rules.append(rule)

    def interceptRequest(self, info):
        url = info.requestUrl().toString()
        url_parts = urlparse(url)
        # Пропускаем безопасные домены
        safe_domains_extended = self.safe_domains.union(
            {
                "youtube.com",
                "ytimg.com",
                "googleusercontent.com",
                "wikipedia.org",
                "stackoverflow.com",
                "reddit.com",
                "twitter.com",
                "facebook.com",
                "instagram.com",
                "linkedin.com",
                "discord.com",
                "telegram.org",
                "whatsapp.com",
                "fontawesome.com",
                "fonts.googleapis.com",
                "fonts.gstatic.com",
                "cdnjs.cloudflare.com",
                "elvenar.com",
                "forgeofempires.com",
                "ru2.elvenar.com",
                "ru0.elvenar.com",
                "ru15.forgeofempires.com",
                "ru0.forgeofempires.com",
            }
        )
        if any(url_parts.netloc.endswith(domain) for domain in safe_domains_extended):
            return
        # Пропускаем все статические ресурсы
        path = url_parts.path.lower()
        static_extensions = (
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".json",
            ".xml",
        )
        if "/favicon." in path or path.endswith(static_extensions):
            return
        # Пропускаем основные пути сайтов
        if path in ("/", "", "/index.html", "/home", "/main"):
            return
        # СНАЧАЛА проверяем исключения (приоритет)
        for rule in self.rules:
            if rule.is_exception and rule.matches_url(url):
                return
        # Проверяем блокирующие правила только для явной рекламы
        for rule in self.rules:
            if not rule.is_exception and not rule.is_html and rule.matches_url(url):
                # Дополнительная проверка - блокируем только явную рекламу
                if any(
                    ad_word in url.lower()
                    for ad_word in [
                        "/ads/",
                        "/ad/",
                        "/advertisement/",
                        "/banner/",
                        "/popup/",
                    ]
                ):
                    info.block(True)
                    blocked_urls.append(url)
                    # print(f"Заблокирован рекламный URL: {url}")
                    return

    def get_blocked_count(self):
        """Возвращает количество заблокированных URL"""
        return len(blocked_urls)

    def clear_blocked_stats(self):
        """Очищает статистику блокировки"""
        blocked_urls.clear()


class LegacyAdBlocker(QWebEngineUrlRequestInterceptor):
    """Старый класс AdBlocker для обратной совместимости"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.blocked_domains = {
            "googleads.g.doubleclick.net",
            "googlesyndication.com",
            "google-analytics.com",
            "facebook.com/tr",
            "ads.yahoo.com",
            "amazon-adsystem.com",
            "adsystem.amazon.com",
            "pagead2.googlesyndication.com",
            "googletagmanager.com",
            "googletagservices.com",
        }
        self.blocked_keywords = [
            "/ads/",
            "/ad/",
            "/banner/",
            "/popup/",
            "/advert/",
            "/adsystem/",
            "/googletag/",
            "/doubleclick/",
            "/analytics/",
            "/facebook.com/tr",
            "ads.js",
            "adsbygoogle",
            "googletagmanager",
            "googletagservices",
            "amazon-adsystem",
            "criteo",
            "outbrain",
            "taboola",
            "prebid",
        ]
        logger.info("LegacyAdBlocker инициализирован с базовыми правилами")

    def interceptRequest(self, info):
        url = info.requestUrl().toString().lower()
        # НЕ блокируем Google домены
        if any(
            google_domain in url
            for google_domain in [
                "google.com",
                "googleapis.com",
                "googleusercontent.com",
                "gstatic.com",
                "ru2.elvenar.com",
                "ru15.forgeofempires.com",
            ]
        ):
            return
        # Проверяем домены
        for domain in self.blocked_domains:
            if domain in url:
                info.block(True)
                return
        # Проверяем ключевые слова только для определенных типов ресурсов
        resource_type = info.resourceType()
        if resource_type in [
            QWebEngineUrlRequestInfo.ResourceType.ResourceTypeScript,
            QWebEngineUrlRequestInfo.ResourceType.ResourceTypeImage,
            QWebEngineUrlRequestInfo.ResourceType.ResourceTypeSubFrame,
        ]:
            for keyword in self.blocked_keywords:
                if keyword in url:
                    info.block(True)
                    return


class BrowserProfile:
    def __init__(self, profile_name="default"):
        self.profile_name = profile_name

        documents_path = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.AppDataLocation
        )

        self.profile_dir = os.path.join(documents_path, "profiles", profile_name)

        logger.info(
            f"📁 Профиль браузера инициализирован с директорией: {self.profile_dir}"
        )
        # print(f"📁 Путь к профилю: {self.profile_dir}")
        try:
            # Даже для "default" создаем именованный профиль
            # actual_profile_name = (
            #     f"ollegra_{profile_name}" if profile_name == "default" else profile_name
            # )
            self.profile = QWebEngineProfile(self.profile_name)
            self.profile.setPersistentStoragePath(self.profile_dir)

            # Настраиваем профиль
            # self.profile.setPersistentCookiesPolicy(
            #    QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
            # )
            # self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
            # self.profile.setCachePath(self.profile_dir)  # Кэш
            # self.profile.setPersistentStoragePath(
            #    self.profile_dir
            # )  # Данные (cookies, IndexedDB и т.д.)

            # //? ВАЖНО: Устанавливаем политику постоянного хранения
            # self.profile.setPersistentCookiesPolicy(
            #     QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
            # )

            # print(f"✅ Профиль '{self.profile_name}' создан с постоянным хранилищем")
            logger.info(
                f"⚡ Профиль '{self.profile_name}' создан с постоянным хранилищем"
            )

        except Exception as e:
            logger.error(f"🆘 Ошибка при создании профиля: {e}")
            # В случае ошибки создаем базовый профиль
            self.profile = QWebEngineProfile("fallback_profile")
            self.profile.setPersistentStoragePath(self.profile_dir)

        # Настройка загрузок
        self.profile.downloadRequested.connect(self.handle_download)
        # Путь для загрузок по умолчанию
        self.default_download_path = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DownloadLocation
        )
        # self.profile.cookieStore().cookieAdded.connect(self.handle_cookie)

        # Создаем AdBlock интерцептор для профиля
        self.interceptor = AdBlockInterceptor()
        self.profile.setUrlRequestInterceptor(self.interceptor)
        # Включаем поддержку плагинов и других функций
        self.setup_profile_settings()
        # Добавляем JavaScript для HTML-правил
        self.setup_html_filters()

    def handle_cookie(self, cookie):
        # print("cookieAdded triggered")
        name = bytes(cookie.name()).decode()
        value = bytes(cookie.value()).decode()
        domain = cookie.domain()
        logger.info(f"🍪 Cookie добавлен: {name} = {value} (домен: {domain})")

    def setup_profile_settings(self):
        """Настраивает параметры профиля"""
        settings = self.profile.settings()

        # ИСПРАВЛЕНО: Включаем все необходимые настройки для сохранения данных
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True
        )
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PdfViewerEnabled, True)
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.HyperlinkAuditingEnabled, True
        )
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.AutoLoadIconsForPage, True
        )
        settings.setAttribute(QWebEngineSettings.WebAttribute.TouchIconsEnabled, True)

        # КРИТИЧНО: Включаем локальное хранилище и базы данных
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True
        )
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True
        )

        # Увеличиваем лимиты хранения
        settings.setDefaultTextEncoding("utf-8")

        # Настройка языка и региона
        self.profile.setHttpAcceptLanguage("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")

        # ИСПРАВЛЕНО: Устанавливаем реалистичный User-Agent
        # self.profile.setHttpUserAgent(
        #    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        #    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        # )

        # Включаем кэширование
        self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
        self.profile.setHttpCacheMaximumSize(100 * 1024 * 1024)  # 100MB

        # print("✅ Настройки профиля применены для сохранения данных")
        logger.info("✅ Настройки профиля применены для сохранения данных")

        self.setup_html_filters()

    def setup_html_filters(self):
        """Настраивает фильтрацию HTML-элементов"""
        html_rules = """
        function applyAdBlockRules() {
            const rules = %s;
            rules.forEach(rule => {
                try {
                    const elements = document.querySelectorAll(rule);
                    elements.forEach(element => {
                        element.style.display = 'none';
                    });
                } catch (e) {
                    console.log('Invalid selector:', rule);
                }
            });
        }
        // Применяем правила при загрузке
        document.addEventListener('DOMContentLoaded', applyAdBlockRules);
        // Наблюдаем за изменениями
        const observer = new MutationObserver(applyAdBlockRules);
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
        """
        # Собираем HTML-селекторы из правил
        html_selectors = [
            rule.patterns
            for rule in self.interceptor.rules
            if rule.is_html and not rule.is_exception
        ]
        # Создаем и добавляем скрипт
        script = QWebEngineScript()
        script.setName("adblock_html")
        script.setSourceCode(html_rules % json.dumps(html_selectors))
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script.setRunsOnSubFrames(True)

        self.profile.scripts().insert(script)

    def add_custom_rule(self, rule_text):
        """Добавляет пользовательское правило"""
        rule = AdBlockRule(rule_text)
        if not rule.is_comment:
            self.interceptor.rules.append(rule)
        # Обновляем HTML-фильтры, если необходимо
        if rule.is_html:
            self.setup_html_filters()

    def handle_download(self, download):
        """Обрабатывает загрузки"""
        try:
            # Получаем путь для загрузок из настроек браузера
            parent_browser = self.get_parent_browser()
            if parent_browser:
                custom_download_path = parent_browser.db_manager.get_setting(
                    "download_path", ""
                )
                if custom_download_path and os.path.exists(custom_download_path):
                    self.default_download_path = custom_download_path
            # Создаем папку загрузок, если её нет
            os.makedirs(self.default_download_path, exist_ok=True)

            # Получаем имя файла
            filename = download.suggestedFileName()
            if not filename:
                filename = "download"
            # Полный путь для сохранения
            download_path = os.path.join(self.default_download_path, filename)

            # Проверяем, не существует ли уже файл с таким именем
            counter = 1
            original_path = download_path
            while os.path.exists(download_path):
                name, ext = os.path.splitext(original_path)
                download_path = f"{name}_{counter}{ext}"
                counter += 1
            # ВАЖНО: Устанавливаем путь ДО принятия загрузки
            try:
                download.setDownloadDirectory(os.path.dirname(download_path))
                download.setDownloadFileName(os.path.basename(download_path))
            except Exception as e:
                # print(f"Не удалось установить путь загрузки: {e}")
                logger.error(f"🆘 Не удалось установить путь загрузки: {e}")
                # Используем setPath для PyQt6
                try:
                    download.setPath(download_path)
                except Exception as e2:
                    # print(f"Не удалось установить путь через setPath: {e2}")
                    logger.error(f"🆘 Не удалось установить путь через setPath: {e2}")

            # Создаем окно загрузки
            parent_browser = self.get_parent_browser()
            if parent_browser:
                parent_browser.show_download_progress(download, filename, download_path)

            # Подключаем сигналы для отслеживания прогресса (правильные имена сигналов)
            try:
                # Пробуем разные варианты названий сигналов
                if hasattr(download, "downloadProgress"):
                    download.downloadProgress.connect(
                        lambda bytes_received,
                        bytes_total: self.update_download_progress(
                            download, bytes_received, bytes_total, filename
                        )
                    )
                elif hasattr(download, "receivedBytesChanged"):
                    download.receivedBytesChanged.connect(
                        lambda: self.update_download_progress_simple(download, filename)
                    )

                if hasattr(download, "finished"):
                    download.finished.connect(
                        lambda: self.download_finished(download, download_path)
                    )
                elif hasattr(download, "stateChanged"):
                    download.stateChanged.connect(
                        lambda state: self.download_state_changed(
                            download, state, download_path
                        )
                    )

            except Exception as e:
                # print(f"Не удалось подключить сигналы загрузки: {e}")
                logger.error(f"🆘 Не удалось подключить сигналы загрузки: {e}")

            # Принимаем загрузку
            download.accept()
            # print(f"✅ Загрузка начата: {filename} -> {download_path}")
            logger.info(f"✅ Загрузка начата: {filename} -> {download_path}")
            # Показываем уведомление о начале загрузки
            self.show_download_started(filename)
        except Exception as e:
            # print(f"Ошибка при обработке загрузки: {e}")
            logger.error(f"🆘 Ошибка при обработке загрузки: {e}")
            try:
                download.accept()  # Принимаем загрузку с настройками по умолчанию
            except Exception as e:
                # print(f"Не удалось принять загрузку: {e}")
                logger.error(f"🆘 Не удалось принять загрузку: {e}")

    def update_download_progress(self, download, bytes_received, bytes_total, filename):
        """Обновляет прогресс загрузки"""
        if bytes_total > 0:
            progress = int((bytes_received / bytes_total) * 100)

            # Обновляем строку состояния
            mb_received = bytes_received / (1024 * 1024)
            mb_total = bytes_total / (1024 * 1024)

            status_text = f"Загрузка {filename}: {progress}% ({mb_received:.1f}/{mb_total:.1f} MB)"

            # Находим родительское окно браузера
            parent_browser = self.get_parent_browser()
            if parent_browser:
                parent_browser.update_status_bar(status_text)

                # Показываем прогресс в прогресс-баре
                parent_browser.progress_bar.setValue(progress)
                parent_browser.progress_bar.setVisible(True)

    def update_download_progress_simple(self, download, filename):
        """Упрощенное обновление прогресса загрузки для PyQt6"""
        try:
            if hasattr(download, "receivedBytes") and hasattr(download, "totalBytes"):
                bytes_received = download.receivedBytes()
                bytes_total = download.totalBytes()

                # Находим родительское окно браузера
                parent_browser = self.get_parent_browser()

                if bytes_total > 0:
                    progress = int((bytes_received / bytes_total) * 100)

                    # Обновляем информацию о загрузке
                    if parent_browser and download in parent_browser.active_downloads:
                        parent_browser.active_downloads[download]["progress"] = progress

                        # Обновляем диалог прогресса
                        dialog = parent_browser.active_downloads[download].get("dialog")
                        if dialog:
                            dialog.setValue(progress)

                            # Обновляем текст диалога
                            mb_received = bytes_received / (1024 * 1024)
                            mb_total = bytes_total / (1024 * 1024)
                            dialog.setLabelText(
                                f"Загрузка: {filename}\n{progress}% ({mb_received:.1f}/{mb_total:.1f} MB)"
                            )

                    # Обновляем строку состояния
                    mb_received = bytes_received / (1024 * 1024)
                    mb_total = bytes_total / (1024 * 1024)

                    status_text = f"📥 Загрузка {filename}: {progress}% ({mb_received:.1f}/{mb_total:.1f} MB)"

                    if parent_browser:
                        parent_browser.update_status_bar(status_text)

                        # Показываем прогресс в прогресс-баре
                        parent_browser.progress_bar.setValue(progress)
                        parent_browser.progress_bar.setVisible(True)
                else:
                    # Показываем неопределенный прогресс
                    if parent_browser:
                        parent_browser.update_status_bar(f"📥 Загрузка {filename}...")
                        parent_browser.progress_bar.setVisible(True)
                        parent_browser.progress_bar.setRange(
                            0, 0
                        )  # Неопределенный прогресс
        except Exception as e:
            # print(f"Ошибка при обновлении прогресса: {e}")
            logger.error(f"🆘 Ошибка при обновлении прогресса: {e}")

    def download_state_changed(self, download, state, download_path):
        """Обработчик изменения состояния загрузки"""
        try:
            if hasattr(download, "DownloadState"):
                if state == download.DownloadState.DownloadCompleted:
                    self.download_finished(download, download_path)
                elif state == download.DownloadState.DownloadCancelled:
                    parent_browser = self.get_parent_browser()
                    if parent_browser:
                        parent_browser.progress_bar.setVisible(False)
                        parent_browser.update_status_bar("Загрузка отменена")
                elif state == download.DownloadState.DownloadInterrupted:
                    parent_browser = self.get_parent_browser()
                    if parent_browser:
                        parent_browser.progress_bar.setVisible(False)
                        parent_browser.update_status_bar("Загрузка прервана")
        except Exception as e:
            # print(f"Ошибка при обработке состояния загрузки: {e}")
            logger.error(f"🆘 Ошибка при обработке состояния загрузки: {e}")

    def download_finished(self, download, download_path):
        """Обрабатывает завершение загрузки"""
        parent_browser = self.get_parent_browser()

        # Получаем информацию о загрузке
        download_info = None
        if parent_browser and download in parent_browser.active_downloads:
            download_info = parent_browser.active_downloads[download]

        filename = download_info.get("filename", "файл") if download_info else "файл"

        # Закрываем диалог прогресса
        if download_info and "dialog" in download_info:
            dialog = download_info["dialog"]
            dialog.close()

        # Скрываем прогресс-бар
        if parent_browser:
            parent_browser.progress_bar.setVisible(False)

        # Удаляем из активных загрузок
        if parent_browser and download in parent_browser.active_downloads:
            del parent_browser.active_downloads[download]

        # Проверяем состояние загрузки
        try:
            download_state = download.state()

            # Проверяем, если файл существует - считаем загрузку успешной
            download_successful = False
            if os.path.exists(download_path) and os.path.getsize(download_path) > 0:
                download_successful = True

                # Дополнительная проверка для WebP файлов
                if download_path.lower().endswith(".webp"):
                    # print(f"✅ WebP файл загружен: {filename}")
                    logger.info(f"✅ WebP файл загружен: {filename}")

            if download_successful:
                # Успешная загрузка - показываем уведомление в статус-баре
                if parent_browser:
                    file_ext = os.path.splitext(filename)[1].lower()
                    if file_ext == ".webp":
                        parent_browser.update_status_bar(
                            f"✅ WebP изображение загружено: {filename}"
                        )
                    else:
                        parent_browser.update_status_bar(
                            f"✅ Загрузка завершена: {filename}"
                        )

                # Обновляем статус в менеджере загрузок
                if parent_browser and hasattr(parent_browser, "download_manager"):
                    url = getattr(download, "url", lambda: download_path)()
                    if hasattr(url, "toString"):
                        url = url.toString()
                    parent_browser.download_manager.download_completed(
                        url, download_path, True
                    )

                # Обновляем статус в базе данных
                if parent_browser:
                    try:
                        url = getattr(download, "url", lambda: download_path)()
                        if hasattr(url, "toString"):
                            url = url.toString()
                        parent_browser.db_manager.update_download_status(
                            url, download_path, "completed"
                        )
                    except Exception as e:
                        # print(f"Ошибка при обновлении статуса в БД: {e}")
                        logger.error(f"🆘 Ошибка при обновлении статуса в БД: {e}")

                # Показываем уведомление с информацией о формате
                if parent_browser:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Icon.Information)
                    msg.setWindowTitle("Загрузка завершена")

                    # Определяем тип файла
                    file_ext = os.path.splitext(filename)[1].lower()
                    if file_ext == ".webp":
                        msg.setText(f"WebP изображение загружено: {filename}")
                        msg.setInformativeText(
                            f"Сохранено в: {download_path}\n\nWebP - современный формат изображений с хорошим сжатием."
                        )
                    elif file_ext in [
                        ".jpg",
                        ".jpeg",
                        ".png",
                        ".gif",
                        ".bmp",
                        ".svg",
                        ".ico",
                        ".tiff",
                    ]:
                        msg.setText(f"Изображение загружено: {filename}")
                        msg.setInformativeText(
                            f"Сохранено в: {download_path}\n\nФормат: {file_ext.upper()}"
                        )
                    else:
                        msg.setText(f"Файл успешно загружен: {filename}")
                        msg.setInformativeText(f"Сохранено в: {download_path}")

                    # Кнопки действий
                    open_file_button = msg.addButton(
                        "Открыть файл", QMessageBox.ButtonRole.ActionRole
                    )
                    open_folder_button = msg.addButton(
                        "Открыть папку", QMessageBox.ButtonRole.ActionRole
                    )
                    show_downloads_button = msg.addButton(
                        "Менеджер загрузок", QMessageBox.ButtonRole.ActionRole
                    )
                    msg.addButton("OK", QMessageBox.ButtonRole.AcceptRole)

                    msg.exec()

                    # Обрабатываем нажатие кнопок
                    if msg.clickedButton() == open_file_button:
                        try:
                            import subprocess
                            import platform

                            system = platform.system()
                            if system == "Windows":
                                os.startfile(download_path)
                            elif system == "Darwin":  # macOS
                                subprocess.run(["open", download_path])
                            else:  # Linux
                                subprocess.run(["xdg-open", download_path])
                        except Exception as e:
                            # print(f"Ошибка при открытии файла: {e}")
                            logger.error(f"🆘 Ошибка при открытии файла: {e}")
                    elif msg.clickedButton() == open_folder_button:
                        self.open_download_folder(download_path)
                    elif msg.clickedButton() == show_downloads_button:
                        parent_browser.show_downloads()

            else:
                # Ошибка загрузки
                if parent_browser:
                    parent_browser.update_status_bar("❌ Ошибка при загрузке файла")

        except Exception as e:
            # print(f"Ошибка при проверке состояния загрузки: {e}")
            logger.error(f"🆘 Ошибка при проверке состояния загрузки: {e}")
            # Если не можем проверить состояние, проверяем наличие файла
            if os.path.exists(download_path) and os.path.getsize(download_path) > 0:
                if parent_browser:
                    parent_browser.update_status_bar(
                        f"✅ Загрузка завершена: {filename}"
                    )
            else:
                if parent_browser:
                    parent_browser.update_status_bar("❌ Ошибка при загрузке файла")

    def open_download_folder(self, file_path):
        """Открывает папку с загруженным файлом"""
        try:
            import subprocess
            import platform

            system = platform.system()
            if system == "Windows":
                subprocess.run(["explorer", "/select,", file_path])
            elif system == "Darwin":  # macOS
                subprocess.run(["open", "-R", file_path])
            else:  # Linux
                subprocess.run(["xdg-open", os.path.dirname(file_path)])
        except Exception as e:
            # print(f"Ошибка при открытии папки: {e}")
            logger.error(f"🆘 Ошибка при открытии папки: {e}")
            # Альтернативный способ - открыть только папку
            try:
                import webbrowser

                webbrowser.open(f"file://{os.path.dirname(file_path)}")
            except Exception as e2:
                # print(f"Альтернативный способ тоже не сработал: {e2}")
                logger.error(f"🆘 Альтернативный способ тоже не сработал: {e2}")

    def show_download_started(self, filename):
        """Показывает уведомление о начале загрузки"""
        parent_browser = self.get_parent_browser()
        if parent_browser:
            parent_browser.update_status_bar(f"📥 Начата загрузка: {filename}")

    def get_parent_browser(self):
        """Находит родительское окно браузера"""
        # Ищем среди открытых окон главное окно браузера
        for widget in QApplication.topLevelWidgets():
            if hasattr(widget, "update_status_bar") and hasattr(
                widget, "active_downloads"
            ):
                return widget
        return None

    def get_profile(self):
        """Возвращает профиль WebEngine"""
        return self.profile

    def set_adblock_enabled(self, enabled):
        """Включает/выключает AdBlock для профиля"""
        if enabled:
            self.profile.setUrlRequestInterceptor(self.interceptor)
        else:
            self.profile.setUrlRequestInterceptor(None)

    def get_adblock_stats(self):
        """Возвращает статистику блокировки"""
        return self.interceptor.get_blocked_count()

    def clear_adblock_stats(self):
        """Очищает статистику блокировки"""
        self.interceptor.clear_blocked_stats()

    def backup_profile_data(self):
        """Создает резервную копию данных профиля"""
        try:
            import shutil

            backup_dir = os.path.join(self.profile_dir, "backup")
            os.makedirs(backup_dir, exist_ok=True)

            # Копируем важные файлы
            for file_pattern in [
                "Cookies",
                "Local Storage",
                "Session Storage",
                "IndexedDB",
            ]:
                source_path = os.path.join(self.profile_dir, file_pattern)
                if os.path.exists(source_path):
                    if os.path.isdir(source_path):
                        shutil.copytree(
                            source_path,
                            os.path.join(backup_dir, file_pattern),
                            dirs_exist_ok=True,
                        )
                    else:
                        shutil.copy2(source_path, backup_dir)

            # print(f"✅ Резервная копия профиля создана: {backup_dir}")
            logger.info(f"✅ Резервная копия профиля создана: {backup_dir}")
            return backup_dir
        except Exception as e:
            # print(f"❌ Ошибка при создании резервной копии: {e}")
            logger.error(f"❌ Ошибка при создании резервной копии: {e}")
            return None

    def get_profile_info(self):
        """Возвращает информацию о профиле"""
        info = {
            "name": self.profile_name,
            "path": self.profile_dir,
            "cache_path": self.profile.cachePath(),
            "persistent_storage_path": self.profile.persistentStoragePath(),
            "cookies_policy": self.profile.persistentCookiesPolicy(),
            "cache_type": self.profile.httpCacheType(),
            "cache_max_size": self.profile.httpCacheMaximumSize(),
        }
        return info


class DatabaseManager:
    def __init__(self, db_path="browser_data.db"):
        self.db_path = db_path
        try:
            self.init_database()

        except Exception as e:
            logger.error("🆘 Ошибка при инициализации базы данных: %s", e)
            logger.info("🚩 Попытка восстановить базу данных...")
            self.repair_database()

    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    title TEXT,
                    icon BLOB,
                    visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bookmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    title TEXT,
                    icon BLOB,
                    is_favorite BOOLEAN DEFAULT 0,
                    added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS downloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    file_path TEXT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'downloading'
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            # Миграция базы данных - добавляем отсутствующие колонки
            # self.migrate_database(cursor)
            conn.commit()
            logger.info("✅ Database инициализирована успешно")

    def migrate_database(self, cursor):
        """Выполняет миграцию базы данных для обновления схемы"""
        try:
            # Проверяем, есть ли колонка added_time в таблице bookmarks
            cursor.execute("PRAGMA table_info(bookmarks)")
            columns = [column[1] for column in cursor.fetchall()]

            if "added_time" not in columns:
                logger.info("✅ Добавляем колонку added_time в таблицу bookmarks...")
                cursor.execute("""
                    ALTER TABLE bookmarks 
                    ADD COLUMN added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                """)

                # Обновляем существующие записи
                cursor.execute("""
                    UPDATE bookmarks 
                    SET added_time = CURRENT_TIMESTAMP 
                    WHERE added_time IS NULL
                """)
                logger.info("✅ Миграция bookmarks завершена!")

            # Добавляем колонку icon для bookmarks
            if "icon" not in columns:
                logger.info("✅ Добавляем колонку icon в таблицу bookmarks...")
                cursor.execute("""
                    ALTER TABLE bookmarks 
                    ADD COLUMN icon BLOB
                """)

            # Добавляем колонку is_favorite для bookmarks
            if "is_favorite" not in columns:
                logger.info("✅ Добавляем колонку is_favorite в таблицу bookmarks...")
                cursor.execute("""
                    ALTER TABLE bookmarks 
                    ADD COLUMN is_favorite BOOLEAN DEFAULT 0
                """)

            # Проверяем таблицу history
            cursor.execute("PRAGMA table_info(history)")
            history_columns = [column[1] for column in cursor.fetchall()]

            # Добавляем колонку icon для history
            if "icon" not in history_columns:
                logger.info("✅ Добавляем колонку icon в таблицу history...")
                cursor.execute("""
                    ALTER TABLE history 
                    ADD COLUMN icon BLOB
                """)

            # Добавляем колонку visit_time для history (если её нет)
            if "visit_time" not in history_columns:
                logger.info("✅ Добавляем колонку visit_time в таблицу history...")
                cursor.execute("""
                    ALTER TABLE history 
                    ADD COLUMN visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                """)

                # Обновляем существующие записи с текущим временем
                cursor.execute("""
                    UPDATE history 
                    SET visit_time = datetime('now', 'localtime') 
                    WHERE visit_time IS NULL
                """)

        except sqlite3.Error as e:
            logger.error(f"🆘 Ошибка при миграции базы данных: {e}")
            # Если миграция не удалась, пересоздаем таблицы
            try:
                cursor.execute("DROP TABLE IF EXISTS bookmarks")
                cursor.execute("""
                    CREATE TABLE bookmarks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT NOT NULL,
                        title TEXT,
                        icon BLOB,
                        is_favorite BOOLEAN DEFAULT 0,
                        added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute("DROP TABLE IF EXISTS history")
                cursor.execute("""
                    CREATE TABLE history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT NOT NULL,
                        title TEXT,
                        icon BLOB,
                        visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                logger.info("✅ Таблицы пересозданы с поддержкой иконок!")
            except sqlite3.Error as e2:
                logger.error(f"🆘 Критическая ошибка при пересоздании таблиц: {e2}")

    def icon_to_blob(self, icon):
        """Конвертирует QIcon в BLOB для хранения в базе данных"""
        if icon and not icon.isNull():
            pixmap = icon.pixmap(16, 16)
            byte_array = QByteArray()
            buffer = QBuffer(byte_array)
            buffer.open(QBuffer.OpenModeFlag.WriteOnly)
            pixmap.save(buffer, "PNG")
            return byte_array.data()
        return None

    def blob_to_icon(self, blob_data):
        """Конвертирует BLOB обратно в QIcon"""
        if blob_data:
            pixmap = QPixmap()
            pixmap.loadFromData(blob_data)
            return QIcon(pixmap)
        return QIcon()

    def add_history(self, url, title, icon=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            icon_blob = self.icon_to_blob(icon) if icon else None

            try:
                # Пытаемся вставить с текущим временем
                cursor.execute(
                    "INSERT INTO history (url, title, icon, visit_time) VALUES (?, ?, ?, datetime('now', 'localtime'))",
                    (url, title, icon_blob),
                )
            except sqlite3.OperationalError as e:
                if "no such column: visit_time" in str(e):
                    # Если колонки visit_time нет, используем старый формат
                    cursor.execute(
                        "INSERT INTO history (url, title, icon) VALUES (?, ?, ?)",
                        (url, title, icon_blob),
                    )
                else:
                    raise e

            conn.commit()

    def update_history_icon(self, url, icon):
        """Обновляет иконку для последней записи с данным URL в истории"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            icon_blob = self.icon_to_blob(icon) if icon else None
            try:
                # Обновляем иконку для последней записи с этим URL
                cursor.execute(
                    "UPDATE history SET icon = ? WHERE url = ? AND id = (SELECT id FROM history WHERE url = ? ORDER BY visit_time DESC LIMIT 1)",
                    (icon_blob, url, url),
                )
                conn.commit()
            except sqlite3.OperationalError:
                # Если структура таблицы старая, обновляем без учета времени
                cursor.execute(
                    "UPDATE history SET icon = ? WHERE url = ? AND id = (SELECT MAX(id) FROM history WHERE url = ?)",
                    (icon_blob, url, url),
                )
                conn.commit()

    def get_history(self, limit=100):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT url, title, icon, visit_time FROM history ORDER BY visit_time DESC LIMIT ?",
                    (limit,),
                )
                return cursor.fetchall()
            except sqlite3.OperationalError as e:
                if "no such column: visit_time" in str(e):
                    # Если нет колонки visit_time, используем id с текущим временем
                    print(
                        "Колонка visit_time не найдена, используем резервный запрос..."
                    )
                    try:
                        cursor.execute(
                            "SELECT url, title, icon, datetime('now', 'localtime') as visit_time FROM history ORDER BY id DESC LIMIT ?",
                            (limit,),
                        )
                        return cursor.fetchall()
                    except sqlite3.OperationalError:
                        # Если и icon нет, то обходимся без неё
                        cursor.execute(
                            "SELECT url, title, NULL as icon, datetime('now', 'localtime') as visit_time FROM history ORDER BY id DESC LIMIT ?",
                            (limit,),
                        )
                        return cursor.fetchall()
                elif "no such column: icon" in str(e):
                    # Если нет колонки icon, но есть visit_time
                    logger.warning(
                        "🚩 Колонка icon не найдена, используем резервный запрос..."
                    )
                    cursor.execute(
                        "SELECT url, title, NULL as icon, visit_time FROM history ORDER BY visit_time DESC LIMIT ?",
                        (limit,),
                    )
                    return cursor.fetchall()
                else:
                    raise e

    def add_bookmark(self, url, title, icon=None, is_favorite=False):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            icon_blob = self.icon_to_blob(icon) if icon else None
            cursor.execute(
                "INSERT INTO bookmarks (url, title, icon, is_favorite) VALUES (?, ?, ?, ?)",
                (url, title, icon_blob, is_favorite),
            )
            conn.commit()

    def get_bookmarks(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT url, title, icon, is_favorite, added_time FROM bookmarks ORDER BY added_time DESC"
                )
                return cursor.fetchall()
            except sqlite3.OperationalError as e:
                if "no such column" in str(e):
                    # Пытаемся получить закладки без отсутствующих колонок
                    logger.warning("🚩 Используем резервный запрос для закладок...")
                    cursor.execute(
                        "SELECT url, title, NULL as icon, 0 as is_favorite, 'Unknown' as added_time FROM bookmarks ORDER BY id DESC"
                    )
                    return cursor.fetchall()
                else:
                    raise e

    def get_favorites(self):
        """Получает список избранных закладок"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT url, title, icon FROM bookmarks WHERE is_favorite = 1 ORDER BY added_time DESC"
                )
                return cursor.fetchall()
            except sqlite3.OperationalError:
                return []

    def toggle_favorite(self, url):
        """Переключает статус избранного для закладки"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "UPDATE bookmarks SET is_favorite = NOT is_favorite WHERE url = ?",
                    (url,),
                )
                conn.commit()
                return True
            except sqlite3.OperationalError:
                return False

    def remove_bookmark(self, url):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM bookmarks WHERE url = ?", (url,))
            conn.commit()

    def save_setting(self, key, value):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()

    def get_setting(self, key, default=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            result = cursor.fetchone()
            return result[0] if result else default

    def clear_history(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM history")
            conn.commit()

    def add_download(self, url, file_path, status="downloading"):
        """Добавляет загрузку в базу данных"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO downloads (url, file_path, status) VALUES (?, ?, ?)",
                (url, file_path, status),
            )
            conn.commit()

    def get_downloads(self):
        """Получает список загрузок"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT url, file_path, start_time, status FROM downloads ORDER BY start_time DESC"
                )
                return cursor.fetchall()
            except sqlite3.OperationalError as e:
                if "no such column" in str(e):
                    logger.warning("🚩 Используем резервный запрос для загрузок...")
                    cursor.execute(
                        "SELECT url, file_path, 'Unknown' as start_time, 'completed' as status FROM downloads ORDER BY id DESC"
                    )
                    return cursor.fetchall()
                else:
                    raise e

    def update_download_status(self, url, file_path, status):
        """Обновляет статус загрузки"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE downloads SET status = ? WHERE url = ? AND file_path = ?",
                (status, url, file_path),
            )
            conn.commit()

    def clear_all_data(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM history")
            cursor.execute("DELETE FROM bookmarks")
            cursor.execute("DELETE FROM downloads")
            conn.commit()

    def recreate_database(self):
        """Пересоздает базу данных с нуля"""
        try:
            # Удаляем файл базы данных
            if os.path.exists(self.db_path):
                os.remove(self.db_path)

            # Создаем новую базу данных
            self.init_database()
            logger.info("✅ База данных пересоздана успешно!")

        except Exception as e:
            logger.error(f"🆘 Ошибка при пересоздании базы данных: {e}")

    def repair_database(self):
        """Пытается исправить проблемы с базой данных"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Проверяем целостность
                cursor.execute("PRAGMA integrity_check")
                result = cursor.fetchone()

                if result[0] != "ok":
                    logger.warning("Обнаружены проблемы с целостностью базы данных")
                    self.recreate_database()
                    return False

                # Проверяем схему и добавляем отсутствующие колонки
                self.migrate_database(cursor)
                conn.commit()

                logger.info("✅ База данных проверена и исправлена!")
                return True

        except Exception as e:
            logger.error(f"🆘 Ошибка при проверке базы данных: {e}")
            self.recreate_database()
            return False


class BrowserTab(QWidget):
    urlChanged = pyqtSignal(str)
    titleChanged = pyqtSignal(str)
    loadProgress = pyqtSignal(int)
    iconChanged = pyqtSignal(QIcon)
    zoomChanged = pyqtSignal(float)

    def __init__(self, url="https://www.google.com", profile=None):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.web_view = QWebEngineView()
        logger.info(f"✅BrowserTab initialized with URL: {url}")

        # Устанавливаем профиль для вкладки
        if profile:
            try:
                page = QWebEnginePage(profile, self)
                logger.info("✅ QWebEnginePage создана успешно")
                self.web_view.setPage(page)
            except Exception as e:
                logger.error(f"🆘 Ошибка при установке профиля для вкладки: {e}")

        self.layout.addWidget(self.web_view)

        self.web_view.urlChanged.connect(self.handle_url_changed)
        self.web_view.titleChanged.connect(self.handle_title_changed)
        self.web_view.loadProgress.connect(
            lambda progress: self.loadProgress.emit(progress)
        )
        self.web_view.iconChanged.connect(self.handle_icon_changed)

        # Отслеживание масштаба
        self.current_zoom = 1.0
        self.web_view.page().zoomFactorChanged.connect(self.on_zoom_changed)

        # Контекстное меню
        self.web_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.web_view.customContextMenuRequested.connect(self.show_context_menu)

        # Отслеживание наведения мыши на ссылки
        self.web_view.page().linkHovered.connect(self.on_link_hovered)

        # Включаем обработку колесика мыши для масштабирования
        self.web_view.wheelEvent = self.handle_wheel_event

        # Проверяем, что url является строкой
        if isinstance(url, str) and url:
            self.web_view.load(QUrl(url))
        else:
            # Загружаем Google по умолчанию
            self.web_view.load(QUrl("https://www.google.com"))

    def is_alive(self, obj):
        try:
            # Попытка доступа к методу для проверки
            bool(obj)
        except RuntimeError:
            return False
        return True

    def handle_url_changed(self, url):
        if self.is_alive(self):
            self.urlChanged.emit(url.toString())

    def handle_title_changed(self, title):
        if self.is_alive(self):
            self.titleChanged.emit(title)

    def handle_icon_changed(self, icon):
        if self.is_alive(self):
            self.iconChanged.emit(icon)

    def navigate_to_url(self, url):
        # Проверяем, что url является строкой
        if not isinstance(url, str):
            logger.error(f"🆘 Ошибка: URL не является строкой: {url}")
            return

        # Убираем пробелы
        url = url.strip()

        if not url:
            url = "https://www.google.com"
        elif not url.startswith(("http://", "https://")):
            if url.startswith("www.") or "." in url:
                url = "https://" + url
            else:
                url = f"https://www.google.com/search?q={url}"

        try:
            self.web_view.load(QUrl(url))
        except Exception as e:
            # print(f"Ошибка при загрузке URL {url}: {e}")
            logger.error(f"🆘 Error loading URL {url}: {e}")
            # Загружаем Google в случае ошибки
            self.web_view.load(QUrl("https://www.google.com"))

    def get_current_url(self):
        try:
            return self.web_view.url().toString()
        except Exception as e:
            # print(f"Ошибка при обработке загрузки: {e}")
            logger.error(f"🆘 Ошибка при получении текущего URL: {e}")
            return ""

    def get_current_title(self):
        try:
            return self.web_view.title()
        except:
            return "Новая вкладка"

    def get_current_icon(self):
        try:
            return self.web_view.icon()
        except:
            return QIcon()

    def reload(self):
        self.web_view.reload()

    def back(self):
        self.web_view.back()

    def forward(self):
        self.web_view.forward()

    def stop(self):
        self.web_view.stop()

    def on_zoom_changed(self, zoom_factor):
        """Обработчик изменения масштаба"""
        self.current_zoom = zoom_factor
        self.zoomChanged.emit(zoom_factor)

    def get_current_zoom(self):
        """Возвращает текущий масштаб"""
        return self.current_zoom

    def zoom_in(self):
        """Увеличивает масштаб"""
        new_zoom = min(self.current_zoom * 1.1, 3.0)
        self.web_view.setZoomFactor(new_zoom)

    def zoom_out(self):
        """Уменьшает масштаб"""
        new_zoom = max(self.current_zoom / 1.1, 0.25)
        self.web_view.setZoomFactor(new_zoom)

    def reset_zoom(self):
        """Сбрасывает масштаб к 100%"""
        self.web_view.setZoomFactor(1.0)

    def show_context_menu(self, position):
        """Показывает контекстное меню"""
        menu = QMenu(self)

        # Получаем ссылку на родительский браузер
        parent_browser = None
        widget = self.parent()
        while widget:
            if hasattr(widget, "new_tab"):
                parent_browser = widget
                break
            widget = widget.parent()

        # Навигация
        back_action = QAction(QIcon(os.path.join("images", "back.png")), "Назад", self)
        back_action.triggered.connect(self.back)
        back_action.setEnabled(self.web_view.page().history().canGoBack())
        menu.addAction(back_action)

        forward_action = QAction(
            QIcon(os.path.join("images", "forward.png")), "Вперед", self
        )
        forward_action.triggered.connect(self.forward)
        forward_action.setEnabled(self.web_view.page().history().canGoForward())
        menu.addAction(forward_action)

        reload_action = QAction(
            QIcon(os.path.join("images", "refresh.png")), "Обновить", self
        )
        reload_action.triggered.connect(self.reload)
        menu.addAction(reload_action)

        menu.addSeparator()

        # Работа с буфером обмена
        copy_link_action = QAction(
            QIcon(os.path.join("images", "copyurl.png")), "Копировать текущий URL", self
        )
        copy_link_action.triggered.connect(self.copy_current_url)
        menu.addAction(copy_link_action)

        copy_web_link_action = QAction(
            QIcon(os.path.join("images", "copylink.png")), "Копировать ссылку", self
        )
        copy_web_link_action.triggered.connect(self.copy_web_link)
        menu.addAction(copy_web_link_action)

        paste_url_action = QAction(
            QIcon(os.path.join("images", "paste.png")), "Вставить ссылку", self
        )
        paste_url_action.triggered.connect(self.paste_url)
        menu.addAction(paste_url_action)

        copy_text_action = QAction(
            QIcon(os.path.join("images", "copytext.png")), "Копировать как текст", self
        )
        copy_text_action.triggered.connect(self.copy_selected_text)
        copy_text_action.setEnabled(True)  # Всегда доступно
        menu.addAction(copy_text_action)

        menu.addSeparator()

        # Новая вкладка
        if parent_browser:
            new_tab_action = QAction(
                QIcon(os.path.join("images", "opennew.png")),
                "Открыть в новой вкладке",
                self,
            )
            new_tab_action.triggered.connect(
                lambda: parent_browser.new_tab(self.get_copy_url())
            )
            menu.addAction(new_tab_action)

        menu.addSeparator()

        # Загрузки
        download_submenu = QMenu("🔽 Загрузить", self)

        # Сохранить страницу как MHTML
        save_page_action = QAction(
            QIcon(os.path.join("images", "mhtml.png")),
            "Сохранить страницу (MHTML)",
            self,
        )
        save_page_action.triggered.connect(self.save_page_as_mhtml)
        download_submenu.addAction(save_page_action)

        # Сохранить как HTML
        save_html_action = QAction(
            QIcon(os.path.join("images", "html.png")), "Сохранить как HTML", self
        )
        save_html_action.triggered.connect(self.save_page_as_html)
        download_submenu.addAction(save_html_action)

        # Сохранить как PDF
        save_pdf_action = QAction(
            QIcon(os.path.join("images", "pdf.png")), "Сохранить как PDF", self
        )
        save_pdf_action.triggered.connect(self.save_page_as_pdf)
        download_submenu.addAction(save_pdf_action)

        download_submenu.addSeparator()

        # Загрузить изображение
        download_image_action = QAction(
            QIcon(os.path.join("images", "image.png")), "Загрузить изображение", self
        )
        download_image_action.triggered.connect(self.download_image)
        download_submenu.addAction(download_image_action)

        # Альтернативные методы загрузки изображений
        download_image_alt_action = QAction(
            QIcon(os.path.join("images", "images.png")),
            "Выбрать изображение для загрузки",
            self,
        )
        download_image_alt_action.triggered.connect(self.download_image_alternative)
        download_submenu.addAction(download_image_alt_action)

        # Загрузить медиа
        download_media_action = QAction(
            QIcon(os.path.join("images", "media.png")), "Загрузить медиа", self
        )
        download_media_action.triggered.connect(self.download_media)
        download_submenu.addAction(download_media_action)

        # Загрузить ссылку
        download_link_action = QAction(
            QIcon(os.path.join("images", "link.png")), "Загрузить по ссылке", self
        )
        download_link_action.triggered.connect(self.download_link)
        download_submenu.addAction(download_link_action)

        menu.addMenu(download_submenu)

        copy_image_action = QAction(
            QIcon(os.path.join("images", "imagcopy.png")),
            "Копировать изображение",
            self,
        )
        copy_image_action.triggered.connect(self.copy_image)
        menu.addAction(copy_image_action)

        # Информация о поддержке форматов
        info_action = QAction(
            QIcon(os.path.join("images", "info.png")), "Поддержка форматов", self
        )
        info_action.triggered.connect(self.show_image_format_info)
        menu.addAction(info_action)

        menu.addSeparator()

        # Масштаб
        zoom_in_action = QAction(
            QIcon(os.path.join("images", "zoomin.png")), "Увеличить", self
        )
        zoom_in_action.triggered.connect(self.zoom_in)
        menu.addAction(zoom_in_action)

        zoom_out_action = QAction(
            QIcon(os.path.join("images", "zoomout.png")), "Уменьшить", self
        )
        zoom_out_action.triggered.connect(self.zoom_out)
        menu.addAction(zoom_out_action)

        reset_zoom_action = QAction(
            QIcon(os.path.join("images", "zoomreset.png")), "Сбросить масштаб", self
        )
        reset_zoom_action.triggered.connect(self.reset_zoom)
        menu.addAction(reset_zoom_action)

        menu.exec(self.web_view.mapToGlobal(position))

    def copy_current_url(self):
        """Копирует текущий URL в буфер обмена"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.get_current_url())

    def copy_web_link(self):
        """Копирует веб-ссылку в буфер обмена"""
        self.web_view.page().triggerAction(QWebEnginePage.WebAction.CopyLinkToClipboard)

    def get_copy_url(self):
        self.web_view.page().triggerAction(QWebEnginePage.WebAction.CopyLinkToClipboard)
        clipboard = QApplication.clipboard()
        url = clipboard.text().strip()
        return url

    def paste_url(self):
        """Вставляет URL из буфера обмена и переходит по нему"""
        clipboard = QApplication.clipboard()
        url = clipboard.text().strip()
        if url:
            self.navigate_to_url(url)

    def copy_selected_text(self):
        """Копирует выделенный текст в буфер обмена"""
        self.web_view.page().triggerAction(QWebEnginePage.WebAction.Copy)

    def save_page_as_mhtml(self):
        """Сохраняет страницу как MHTML (веб-архив)"""
        self.web_view.page().triggerAction(QWebEnginePage.WebAction.SavePage)

    def save_page_as_html(self):
        """Сохраняет страницу как HTML файл"""
        try:
            # Получаем заголовок страницы для имени файла
            title = self.get_current_title()
            if not title or title == "Новая вкладка":
                title = "webpage"

            # Очищаем заголовок от недопустимых символов
            import re

            safe_title = re.sub(r'[<>:"/\\|?*]', "", title)

            # Диалог сохранения файла
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить как HTML",
                f"{safe_title}.html",
                "HTML файлы (*.html);;Все файлы (*.*)",
            )

            if file_path:
                # Получаем HTML содержимое страницы
                self.web_view.page().toHtml(
                    lambda html: self.save_html_content(html, file_path)
                )

        except Exception as e:
            print(f"Ошибка при сохранении HTML: {e}")

    def save_html_content(self, html_content, file_path):
        """Сохраняет HTML содержимое в файл"""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            # Показываем уведомление
            parent_browser = self.get_parent_browser()
            if parent_browser:
                parent_browser.update_status_bar(
                    f"✅ HTML сохранен: {os.path.basename(file_path)}"
                )

                # Добавляем в менеджер загрузок
                if hasattr(parent_browser, "download_manager"):
                    parent_browser.download_manager.add_download(
                        self.get_current_url(), file_path, os.path.getsize(file_path)
                    )
                    parent_browser.download_manager.download_completed(
                        self.get_current_url(), file_path, True
                    )

        except Exception as e:
            logger.error(f"🆘 Ошибка при записи HTML файла: {e}")

    def save_page_as_pdf(self):
        """Сохраняет страницу как PDF"""
        try:
            # Получаем заголовок страницы для имени файла
            title = self.get_current_title()
            if not title or title == "Новая вкладка":
                title = "webpage"

            # Очищаем заголовок от недопустимых символов
            import re

            safe_title = re.sub(r'[<>:"/\\|?*]', "", title)

            # Диалог сохранения файла
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить как PDF",
                f"{safe_title}.pdf",
                "PDF файлы (*.pdf);;Все файлы (*.*)",
            )

            if file_path:
                # Создаем принтер для PDF
                printer = QPrinter(QPrinter.PrinterMode.HighResolution)
                printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
                printer.setOutputFileName(file_path)

                # Печатаем страницу в PDF
                self.web_view.page().print(
                    printer, lambda success: self.pdf_print_finished(success, file_path)
                )

        except Exception as e:
            logger.error(f"🆘 Ошибка при сохранении PDF: {e}")
            # Альтернативный метод через браузер
            self.web_view.page().printToPdf(file_path)

    def pdf_print_finished(self, success, file_path):
        """Обрабатывает завершение печати в PDF"""
        parent_browser = self.get_parent_browser()
        if parent_browser:
            if success:
                parent_browser.update_status_bar(
                    f"✅ PDF сохранен: {os.path.basename(file_path)}"
                )

                # Добавляем в менеджер загрузок
                if hasattr(parent_browser, "download_manager"):
                    parent_browser.download_manager.add_download(
                        self.get_current_url(),
                        file_path,
                        os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                    )
                    parent_browser.download_manager.download_completed(
                        self.get_current_url(), file_path, True
                    )
            else:
                parent_browser.update_status_bar("❌ Ошибка при сохранении PDF")

    def download_image(self):
        """Загружает изображение под курсором"""
        try:
            # Используем стандартное действие браузера для загрузки изображения
            self.web_view.page().triggerAction(
                QWebEnginePage.WebAction.DownloadImageToDisk
            )

            # Показываем уведомление
            parent_browser = self.get_parent_browser()
            if parent_browser:
                parent_browser.update_status_bar("📥 Загрузка изображения начата...")
        except Exception as e:
            logger.error(f"🆘 Ошибка при загрузке изображения: {e}")
            # Альтернативный способ загрузки
            self.download_image_alternative()

    def download_media(self):
        """Загружает медиа-файл под курсором"""
        self.web_view.page().triggerAction(QWebEnginePage.WebAction.DownloadMediaToDisk)

    def download_link(self):
        """Загружает файл по ссылке под курсором"""
        self.web_view.page().triggerAction(QWebEnginePage.WebAction.DownloadLinkToDisk)

    def copy_image(self):
        """Копирует изображение под курсором"""
        self.web_view.page().triggerAction(
            QWebEnginePage.WebAction.CopyImageToClipboard
        )

    def download_image_alternative(self):
        """Альтернативный метод загрузки изображений"""
        try:
            # Получаем HTML страницы для поиска изображений
            self.web_view.page().toHtml(self.find_and_download_images)
        except Exception as e:
            logger.error(f"🆘 Ошибка при альтернативной загрузке: {e}")

    def find_and_download_images(self, html_content):
        """Ищет изображения в HTML и предлагает загрузить"""
        try:
            # Ищем все изображения в HTML
            img_patterns = [
                r'<img[^>]*src=["\']([^"\']*)["\']',
                r'background-image:\s*url\(["\']?([^"\')\s]+)["\']?\)',
                r'data-src=["\']([^"\']*)["\']',
                r'srcset=["\']([^"\']*)["\']',
            ]

            found_images = []
            for pattern in img_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if match and not match.startswith("data:"):
                        found_images.append(match)

            # Убираем дубликаты
            found_images = list(set(found_images))

            if found_images:
                # Показываем диалог выбора изображения
                image_url, ok = QInputDialog.getItem(
                    self,
                    "Выбор изображения",
                    "Выберите изображение для загрузки:",
                    found_images,
                    0,
                    False,
                )

                if ok and image_url:
                    self.download_image_by_url(image_url)
            else:
                parent_browser = self.get_parent_browser()
                if parent_browser:
                    parent_browser.update_status_bar(
                        "❌ Изображения не найдены на странице"
                    )

        except Exception as e:
            logger.error(f"🆘 Ошибка при поиске изображений: {e}")

    def download_image_by_url(self, image_url):
        """Загружает изображение по URL"""
        try:
            # Получаем базовый URL страницы
            base_url = self.get_current_url()

            # Преобразуем относительный URL в абсолютный
            if not image_url.startswith(("http://", "https://")):
                image_url = urljoin(base_url, image_url)

            # Определяем имя файла
            parsed_url = urlparse(image_url)
            filename = os.path.basename(parsed_url.path)

            # Если имя файла пустое, генерируем его
            if not filename or "." not in filename:
                filename = f"image_{hash(image_url) % 10000}.webp"

            # Определяем расширение файла
            if not os.path.splitext(filename)[1]:
                # Если нет расширения, добавляем .webp как наиболее вероятное
                filename += ".webp"

            # Диалог сохранения
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить изображение",
                filename,
                "Изображения (*.webp *.png *.jpg *.jpeg *.gif *.bmp *.svg *.ico *.tiff);;WebP (*.webp);;PNG (*.png);;JPEG (*.jpg *.jpeg);;GIF (*.gif);;Все файлы (*.*)",
            )

            if file_path:
                # Показываем прогресс
                parent_browser = self.get_parent_browser()
                if parent_browser:
                    parent_browser.update_status_bar(
                        f"📥 Загрузка изображения: {filename}"
                    )

                # Загружаем изображение
                response = requests.get(image_url, stream=True, timeout=10)
                response.raise_for_status()

                # Сохраняем файл
                with open(file_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                # Уведомляем о завершении
                if parent_browser:
                    parent_browser.update_status_bar(
                        f"✅ Изображение сохранено: {os.path.basename(file_path)}"
                    )

                    # Добавляем в менеджер загрузок
                    if hasattr(parent_browser, "download_manager"):
                        parent_browser.download_manager.add_download(
                            image_url, file_path, os.path.getsize(file_path)
                        )
                        parent_browser.download_manager.download_completed(
                            image_url, file_path, True
                        )

        except Exception as e:
            logger.error(f"🆘 Ошибка при загрузке изображения по URL: {e}")
            parent_browser = self.get_parent_browser()
            if parent_browser:
                parent_browser.update_status_bar(
                    f"❌ Ошибка при загрузке изображения: {str(e)}"
                )

            QMessageBox.warning(
                self, "Ошибка загрузки", f"Не удалось загрузить изображение:\n{str(e)}"
            )

    def get_parent_browser(self):
        """Находит родительский браузер"""
        widget = self.parent()
        while widget:
            if hasattr(widget, "update_status_bar"):
                return widget
            widget = widget.parent()
        return None

    def show_image_format_info(self):
        """Показывает информацию о поддерживаемых форматах изображений"""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle("Поддерживаемые форматы изображений")
        msg.setText("Браузер поддерживает загрузку следующих форматов:")

        formats_info = """
<b>Современные форматы:</b>
• WebP - высокое качество при малом размере
• AVIF - новейший формат с лучшим сжатием
• SVG - векторная графика

<b>Классические форматы:</b>
• JPEG/JPG - для фотографий
• PNG - для изображений с прозрачностью
• GIF - для анимации
• BMP - без сжатия
• TIFF - для профессиональной печати
• ICO - для иконок

<b>Особенности WebP:</b>
• Размер файла на 25-35% меньше JPEG
• Поддержка прозрачности
• Поддержка анимации
• Хорошая поддержка в браузерах
        """

        msg.setInformativeText(formats_info)
        msg.exec()

    def on_link_hovered(self, url):
        """Обработчик наведения мыши на ссылку"""
        # Получаем ссылку на родительский браузер
        parent_browser = None
        widget = self.parent()
        while widget:
            if hasattr(widget, "update_status_bar"):
                parent_browser = widget
                break
            widget = widget.parent()

        if parent_browser:
            if url:
                # Показываем URL в статус-баре
                parent_browser.update_status_bar(f"🔗 {url}")
            else:
                # Очищаем статус-бар, если мышь не на ссылке
                parent_browser.status_bar.clearMessage()

    def handle_wheel_event(self, event):
        """Обрабатывает колесико мыши для масштабирования (Ctrl + колесико)"""
        # Проверяем, зажат ли Ctrl
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            # Получаем направление прокрутки
            delta = event.angleDelta().y()

            if delta > 0:
                # Прокрутка вверх - увеличиваем масштаб
                self.zoom_in()
            elif delta < 0:
                # Прокрутка вниз - уменьшаем масштаб
                self.zoom_out()

            # Предотвращаем дальнейшую обработку события
            event.accept()
        else:
            # Обычная прокрутка - вызываем стандартное поведение
            QWebEngineView.wheelEvent(self.web_view, event)

    def __del__(self):
        """ИСПРАВЛЕНО: Деструктор для корректной очистки ресурсов"""
        try:
            if hasattr(self, "web_view") and self.web_view:
                # Останавливаем загрузку
                self.web_view.stop()
                # Очищаем страницу
                page = self.web_view.page()
                if page:
                    page.setParent(None)
                    page.deleteLater()
                # Очищаем веб-вью
                self.web_view.setParent(None)
            logger.info("🗑️ BrowserTab destructor: ресурсы очищены")
        except Exception as e:
            logger.error(f"🆘 Ошибка в деструкторе BrowserTab: {e}")

    def cleanup_resources(self):
        """ИСПРАВЛЕНО: Публичный метод для принудительной очистки ресурсов"""
        try:
            if hasattr(self, "web_view") and self.web_view:
                # Отключаем все сигналы
                try:
                    self.web_view.disconnect()
                except:
                    pass

                # Останавливаем загрузку
                self.web_view.stop()

                # Очищаем страницу
                page = self.web_view.page()
                if page:
                    try:
                        page.disconnect()
                    except:
                        pass
                    page.setParent(None)
                    page.deleteLater()

                # Устанавливаем None
                self.web_view.setPage(None)
                self.web_view.setParent(None)
                self.web_view = None

            logger.info("✅ BrowserTab ресурсы принудительно очищены")
        except Exception as e:
            logger.error(f"🆘 Ошибка при принудительной очистке BrowserTab: {e}")


class FavoritesBar(QWidget):
    """Панель избранного"""

    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.parent_browser = parent
        self.init_ui()
        logger.info("✅ Панель избранного (FavoritesBar) инициализирована")

    def init_ui(self):
        self.setMaximumHeight(35)
        self.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px 10px;
                text-align: left;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }
        """)

        # Создаем горизонтальный layout с прокруткой
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(5, 2, 5, 2)

        # Создаем скроллируемую область
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # Виджет для кнопок избранного
        self.favorites_widget = QWidget()
        self.favorites_layout = QHBoxLayout(self.favorites_widget)
        self.favorites_layout.setContentsMargins(0, 0, 0, 0)
        self.favorites_layout.setSpacing(2)
        self.favorites_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        scroll_area.setWidget(self.favorites_widget)
        main_layout.addWidget(scroll_area)

        # Кнопка управления избранным
        self.manage_button = QPushButton("")
        self.manage_button.setIcon(QIcon(os.path.join("images", "histors.png")))
        self.manage_button.setMaximumWidth(30)
        self.manage_button.setToolTip("Управление избранным")
        self.manage_button.clicked.connect(self.manage_favorites)
        main_layout.addWidget(self.manage_button)

        # Сначала добавляем растягивающийся элемент
        self.favorites_layout.addStretch()

        # Затем загружаем избранное
        self.refresh_favorites()

    def refresh_favorites(self):
        """Обновляет список избранного"""
        # Очищаем только кнопки избранного (не растягивающийся элемент)
        self.clear_favorite_buttons()

        # Получаем избранное из базы данных
        favorites = self.db_manager.get_favorites()

        # Добавляем кнопки для каждого избранного
        for url, title, icon_blob in favorites:
            self.add_favorite_button(url, title, icon_blob)

    def clear_favorite_buttons(self):
        """Очищает только кнопки избранного, сохраняя растягивающийся элемент"""
        items_to_remove = []

        # Собираем все виджеты (кнопки) для удаления
        for i in range(self.favorites_layout.count()):
            item = self.favorites_layout.itemAt(i)
            if item and item.widget():
                items_to_remove.append(item.widget())

        # Удаляем собранные виджеты
        for widget in items_to_remove:
            widget.setParent(None)
            widget.deleteLater()

    def clear_favorites_layout(self):
        """Полностью очищает layout панели избранного"""
        while self.favorites_layout.count():
            item = self.favorites_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.spacerItem():
                del item

    def open_favorite(self, url):
        """Открывает избранную закладку"""
        if self.parent_browser and isinstance(url, str):
            # Открываем в текущей вкладке
            current_tab = self.parent_browser.tab_widget.currentWidget()
            if current_tab:
                current_tab.navigate_to_url(url)
            else:
                self.parent_browser.new_tab(url)

    def show_context_menu(self, position, url, button):
        """Показывает контекстное меню для избранного"""
        menu = QMenu(self)

        open_action = QAction(
            QIcon(os.path.join("images", "tabs.png")), "Открыть", self
        )
        open_action.triggered.connect(lambda: self.open_favorite(url))
        menu.addAction(open_action)

        open_new_tab_action = QAction(
            QIcon(os.path.join("images", "ntabs.png")), "Открыть в новой вкладке", self
        )
        open_new_tab_action.triggered.connect(
            lambda: self.parent_browser.new_tab(url) if isinstance(url, str) else None
        )
        menu.addAction(open_new_tab_action)

        remove_action = QAction(
            QIcon(os.path.join("images", "delete.png")), "Удалить из избранного", self
        )
        remove_action.triggered.connect(lambda: self.remove_from_favorites(url))
        menu.addAction(remove_action)

        menu.exec(button.mapToGlobal(position))

    def remove_from_favorites(self, url):
        """Удаляет из избранного"""
        self.db_manager.toggle_favorite(url)
        self.refresh_favorites()

    def add_favorite_button(self, url, title, icon_blob):
        """Добавляет кнопку избранного в панель"""
        icon = self.db_manager.blob_to_icon(icon_blob) if icon_blob else QIcon()

        button = QPushButton()
        button.setIcon(icon)
        button.setText(title[:20] + "..." if len(title) > 20 else title)
        button.setToolTip(f"{title}\n{url}")
        button.setMaximumWidth(150)
        button.clicked.connect(lambda checked, u=url: self.open_favorite(u))

        # Контекстное меню
        button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        button.customContextMenuRequested.connect(
            lambda pos, u=url, b=button: self.show_context_menu(pos, u, b)
        )

        # Находим позицию для вставки (перед растягивающимся элементом)
        insert_index = 0

        # Ищем позицию перед растягивающимся элементом
        for i in range(self.favorites_layout.count()):
            item = self.favorites_layout.itemAt(i)
            if item and item.spacerItem():
                insert_index = i
                break
            else:
                insert_index = i + 1

        self.favorites_layout.insertWidget(insert_index, button)
        return button

    def manage_favorites(self):
        """Открывает окно управления избранным"""
        if self.parent_browser:
            self.parent_browser.show_bookmarks()


class DownloadItem(QWidget):
    def __init__(self, url, file_path, file_size=0):
        super().__init__()
        self.url = url
        self.file_path = file_path
        self.file_size = file_size
        self.start_time = datetime.now()
        self.bytes_downloaded = 0

        self.init_ui()
        logger.info(f"DownloadItem initialized with URL: {url}, File Path: {file_path}")

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)

        # Верхняя строка: имя файла и кнопки
        top_layout = QHBoxLayout()

        # Иконка файла
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(32, 32)
        self.set_file_icon()
        top_layout.addWidget(self.icon_label)

        # Информация о файле
        info_layout = QVBoxLayout()

        self.filename_label = QLabel(os.path.basename(self.file_path))
        self.filename_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        info_layout.addWidget(self.filename_label)

        self.url_label = QLabel(self.url)
        self.url_label.setStyleSheet("color: #666; font-size: 10px;")
        self.url_label.setWordWrap(True)
        info_layout.addWidget(self.url_label)

        top_layout.addLayout(info_layout)
        top_layout.addStretch()

        # Кнопки действий
        self.open_button = QPushButton("Открыть")
        self.open_button.setMaximumWidth(80)
        self.open_button.clicked.connect(self.open_file)
        self.open_button.setEnabled(False)  # Включается после завершения
        top_layout.addWidget(self.open_button)

        self.folder_button = QPushButton("Папка")
        self.folder_button.setMaximumWidth(80)
        self.folder_button.clicked.connect(self.open_folder)
        top_layout.addWidget(self.folder_button)

        layout.addLayout(top_layout)

        # Прогресс-бар
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)

        # Нижняя строка: статус и размер
        bottom_layout = QHBoxLayout()

        self.status_label = QLabel("Загрузка...")
        self.status_label.setStyleSheet("color: #333; font-size: 11px;")
        bottom_layout.addWidget(self.status_label)

        bottom_layout.addStretch()

        self.size_label = QLabel(self.format_size(self.file_size))
        self.size_label.setStyleSheet("color: #666; font-size: 11px;")
        bottom_layout.addWidget(self.size_label)

        layout.addLayout(bottom_layout)

    def set_file_icon(self):
        """Устанавливает иконку в зависимости от типа файла"""
        filename = os.path.basename(self.file_path).lower()

        if filename.endswith(
            (
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".bmp",
                ".webp",
                ".svg",
                ".ico",
                ".tiff",
                ".tif",
            )
        ):
            icon_text = "🖼️"
        elif filename.endswith(
            (".mp4", ".avi", ".mkv", ".mov", ".webm", ".flv", ".wmv", ".m4v")
        ):
            icon_text = "🎬"
        elif filename.endswith(
            (".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a")
        ):
            icon_text = "🎵"
        elif filename.endswith((".pdf")):
            icon_text = "📄"
        elif filename.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz")):
            icon_text = "📦"
        elif filename.endswith((".exe", ".msi", ".deb", ".rpm", ".dmg")):
            icon_text = "⚙️"
        elif filename.endswith((".txt", ".log", ".md", ".readme")):
            icon_text = "📝"
        elif filename.endswith((".doc", ".docx", ".odt")):
            icon_text = "📄"
        elif filename.endswith((".xls", ".xlsx", ".ods")):
            icon_text = "📊"
        elif filename.endswith((".ppt", ".pptx", ".odp")):
            icon_text = "📈"
        elif filename.endswith((".html", ".htm", ".xml")):
            icon_text = "🌐"
        elif filename.endswith(
            (".css", ".js", ".json", ".py", ".cpp", ".java", ".php")
        ):
            icon_text = "💻"
        else:
            icon_text = "📁"

        self.icon_label.setText(icon_text)
        self.icon_label.setStyleSheet("font-size: 24px;")

    def update_progress(self, bytes_received, bytes_total):
        """Обновляет прогресс загрузки"""
        self.bytes_downloaded = bytes_received

        if bytes_total > 0:
            progress = int((bytes_received / bytes_total) * 100)
            self.progress_bar.setValue(progress)

            # Обновляем размер
            size_text = (
                f"{self.format_size(bytes_received)} / {self.format_size(bytes_total)}"
            )
            self.size_label.setText(size_text)

            # Рассчитываем скорость
            elapsed_time = (datetime.now() - self.start_time).total_seconds()
            if elapsed_time > 0:
                speed = bytes_received / elapsed_time
                speed_text = f"{self.format_size(speed)}/с"

                # Оценка времени
                if speed > 0 and bytes_total > bytes_received:
                    remaining_time = (bytes_total - bytes_received) / speed
                    time_text = self.format_time(remaining_time)
                    status_text = f"{speed_text} • Осталось: {time_text}"
                else:
                    status_text = speed_text

                self.status_label.setText(status_text)

    def download_completed(self, success=True):
        """Отмечает загрузку как завершенную"""
        if success:
            self.progress_bar.setValue(100)
            self.status_label.setText("✅ Загрузка завершена")
            self.status_label.setStyleSheet("color: green; font-size: 11px;")
            self.open_button.setEnabled(True)
        else:
            self.status_label.setText("❌ Ошибка загрузки")
            self.status_label.setStyleSheet("color: red; font-size: 11px;")

    def open_file(self):
        """Открывает загруженный файл"""
        if os.path.exists(self.file_path):
            try:
                import subprocess
                import platform

                system = platform.system()
                if system == "Windows":
                    os.startfile(self.file_path)
                elif system == "Darwin":  # macOS
                    subprocess.run(["open", self.file_path])
                else:  # Linux
                    subprocess.run(["xdg-open", self.file_path])
            except Exception as e:
                logger.error(f"🆘 Ошибка при открытии файла: {e}")

    def open_folder(self):
        """Открывает папку с файлом"""
        try:
            import subprocess
            import platform

            system = platform.system()
            if system == "Windows":
                subprocess.run(["explorer", "/select,", self.file_path])
            elif system == "Darwin":  # macOS
                subprocess.run(["open", "-R", self.file_path])
            else:  # Linux
                subprocess.run(["xdg-open", os.path.dirname(self.file_path)])
        except Exception as e:
            logger.error(f"🆘 Ошибка при открытии папки: {e}")

    @staticmethod
    def format_size(size_bytes):
        """Форматирует размер файла в читаемый вид"""
        if size_bytes == 0:
            return "0 Б"

        size_names = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1

        return f"{size_bytes:.1f} {size_names[i]}"

    @staticmethod
    def format_time(seconds):
        """Форматирует время в читаемый вид"""
        if seconds < 60:
            return f"{int(seconds)}с"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            seconds = int(seconds % 60)
            return f"{minutes}м {seconds}с"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}ч {minutes}м"


class DownloadManager(QDialog):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.parent_browser = parent
        self.download_items = {}  # Словарь для отслеживания элементов загрузки

        self.init_ui()

        self.load_downloads()

    def init_ui(self):
        self.setWindowTitle("📥 Менеджер загрузок")
        self.setGeometry(300, 300, 700, 500)

        layout = QVBoxLayout(self)

        # Заголовок
        header_layout = QHBoxLayout()

        title_label = QLabel("📥 Загрузки")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Путь загрузок
        path_label = QLabel(f"📁 Папка: {self.get_download_path()}")
        path_label.setStyleSheet("color: #666; margin: 10px;")
        header_layout.addWidget(path_label)

        layout.addLayout(header_layout)

        # Список загрузок с прокруткой
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.downloads_widget = QWidget()
        self.downloads_layout = QVBoxLayout(self.downloads_widget)
        self.downloads_layout.addStretch()  # Растягивающий элемент в конце

        scroll_area.setWidget(self.downloads_widget)
        layout.addWidget(scroll_area)

        # Кнопки управления
        button_layout = QHBoxLayout()

        refresh_button = QPushButton("Обновить")
        refresh_button.clicked.connect(self.refresh_downloads)
        button_layout.addWidget(refresh_button)

        open_folder_button = QPushButton("Открыть папку загрузок")
        open_folder_button.clicked.connect(self.open_download_folder)
        button_layout.addWidget(open_folder_button)

        clear_completed_button = QPushButton("Очистить завершенные")
        clear_completed_button.clicked.connect(self.clear_completed)
        button_layout.addWidget(clear_completed_button)

        clear_all_button = QPushButton("Очистить все")
        clear_all_button.clicked.connect(self.clear_all)
        button_layout.addWidget(clear_all_button)

        button_layout.addStretch()

        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)
        logger.info("✅ Менеджер загрузок инициализирован")

    def get_download_path(self):
        """Получает путь для загрузок из настроек"""
        if self.parent_browser:
            custom_path = self.parent_browser.db_manager.get_setting(
                "download_path", ""
            )
            if custom_path and os.path.exists(custom_path):
                return custom_path

        # Используем папку загрузок по умолчанию
        return QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DownloadLocation
        )

    def add_download(self, url, file_path, file_size=0):
        """Добавляет новую загрузку в менеджер"""
        download_item = DownloadItem(url, file_path, file_size)

        # Добавляем в начало списка (перед растягивающим элементом)
        self.downloads_layout.insertWidget(0, download_item)

        # Сохраняем ссылку для обновления прогресса
        download_key = f"{url}_{os.path.basename(file_path)}"
        self.download_items[download_key] = download_item

        # Сохраняем в базу данных
        try:
            self.db_manager.add_download(url, file_path)
        except Exception as e:
            logger.error(f"🆘 Ошибка при сохранении загрузки в БД: {e}")

        return download_item

    def update_download_progress(self, url, file_path, bytes_received, bytes_total):
        """Обновляет прогресс загрузки"""
        download_key = f"{url}_{os.path.basename(file_path)}"
        if download_key in self.download_items:
            self.download_items[download_key].update_progress(
                bytes_received, bytes_total
            )

    def download_completed(self, url, file_path, success=True):
        """Отмечает загрузку как завершенную"""
        download_key = f"{url}_{os.path.basename(file_path)}"
        if download_key in self.download_items:
            self.download_items[download_key].download_completed(success)

    def load_downloads(self):
        """Загружает историю загрузок из базы данных"""
        try:
            downloads = self.db_manager.get_downloads()
            for url, file_path, start_time, status in downloads:
                if os.path.exists(file_path):
                    download_item = DownloadItem(url, file_path)
                    if status == "completed":
                        download_item.download_completed(True)

                    self.downloads_layout.insertWidget(0, download_item)

                    download_key = f"{url}_{os.path.basename(file_path)}"
                    self.download_items[download_key] = download_item
            logger.info("✅ История загрузок загружена")
        except Exception as e:
            logger.error(f"🆘 Ошибка при загрузке истории загрузок: {e}")

    def refresh_downloads(self):
        """Обновляет список загрузок"""
        # Очищаем текущий список
        self.clear_all_items()

        # Перезагружаем
        self.load_downloads()

    def clear_completed(self):
        """Удаляет завершенные загрузки из списка"""
        items_to_remove = []

        for i in range(
            self.downloads_layout.count() - 1
        ):  # -1 из-за растягивающего элемента
            item = self.downloads_layout.itemAt(i)
            if item and item.widget():
                download_item = item.widget()
                if isinstance(download_item, DownloadItem):
                    if "завершена" in download_item.status_label.text():
                        items_to_remove.append(download_item)

        for item in items_to_remove:
            item.setParent(None)
            # Удаляем из словаря
            for key, value in list(self.download_items.items()):
                if value == item:
                    del self.download_items[key]

    def clear_all(self):
        """Очищает весь список загрузок"""
        reply = QMessageBox.question(
            self,
            "Очистить все",
            "Удалить все загрузки из списка?\n\nФайлы на диске сохранятся.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.clear_all_items()
            self.download_items.clear()

    def clear_all_items(self):
        """Удаляет все виджеты загрузок"""
        for i in reversed(
            range(self.downloads_layout.count() - 1)
        ):  # -1 из-за растягивающего элемента
            item = self.downloads_layout.itemAt(i)
            if item and item.widget():
                item.widget().setParent(None)

    def open_download_folder(self):
        """Открывает папку загрузок"""
        download_path = self.get_download_path()
        try:
            import subprocess
            import platform

            system = platform.system()
            if system == "Windows":
                subprocess.run(["explorer", download_path])
            elif system == "Darwin":  # macOS
                subprocess.run(["open", download_path])
            else:  # Linux
                subprocess.run(["xdg-open", download_path])
        except Exception as e:
            logger.error(f"🆘 Ошибка при открытии папки загрузок: {e}")
            QMessageBox.warning(
                self, "Ошибка", f"Не удалось открыть папку загрузок:\n{e}"
            )


class HistoryManager(QDialog):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.parent_browser = parent
        self.setWindowTitle("История")
        self.resize(400, 700)
        self.setStyleSheet("""
                    QListWidget::item {
                        color: blue;
                    }
                    QListWidget::item:hover {
                        color: #FF0000;
                        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                                    stop: 0 #FAFBFE, stop: 1 lightblue);
                    }
                    QListWidget {
                        background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                                    stop: 0 lightblue, stop: 1 #FAFBFE);
                        border: 1px solid gray;
                        border-radius: 7px;
                        padding: 5px;
                    }
                    QListWidget::item:selected {
                        color: black;
                        background-color: #e3f2fd;
                    }
        """)

        layout = QVBoxLayout(self)

        # Заголовок
        header_label = QLabel("📜 История посещений")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold; margin: 5px;")
        layout.addWidget(header_label)

        # Список истории с улучшенным стилем
        self.history_list = QListWidget()

        self.history_list.itemDoubleClicked.connect(self.open_history_item)
        layout.addWidget(self.history_list)

        # Кнопки управления
        button_layout = QHBoxLayout()

        refresh_button = QPushButton("Обновить")
        refresh_button.clicked.connect(self.refresh_history)
        button_layout.addWidget(refresh_button)

        open_button = QPushButton("Открыть")
        open_button.clicked.connect(self.open_history_item)
        button_layout.addWidget(open_button)

        open_new_tab_button = QPushButton("Открыть в новой вкладке")
        open_new_tab_button.clicked.connect(self.open_in_new_tab)
        button_layout.addWidget(open_new_tab_button)

        copy_link_button = QPushButton("Копировать ссылку")
        copy_link_button.clicked.connect(self.copy_link)
        button_layout.addWidget(copy_link_button)

        button_layout.addStretch()

        clear_button = QPushButton("Очистить историю")
        clear_button.clicked.connect(self.clear_history)
        button_layout.addWidget(clear_button)

        layout.addLayout(button_layout)
        logger.info("✅ История посещений загружена")
        self.refresh_history()

    def refresh_history(self):
        self.history_list.clear()
        history = self.db_manager.get_history()

        for row in history:
            if len(row) >= 4:  # Новый формат с иконками
                url, title, icon_blob, visit_time = row
                icon = (
                    self.db_manager.blob_to_icon(icon_blob)
                    if icon_blob
                    else self.get_default_icon_for_url(url)
                )
            else:  # Старый формат без иконок
                url, title, visit_time = row
                icon = self.get_default_icon_for_url(url)

            # Форматируем отображение
            display_title = title or url
            if len(display_title) > 60:
                display_title = display_title[:60] + "..."

            # Форматируем URL для отображения
            display_url = url
            if len(display_url) > 80:
                display_url = display_url[:80] + "..."

            # Форматируем время для лучшего отображения
            formatted_time = self.format_visit_time(visit_time)

            item_text = f"{display_title}\n🔗 {display_url}\n📅 {formatted_time}"
            item = QListWidgetItem(icon, item_text)
            item.setData(256, url)  # Сохраняем URL
            item.setData(257, title)  # Сохраняем заголовок
            item.setToolTip(f"Заголовок: {title}\nURL: {url}\nВремя: {formatted_time}")
            self.history_list.addItem(item)

    def format_visit_time(self, visit_time):
        """Форматирует время посещения для лучшего отображения"""
        if not visit_time or visit_time == "Unknown":
            return "Неизвестно"

        try:
            # Пытаемся распарсить время
            if isinstance(visit_time, str):
                # Пробуем разные форматы времени
                time_formats = [
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d",
                    "%d.%m.%Y %H:%M:%S",
                    "%d.%m.%Y %H:%M",
                    "%d/%m/%Y %H:%M:%S",
                ]

                parsed_time = None
                for fmt in time_formats:
                    try:
                        parsed_time = datetime.strptime(visit_time, fmt)
                        break
                    except ValueError:
                        continue

                if parsed_time:
                    # Вычисляем разность с текущим временем
                    now = datetime.now()
                    delta = now - parsed_time

                    if delta.days == 0:
                        # Сегодня - показываем время
                        return f"Сегодня, {parsed_time.strftime('%H:%M')}"
                    elif delta.days == 1:
                        # Вчера
                        return f"Вчера, {parsed_time.strftime('%H:%M')}"
                    elif delta.days < 7:
                        # На этой неделе
                        weekdays = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
                        weekday = weekdays[parsed_time.weekday()]
                        return f"{weekday}, {parsed_time.strftime('%H:%M')}"
                    elif delta.days < 365:
                        # В этом году
                        return parsed_time.strftime("%d.%m, %H:%M")
                    else:
                        # Давно
                        return parsed_time.strftime("%d.%m.%Y")
                else:
                    # Если не удалось распарсить, возвращаем как есть
                    return visit_time
            else:
                return str(visit_time)

        except Exception as e:
            logger.error(f"🆘 Ошибка при форматировании времени: {e}")
            return str(visit_time) if visit_time else "Неизвестно"

    def get_default_icon_for_url(self, url):
        """Возвращает иконку по умолчанию в зависимости от URL"""
        try:
            domain = urlparse(url).netloc.lower()

            # Создаем иконку с первой буквой домена
            pixmap = QPixmap(16, 16)
            pixmap.fill(Qt.GlobalColor.transparent)

            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)

            # Определяем цвет фона по домену
            if "google" in domain:
                color = QColor(66, 133, 244)  # Google Blue
                letter = "G"
            elif "github" in domain:
                color = QColor(36, 41, 46)  # GitHub Dark
                letter = "G"
            elif "stackoverflow" in domain:
                color = QColor(244, 128, 36)  # Stack Overflow Orange
                letter = "S"
            elif "wikipedia" in domain:
                color = QColor(153, 153, 153)  # Wikipedia Gray
                letter = "W"
            elif "youtube" in domain:
                color = QColor(255, 0, 0)  # YouTube Red
                letter = "Y"
            elif "facebook" in domain:
                color = QColor(24, 119, 242)  # Facebook Blue
                letter = "F"
            elif "twitter" in domain:
                color = QColor(29, 161, 242)  # Twitter Blue
                letter = "T"
            elif "reddit" in domain:
                color = QColor(255, 69, 0)  # Reddit Orange
                letter = "R"
            elif "amazon" in domain:
                color = QColor(255, 153, 0)  # Amazon Orange
                letter = "A"
            else:
                # Генерируем цвет на основе домена
                hash_val = hash(domain) % 360
                color = QColor.fromHsv(hash_val, 200, 200)
                letter = domain[0].upper() if domain else "W"

            # Рисуем круг с цветом
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(1, 1, 14, 14)

            # Добавляем первую букву домена
            font = QFont()
            font.setPixelSize(10)
            font.setBold(True)
            painter.setFont(font)
            painter.setPen(QColor(255, 255, 255))  # Белый текст

            painter.drawText(0, 0, 16, 16, Qt.AlignmentFlag.AlignCenter, letter)

            painter.end()
            return QIcon(pixmap)

        except Exception as e:
            logger.error(f"🆘 Ошибка при создании иконки: {e}")
            # Возвращаем простую иконку
            pixmap = QPixmap(16, 16)
            pixmap.fill(QColor(100, 100, 100))
            return QIcon(pixmap)

    def open_history_item(self):
        """Открывает выбранный элемент истории в текущей вкладке"""
        current_item = self.history_list.currentItem()
        if current_item and self.parent_browser:
            url = current_item.data(256)
            if url:
                # Открываем в текущей вкладке
                current_tab = self.parent_browser.tab_widget.currentWidget()
                if current_tab:
                    current_tab.navigate_to_url(url)
                    self.close()

    def open_in_new_tab(self):
        """Открывает выбранный элемент истории в новой вкладке"""
        current_item = self.history_list.currentItem()
        if current_item and self.parent_browser:
            url = current_item.data(256)
            if url:
                self.parent_browser.new_tab(url)
                self.close()

    def copy_link(self):
        """Копирует ссылку в буфер обмена"""
        current_item = self.history_list.currentItem()
        if current_item:
            url = current_item.data(256)
            if url:
                clipboard = QApplication.clipboard()
                clipboard.setText(url)
                QMessageBox.information(
                    self, "Скопировано", f"Ссылка скопирована в буфер обмена:\n{url}"
                )

    def clear_history(self):
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Очистить всю историю?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.db_manager.clear_history()
            self.refresh_history()
            QMessageBox.information(
                self, "История очищена", "История посещений очищена!"
            )


class BookmarkManager(QDialog):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.parent_browser = parent
        self.setWindowTitle("Управление закладками")
        # self.setGeometry(300, 300, 700, 500)
        self.resize(400, 700)
        self.setStyleSheet("""
                    QListWidget::item {
                        color: blue;
                    }
                    QListWidget::item:hover {
                        color: #FF0000;
                        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                                    stop: 0 #FAFBFE, stop: 1 lightblue);
                    }
                    QListWidget {
                        background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                                    stop: 0 lightblue, stop: 1 #FAFBFE);
                        border: 1px solid gray;
                        border-radius: 7px;
                        padding: 5px;
                    }
                    QListWidget::item:selected {
                        color: black;
                        background-color: #e3f2fd;
                    }
        """)

        layout = QVBoxLayout(self)

        # Создаем виджет вкладок
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Вкладка "Все закладки"
        self.bookmarks_tab = QWidget()
        self.tab_widget.addTab(self.bookmarks_tab, "📚 Все закладки")
        self.setup_bookmarks_tab()

        # Вкладка "Избранное"
        self.favorites_tab = QWidget()
        self.tab_widget.addTab(self.favorites_tab, "⭐ Избранное")
        self.setup_favorites_tab()

        # Общие кнопки
        button_layout = QHBoxLayout()
        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(self.close)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)
        logger.info("✅ Закладки (BookmarkManager) загружены")
        # Обновляем содержимое
        self.refresh_all()

    def setup_bookmarks_tab(self):
        """Настраивает вкладку всех закладок"""
        layout = QVBoxLayout(self.bookmarks_tab)

        # Заголовок
        header_label = QLabel("📚 Все закладки")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold; margin: 5px;")
        layout.addWidget(header_label)

        # Список закладок
        self.bookmark_list = QListWidget()

        self.bookmark_list.itemDoubleClicked.connect(self.open_bookmark)
        layout.addWidget(self.bookmark_list)

        # Кнопки управления закладками
        bookmark_buttons = QHBoxLayout()

        refresh_bookmarks_button = QPushButton("Обновить")
        refresh_bookmarks_button.clicked.connect(self.refresh_bookmarks)
        bookmark_buttons.addWidget(refresh_bookmarks_button)

        open_bookmark_button = QPushButton("Открыть")
        open_bookmark_button.clicked.connect(self.open_bookmark)
        bookmark_buttons.addWidget(open_bookmark_button)

        add_to_favorites_button = QPushButton("Добавить в избранное")
        add_to_favorites_button.clicked.connect(self.add_to_favorites)
        bookmark_buttons.addWidget(add_to_favorites_button)

        remove_bookmark_button = QPushButton("Удалить")
        remove_bookmark_button.clicked.connect(self.remove_bookmark)
        bookmark_buttons.addWidget(remove_bookmark_button)

        layout.addLayout(bookmark_buttons)

    def setup_favorites_tab(self):
        """Настраивает вкладку избранного"""
        layout = QVBoxLayout(self.favorites_tab)

        # Заголовок
        header_label = QLabel("⭐ Избранные закладки")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold; margin: 5px;")
        layout.addWidget(header_label)

        # Список избранного
        self.favorites_list = QListWidget()

        self.favorites_list.itemDoubleClicked.connect(self.open_favorite)
        layout.addWidget(self.favorites_list)

        # Кнопки управления избранным
        favorites_buttons = QHBoxLayout()

        refresh_favorites_button = QPushButton("Обновить")
        refresh_favorites_button.clicked.connect(self.refresh_favorites)
        favorites_buttons.addWidget(refresh_favorites_button)

        open_favorite_button = QPushButton("Открыть")
        open_favorite_button.clicked.connect(self.open_favorite)
        favorites_buttons.addWidget(open_favorite_button)

        remove_from_favorites_button = QPushButton("Убрать из избранного")
        remove_from_favorites_button.clicked.connect(self.remove_from_favorites)
        favorites_buttons.addWidget(remove_from_favorites_button)

        delete_favorite_button = QPushButton("Удалить полностью")
        delete_favorite_button.clicked.connect(self.delete_favorite)
        favorites_buttons.addWidget(delete_favorite_button)

        layout.addLayout(favorites_buttons)

    def refresh_all(self):
        """Обновляет содержимое всех вкладок"""
        self.refresh_bookmarks()
        self.refresh_favorites()

    def refresh_bookmarks(self):
        """Обновляет список всех закладок"""
        self.bookmark_list.clear()
        bookmarks = self.db_manager.get_bookmarks()

        for row in bookmarks:
            if len(row) >= 5:  # Новый формат с иконками
                url, title, icon_blob, is_favorite, added_time = row
                if icon_blob:
                    icon = self.db_manager.blob_to_icon(icon_blob)
                else:
                    # Создаем иконку по умолчанию для закладки
                    icon = self.get_default_icon_for_url(url)
                favorite_mark = "⭐ " if is_favorite else "📄 "
            else:  # Старый формат без иконок
                url, title, added_time = row
                icon = self.get_default_icon_for_url(url)
                favorite_mark = "📄 "

            # Форматируем отображение
            display_title = title or url
            if len(display_title) > 50:
                display_title = display_title[:50] + "..."

            item_text = (
                f"{favorite_mark}{display_title}\n   🔗 {url}\n   📅 {added_time}"
            )
            item = QListWidgetItem(icon, item_text)
            item.setData(256, url)  # Сохраняем URL
            item.setData(257, title)  # Сохраняем заголовок
            item.setData(
                258, is_favorite if len(row) >= 5 else False
            )  # Сохраняем статус избранного
            self.bookmark_list.addItem(item)

    def get_default_icon_for_url(self, url):
        """Возвращает иконку по умолчанию в зависимости от URL"""
        # Используем тот же метод что и в HistoryManager
        try:
            domain = urlparse(url).netloc.lower()

            # Создаем иконку с первой буквой домена
            pixmap = QPixmap(16, 16)
            pixmap.fill(Qt.GlobalColor.transparent)

            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)

            # Определяем цвет фона по домену
            if "google" in domain:
                color = QColor(66, 133, 244)  # Google Blue
                letter = "G"
            elif "github" in domain:
                color = QColor(36, 41, 46)  # GitHub Dark
                letter = "G"
            elif "stackoverflow" in domain:
                color = QColor(244, 128, 36)  # Stack Overflow Orange
                letter = "S"
            elif "wikipedia" in domain:
                color = QColor(153, 153, 153)  # Wikipedia Gray
                letter = "W"
            elif "youtube" in domain:
                color = QColor(255, 0, 0)  # YouTube Red
                letter = "Y"
            elif "facebook" in domain:
                color = QColor(24, 119, 242)  # Facebook Blue
                letter = "F"
            elif "twitter" in domain:
                color = QColor(29, 161, 242)  # Twitter Blue
                letter = "T"
            elif "reddit" in domain:
                color = QColor(255, 69, 0)  # Reddit Orange
                letter = "R"
            elif "amazon" in domain:
                color = QColor(255, 153, 0)  # Amazon Orange
                letter = "A"
            else:
                # Генерируем цвет на основе домена
                hash_val = hash(domain) % 360
                color = QColor.fromHsv(hash_val, 200, 200)
                letter = domain[0].upper() if domain else "W"

            # Рисуем круг с цветом
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(1, 1, 14, 14)

            # Добавляем первую букву домена
            font = QFont()
            font.setPixelSize(10)
            font.setBold(True)
            painter.setFont(font)
            painter.setPen(QColor(255, 255, 255))  # Белый текст

            painter.drawText(0, 0, 16, 16, Qt.AlignmentFlag.AlignCenter, letter)

            painter.end()
            return QIcon(pixmap)

        except Exception as e:
            logger.error(f"🆘 Ошибка при создании иконки: {e}")
            # Возвращаем простую иконку
            pixmap = QPixmap(16, 16)
            pixmap.fill(QColor(100, 100, 100))
            return QIcon(pixmap)

    def refresh_favorites(self):
        """Обновляет список избранного"""
        self.favorites_list.clear()
        favorites = self.db_manager.get_favorites()

        for url, title, icon_blob in favorites:
            if icon_blob:
                icon = self.db_manager.blob_to_icon(icon_blob)
            else:
                # Создаем иконку по умолчанию для избранного
                icon = self.get_default_icon_for_url(url)

            # Форматируем отображение
            display_title = title or url
            if len(display_title) > 50:
                display_title = display_title[:50] + "..."

            item_text = f"⭐ {display_title}\n   🔗 {url}"
            item = QListWidgetItem(icon, item_text)
            item.setData(256, url)  # Сохраняем URL
            item.setData(257, title)  # Сохраняем заголовок
            self.favorites_list.addItem(item)

    def open_bookmark(self):
        """Открывает выбранную закладку"""
        current_item = self.bookmark_list.currentItem()
        if current_item and self.parent_browser:
            url = current_item.data(256)
            if url:
                # Открываем в новой вкладке
                self.parent_browser.new_tab(url)
                self.close()

    def open_favorite(self):
        """Открывает выбранное избранное"""
        current_item = self.favorites_list.currentItem()
        if current_item and self.parent_browser:
            url = current_item.data(256)
            if url:
                # Открываем в новой вкладке
                self.parent_browser.new_tab(url)
                self.close()

    def add_to_favorites(self):
        """Добавляет выбранную закладку в избранное"""
        current_item = self.bookmark_list.currentItem()
        if current_item:
            url = current_item.data(256)
            is_favorite = current_item.data(258)

            if not is_favorite:
                self.db_manager.toggle_favorite(url)
                self.refresh_all()

                # Обновляем панель избранного в браузере
                if self.parent_browser:
                    self.parent_browser.favorites_bar.refresh_favorites()

                QMessageBox.information(
                    self, "Добавлено", "Закладка добавлена в избранное!"
                )
            else:
                QMessageBox.information(
                    self, "Уже в избранном", "Эта закладка уже в избранном!"
                )

    def remove_from_favorites(self):
        """Убирает из избранного (но не удаляет закладку)"""
        current_item = self.favorites_list.currentItem()
        if current_item:
            url = current_item.data(256)
            title = current_item.data(257)

            reply = QMessageBox.question(
                self,
                "Убрать из избранного",
                f"Убрать '{title}' из избранного?\n\nЗакладка останется в общем списке.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.db_manager.toggle_favorite(url)
                self.refresh_all()

                # Обновляем панель избранного в браузере
                if self.parent_browser:
                    self.parent_browser.favorites_bar.refresh_favorites()

                QMessageBox.information(
                    self, "Убрано", "Закладка убрана из избранного!"
                )

    def delete_favorite(self):
        """Полностью удаляет избранную закладку"""
        current_item = self.favorites_list.currentItem()
        if current_item:
            url = current_item.data(256)
            title = current_item.data(257)

            reply = QMessageBox.question(
                self,
                "Удалить закладку",
                f"Полностью удалить '{title}'?\n\nЗакладка будет удалена навсегда.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.db_manager.remove_bookmark(url)
                self.refresh_all()

                # Обновляем панель избранного в браузере
                if self.parent_browser:
                    self.parent_browser.favorites_bar.refresh_favorites()

                QMessageBox.information(self, "Удалено", "Закладка удалена!")

    def remove_bookmark(self):
        """Удаляет выбранную закладку"""
        current_item = self.bookmark_list.currentItem()
        if current_item:
            url = current_item.data(256)
            title = current_item.data(257)

            reply = QMessageBox.question(
                self,
                "Удалить закладку",
                f"Удалить '{title}'?\n\nЗакладка будет удалена навсегда.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.db_manager.remove_bookmark(url)
                self.refresh_all()

                # Обновляем панель избранного в браузере
                if self.parent_browser:
                    self.parent_browser.favorites_bar.refresh_favorites()

                QMessageBox.information(self, "Удалено", "Закладка удалена!")


class SettingsManager(QDialog):
    def __init__(self, db_manager, parent_browser=None, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.parent_browser = parent_browser
        self.setWindowTitle("Настройки")
        self.setGeometry(300, 300, 400, 300)

        layout = QVBoxLayout(self)

        # Настройки загрузок
        download_group = QGroupBox("Загрузки")
        download_layout = QVBoxLayout()

        download_path_layout = QHBoxLayout()
        download_path_layout.addWidget(QLabel("Папка загрузок:"))
        self.download_path_edit = QLineEdit(
            self.db_manager.get_setting("download_path", "")
        )
        browse_button = QPushButton("Обзор")
        browse_button.clicked.connect(self.browse_download_path)

        download_path_layout.addWidget(self.download_path_edit)
        download_path_layout.addWidget(browse_button)
        download_layout.addLayout(download_path_layout)

        download_group.setLayout(download_layout)
        layout.addWidget(download_group)

        # Настройки AdBlock
        adblock_group = QGroupBox("Блокировка рекламы")
        adblock_layout = QVBoxLayout()

        self.adblock_checkbox = QCheckBox("Включить блокировку рекламы")
        self.adblock_checkbox.setChecked(
            self.db_manager.get_setting("adblock_enabled", "true") == "true"
        )
        self.adblock_checkbox.stateChanged.connect(self.toggle_adblock)
        adblock_layout.addWidget(self.adblock_checkbox)

        # Режим AdBlock
        adblock_mode_layout = QHBoxLayout()
        adblock_mode_layout.addWidget(QLabel("Режим AdBlock:"))

        self.adblock_mode_combo = QComboBox()
        self.adblock_mode_combo.addItems(["Продвинутый (EasyList)", "Базовый"])
        current_mode = self.db_manager.get_setting("adblock_mode", "advanced")
        self.adblock_mode_combo.setCurrentIndex(0 if current_mode == "advanced" else 1)
        adblock_mode_layout.addWidget(self.adblock_mode_combo)

        adblock_layout.addLayout(adblock_mode_layout)

        # Статистика AdBlock
        if self.parent_browser:
            stats_label = QLabel(
                f"Заблокировано URL: {self.parent_browser.get_adblock_stats()}"
            )
            adblock_layout.addWidget(stats_label)

        adblock_group.setLayout(adblock_layout)
        layout.addWidget(adblock_group)

        # Кнопка сохранения
        save_button = QPushButton("Сохранить")
        save_button.clicked.connect(self.save_settings)
        layout.addWidget(save_button)
        logger.info("✅ Менеджер настроек инициализирован")

    def browse_download_path(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку для загрузок")
        if path:
            self.download_path_edit.setText(path)
            logger.info(f"✅ Папка загрузок изменена на: {path}")

    def toggle_adblock(self, state):
        enabled = state == 2  # Qt.CheckState.Checked
        self.db_manager.save_setting("adblock_enabled", "true" if enabled else "false")
        if self.parent_browser:
            self.parent_browser.toggle_adblock(enabled)
            logger.info(
                f"✅ Блокировка рекламы {'включена' if enabled else 'выключена'}"
            )

    def save_settings(self):
        self.db_manager.save_setting("download_path", self.download_path_edit.text())

        # Сохраняем режим AdBlock
        if hasattr(self, "adblock_mode_combo"):
            mode = (
                "advanced" if self.adblock_mode_combo.currentIndex() == 0 else "basic"
            )
            self.db_manager.save_setting("adblock_mode", mode)

            # Обновляем режим в браузере
            if self.parent_browser:
                self.parent_browser.use_advanced_adblock = mode == "advanced"
                if (
                    self.parent_browser.db_manager.get_setting(
                        "adblock_enabled", "true"
                    )
                    == "true"
                ):
                    self.parent_browser.toggle_adblock(True)
        logger.info("✅ Настройки сохранены!")
        QMessageBox.information(self, "Настройки", "Настройки сохранены!")


class MainBrowser(QMainWindow):
    def __init__(self, profile_name="default"):
        super().__init__()
        logger.info("MainBrowser loaded")
        self.db_manager = DatabaseManager()
        # Создаем профиль браузера
        self.browser_profile = BrowserProfile(profile_name)
        self.current_profile = self.browser_profile.get_profile()
        # Для обратной совместимости
        self.adblock_interceptor = self.browser_profile.interceptor
        self.legacy_adblock_interceptor = LegacyAdBlocker()
        # Загружаем сохраненный режим AdBlock (по умолчанию базовый для стабильности)
        saved_mode = self.db_manager.get_setting("adblock_mode", "basic")
        self.use_advanced_adblock = saved_mode == "advanced"

        # Активные загрузки
        self.active_downloads = {}

        self.init_ui()

        self.setup_adblock()
        # self.setup_download_handling()
        # logger.info("MainBrowser download handling setup completed")

    def init_ui(self):
        self.setWindowTitle("OBrowser")
        self.setWindowIcon(QIcon(os.path.join("images", "browser.png")))
        self.setGeometry(100, 100, 1200, 800)
        self.setIconSize(QSize(32, 32))
        self.setStyleSheet("""
                            QTabWidget::tab-bar {
                                border: 2px solid blue;
                            }
                            QTabWidget::pane { 
                                border: none;
                            }
                            QTabBar {
                                background-color: #DBDBDB;
                            }
                            QTabBar::tab {
                                background-color: black;
                                color: white;
                                padding: 6px 6px 6px 6px;
                                border-top-left-radius: 10px;
                                border-top-right-radius: 10px;
                                max-width: 200px;
                                text-align: left;
                            }
                            QTabBar::tab:!selected {
                                background-color: transparent; 
                            }
                            QTabBar::tab:!selected:hover {
                                background-color: #D8BFD8;
                            }
                            QTabBar::tab:selected {
                                background-color: #92C6D9; 
                                color: white;;
                            }
                            QStatusBar {
                                color: blue;
                                font-size: 12px;
                                border: 1px solid gray;
                                border-radius: 7px;
                            }
                            QStatusBar::QProgressBar {
                                border: 2px solid #2196F3;     
                                border-radius: 7px;
                                background-color: #E0E0E0;
                                color: gray;
                            }
                            QPushButton {
                                background-color: transparent;
                                border: 1px outset gray;
                                padding: 2px 3px;
                                border-radius: 7px;
                            }
                            QPushButton:hover {
                                background-color: #e0e0e0;
                                color: blue;
                            }
                            QPushButton:pressed {
                                background-color: #d0d0d0;
                            }
                            QToolTip {
                                background-color: #CCF0FE;
                                color: blue;
                                border: 2px dashed #FF0000;
                                border-radius: 7px;
                                padding: 2px;
                                font: 10pt "Segoe UI";
                            }
                        """)
        logger.info("Стили браузера загружены")

        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Панель навигации
        nav_layout = QHBoxLayout()
        nav_layout.setContentsMargins(3, 2, 3, 2)

        self.back_button = QPushButton("")
        self.back_button.setStyleSheet("""QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px 10px;
                text-align: left;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }""")
        self.back_button.setIcon(QIcon(os.path.join("images", "back.png")))
        self.back_button.setToolTip("Назад")
        self.forward_button = QPushButton("")
        self.forward_button.setStyleSheet("""QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px 10px;
                text-align: left;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }""")
        self.forward_button.setIcon(QIcon(os.path.join("images", "forward.png")))
        self.forward_button.setToolTip("Вперед")
        self.reload_button = QPushButton("")
        self.reload_button.setStyleSheet("""QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px 10px;
                text-align: left;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }""")
        self.reload_button.setIcon(QIcon(os.path.join("images", "refresh.png")))
        self.reload_button.setToolTip("Перезагрузить страницу")
        self.home_button = QPushButton("")
        self.home_button.setStyleSheet("""QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px 10px;
                text-align: left;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }""")
        self.home_button.setIcon(QIcon(os.path.join("images", "home.png")))
        self.home_button.setToolTip("Домашняя страница")

        self.address_bar = QLineEdit()
        self.address_bar.setPlaceholderText("Введите URL или поисковый запрос")
        self.address_bar.returnPressed.connect(self.navigate_to_url)

        # Автоматическое выделение адреса при щелчке
        self.address_bar.mousePressEvent = self.address_bar_click

        self.bookmark_button = QPushButton("")
        self.bookmark_button.setStyleSheet("""QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px 10px;
                text-align: left;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }""")
        self.bookmark_button.setIcon(QIcon(os.path.join("images", "bookmarks_.png")))
        self.bookmark_button.setToolTip("Добавить в закладки")
        self.bookmark_button.clicked.connect(self.add_bookmark)

        nav_layout.addWidget(self.back_button)
        nav_layout.addWidget(self.forward_button)
        nav_layout.addWidget(self.reload_button)
        nav_layout.addWidget(self.home_button)
        nav_layout.addWidget(self.address_bar)
        nav_layout.addWidget(self.bookmark_button)

        main_layout.addLayout(nav_layout)

        # Панель избранного
        self.favorites_bar = FavoritesBar(self.db_manager, self)
        main_layout.addWidget(self.favorites_bar)

        # Вкладки
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.currentChanged.connect(self.tab_changed)
        self.tab_widget.tabBarDoubleClicked.connect(self.tab_bar_double_click)

        # Добавляем обработчик двойного клика для создания новой вкладки
        # self.tab_widget.mouseDoubleClickEvent = self.tab_widget_double_click

        # Кнопка новой вкладки
        # new_tab_button = QPushButton("")
        # new_tab_button.setIcon(QIcon(os.path.join("images", "plus.png")))
        # new_tab_button.setMaximumWidth(30)
        # new_tab_button.setToolTip(
        #     "Создать новую вкладку\n(или двойной клик на свободной области)"
        # )
        # new_tab_button.setStyleSheet("""QPushButton {
        #         background-color: transparent;
        #         border: none;
        #         padding: 5px 10px;
        #         text-align: left;
        #         border-radius: 5px;
        #     }
        #     QPushButton:hover {
        #         background-color: #e0e0e0;
        #     }
        #     QPushButton:pressed {
        #         background-color: #d0d0d0;
        #     }""")
        # new_tab_button.clicked.connect(self.new_tab)
        # self.tab_widget.setCornerWidget(new_tab_button)

        main_layout.addWidget(self.tab_widget)

        # Строка состояния
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Прогресс-бар
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        # Индикатор масштаба (кликабельный)
        self.zoom_label = QLabel("100%")
        self.zoom_label.setMinimumWidth(50)
        self.zoom_label.setStyleSheet("""
            QLabel {
                padding: 2px 5px;
                border: 1px solid #ccc;
                border-radius: 3px;
                background-color: #f9f9f9;
            }
            QLabel:hover {
                background-color: #e6e6e6;
                border-color: #999;
            }
        """)
        self.zoom_label.setToolTip("Масштаб страницы (щелкните для быстрого сброса)")
        self.zoom_label.mousePressEvent = self.zoom_label_clicked
        self.status_bar.addPermanentWidget(self.zoom_label)

        # Подключение кнопок навигации
        self.back_button.clicked.connect(self.go_back)
        self.forward_button.clicked.connect(self.go_forward)
        self.reload_button.clicked.connect(self.reload_page)
        self.home_button.clicked.connect(self.go_home)
        logger.info("браузер инициализирован")
        # Дополнительная настройка адресной строки
        self.setup_address_bar()

        # Создание меню
        self.create_menu()

        # Загружаем настройки видимости панели избранного
        favorites_visible = self.db_manager.get_setting("favorites_bar_visible", "true")
        if favorites_visible == "false":
            self.favorites_bar.hide()

        # Первая вкладка
        try:
            self.new_tab("https://www.google.com", self.current_profile)
            logger.info("✅ Первая вкладка браузера создана")
        except Exception as e:
            # print(f"Ошибка при создании первой вкладки: {e}")
            logger.error(f"🆘 Ошибка при создании первой вкладки: {e}")
            # Создаем простую вкладку
            try:
                tab = BrowserTab("https://www.google.com", None)
                index = self.tab_widget.addTab(tab, "Google")
                self.tab_widget.setCurrentIndex(index)
            except Exception as e2:
                logger.error(f"🆘 Критическая ошибка: {e2}")
                # В крайнем случае создаем пустую вкладку
                label = QLabel("Ошибка при создании вкладки")
                self.tab_widget.addTab(label, "Ошибка")

    def tab_bar_double_click(self, index):
        if index == -1:
            self.new_tab("https://www.google.com")
            self.update_status_bar("📑 Новая вкладка создана двойным кликом")
        else:
            # Двойной клик по существующей вкладке - ничего не делаем
            self.update_status_bar("📑 Двойной клик по вкладке - ничего не происходит")

    def create_menu(self):
        menubar = self.menuBar()

        # Меню Файл
        file_menu = menubar.addMenu("Файл")

        new_tab_action = QAction(
            QIcon(os.path.join("images", "newtab.png")), "Новая вкладка", self
        )
        new_tab_action.setShortcut("Ctrl+T")
        new_tab_action.setStatusTip(
            "Создать новую вкладку (Ctrl+T или двойной клик на панели вкладок)"
        )
        new_tab_action.triggered.connect(self.new_tab)
        file_menu.addAction(new_tab_action)

        new_window_action = QAction(
            QIcon(os.path.join("images", "window.png")), "Новое окно", self
        )
        new_window_action.setShortcut("Ctrl+N")
        new_window_action.triggered.connect(self.new_window)
        file_menu.addAction(new_window_action)

        new_profile_action = QAction(
            QIcon(os.path.join("images", "profile.png")), "Новый профиль", self
        )
        new_profile_action.setShortcut("Ctrl+Shift+N")
        new_profile_action.triggered.connect(self.new_profile_window)
        file_menu.addAction(new_profile_action)

        file_menu.addSeparator()

        # Работа с файлами
        open_html_action = QAction(
            QIcon(os.path.join("images", "html.png")), "Открыть HTML файл", self
        )
        open_html_action.setShortcut("Ctrl+O")
        open_html_action.triggered.connect(self.open_html_file)
        file_menu.addAction(open_html_action)

        # Подменю сохранения
        save_submenu = file_menu.addMenu(
            QIcon(os.path.join("images", "savemod.png")), "Сохранить как..."
        )

        save_mhtml_action = QAction(
            QIcon(os.path.join("images", "mhtml.png")), "Сохранить как MHTML", self
        )
        save_mhtml_action.setShortcut("Ctrl+S")
        save_mhtml_action.triggered.connect(self.save_current_page_mhtml)
        save_submenu.addAction(save_mhtml_action)

        save_html_action = QAction(
            QIcon(os.path.join("images", "html_.png")), "Сохранить как HTML", self
        )
        save_html_action.setShortcut("Ctrl+Shift+S")
        save_html_action.triggered.connect(self.save_current_page_html)
        save_submenu.addAction(save_html_action)

        save_pdf_action = QAction(
            QIcon(os.path.join("images", "pdf.png")), "Сохранить как PDF", self
        )
        save_pdf_action.setShortcut("Ctrl+P")
        save_pdf_action.triggered.connect(self.save_current_page_pdf)
        save_submenu.addAction(save_pdf_action)

        file_menu.addSeparator()

        exit_action = QAction(QIcon(os.path.join("images", "exit.png")), "Выход", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Меню История
        history_menu = menubar.addMenu("История")

        show_history_action = QAction(
            QIcon(os.path.join("images", "history.png")), "Показать историю", self
        )
        show_history_action.triggered.connect(self.show_history)
        history_menu.addAction(show_history_action)

        # Меню Закладки
        bookmarks_menu = menubar.addMenu("Закладки")

        add_bookmark_action = QAction(
            QIcon(os.path.join("images", "bookmark.png")), "Добавить закладку", self
        )
        add_bookmark_action.setShortcut("Ctrl+D")
        add_bookmark_action.triggered.connect(self.add_bookmark)
        bookmarks_menu.addAction(add_bookmark_action)

        bookmarks_menu.addSeparator()

        show_bookmarks_action = QAction(
            QIcon(os.path.join("images", "bookmark1.png")),
            "Управление закладками",
            self,
        )
        show_bookmarks_action.triggered.connect(self.show_bookmarks)
        bookmarks_menu.addAction(show_bookmarks_action)

        # Меню Вид
        view_menu = menubar.addMenu("Вид")

        # Подменю управления масштабом
        zoom_submenu = view_menu.addMenu(
            QIcon(os.path.join("images", "zoom.png")), "Масштаб"
        )

        zoom_in_action = QAction(
            QIcon(os.path.join("images", "zoomin.png")), "Увеличить", self
        )
        zoom_in_action.setShortcut("Ctrl++")
        zoom_in_action.triggered.connect(self.zoom_in)
        zoom_submenu.addAction(zoom_in_action)

        zoom_out_action = QAction(
            QIcon(os.path.join("images", "zoomout.png")), "Уменьшить", self
        )
        zoom_out_action.setShortcut("Ctrl+-")
        zoom_out_action.triggered.connect(self.zoom_out)
        zoom_submenu.addAction(zoom_out_action)

        reset_zoom_action = QAction(
            QIcon(os.path.join("images", "zoomreset.png")),
            "Сбросить масштаб (100%)",
            self,
        )
        reset_zoom_action.setShortcut("Ctrl+0")
        reset_zoom_action.triggered.connect(self.reset_zoom)
        zoom_submenu.addAction(reset_zoom_action)

        zoom_submenu.addSeparator()

        # Предустановленные масштабы
        zoom_50_action = QAction("50%", self)
        zoom_50_action.triggered.connect(lambda: self.set_zoom(0.5))
        zoom_submenu.addAction(zoom_50_action)

        zoom_75_action = QAction("75%", self)
        zoom_75_action.triggered.connect(lambda: self.set_zoom(0.75))
        zoom_submenu.addAction(zoom_75_action)

        zoom_100_action = QAction("100%", self)
        zoom_100_action.triggered.connect(lambda: self.set_zoom(1.0))
        zoom_submenu.addAction(zoom_100_action)

        zoom_125_action = QAction("125%", self)
        zoom_125_action.triggered.connect(lambda: self.set_zoom(1.25))
        zoom_submenu.addAction(zoom_125_action)

        zoom_150_action = QAction("150%", self)
        zoom_150_action.triggered.connect(lambda: self.set_zoom(1.5))
        zoom_submenu.addAction(zoom_150_action)

        zoom_200_action = QAction("200%", self)
        zoom_200_action.triggered.connect(lambda: self.set_zoom(2.0))
        zoom_submenu.addAction(zoom_200_action)

        zoom_submenu.addSeparator()

        # Полноэкранный режим
        fullscreen_action = QAction(
            QIcon(os.path.join("images", "fullscreen.png")), "Полноэкранный режим", self
        )
        fullscreen_action.setShortcut("F11")
        fullscreen_action.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(fullscreen_action)

        view_menu.addSeparator()

        # Панели
        toggle_favorites_bar_action = QAction(
            QIcon(os.path.join("images", "favorite.png")),
            "Показать/скрыть панель избранного",
            self,
        )
        toggle_favorites_bar_action.triggered.connect(self.toggle_favorites_bar)
        view_menu.addAction(toggle_favorites_bar_action)

        # Меню Инструменты
        tools_menu = menubar.addMenu("Инструменты")

        downloads_action = QAction(
            QIcon(os.path.join("images", "download.png")), "Загрузки", self
        )
        downloads_action.triggered.connect(self.show_downloads)
        tools_menu.addAction(downloads_action)

        settings_action = QAction(
            QIcon(os.path.join("images", "settings.png")), "Настройки", self
        )
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)

        profile_info_action = QAction(
            QIcon(os.path.join("images", "userprofile.png")),
            "Информация о профиле",
            self,
        )
        profile_info_action.triggered.connect(self.show_profile_info)
        tools_menu.addAction(profile_info_action)

        backup_profile_action = QAction(
            QIcon(os.path.join("images", "backup.png")),
            "Создать резервную копию профиля",
            self,
        )
        backup_profile_action.triggered.connect(self.backup_profile)
        tools_menu.addAction(backup_profile_action)

        tools_menu.addSeparator()

        # AdBlock настройки
        adblock_submenu = tools_menu.addMenu(
            QIcon(os.path.join("images", "adblockplus.png")), "AdBlock"
        )

        # Быстрое отключение/включение AdBlock
        disable_adblock_action = QAction(
            QIcon(os.path.join("images", "adblockoff.png")),
            "Отключить AdBlock для этого сайта",
            self,
        )
        disable_adblock_action.triggered.connect(self.disable_adblock_for_site)
        adblock_submenu.addAction(disable_adblock_action)

        enable_adblock_action = QAction(
            QIcon(os.path.join("images", "adblock.png")),
            "Включить AdBlock",
            self,
        )
        enable_adblock_action.triggered.connect(lambda: self.toggle_adblock(True))
        adblock_submenu.addAction(enable_adblock_action)

        adblock_submenu.addSeparator()

        toggle_adblock_mode_action = QAction(
            QIcon(os.path.join("images", "offone.png")),
            "Переключить режим AdBlock",
            self,
        )
        toggle_adblock_mode_action.triggered.connect(self.toggle_adblock_mode)
        adblock_submenu.addAction(toggle_adblock_mode_action)

        show_adblock_stats_action = QAction(
            QIcon(os.path.join("images", "statistics.png")),
            "Показать статистику блокировки",
            self,
        )
        show_adblock_stats_action.triggered.connect(self.show_adblock_stats)
        adblock_submenu.addAction(show_adblock_stats_action)

        view_blocked_urls_action = QAction(
            QIcon(os.path.join("images", "listurl.png")),
            "Просмотреть заблокированные URL",
            self,
        )
        view_blocked_urls_action.triggered.connect(self.view_blocked_urls)
        adblock_submenu.addAction(view_blocked_urls_action)

        add_custom_rule_action = QAction(
            QIcon(os.path.join("images", "ruleadd.png")),
            "Добавить пользовательское правило",
            self,
        )
        add_custom_rule_action.triggered.connect(self.add_custom_adblock_rule)
        adblock_submenu.addAction(add_custom_rule_action)

        tools_menu.addSeparator()

        clear_data_action = QAction(
            QIcon(os.path.join("images", "clearall.png")),
            "Очистить данные браузера",
            self,
        )
        clear_data_action.triggered.connect(self.clear_browser_data)
        tools_menu.addAction(clear_data_action)

        reset_for_google_action = QAction(
            QIcon(os.path.join("images", "skip.png")),
            "Сбросить для авторизации в Google",
            self,
        )
        reset_for_google_action.triggered.connect(self.reset_for_google_auth)
        tools_menu.addAction(reset_for_google_action)

        google_mode_action = QAction(
            QIcon(os.path.join("images", "google.png")),
            "Режим Google (без ограничений)",
            self,
        )
        google_mode_action.triggered.connect(self.enable_google_mode)
        tools_menu.addAction(google_mode_action)
        logger.info("Главное меню настроено")

    def show_profile_info(self):
        """Показывает информацию о текущем профиле"""
        info = self.browser_profile.get_profile_info()
        # print(info)
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle("Информация о профиле браузера")
        msg.setText("Данные профиля для сохранения авторизаций:")

        info_text = f"""
📁 Имя профиля: {info["name"]}
📂 Путь к данным: {info["path"]}
💾 Путь кэша: {info["cache_path"]}
🍪 Политика cookies: {info["cookies_policy"]}
🗃️ Тип кэша: {info["cache_type"]}
📊 Размер кэша: {info["cache_max_size"] // (1024 * 1024)} МБ

📋 Файлы профиля:
"""

        # Проверяем наличие важных файлов
        profile_files = [
            ("Cookies", "🍪 Файл cookies"),
            ("Local Storage", "💾 Локальное хранилище"),
            ("Session Storage", "📱 Сессионное хранилище"),
            ("IndexedDB", "🗄️ База данных IndexedDB"),
            ("Web Data", "🌐 Веб-данные"),
            ("Preferences", "⚙️ Настройки"),
        ]

        for filename, description in profile_files:
            file_path = os.path.join(info["path"], filename)

            if os.path.exists(file_path):
                if os.path.isdir(file_path):
                    size = sum(
                        os.path.getsize(os.path.join(file_path, f))
                        for f in os.listdir(file_path)
                        if os.path.isfile(os.path.join(file_path, f))
                    )
                else:
                    size = os.path.getsize(file_path)
                size_mb = size / (1024 * 1024)
                info_text += f"✅ {description}: {size_mb:.3f} МБ\n"
            else:
                info_text += f"❌ {description}: не найден\n"

        msg.setInformativeText(info_text)

        # Кнопки действий
        open_folder_btn = msg.addButton(
            "📂 Открыть папку профиля", QMessageBox.ButtonRole.ActionRole
        )
        backup_btn = msg.addButton(
            "💾 Создать резервную копию", QMessageBox.ButtonRole.ActionRole
        )
        msg.addButton("OK", QMessageBox.ButtonRole.AcceptRole)

        msg.exec()

        if msg.clickedButton() == open_folder_btn:
            self.open_profile_folder()
        elif msg.clickedButton() == backup_btn:
            self.backup_profile()

    def open_profile_folder(self):
        """Открывает папку профиля в проводнике"""
        try:
            profile_path = self.browser_profile.profile_dir
            import subprocess
            import platform

            system = platform.system()
            if system == "Windows":
                subprocess.run(["explorer", profile_path])
            elif system == "Darwin":  # macOS
                subprocess.run(["open", profile_path])
            else:  # Linux
                subprocess.run(["xdg-open", profile_path])

            self.update_status_bar(f"📂 Открыта папка профиля: {profile_path}")
        except Exception as e:
            QMessageBox.warning(
                self, "Ошибка", f"Не удалось открыть папку профиля:\n{e}"
            )

    def backup_profile(self):
        """Создает резервную копию профиля"""
        try:
            backup_path = self.browser_profile.backup_profile_data()
            if backup_path:
                QMessageBox.information(
                    self,
                    "Резервная копия создана",
                    f"Резервная копия профиля создана:\n{backup_path}\n\n"
                    "Это поможет восстановить ваши данные в случае проблем.",
                )
                self.update_status_bar("💾 Резервная копия профиля создана")
            else:
                QMessageBox.warning(
                    self, "Ошибка", "Не удалось создать резервную копию профиля"
                )
        except Exception as e:
            QMessageBox.warning(
                self, "Ошибка", f"Ошибка при создании резервной копии:\n{e}"
            )

    def setup_adblock(self):
        if self.db_manager.get_setting("adblock_enabled", "true") == "true":
            self.toggle_adblock(True)

    def show_download_progress(self, download, filename, download_path):
        """Показывает окно прогресса загрузки"""
        try:
            # Создаем окно прогресса загрузки
            progress_dialog = QProgressDialog(
                f"Загрузка: {filename}", "Отмена", 0, 100, self
            )
            progress_dialog.setWindowTitle("Загрузка файла")
            progress_dialog.setAutoClose(False)
            progress_dialog.setAutoReset(False)
            progress_dialog.show()

            # Сохраняем ссылку на диалог
            self.active_downloads[download] = {
                "filename": filename,
                "path": download_path,
                "progress": 0,
                "dialog": progress_dialog,
            }

            # Подключаем кнопку отмены
            progress_dialog.canceled.connect(lambda: self.cancel_download(download))

            # Добавляем загрузку в менеджер загрузок
            if hasattr(self, "download_manager"):
                # Если менеджер открыт, добавляем сразу
                url = getattr(download, "url", lambda: download_path)()
                if hasattr(url, "toString"):
                    url = url.toString()

                self.download_manager.add_download(url, download_path)

            # Показываем уведомление в статус-баре
            self.update_status_bar(f"📥 Начата загрузка: {filename}")

        except Exception as e:
            logger.error(f"🆘 Ошибка при создании окна прогресса: {e}")

    def cancel_download(self, download):
        """Отменяет загрузку"""
        try:
            if hasattr(download, "cancel"):
                download.cancel()

            # Удаляем из активных загрузок
            if download in self.active_downloads:
                del self.active_downloads[download]

            self.update_status_bar("❌ Загрузка отменена")

        except Exception as e:
            logger.error(f"🆘 Ошибка при отмене загрузки: {e}")

    def open_download_folder(self, file_path):
        """Открывает папку с загруженным файлом"""
        try:
            import subprocess
            import platform

            system = platform.system()
            if system == "Windows":
                subprocess.run(["explorer", "/select,", file_path])
            elif system == "Darwin":  # macOS
                subprocess.run(["open", "-R", file_path])
            else:  # Linux
                subprocess.run(["xdg-open", os.path.dirname(file_path)])
        except Exception as e:
            logger.error(f"🆘 Ошибка при открытии папки: {e}")
            # Альтернативный способ - открыть только папку
            try:
                import webbrowser

                webbrowser.open(f"file://{os.path.dirname(file_path)}")
            except Exception as e2:
                logger.error(f"🆘 Альтернативный способ тоже не сработал: {e2}")

    def toggle_adblock(self, enabled):
        if enabled:
            # Используем продвинутый или базовый AdBlock в зависимости от настроек
            if self.use_advanced_adblock:
                self.current_profile.setUrlRequestInterceptor(self.adblock_interceptor)
            else:
                self.current_profile.setUrlRequestInterceptor(
                    self.legacy_adblock_interceptor
                )
        else:
            self.current_profile.setUrlRequestInterceptor(None)

    def toggle_adblock_mode(self):
        """Переключает между продвинутым и базовым AdBlock"""
        self.use_advanced_adblock = not self.use_advanced_adblock
        if self.db_manager.get_setting("adblock_enabled", "true") == "true":
            self.toggle_adblock(True)

        mode_text = "продвинутый" if self.use_advanced_adblock else "базовый"
        self.db_manager.save_setting(
            "adblock_mode", "advanced" if self.use_advanced_adblock else "basic"
        )
        self.update_status_bar(f"AdBlock режим: {mode_text}")
        logger.info(f"✅ AdBlock режим переключен на: {mode_text}")

    def get_adblock_stats(self):
        """Получает статистику блокировки"""
        if self.use_advanced_adblock:
            return self.browser_profile.get_adblock_stats()
        return 0

    def show_adblock_stats(self):
        """Показывает статистику блокировки AdBlock"""
        blocked_count = self.get_adblock_stats()
        mode_text = "продвинутый" if self.use_advanced_adblock else "базовый"

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle("Статистика AdBlock")
        msg.setText(f"Статистика блокировки рекламы")
        msg.setInformativeText(
            f"Режим AdBlock: {mode_text}\n"
            f"Заблокировано URL: {blocked_count}\n\n"
            f"Продвинутый режим использует EasyList и расширенные правила.\n"
            f"Базовый режим использует простые правила блокировки."
        )
        msg.exec()

    def view_blocked_urls(self):
        """Показывает диалог с заблокированными URL"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Заблокированные URL")
        # dialog.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        text_edit.setPlaceholderText("Здесь будут показаны заблокированные URL")
        text_edit.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)

        #

        # Получаем список заблокированных URL
        # blocked_urls = []  # Здесь нужно хранить историю блокировок
        text_edit.setText("\nURL-".join(blocked_urls))

        layout.addWidget(text_edit)
        dialog.setLayout(layout)
        dialog.resize(800, 600)
        dialog.show()

    def clear_adblock_stats(self):
        """Очищает статистику блокировки"""
        if self.use_advanced_adblock:
            self.browser_profile.clear_adblock_stats()

        QMessageBox.information(
            self, "Статистика очищена", "Статистика блокировки AdBlock очищена."
        )

    def new_tab(self, url="https://www.google.com", profile=None):
        try:
            # Проверяем, что url является строкой
            if not isinstance(url, str):
                # print(
                #    f"Предупреждение: URL не является строкой: {url}, используем Google"
                # )
                logger.warning(
                    f"🚩 Предупреждение: URL не является строкой: {url}, используем Google"
                )
                url = "https://www.google.com"

            tab = BrowserTab(url, self.current_profile)
            index = self.tab_widget.addTab(tab, "Новая вкладка")
            self.tab_widget.setCurrentIndex(index)

            tab.urlChanged.connect(self.url_changed)
            tab.titleChanged.connect(self.title_changed)
            tab.loadProgress.connect(self.load_progress)
            tab.iconChanged.connect(self.icon_changed)
            tab.zoomChanged.connect(self.zoom_changed)

            return tab
        except Exception as e:
            # print(f"Ошибка при создании вкладки: {e}")
            logger.error(f"🆘 Ошибка при создании вкладки: {e}")
            # Создаем вкладку без профиля
            try:
                tab = BrowserTab(
                    url if isinstance(url, str) else "https://www.google.com", None
                )
                index = self.tab_widget.addTab(tab, "Новая вкладка")
                self.tab_widget.setCurrentIndex(index)

                tab.urlChanged.connect(self.url_changed)
                tab.titleChanged.connect(self.title_changed)
                tab.loadProgress.connect(self.load_progress)
                tab.iconChanged.connect(self.icon_changed)
                tab.zoomChanged.connect(self.zoom_changed)

                return tab
            except Exception as e2:
                # print(f"Критическая ошибка при создании вкладки: {e2}")
                logger.error(f"🆘 Критическая ошибка при создании вкладки: {e2}")
                return None

    def close_tab(self, index):
        """ИСПРАВЛЕНО: Закрывает вкладку с корректной очисткой ресурсов"""
        if self.tab_widget.count() > 1:
            # Получаем вкладку перед удалением
            tab_widget = self.tab_widget.widget(index)

            # Корректно очищаем ресурсы WebEnginePage
            if tab_widget and hasattr(tab_widget, "web_view"):
                web_view = tab_widget.web_view
                if web_view:
                    # Останавливаем загрузку
                    web_view.stop()
                    # Очищаем страницу
                    page = web_view.page()
                    if page:
                        logger.info("Очищаем страницу WebEnginePage...")
                        # Отключаем все сигналы
                        try:
                            page.disconnect()
                            page.deleteLater()
                        except:
                            pass
                        # Устанавливаем пустую страницу
                        web_view.setPage(None)
                    # Очищаем веб-вью
                    web_view.setParent(None)

            # Удаляем вкладку
            self.tab_widget.removeTab(index)

            # ВАЖНО: Принудительно удаляем виджет вкладки
            if tab_widget:
                tab_widget.setParent(None)
                tab_widget.deleteLater()

            logger.info("✅ Вкладка корректно закрыта с очисткой WebEnginePage")
        else:
            self.close()

    def tab_changed(self, index):
        """Обрабатывает смену вкладки"""
        if index >= 0:
            current_tab = self.tab_widget.widget(index)
            if current_tab:
                try:
                    self.address_bar.setText(current_tab.get_current_url())
                except Exception as e:
                    # print(f"Ошибка при смене вкладки: {e}")
                    logger.error(f"🆘 Ошибка при смене вкладки: {e}")
                    self.address_bar.setText("")

    def navigate_to_url(self):
        url = self.address_bar.text()
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.navigate_to_url(url)

    def address_bar_click(self, event):
        """Обрабатывает щелчок мыши в адресной строке"""
        # Сначала вызываем стандартное поведение
        QLineEdit.mousePressEvent(self.address_bar, event)

        # Затем выделяем весь текст
        self.address_bar.selectAll()

        # Обновляем статус-бар
        self.update_status_bar(
            "Адрес выделен - введите новый URL или нажмите Ctrl+C для копирования"
        )

    def setup_address_bar(self):
        """Настраивает дополнительную функциональность адресной строки"""
        # Добавляем контекстное меню
        self.address_bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.address_bar.customContextMenuRequested.connect(
            self.show_address_bar_context_menu
        )

        # Добавляем обработчик получения фокуса
        self.address_bar.focusInEvent = self.address_bar_focus_in

        # Стилизация адресной строки
        self.address_bar.setStyleSheet("""
            QLineEdit {
                padding: 5px 5px;
                border: 2px solid #ddd;
                border-radius: 15px;
                font-size: 12px;
                background-color: white;
            }
            QLineEdit:focus {
                border: 2px solid #4285f4;
                background-color: #fff;
            }
            QLineEdit:hover {
                border: 2px solid #bbb;
            }
        """)

        # Добавляем плейсхолдер
        self.address_bar.setPlaceholderText("🔍 Введите URL или поисковый запрос...")
        logger.info("✅ Адресная строка настроена")

    def address_bar_focus_in(self, event):
        """Обрабатывает получение фокуса адресной строкой"""
        # Сначала вызываем стандартное поведение
        QLineEdit.focusInEvent(self.address_bar, event)

        # Выделяем весь текст при получении фокуса
        self.address_bar.selectAll()

    def show_address_bar_context_menu(self, position):
        """Показывает контекстное меню адресной строки"""
        menu = QMenu(self)

        # Стандартные действия
        if self.address_bar.hasSelectedText():
            cut_action = QAction(
                QIcon(os.path.join("images", "cut.png")), "Вырезать", self
            )
            cut_action.triggered.connect(self.address_bar.cut)
            menu.addAction(cut_action)

            copy_action = QAction(
                QIcon(os.path.join("images", "copy.png")), "Копировать", self
            )
            copy_action.triggered.connect(self.address_bar.copy)
            menu.addAction(copy_action)

        # Вставить
        # from PyQt6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        if clipboard.text():
            paste_action = QAction(
                QIcon(os.path.join("images", "paste.png")), "Вставить", self
            )
            paste_action.triggered.connect(self.address_bar.paste)
            menu.addAction(paste_action)

            paste_and_go_action = QAction(
                QIcon(os.path.join("images", "paste_.png")),
                "Вставить и перейти",
                self,
            )
            paste_and_go_action.triggered.connect(self.paste_and_go)
            menu.addAction(paste_and_go_action)

        menu.addSeparator()

        # Выделить всё
        select_all_action = QAction(
            QIcon(os.path.join("images", "select.png")), "Выделить всё", self
        )
        select_all_action.triggered.connect(self.address_bar.selectAll)
        menu.addAction(select_all_action)

        # Очистить
        clear_action = QAction(
            QIcon(os.path.join("images", "clear.png")), "Очистить", self
        )
        clear_action.triggered.connect(self.address_bar.clear)
        menu.addAction(clear_action)

        menu.addSeparator()

        # Копировать как поисковый запрос
        search_action = QAction(
            QIcon(os.path.join("images", "search.png")), "Поиск в Google", self
        )
        search_action.triggered.connect(self.search_in_google)
        menu.addAction(search_action)

        menu.exec(self.address_bar.mapToGlobal(position))

    def paste_and_go(self):
        """Вставляет текст из буфера обмена и сразу переходит по адресу"""
        self.address_bar.paste()
        self.navigate_to_url()

    def search_in_google(self):
        """Выполняет поиск выделенного текста в Google"""
        selected_text = self.address_bar.selectedText()
        if not selected_text:
            selected_text = self.address_bar.text()

        if selected_text:
            search_url = f"https://www.google.com/search?q={selected_text}"
            self.address_bar.setText(search_url)
            self.navigate_to_url()

    def url_changed(self, url):
        sender = self.sender()
        if sender == self.tab_widget.currentWidget():
            self.address_bar.setText(url)
            if url and url != "about:blank":
                # Сохраняем в историю сразу
                self.save_to_history(url, sender)

    def title_changed(self, title):
        """Обрабатывает изменение заголовка"""
        sender = self.sender()
        current_index = self.tab_widget.indexOf(sender)
        if current_index >= 0:
            self.tab_widget.setTabText(
                current_index, title[:30] + "..." if len(title) > 30 else title
            )

    def icon_changed(self, icon):
        sender = self.sender()
        current_index = self.tab_widget.indexOf(sender)
        if current_index >= 0:
            self.tab_widget.setTabIcon(current_index, icon)

            # Обновляем иконку в истории для текущего URL
            if sender and hasattr(sender, "get_current_url"):
                url = sender.get_current_url()
                if url and url != "about:blank" and icon and not icon.isNull():
                    # Обновляем иконку в базе данных
                    self.db_manager.update_history_icon(url, icon)

    def load_progress(self, progress):
        if progress < 100:
            self.progress_bar.setValue(progress)
            self.progress_bar.setVisible(True)
        else:
            self.progress_bar.setVisible(False)

            # Когда страница полностью загружена, пытаемся обновить иконку
            sender = self.sender()
            if sender and hasattr(sender, "get_current_url"):
                url = sender.get_current_url()
                if url and url != "about:blank":
                    # Запланируем обновление иконки через 2 секунды
                    QTimer.singleShot(
                        2000, lambda: self.try_update_favicon(url, sender)
                    )

    def try_update_favicon(self, url, tab):
        """Попытка обновить фавикон для страницы"""
        try:
            if tab and hasattr(tab, "get_current_icon"):
                icon = tab.get_current_icon()
                if icon and not icon.isNull():
                    # Обновляем иконку в истории
                    self.db_manager.update_history_icon(url, icon)
                    logger.info(f"Обновлена иконка для {url}")
        except Exception as e:
            logger.error(f"Ошибка при обновлении фавикона: {e}")

    def go_back(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.back()

    def go_forward(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.forward()

    def reload_page(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.reload()

    def go_home(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.navigate_to_url("https://www.google.com")

    def add_bookmark(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            url = current_tab.get_current_url()
            title = current_tab.get_current_title()
            icon = current_tab.get_current_icon()

            # Спрашиваем, добавить ли в избранное
            reply = QMessageBox.question(
                self,
                "Добавить закладку",
                f"Добавить '{title}' в закладки?\n\nДобавить в избранное?",
                QMessageBox.StandardButton.Yes
                | QMessageBox.StandardButton.No
                | QMessageBox.StandardButton.Cancel,
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.db_manager.add_bookmark(url, title, icon, is_favorite=True)
                self.favorites_bar.refresh_favorites()
                QMessageBox.information(
                    self, "Закладка", "Закладка добавлена в избранное!"
                )
            elif reply == QMessageBox.StandardButton.No:
                self.db_manager.add_bookmark(url, title, icon, is_favorite=False)
                QMessageBox.information(self, "Закладка", "Закладка добавлена!")

    def new_window(self):
        new_browser = MainBrowser(self.browser_profile.profile_name)
        new_browser.show()

    def new_profile_window(self):
        """Создает новое окно с новым профилем"""
        profile_name, ok = QInputDialog.getText(
            self, "Новый профиль", "Введите имя профиля:"
        )
        if ok and profile_name:
            # Создаем новый профиль
            new_browser = MainBrowser(profile_name)
            new_browser.show()

            # Добавляем правило пользователя в новый профиль
            if hasattr(self, "custom_rules"):
                for rule in self.custom_rules:
                    new_browser.browser_profile.add_custom_rule(rule)

    def disable_adblock_for_site(self):
        """Отключает AdBlock для текущего сайта"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            url = current_tab.get_current_url()
            if url:
                domain = urlparse(url).netloc

                reply = QMessageBox.question(
                    self,
                    "Отключить AdBlock",
                    f"Отключить AdBlock для {domain}?\n\n"
                    "Это поможет, если сайт отображается некорректно.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )

                if reply == QMessageBox.StandardButton.Yes:
                    # Временно отключаем AdBlock
                    self.current_profile.setUrlRequestInterceptor(None)

                    # Перезагружаем страницу
                    current_tab.reload()

                    self.update_status_bar(f"AdBlock отключен для {domain}")

                    QMessageBox.information(
                        self,
                        "AdBlock отключен",
                        f"AdBlock отключен для {domain}.\n"
                        "Перезапустите браузер для восстановления блокировки.",
                    )

    def add_custom_adblock_rule(self):
        """Добавляет пользовательское правило AdBlock"""
        rule_text, ok = QInputDialog.getText(
            self, "Добавить правило", "Введите правило AdBlock:"
        )
        if ok and rule_text:
            self.browser_profile.add_custom_rule(rule_text)

            # Сохраняем правило для будущих сессий
            if not hasattr(self, "custom_rules"):
                self.custom_rules = []
            self.custom_rules.append(rule_text)

            QMessageBox.information(
                self, "Правило добавлено", f"Правило '{rule_text}' добавлено в AdBlock."
            )

    def show_history(self):
        history_dialog = HistoryManager(self.db_manager, self)
        history_dialog.exec()

    def show_bookmarks(self):
        bookmark_dialog = BookmarkManager(self.db_manager, self)
        bookmark_dialog.exec()

    def show_downloads(self):
        """Показывает менеджер загрузок"""
        if not hasattr(self, "download_manager"):
            self.download_manager = DownloadManager(self.db_manager, self)
        self.download_manager.show()
        self.download_manager.raise_()
        self.download_manager.activateWindow()

    def show_settings(self):
        settings_dialog = SettingsManager(self.db_manager, self, self)
        settings_dialog.exec()

    def clear_browser_data(self):
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Очистить все данные браузера?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.db_manager.clear_all_data()
            self.current_profile.clearHttpCache()
            QMessageBox.information(
                self, "Данные очищены", "Все данные браузера очищены!"
            )

    def reset_for_google_auth(self):
        """Сбрасывает настройки браузера для корректной авторизации в Google"""
        # Очищаем куки и кэш
        self.current_profile.clearHttpCache()
        self.current_profile.cookieStore().deleteAllCookies()

        # Временно отключаем AdBlock
        self.current_profile.setUrlRequestInterceptor(None)

        # Создаем новую вкладку с Google
        self.new_tab("https://accounts.google.com")

        QMessageBox.information(
            self,
            "Сброс выполнен",
            "Настройки сброшены для авторизации в Google.\n"
            "AdBlock временно отключен.\n"
            "Перезапустите браузер для восстановления всех функций.",
        )

    def enable_google_mode(self):
        """Включает специальный режим для работы с Google сервисами"""
        # Отключаем перехватчик
        self.current_profile.setUrlRequestInterceptor(None)

        # Устанавливаем User-Agent Chrome
        self.current_profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

        self.new_tab("https://www.google.com")

        QMessageBox.information(
            self,
            "Режим Google",
            "Включен режим совместимости с Google сервисами.\n"
            "Все блокировки отключены.",
        )

    def toggle_favorites_bar(self):
        """Переключает видимость панели избранного"""
        if self.favorites_bar.isVisible():
            self.favorites_bar.hide()
            self.db_manager.save_setting("favorites_bar_visible", "false")
        else:
            self.favorites_bar.show()
            self.db_manager.save_setting("favorites_bar_visible", "true")

    def update_status_bar(self, message):
        """Обновляет сообщение в строке состояния"""
        self.status_bar.showMessage(message, 5000)  # Показываем на 5 секунд

    def zoom_changed(self, zoom_factor):
        """Обработчик изменения масштаба"""
        zoom_percent = int(zoom_factor * 100)
        self.zoom_label.setText(f"{zoom_percent}%")

    def zoom_in(self):
        """Увеличивает масштаб текущей вкладки"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab and hasattr(current_tab, "zoom_in"):
            current_tab.zoom_in()
            self.update_status_bar("🔍+ Масштаб увеличен")

    def zoom_out(self):
        """Уменьшает масштаб текущей вкладки"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab and hasattr(current_tab, "zoom_out"):
            current_tab.zoom_out()
            self.update_status_bar("🔍- Масштаб уменьшен")

    def reset_zoom(self):
        """Сбрасывает масштаб текущей вкладки к 100%"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab and hasattr(current_tab, "reset_zoom"):
            current_tab.reset_zoom()
            self.update_status_bar("🔍 Масштаб сброшен к 100%")

    def set_zoom(self, zoom_factor):
        """Устанавливает конкретный масштаб для текущей вкладки"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab and hasattr(current_tab, "web_view"):
            current_tab.web_view.setZoomFactor(zoom_factor)
            zoom_percent = int(zoom_factor * 100)
            self.update_status_bar(f"🔍 Масштаб установлен: {zoom_percent}%")

    def toggle_fullscreen(self):
        """Переключает полноэкранный режим"""
        if self.isFullScreen():
            self.showNormal()
            self.update_status_bar("📺 Выход из полноэкранного режима")
        else:
            self.showFullScreen()
            self.update_status_bar("📺 Полноэкранный режим включен (F11 для выхода)")

    def get_current_zoom(self):
        """Получает текущий масштаб активной вкладки"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab and hasattr(current_tab, "get_current_zoom"):
            return current_tab.get_current_zoom()
        return 1.0

    def zoom_label_clicked(self, event):
        """Обрабатывает клик по индикатору масштаба"""
        # При клике левой кнопкой мыши сбрасываем масштаб
        if event.button() == Qt.MouseButton.LeftButton:
            self.reset_zoom()
        # При клике правой кнопкой мыши показываем меню масштаба
        elif event.button() == Qt.MouseButton.RightButton:
            global_pos = self.zoom_label.mapToGlobal(event.pos())
            self.show_zoom_menu(global_pos)

    def show_zoom_menu(self, position):
        """Показывает контекстное меню с опциями масштаба"""
        menu = QMenu(self)

        # Текущий масштаб
        current_zoom = self.get_current_zoom()
        current_percent = int(current_zoom * 100)

        menu.addAction(
            QIcon(os.path.join("images", "zoom.png")),
            f"Текущий масштаб: {current_percent}%",
        ).setEnabled(False)
        menu.addSeparator()

        # Быстрые опции
        zoom_in_action = menu.addAction(
            QIcon(os.path.join("images", "zoomin.png")), "Увеличить (Ctrl++)"
        )
        zoom_in_action.triggered.connect(self.zoom_in)

        zoom_out_action = menu.addAction(
            QIcon(os.path.join("images", "zoomout.png")), "Уменьшить (Ctrl+-)"
        )
        zoom_out_action.triggered.connect(self.zoom_out)

        reset_action = menu.addAction(
            QIcon(os.path.join("images", "zoomreset.png")), "Сбросить к 100% (Ctrl+0)"
        )
        reset_action.triggered.connect(self.reset_zoom)

        menu.addSeparator()

        # Предустановленные значения
        zoom_values = [50, 75, 100, 125, 150, 200, 300]
        for zoom in zoom_values:
            action = menu.addAction(f"{zoom}%")
            action.triggered.connect(lambda checked, z=zoom: self.set_zoom(z / 100))

            # Отмечаем текущий масштаб
            if abs(current_percent - zoom) < 5:
                action.setEnabled(False)
                action.setText(f"● {zoom}%")

        menu.exec(position)

    def open_html_file(self):
        """Открывает HTML файл"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Открыть HTML файл", "", "HTML файлы (*.html *.htm);;Все файлы (*.*)"
        )
        if file_path:
            # Конвертируем путь к файлу в URL
            file_url = QUrl.fromLocalFile(file_path)
            self.new_tab(file_url.toString())
            logger.info(f"✅ Открыт HTML файл: {file_path}")

    def save_current_page_mhtml(self):
        """Сохраняет текущую страницу как MHTML"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.save_page_as_mhtml()
            logger.info("✅ Текущая страница сохранена как MHTML")

    def save_current_page_html(self):
        """Сохраняет текущую страницу как HTML"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.save_page_as_html()
        logger.info("✅ Текущая страница сохранена как HTML")

    def save_current_page_pdf(self):
        """Сохраняет текущую страницу как PDF"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.save_page_as_pdf()
        logger.info("✅ Текущая страница сохранена как PDF")

    def save_html_file(self):
        """Сохраняет текущую страницу как HTML (устаревший метод)"""
        self.save_current_page_html()
        logger.warning(
            "⚠️ Метод save_html_file устарел, используйте save_current_page_html"
        )

    def save_to_history(self, url, tab):
        """Сохраняет URL в историю с иконкой"""
        try:
            if (
                tab
                and hasattr(tab, "get_current_title")
                and hasattr(tab, "get_current_icon")
            ):
                title = tab.get_current_title()
                icon = tab.get_current_icon()

                # Проверяем, что иконка не пустая
                if icon and not icon.isNull():
                    self.db_manager.add_history(url, title, icon)
                else:
                    # Если иконка пустая, попробуем получить её позже
                    self.db_manager.add_history(url, title, None)
                    # Запланируем повторную попытку через 3 секунды
                    QTimer.singleShot(3000, lambda: self.update_history_icon(url, tab))
        except Exception as e:
            logger.error(f"🆘 Ошибка при сохранении в историю: {e}")
            # Сохраняем без иконки
            try:
                self.db_manager.add_history(
                    url, tab.get_current_title() if tab else "", None
                )
            except:
                pass

    def update_history_icon(self, url, tab):
        """Обновляет иконку в истории, если она стала доступна"""
        try:
            if tab and hasattr(tab, "get_current_icon"):
                icon = tab.get_current_icon()
                if icon and not icon.isNull():
                    # Обновляем иконку в базе данных
                    self.db_manager.update_history_icon(url, icon)
        except Exception as e:
            logger.error(f"🆘 Ошибка при обновлении иконки в истории: {e}")

    # def closeEvent(self, event):
    #    self.page.deleteLater()  # сначала удаляем страницу
    #    super().closeEvent(event)


def main():
    # Настройки для QtWebEngine - минимальные для максимальной совместимости с Google
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        "--disable-features=VizDisplayCompositor "
        "--ignore-certificate-errors-spki-list "
        "--ignore-ssl-errors-ignore-certificate-errors "
        "--disable-extensions-http-throttling "
        "--enable-features=WebRTC-H264WithOpenH264FFmpeg "
        "--autoplay-policy=no-user-gesture-required "
        "--disable-blink-features=AutomationControlled "
        "--disable-infobars"
    )

    app = QApplication(sys.argv)
    # app.setStyle("Fusion")
    app.setApplicationName("OBrowser")
    app.setApplicationVersion("1.0")

    # Установка иконки приложения (опционально)
    app.setWindowIcon(QIcon(os.path.join("images", "browser.png")))

    browser = MainBrowser()
    browser.showMaximized()

    sys.exit(app.exec())


if __name__ == "__main__":
    # Проверяем доступность PyQt6
    main()
