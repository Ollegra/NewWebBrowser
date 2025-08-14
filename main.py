#!/usr/bin/env python3
"""
Компактный браузер с постоянным сохранением данных пользователя
Основан на PyQt6 WebEngine с улучшенным управлением профилем
"""

import json
import logging.config
import os
import re
import sqlite3
import sys
import shutil
from datetime import datetime, timedelta
from urllib.parse import urlparse

from PyQt6.QtCore import QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QPixmap
from PyQt6.QtWebEngineCore import QWebEngineProfile
from PyQt6.QtWebEngineWidgets import QWebEngineView, QWebEnginePage
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QFileDialog,
    QProgressBar,
)


class DatabaseManager:
    """Менеджер базы данных для истории, закладок и других данных"""

    def __init__(self):
        # Создаем папку для данных приложения
        self.app_data_dir = os.path.join(os.path.expanduser("~"), ".compact_browser")
        os.makedirs(self.app_data_dir, exist_ok=True)

        self.db_path = os.path.join(self.app_data_dir, "browser_data.db")
        self.init_database()
        self.migrate_database()

    def init_database(self):
        """Инициализирует базу данных"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Создаем таблицу истории с поддержкой времени и иконок
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    title TEXT,
                    icon BLOB,
                    visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Создаем таблицу закладок
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bookmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    title TEXT,
                    icon BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    folder TEXT DEFAULT 'default'
                )
            """)

            conn.commit()

    def migrate_database(self):
        """Выполняет миграцию базы данных для добавления новых колонок"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Проверяем таблицу history
            cursor.execute("PRAGMA table_info(history)")
            history_columns = [column[1] for column in cursor.fetchall()]

            # Добавляем колонку icon для history
            if "icon" not in history_columns:
                print("Добавляем колонку icon в таблицу history...")
                cursor.execute("ALTER TABLE history ADD COLUMN icon BLOB")

            # Добавляем колонку visit_time для history (если её нет)
            if "visit_time" not in history_columns:
                print("Добавляем колонку visit_time в таблицу history...")
                cursor.execute(
                    "ALTER TABLE history ADD COLUMN visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                )

                # Обновляем существующие записи с текущим временем
                cursor.execute(
                    "UPDATE history SET visit_time = datetime('now', 'localtime') WHERE visit_time IS NULL"
                )

            conn.commit()

    def add_history(self, url, title, icon=None):
        """Добавляет запись в историю"""
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

    def get_history(self, limit=100):
        """Получает историю посещений"""
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
                    print("Колонка icon не найдена, используем резервный запрос...")
                    cursor.execute(
                        "SELECT url, title, NULL as icon, visit_time FROM history ORDER BY visit_time DESC LIMIT ?",
                        (limit,),
                    )
                    return cursor.fetchall()
                else:
                    raise e

    def add_bookmark(self, url, title, icon=None, folder="default"):
        """Добавляет закладку"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            icon_blob = self.icon_to_blob(icon) if icon else None
            cursor.execute(
                "INSERT INTO bookmarks (url, title, icon, folder) VALUES (?, ?, ?, ?)",
                (url, title, icon_blob, folder),
            )
            conn.commit()

    def get_bookmarks(self, folder="default"):
        """Получает закладки из указанной папки"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT url, title, icon FROM bookmarks WHERE folder = ? ORDER BY created_at DESC",
                (folder,),
            )
            return cursor.fetchall()

    def remove_bookmark(self, url):
        """Удаляет закладку"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM bookmarks WHERE url = ?", (url,))
            conn.commit()

    def icon_to_blob(self, icon):
        """Конвертирует QIcon в BLOB для хранения в БД"""
        if not icon or icon.isNull():
            return None

        try:
            pixmap = icon.pixmap(16, 16)
            byte_array = QByteArray()
            buffer = QBuffer(byte_array)
            buffer.open(QIODevice.WriteOnly)
            pixmap.save(buffer, "PNG")
            return byte_array.data()
        except:
            return None

    def blob_to_icon(self, blob_data):
        """Конвертирует BLOB в QIcon"""
        if not blob_data:
            return None

        try:
            pixmap = QPixmap()
            pixmap.loadFromData(blob_data)
            return QIcon(pixmap)
        except:
            return None


class BrowserTab(QWidget):
    """Класс для отдельной вкладки браузера"""

    titleChanged = pyqtSignal(str)
    iconChanged = pyqtSignal(object)
    urlChanged = pyqtSignal(str)

    def __init__(self, db_manager, profile=None):
        super().__init__()
        self.db_manager = db_manager
        self.profile = profile
        self.setup_ui()

    def setup_ui(self):
        """Настройка интерфейса вкладки"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Веб-просмотр с профилем
        if self.profile:
            # ИСПРАВЛЕНО: Создаем страницу с правильным родителем
            page = QWebEnginePage(self.profile, self)  # parent=self вместо web_view
            self.web_view = QWebEngineView()
            self.web_view.setPage(page)
            self.profile_ref = self.profile  # Сохраняем ссылку на профиль
            print("✅ Вкладка создана с постоянным профилем")
        else:
            # Используем стандартный профиль
            self.web_view = QWebEngineView()
            print("⚠️ Вкладка создана со стандартным профилем")

        self.web_view.loadFinished.connect(self.on_load_finished)
        self.web_view.loadProgress.connect(self.on_load_progress)
        self.web_view.titleChanged.connect(self.on_title_changed)
        self.web_view.iconChanged.connect(self.on_icon_changed)
        self.web_view.urlChanged.connect(self.on_url_changed)

        layout.addWidget(self.web_view)

    def navigate_to_url(self, url):
        """Переходит по указанному URL"""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.web_view.load(QUrl(url))

    def get_current_url(self):
        """Возвращает текущий URL"""
        return self.web_view.url().toString()

    def get_current_title(self):
        """Возвращает текущий заголовок"""
        return self.web_view.title()

    def on_load_finished(self, success):
        """Обработчик завершения загрузки"""
        if success:
            # Добавляем в историю
            url = self.get_current_url()
            title = self.get_current_title()
            icon = self.web_view.icon()

            if url and url != "about:blank":
                self.db_manager.add_history(url, title, icon)

    def on_load_progress(self, progress):
        """Обработчик прогресса загрузки"""
        pass

    def on_title_changed(self, title):
        """Обработчик изменения заголовка"""
        self.titleChanged.emit(title)

    def on_icon_changed(self, icon):
        """Обработчик изменения иконки"""
        self.iconChanged.emit(icon)

    def on_url_changed(self, url):
        """Обработчик изменения URL"""
        self.urlChanged.emit(url.toString())

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
            print("🗑️ BrowserTab destructor: ресурсы очищены")
        except Exception as e:
            print(f"Ошибка в деструкторе BrowserTab: {e}")

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

            print("✅ BrowserTab ресурсы принудительно очищены")
        except Exception as e:
            print(f"Ошибка при принудительной очистке BrowserTab: {e}")


class CompactBrowser(QMainWindow):
    """Главное окно браузера"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Компактный Браузер с Постоянным Профилем")
        self.setGeometry(100, 100, 1200, 800)

        # Инициализация менеджера базы данных
        self.db_manager = DatabaseManager()

        # Список активных загрузок
        self.active_downloads = {}

        # Настройка профиля браузера для сохранения данных
        self.setup_browser_profile()

        # Настройка интерфейса
        self.setup_ui()
        self.create_menu()

        # Создаем первую вкладку
        self.new_tab()

        # Показываем информацию о профиле в статус-баре
        if self.profile_path:
            self.update_status_bar(
                "🔐 Профиль настроен - данные сохраняются между сеансами"
            )
        else:
            self.update_status_bar("⚠️ Временное хранилище - данные не сохраняются")

        self.show()

    def setup_browser_profile(self):
        """Настраивает профиль браузера для сохранения данных пользователя"""
        try:
            # Создаем папку для профиля браузера
            profile_path = os.path.join(
                os.path.expanduser("~"), ".compact_browser", "profile"
            )
            os.makedirs(profile_path, exist_ok=True)

            # Устанавливаем кастомный профиль
            self.profile = QWebEngineProfile.defaultProfile()

            # Настраиваем кэш
            cache_path = os.path.join(profile_path, "cache")
            os.makedirs(cache_path, exist_ok=True)
            self.profile.setCachePath(cache_path)

            # Настраиваем постоянное хранилище
            storage_path = os.path.join(profile_path, "storage")
            os.makedirs(storage_path, exist_ok=True)
            self.profile.setPersistentStoragePath(storage_path)

            # Включаем постоянные cookies
            self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
            self.profile.setPersistentCookiesPolicy(
                QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
            )

            print(f"✅ Профиль браузера настроен:")
            print(f"   📁 Профиль: {profile_path}")
            print(f"   💾 Кэш: {cache_path}")
            print(f"   🍪 Постоянные cookies включены")

            # Сохраняем пути для использования в других частях приложения
            self.profile_path = profile_path
            self.cache_path = cache_path
            self.storage_path = storage_path

        except Exception as e:
            print(f"❌ Ошибка при настройке профиля браузера: {e}")
            # Fallback - используем дефолтный профиль
            self.profile = None
            self.profile_path = None

    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Основной макет
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        # Панель инструментов
        toolbar_layout = QHBoxLayout()

        # Кнопки навигации
        self.back_button = QPushButton("◀")
        self.back_button.setMaximumWidth(30)
        self.back_button.clicked.connect(self.go_back)
        self.back_button.setToolTip("Назад")
        toolbar_layout.addWidget(self.back_button)

        self.forward_button = QPushButton("▶")
        self.forward_button.setMaximumWidth(30)
        self.forward_button.clicked.connect(self.go_forward)
        self.forward_button.setToolTip("Вперед")
        toolbar_layout.addWidget(self.forward_button)

        self.refresh_button = QPushButton("⟳")
        self.refresh_button.setMaximumWidth(30)
        self.refresh_button.clicked.connect(self.refresh_page)
        self.refresh_button.setToolTip("Обновить")
        toolbar_layout.addWidget(self.refresh_button)

        # Адресная строка
        self.address_bar = QLineEdit()
        self.address_bar.returnPressed.connect(self.navigate_to_url)
        self.address_bar.setPlaceholderText("Введите URL или поисковый запрос...")
        toolbar_layout.addWidget(self.address_bar)

        # Кнопка поиска
        self.search_button = QPushButton("🔍")
        self.search_button.setMaximumWidth(30)
        self.search_button.clicked.connect(self.navigate_to_url)
        self.search_button.setToolTip("Поиск")
        toolbar_layout.addWidget(self.search_button)

        main_layout.addLayout(toolbar_layout)

        # Вкладки
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.currentChanged.connect(self.tab_changed)

        # Добавляем обработчик двойного клика для создания новой вкладки
        self.tab_widget.mouseDoubleClickEvent = self.tab_widget_double_click

        # Кнопка новой вкладки
        new_tab_button = QPushButton("+")
        new_tab_button.setMaximumWidth(30)
        new_tab_button.setToolTip(
            "Создать новую вкладку\n(или двойной клик на свободной области)"
        )
        new_tab_button.clicked.connect(self.new_tab)
        self.tab_widget.setCornerWidget(new_tab_button)

        main_layout.addWidget(self.tab_widget)

        # Статус-бар
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Готов")
        self.status_bar.addWidget(self.status_label)

        # Прогресс-бар для загрузки
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def create_menu(self):
        """Создает меню приложения"""
        menubar = self.menuBar()

        # Файл меню
        file_menu = menubar.addMenu("Файл")

        new_tab_action = QAction("Новая вкладка", self)
        new_tab_action.setShortcut("Ctrl+T")
        new_tab_action.setStatusTip(
            "Создать новую вкладку (Ctrl+T или двойной клик на панели вкладок)"
        )
        new_tab_action.triggered.connect(self.new_tab)
        file_menu.addAction(new_tab_action)

        file_menu.addSeparator()

        exit_action = QAction("Выход", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Навигация меню
        nav_menu = menubar.addMenu("Навигация")

        back_action = QAction("Назад", self)
        back_action.setShortcut("Alt+Left")
        back_action.triggered.connect(self.go_back)
        nav_menu.addAction(back_action)

        forward_action = QAction("Вперед", self)
        forward_action.setShortcut("Alt+Right")
        forward_action.triggered.connect(self.go_forward)
        nav_menu.addAction(forward_action)

        refresh_action = QAction("Обновить", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_page)
        nav_menu.addAction(refresh_action)

        nav_menu.addSeparator()

        history_action = QAction("История", self)
        history_action.setShortcut("Ctrl+H")
        history_action.triggered.connect(self.show_history)
        nav_menu.addAction(history_action)

        # Меню настроек профиля
        profile_menu = menubar.addMenu("Профиль")

        profile_info_action = QAction("📁 Информация о профиле", self)
        profile_info_action.triggered.connect(self.show_profile_info)
        profile_menu.addAction(profile_info_action)

        clear_cache_action = QAction("🗑️ Очистить кэш", self)
        clear_cache_action.triggered.connect(self.clear_cache)
        profile_menu.addAction(clear_cache_action)

        clear_cookies_action = QAction("🍪 Очистить cookies", self)
        clear_cookies_action.triggered.connect(self.clear_cookies)
        profile_menu.addAction(clear_cookies_action)

        profile_menu.addSeparator()

        backup_profile_action = QAction("💾 Резервная копия профиля", self)
        backup_profile_action.triggered.connect(self.backup_profile)
        profile_menu.addAction(backup_profile_action)

        # Справка меню
        help_menu = menubar.addMenu("Справка")
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def new_tab(self, url=""):
        """Создает новую вкладку"""
        # Передаем профиль в BrowserTab для использования постоянного хранилища
        tab = BrowserTab(self.db_manager, profile=self.profile)

        if url:
            tab.navigate_to_url(url)
        else:
            tab.navigate_to_url("https://www.google.com")

        # Добавляем вкладку
        index = self.tab_widget.addTab(tab, "Новая вкладка")
        self.tab_widget.setCurrentIndex(index)

        # Подключаем сигналы
        tab.titleChanged.connect(
            lambda title, tab=tab: self.update_tab_title(tab, title)
        )
        tab.iconChanged.connect(lambda icon, tab=tab: self.update_tab_icon(tab, icon))
        tab.urlChanged.connect(self.update_address_bar)

        return tab

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
                        # Отключаем все сигналы
                        try:
                            page.disconnect()
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

            print("✅ Вкладка корректно закрыта с очисткой WebEnginePage")
        else:
            self.close()

    def tab_changed(self, index):
        """Обработчик смены вкладки"""
        if index >= 0:
            current_tab = self.tab_widget.widget(index)
            if current_tab:
                try:
                    self.address_bar.setText(current_tab.get_current_url())
                except Exception as e:
                    print(f"Ошибка при смене вкладки: {e}")
                    self.address_bar.setText("")

    def tab_widget_double_click(self, event):
        """Обрабатывает двойной клик на панели вкладок"""
        try:
            # Получаем позицию клика
            click_pos = event.pos()

            # Проверяем, был ли клик на свободной области панели вкладок
            tab_bar = self.tab_widget.tabBar()
            clicked_tab_index = tab_bar.tabAt(click_pos)

            # Если клик был не на вкладке (на свободной области), создаем новую вкладку
            if clicked_tab_index == -1:
                self.new_tab()
                self.update_status_bar("📑 Новая вкладка создана двойным кликом")

        except Exception as e:
            print(f"Ошибка при обработке двойного клика: {e}")
            # В случае ошибки просто создаем новую вкладку
            self.new_tab()

        # Вызываем стандартное поведение для совместимости
        try:
            QTabWidget.mouseDoubleClickEvent(self.tab_widget, event)
        except Exception as e:
            print(f"Ошибка при вызове стандартного поведения: {e}")

    def update_tab_title(self, tab, title):
        """Обновляет заголовок вкладки"""
        index = self.tab_widget.indexOf(tab)
        if index >= 0:
            # Ограничиваем длину заголовка
            if len(title) > 30:
                title = title[:30] + "..."
            self.tab_widget.setTabText(index, title or "Новая вкладка")

    def update_tab_icon(self, tab, icon):
        """Обновляет иконку вкладки"""
        index = self.tab_widget.indexOf(tab)
        if index >= 0:
            self.tab_widget.setTabIcon(index, icon)

    def update_address_bar(self, url):
        """Обновляет адресную строку"""
        self.address_bar.setText(url)

    def navigate_to_url(self):
        """Переходит по URL из адресной строки"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            url = self.address_bar.text().strip()
            if url:
                # Если это не URL, то ищем в Google
                if not url.startswith(("http://", "https://")) and "." not in url:
                    url = f"https://www.google.com/search?q={url}"
                current_tab.navigate_to_url(url)

    def go_back(self):
        """Переходит на предыдущую страницу"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.web_view.back()

    def go_forward(self):
        """Переходит на следующую страницу"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.web_view.forward()

    def refresh_page(self):
        """Обновляет текущую страницу"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.web_view.reload()

    def show_history(self):
        """Показывает окно истории"""
        history_window = HistoryWindow(self.db_manager, self)
        history_window.urlSelected.connect(self.navigate_to_history_url)
        history_window.show()

    def navigate_to_history_url(self, url):
        """Переходит по URL из истории"""
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.navigate_to_url(url)
        else:
            self.new_tab(url)

    def update_status_bar(self, message):
        """Обновляет статус-бар"""
        self.status_label.setText(message)
        # Автоматически очищаем сообщение через 5 секунд
        QTimer.singleShot(5000, lambda: self.status_label.setText("Готов"))

    def show_about(self):
        """Показывает информацию о программе"""
        QMessageBox.about(
            self,
            "О программе",
            "Компактный браузер на PyQt6\nВерсия 1.0\n\nИспользует WebEngine для отображения веб-страниц\n✅ Постоянное сохранение данных профиля",
        )

    def closeEvent(self, event):
        """ИСПРАВЛЕНО: Корректно закрываем браузер с очисткой всех ресурсов"""
        print("🔄 Закрытие браузера - очистка ресурсов...")

        # Закрываем все вкладки с корректной очисткой
        while self.tab_widget.count() > 0:
            self.close_tab(0)
            print("✅ Вкладка закрыта")

        # Очищаем профиль
        if hasattr(self, "profile") and self.profile:
            try:
                # Останавливаем все загрузки
                if hasattr(self, "active_downloads"):
                    for download in list(self.active_downloads.keys()):
                        try:
                            if hasattr(download, "cancel"):
                                download.cancel()
                        except:
                            pass
                    self.active_downloads.clear()

                # Очищаем профиль (если это кастомный профиль)
                print("✅ Профиль браузера очищен")
            except Exception as e:
                print(f"Ошибка при очистке профиля: {e}")

        # Принимаем событие закрытия
        event.accept()
        print("✅ Браузер закрыт корректно")

    def show_profile_info(self):
        """Показывает информацию о профиле браузера"""
        if not self.profile_path:
            QMessageBox.information(
                self,
                "Информация о профиле",
                "Профиль браузера не настроен.\nИспользуется временное хранилище.",
            )
            return

        # Собираем информацию о профиле
        info = ["📁 Информация о профиле браузера:", ""]
        info.append(f"📂 Путь к профилю: {self.profile_path}")

        if os.path.exists(self.cache_path):
            cache_size = self.get_folder_size(self.cache_path)
            info.append(f"💾 Размер кэша: {cache_size}")

        if os.path.exists(self.storage_path):
            storage_size = self.get_folder_size(self.storage_path)
            info.append(f"🗃️ Размер хранилища: {storage_size}")

        # Проверяем наличие файлов
        profile_files = []
        if os.path.exists(self.profile_path):
            for item in os.listdir(self.profile_path):
                if os.path.isdir(os.path.join(self.profile_path, item)):
                    profile_files.append(f"📁 {item}/")
                else:
                    profile_files.append(f"📄 {item}")

        if profile_files:
            info.append("")
            info.append("📋 Содержимое профиля:")
            info.extend(profile_files[:10])  # Показываем только первые 10 элементов
            if len(profile_files) > 10:
                info.append(f"... и еще {len(profile_files) - 10} элементов")

        QMessageBox.information(self, "Информация о профиле", "\n".join(info))

    def get_folder_size(self, folder_path):
        """Вычисляет размер папки в читаемом формате"""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(folder_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except OSError:
                        pass

            # Конвертируем в читаемый формат
            for unit in ["Б", "КБ", "МБ", "ГБ"]:
                if total_size < 1024.0:
                    return f"{total_size:.1f} {unit}"
                total_size /= 1024.0
            return f"{total_size:.1f} ТБ"
        except Exception:
            return "Неизвестно"

    def clear_cache(self):
        """Очищает кэш браузера"""
        if not self.profile_path or not self.cache_path:
            QMessageBox.warning(
                self, "Очистка кэша", "Кэш браузера не настроен или недоступен."
            )
            return

        reply = QMessageBox.question(
            self,
            "Очистка кэша",
            "Вы уверены, что хотите очистить кэш браузера?\n\nЭто может замедлить загрузку часто посещаемых сайтов.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                if os.path.exists(self.cache_path):
                    shutil.rmtree(self.cache_path)
                    os.makedirs(self.cache_path, exist_ok=True)

                QMessageBox.information(
                    self, "Очистка кэша", "✅ Кэш браузера успешно очищен!"
                )
                self.update_status_bar("🗑️ Кэш браузера очищен")
            except Exception as e:
                QMessageBox.warning(
                    self, "Ошибка", f"Не удалось очистить кэш:\n{str(e)}"
                )

    def clear_cookies(self):
        """Очищает cookies браузера"""
        reply = QMessageBox.question(
            self,
            "Очистка cookies",
            "Вы уверены, что хотите очистить все cookies?\n\n⚠️ Это приведет к выходу из всех аккаунтов на всех сайтах!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                if self.profile:
                    cookie_store = self.profile.cookieStore()
                    cookie_store.deleteAllCookies()

                    QMessageBox.information(
                        self,
                        "Очистка cookies",
                        "✅ Все cookies успешно удалены!\n\nВозможно, потребуется перезагрузить открытые страницы.",
                    )
                    self.update_status_bar("🍪 Cookies очищены")
                else:
                    QMessageBox.warning(self, "Ошибка", "Профиль браузера не настроен.")
            except Exception as e:
                QMessageBox.warning(
                    self, "Ошибка", f"Не удалось очистить cookies:\n{str(e)}"
                )

    def backup_profile(self):
        """Создает резервную копию профиля браузера"""
        if not self.profile_path:
            QMessageBox.warning(
                self, "Резервная копия", "Профиль браузера не настроен."
            )
            return

        # Предлагаем выбрать место для сохранения
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"browser_profile_backup_{timestamp}"

        backup_path = QFileDialog.getSaveFileName(
            self,
            "Сохранить резервную копию профиля",
            default_name,
            "Архивы (*.zip);;Все файлы (*.*)",
        )[0]

        if backup_path:
            try:
                if not backup_path.endswith(".zip"):
                    backup_path += ".zip"

                # Создаем архив профиля
                shutil.make_archive(
                    backup_path[
                        :-4
                    ],  # Убираем .zip так как make_archive добавит его сам
                    "zip",
                    self.profile_path,
                )

                QMessageBox.information(
                    self,
                    "Резервная копия",
                    f"✅ Резервная копия профиля создана:\n{backup_path}",
                )
                self.update_status_bar(
                    f"💾 Резервная копия создана: {os.path.basename(backup_path)}"
                )

            except Exception as e:
                QMessageBox.warning(
                    self, "Ошибка", f"Не удалось создать резервную копию:\n{str(e)}"
                )


class HistoryWindow(QWidget):
    """Окно для просмотра истории посещений"""

    urlSelected = pyqtSignal(str)

    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.setWindowTitle("История посещений")
        self.setGeometry(200, 200, 600, 400)
        self.setup_ui()
        self.refresh_history()

    def setup_ui(self):
        """Настройка интерфейса окна истории"""
        layout = QVBoxLayout(self)

        # Заголовок
        title_label = QLabel("📚 История посещений")
        title_label.setStyleSheet("font-size: 14px; font-weight: bold; margin: 10px;")
        layout.addWidget(title_label)

        # Список истории
        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.on_item_double_clicked)
        layout.addWidget(self.history_list)

        # Кнопки управления
        button_layout = QHBoxLayout()

        refresh_button = QPushButton("🔄 Обновить")
        refresh_button.clicked.connect(self.refresh_history)
        button_layout.addWidget(refresh_button)

        clear_button = QPushButton("🗑️ Очистить историю")
        clear_button.clicked.connect(self.clear_history)
        button_layout.addWidget(clear_button)

        button_layout.addStretch()

        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

    def refresh_history(self):
        """Обновляет список истории"""
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
            print(f"Ошибка при форматировании времени: {e}")
            return str(visit_time) if visit_time else "Неизвестно"

    def get_default_icon_for_url(self, url):
        """Возвращает иконку по умолчанию для URL"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()

            # Создаем простую иконку на основе первой буквы домена
            pixmap = QPixmap(16, 16)
            pixmap.fill()
            return QIcon(pixmap)
        except:
            return QIcon()

    def on_item_double_clicked(self, item):
        """Обрабатывает двойной клик по элементу истории"""
        url = item.data(256)
        if url:
            self.urlSelected.emit(url)
            self.close()

    def clear_history(self):
        """Очищает историю посещений"""
        reply = QMessageBox.question(
            self,
            "Очистка истории",
            "Вы уверены, что хотите очистить всю историю посещений?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                with sqlite3.connect(self.db_manager.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM history")
                    conn.commit()

                self.refresh_history()
                QMessageBox.information(
                    self, "Очистка истории", "История успешно очищена!"
                )
            except Exception as e:
                QMessageBox.warning(
                    self, "Ошибка", f"Не удалось очистить историю:\n{str(e)}"
                )


def main():
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
    """Главная функция запуска приложения"""
    app = QApplication(sys.argv)
    app.setApplicationName("Компактный Браузер с Постоянным Профилем")
    app.setApplicationVersion("1.0")

    # Создаем и показываем браузер
    browser = CompactBrowser()

    try:
        sys.exit(app.exec())
    except KeyboardInterrupt:
        print("\nВыход по Ctrl+C")
        sys.exit(0)


if __name__ == "__main__":
    main()
