import tkinter as tk
from tkinter import simpledialog, messagebox
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import re
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from tkinter import ttk
from ttkthemes import ThemedStyle
import pyperclip
from pprint import pprint
import io
import json


class SqlInjectionCheckerGUI:
    def __init__(self, master):
        self.master = master
        master.title("SQL Injection Checker")
        self.style = ThemedStyle(master)
        self.style.set_theme("radiance")




        self.button_check_user_input = ttk.Button(master, text="Проверка вводимых данных", command=self.check_user_input)
        self.button_check_user_input.pack(pady=10)

        self.button_run_sql_test = ttk.Button(master, text="Тестирование", command=self.run_sql_test)
        self.button_run_sql_test.pack(pady=10)


        self.text_result = tk.Text(master, wrap=tk.WORD, width=80, height=30)
        self.text_result.pack(pady=10)
        self.text_result.bind("<Control-c>", self.copy_text)
        self.text_result.bind("<Control-v>", self.paste_text)

        self.button_save_report = ttk.Button(master, text="Сохранить отчет", command=self.save_report)
        self.button_save_report.pack(pady=10)

    def check_user_input(self):
        url = self.get_url_from_user()
        if url:
            user_input_data = self.get_user_input_from_website(url)
            result_text = "Полученные данные из веб-сайта:\n"
            result_text += json.dumps(user_input_data, indent=4)
            if self.is_sql_injection(user_input_data):
                result_text += "\n\nОбнаружена SQL-инъекция."
            else:
                result_text += "\n\nSQL-инъекций не обнаружено."
            self.text_result.delete(1.0, tk.END)
            self.text_result.insert(tk.END, result_text)

    def run_sql_test(self):
        url = self.get_url_from_user()
        if url:
            forms = self.get_forms(url)
            for form in forms:
                form_details = self.get_inf_form(form)
                result_text = f"\nДетали формы: {json.dumps(form_details, indent=4)}"
                for c in "\"'":
                    # Добавление специальных символов (кавычки) в конец деталей формы
                    data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] == "hidden" or input_tag["value"]:
                            try:
                                data[input_tag["name"]] = input_tag["value"] + c
                            except:
                                pass
                        elif input_tag["type"] != "submit":
                            # Здесь происходит добавление кавычки к тому, что мы вводим, в данном случае к слову test
                            data[input_tag["name"]] = f"test{c}"
                            result_text+=f"\nТестирование: {json.dumps(data, indent=4)}"
                    # отправка этих данных на веб-сайт
                    url = urljoin(url, form_details["action"])
                    if form_details["method"] == "post":
                        res = requests.post(url, data=data)
                    elif form_details["method"] == "get":
                        res = requests.get(url, params=data)

                    if self.is_vulnerable(res)== False:
                        result_text += "\n\nCайт уязвим к SQL-инъекциям"
                    else:
                        result_text += "\n\n Cайт не подвержен SQL-инъекциям"
                        break

            self.text_result.delete(1.0, tk.END)
            self.text_result.insert(tk.END, result_text)

    def get_url_from_user(self):
        return simpledialog.askstring("URL-адрес", "Введите URL-адрес:")

    def get_user_input_from_website(self, url):
        driver = webdriver.Chrome()
        driver.get(url)

        # Задержка
        time.sleep(15)


        forms = driver.find_elements(By.TAG_NAME, 'form')
        user_input_data = {}
        print(f"Количество форм на странице: {len(forms)}")

        for form in forms:
            form_details = {}
            form_action = form.get_attribute('action')
            form_method = form.get_attribute('method')
            form_inputs = form.find_elements(By.TAG_NAME, 'input')

            form_details['action'] = form_action
            form_details['method'] = form_method

            input_data = {}
            for input_tag in form_inputs:
                input_name = input_tag.get_attribute('name')

                input_value = driver.execute_script("return arguments[0].value", input_tag)
                input_data[input_name] = input_value

            form_details['inputs'] = input_data
            user_input_data[form_action] = form_details


        driver.quit()

        return user_input_data

    def is_sql_injection(self, user_input_data):

        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND"]

        for form_action, form_details in user_input_data.items():
            for input_name, input_value in form_details["inputs"].items():
                for keyword in sql_keywords:
                    if keyword in input_value.upper():
                        return True

                sql_special_characters = ["'", "\"", ";", "--", "/*", "*/", "xp_", "exec", "sp_"]

                for char in sql_special_characters:
                    if char in input_value:
                        return True

        return False

    def test_sql_injection(self, url):
        forms = self.get_forms(url)
        result_text = f"Обнаружено {len(forms)} форма на веб-сайте {url}.\n"
        for form in forms:
            form_details = self.get_inf_form(form)
            result_text += f"\nДетали формы: {pprint.pformat(form_details)}"
            for c in "\"'":

                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":

                        data[input_tag["name"]] = f"test{c}"
                url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = requests.post(url, data=data)
                elif form_details["method"] == "get":
                    res = requests.get(url, params=data)

                if self.is_vulnerable(res):
                    result_text += f"\nДетали формы: {pprint.pformat(form_details)}"
                    break

        self.text_result.delete(1.0, tk.END)
        self.text_result.insert(tk.END, result_text)

    def get_forms(self, url):
        forms = bs(requests.get(url).content, "html.parser")
        return forms.find_all("form")

    def get_inf_form(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []

        for tag in form.find_all("input"):
            type = tag.attrs.get("type", "text")
            name = tag.attrs.get("name", "")
            value = tag.attrs.get("value", "")
            inputs.append({"type": type, "name": name, "value": value})

        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs

        return details

    def is_vulnerable(self, response):
        errors = {
        # Общие
        "error in your SQL syntax",
        "server error in '/' application",
        "Microsoft OLE DB Provider for ODBC Drivers error",
        # SQLite
        "SQLite/JDBCDriver",
        # MS Access
        "Microsoft Access Driver",
        # DB2
        "CLI Driver SQLCODE",
        # Informix
        "Dynamic Page Generation Error:",
        # Sybase
        "Sybase message:",
        # Firebird
        "Dynamic SQL Error",
        # Ingres
        "Ingres SQLSTATE",
        # HSQLDB
        "org.hsqldb.",
        # Apache Derby
        "Apache Derby Embedded JDBC",
        # MariaDB
        "MariaDB server version for the right syntax",
        # SQLite
        "Warning: SQLite3::query(): Unable to prepare statement",
        # MongoDB
        "MongoDB.Driver.MongoCommandException",
        "MongoDB.Driver.MongoConnectionException",
        # CouchDB
        "couchdb error",
        # Redis
        "READONLY You can't write against a read only slave.",
        # Neo4j
        "Expected end of input, or an expression",
        # Elasticsearch
        "SearchPhaseExecutionException",
        "org.elasticsearch.",
        # Cassandra
        "org.apache.cassandra",
        # Couchbase
        "couchbase network conditions",
        "error in your SQL syntax",
        "server error in '/' application",
        "Microsoft OLE DB Provider for ODBC Drivers error",
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        "MySQLSyntaxErrorException",
        "valid MySQL result",
        "check the manual that (corresponds to|fits) your MySQL server version",
        "Unknown column '[^ ]+' in 'field list'",
        "MySqlClient\.",
        "com\.mysql\.jdbc",
        "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
        "Pdo[./_\\]Mysql",
        "MySqlException",
        "SQLSTATE\[\d+\]: Syntax error or access violation",
        # PostgreSQL
        "PostgreSQL.*?ERROR",
        "Warning.*?\Wpg_",
        "valid PostgreSQL result",
        "Npgsql\.",
        "PG::SyntaxError:",
        "org\.postgresql\.util\.PSQLException",
        "ERROR:\s\ssyntax error at or near",
        "ERROR: parser: parse error at or near",
        "PostgreSQL query failed",
        "org\.postgresql\.jdbc",
        "Pdo[./_\\]Pgsql",
        "PSQLException",
        # SQL Server
        "unclosed quotation mark after the character string",
        "Driver.*? SQL[\-\_\ ]*Server",
        "OLE DB.*? SQL Server",
        "\bSQL Server[^&lt;&quot;]+Driver",
        "Warning.*?\W(mssql|sqlsrv)_",
        "\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        "System\.Data\.SqlClient\.(SqlException|SqlConnection\.OnError)",
        "(?s)Exception.*?\bRoadhouse\.Cms\.",
        # Oracle
        "quoted string not properly terminated",
        "Oracle error",
        "Oracle.*?Driver",
        "Warning.*?\W(oci|ora)_",
        "SQL command not properly ended",
        "macromedia\.jdbc\.oracle",
        "oracle\.jdbc",
        "Zend_Db_(Adapter|Statement)_Oracle_Exception",
        "Pdo[./_\\](Oracle|OCI)",
        "OracleException"

        }
        for error in errors:
            if error in response.content.decode().lower():
                return True
        return False

    def copy_text(self, event=None):
        selected_text = self.text_result.get(tk.SEL_FIRST, tk.SEL_LAST)
        pyperclip.copy(selected_text)

    def paste_text(self, event=None):
        try:
            text_to_paste = pyperclip.paste()
            self.text_result.insert(tk.INSERT, text_to_paste)
        except Exception as e:
            messagebox.showwarning("Ошибка вставки", f"Не удалось вставить текст. Ошибка: {str(e)}")

    def save_report(self):
        result_text = self.text_result.get("1.0", tk.END)
        with open("otchet.txt", "w", encoding="utf-8") as file:
            file.write(result_text)
        messagebox.showinfo("Сохранение отчета", "Отчет успешно сохранен в файл otchet.txt.")



if __name__ == "__main__":
    root = tk.Tk()
    app = SqlInjectionCheckerGUI(root)
    root.mainloop()

#https://demo.testfire.net/index.jsp

#http://testphp.vulnweb.com/artists.php?artist=1

#https://demo.testfire.net/login.jsp

#admin' OR'1'='1
