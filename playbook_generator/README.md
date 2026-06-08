python -m venv venv - створення нового віртуального середовища
venv\Scripts\activate - активація віртуального середовища у Windows
pip install -r requirements.txt - встановлення необхідних бібліотек
copy .env.example .env - створення файлу .env на основі прикладу
notepad .env - відкриття файлу .env для додавання API-ключів
python main.py - запуск Flask-застосунку
http://127.0.0.1:5000 - адреса для відкриття вебінтерфейсу в браузері