# IoC Domain Passive Analyzer

Скрипт для автоматизированного пассивного анализа индикаторов компрометации (IoC) типа Domain с использованием VirusTotal API v3. 

Скрипт группирует исследуемые домены в инфраструктурные кластеры на основе весовой графовой модели связности и выгружает результаты в XLSX-таблицу с цветовой подсветкой общих паттернов.

## Запуск
Необходимо установить зависимости
```bash
pip install requests openpyxl
```
Запуск скрипта
```bash
python main.py -f domains.txt -k YOUR_VIRUSTOTAL_API_KEY -o analysis_result.xlsx
```

Где:

- `-f` / `--file` — файл со списком доменов, по одному домену в строке.
- `-k` / `--api-key` — API-ключ VirusTotal.
- `-o` / `--output` — имя выходного Excel-файла. По умолчанию: `analysis_result.xlsx`.


