# geoip-ru-whitelist

Автоматически обновляемые списки IP-диапазонов российских сетей.

Источник: [runetfreedom/russia-blocked-geoip](https://github.com/runetfreedom/russia-blocked-geoip)  
Обновление: каждые 6 часов через GitHub Actions.

## Два файла — два режима работы Подкопа

### `ru-whitelist.txt` — стандартный режим

РФ-адреса идут **напрямую**, всё остальное тоже напрямую (Подкоп сам решает что через прокси).

```
https://raw.githubusercontent.com/ВАШ_ЛОГИН/geoip-ru-whitelist/main/ru-whitelist.txt
```

### `not-ru.txt` — режим «весь трафик через прокси»

Добавьте этот список в Подкоп (Connection Type: Proxy):
- IP из списка → через прокси (= весь мир кроме РФ)
- IP вне списка → напрямую (= российские сети)

```
https://raw.githubusercontent.com/ВАШ_ЛОГИН/geoip-ru-whitelist/main/not-ru.txt
```

## Формат файлов

Один CIDR на строку, без заголовков:

```
1.0.0.0/24
1.0.1.0/24
...
```

## Ручное обновление

```bash
python3 parse.py
```
