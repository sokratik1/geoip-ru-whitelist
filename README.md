# RU-WHITELIST IP CIDRs

Автоматически обновляемый список IP-диапазонов российских сетей из категории `RU-WHITELIST`.

Источник: [runetfreedom/russia-blocked-geoip](https://github.com/runetfreedom/russia-blocked-geoip)  
Обновление: каждые 6 часов через GitHub Actions.

## Использование в Подкопе

Добавьте прямую ссылку на raw-файл в настройки:

```
https://raw.githubusercontent.com/sokratik1/geoip-ru-whitelist/main/ru-whitelist.txt
```

## Формат файла

Один CIDR на строку, без заголовков и комментариев:

```
2.63.0.0/17
2.63.128.0/18
2.78.0.0/19
...
```

## Ручное обновление

```bash
python3 parse.py
```
