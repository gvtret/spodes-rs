# Архитектура spodes-rs

## Обзор

`spodes-rs` — полная реализация DLMS/COSEM стека на Rust для систем коммерческого учета электроэнергии. Стек соответствует международным стандартам IEC 62056 и российским профилям СПОДЭС (СТО 34.01-5.1-006-2023), СПОДУС (СТО 34.01-5.1-013-2023) и ГОСТ (Р 1323565.1).

## Архитектура по слоям

```text
┌─────────────────────────────────────────────────────────────────┐
│  session (клиент)      server (диспетчер)      spodus           │  драйверы / профили
├─────────────────────────────────────────────────────────────────┤
│  service    GET/SET/ACTION, ACSE, уведомления, шифрование      │  прикладной уровень
│  security   наборы, политика, HLS механизмы, ECDH/GOST         │
├─────────────────────────────────────────────────────────────────┤
│  transport  HDLC (62056-46) и wrapper (62056-47)               │  транспортный уровень
├─────────────────────────────────────────────────────────────────┤
│  classes / interface  -  объекты интерфейсов COSEM             │  модель объектов
│  types (A-XDR/BER)  -  obis                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Слои и модули

### 1. Модель объектов (object model)

**Модули:** `types`, `obis`, `interface`, `classes`

Отвечают за представление данных COSEM и их сериализацию.

- **`types`** — типы данных COSEM (`CosemDataType`) и их A-XDR (BER) сериализация. Поддерживаемые типы: null, bool, integer, unsigned, octet-string, visible-string, date, time, array, structure и др.

- **`obis`** — коды идентификации объектов (OBIS). Формат `A.B.C.D.E.F` идентифицирует каждый объект в устройстве.

- **`interface`** — трейт `InterfaceClass`, общий для всех интерфейсных классов COSEM. Определяет методы: `class_id()`, `version()`, `logical_name()`, `attributes()`, `methods()`.

- **`classes`** — 30 реализованных интерфейсных классов:
  - **Данные:** Data (1), Register (3), Extended register (4), Demand register (5), Register activation (6)
  - **Профили:** Profile generic (7), Clock (8), Script table (9), Schedule (10), Special days table (11)
  - **Управление доступом:** Association LN (15), SAP assignment (17), Security setup (64)
  - **Интерфейсы:** IEC HDLC Setup (23), IEC Local Port Setup (19), TCP-UDP setup (41), IPv4 (42), IPv6 (48), Push setup (40)
  - **Управление:** Activity calendar (20), Register monitor (21), Single action schedule (22), Disconnect control (70), Limiter (71), Arbitrator (68)
  - **Прочие:** Image transfer (18), Data protection (30), GPRS modem (45), GSM diagnostic (47), MAC address (43)

### 2. Транспортный уровень

**Модуль:** `transport`

Абстрагирует физическую среду и обеспечивает фрейминг APDU.

- **`PhysicalTransport`** — трейт физического канала (serial, TCP, UDP). Методы: `send()`, `receive()`.

- **`NetworkTransport`** — маркерный трейт для сетевых транспортов (TCP/UDP). Требуется для wrapper-слоя.

- **`DataLinkLayer`** — трейт канального уровня. Методы: `send_apdu()`, `receive_apdu()`.

- **HDLC** (`transport::hdlc`) — фрейминг по IEC 62056-46. Работает поверх любого `PhysicalTransport` (serial, TCP, UDP).

- **Wrapper** (`transport::wrapper`) — фрейминг по IEC 62056-47. Работает только поверх `NetworkTransport` (TCP/UDP). Заголовок 8 байт: version (2) + source wPort (2) + destination wPort (2) + length (2).

### 3. Прикладной уровень

**Модули:** `service`, `security`

Реализуют xDLMS сервисы и модель безопасности.

#### Сервисы (`service`)

- **GET/SET/ACTION** — нормальные, блочные (с datablocks) и WITH-LIST запросы/ответы
- **ACSE** — ассоциация (AARQ/AARE) и завершение (RLRQ/RLRE)
- **Initiate** — структурированные InitiateRequest/InitiateResponse
- **Уведомления** — DataNotification и EventNotification
- **Ошибки** — ExceptionResponse и ConfirmedServiceError
- **GBT** — общий блочный трансфер
- **Шифрование** — glo-/ded-ciphering и general-glo-/ded-/general-ciphering / general-signing

#### Безопасность (`security`)

- **Наборы безопасности** (SecuritySuite): 0 (AES-GCM-128), 1 (ECDH-ECDSA-P256), 2 (ECDH-ECDSA-P384), GOST
- **Политика безопасности** (SecurityPolicy): none, authentication, encryption, authenticated_encryption
- **Механизмы аутентификации** (AuthMechanism): 0..10, включая GOST HLS (8: CMAC, 9:reserved, 10: GOST 34.10)
- **Согласование ключей:** ECDH (NIST P-256/P-384) и GOST VKO
- **Цифровые подписи:** ECDSA и ГОСТ 34.10-2018
- **Хеширование:** SHA-256, SHA-384, Streebog-256

### 4. Драйверы

**Модули:** `session`, `server`

Высокоуровневые обертки для клиентской и серверной работы.

- **`ClientSession`** — блокирующий клиентский драйвер. Связывает транспорт, сервисы и шифрование в round-trip вызовы GET/SET/ACTION/associate/release.

- **`RequestDispatcher`** — серверный диспетчер. Маршрутизирует входящие GET/SET/ACTION APDU к адресованным COSEM объектам и возвращает ответные APDU.

### 5. Профиль СПОДУС

**Модуль:** `spodus`

Информационная модель ИВКЭ (концентратора/шлюза) по СТО 34.01-5.1-013-2023.

- **Concentrator** (`spodus::node`) — узел концентратора, работающий как DLMS-сервер для ИВК (upstream) и DLMS-клиент для ПУ (downstream)
- **Catalog** (`spodus::catalog`) — стандартные объекты: Clock, SAP assignment, Security setup, Association LN
- **Объекты Appendix A:** nameplate, configured meters, direct channel, channel list, discovered meters, access policies, data-exchange tasks, status table, journals, notifications
- **Новые классы СТО-013:** Table manager (8200), Profile data filter (8201)
- **Прозрачный пропуск** (`spodus::proxy`) — MeterProxy для доступа к отдельному ПУ через концентратор

## Потоки данных

### Клиентский запрос (GET)

```text
ClientSession::get(class_id, obis, attr_id)
  │
  ├── Формирует GetRequest APDU
  ├── Шифрует (если policy != None) через security
  ├── Отправляет через DataLinkLayer::send_apdu()
  │     └── Wrapper/HDLC оборачивает APDU в фрейм
  │           └── PhysicalTransport::send() отправляет по каналу
  │
  └── Ожидает ответ через DataLinkLayer::receive_apdu()
        └── Десериализует GetResponse
```

### Серверный ответ

```text
RequestDispatcher::dispatch(apdu_bytes)
  │
  ├── Десериализует входящий APDU
  ├── Ищет целевой объект по class_id + obis
  ├── Вызывает метод объекта (get/set/action)
  ├── Формирует ответный APDU
  └── Возвращает байты ответа
```

### Шифрование APDU

```text
Encrypt (glo_*_Request):
  ├── SC (Security Control): suite_id || protection_level || key_info
  ├── IC (Invocation Counter): 4 bytes, monotonically increasing
  ├── IV = system_title || IC
  ├── AAD = SC || AK (authenticated encryption) или SC || AK || plaintext (auth only)
  ├── AES-GCM: encrypt(plaintext, key=EK, nonce=IV, aad=AAD)
  └── Результат: tag || IC || ciphertext || truncated_tag
```

## Соответствие стандартам

| Стандарт | Описание | Реализация |
|----------|----------|------------|
| IEC 62056-5-3 | Прикладной уровень DLMS/COSEM | service, session, server |
| IEC 62056-6-2 | Интерфейсные классы COSEM | classes (30 IC) |
| IEC 62056-46 | HDLC транспорт | transport::hdlc |
| IEC 62056-47 | TCP/UDP транспорт (wrapper) | transport::wrapper |
| СТО 34.01-5.1-006-2023 | СПОДЭС — модель ПУ | classes, security |
| СТО 34.01-5.1-013-2023 | СПОДУС — модель ИВКЭ | spodus |
| Р 1323565.1 | ГОСТ криптография | security::gost3410, hls, agreement |
| ГОСТ Р 34.10-2018 | ЭЦП на эллиптических кривых | security::gost3410 |
| ГОСТ Р 34.11-2018 | Хеш-функция Streebog | streebog crate |
| ГОСТ Р 34.12-2018 | Блочный шифр Кузнечик | kuznyechik crate |

## Требования к среде

- **Rust:** ≥ 1.85 (edition 2021)
- **unsafe:** отсутствует в исходном коде крейта
- **feature flags:** не требуются
- **Зависимости:** serde, aes-gcm, p256/p384, ecdsa, streebog, kuznyechik, num-bigint, rand
