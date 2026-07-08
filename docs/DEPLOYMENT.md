# Руководство по развертыванию spodes-rs

## Обзор

`spodes-rs` — библиотека (crate) для Rust, предоставляющая полный DLMS/COSEM стек. Данное руководство описывает интеграцию библиотеки в проект и настройку для работы с приборами учета электроэнергии.

## Требования

- **Rust:** ≥ 1.85 (edition 2021)
- **ОС:** Linux, macOS, Windows (any)
- **Сеть:** TCP/UDP порты 4059/4065 (стандартные DLMS порты) или последовательный порт для HDLC

## Быстрый старт

### Добавление зависимости

```toml
# Cargo.toml
[dependencies]
spodes-rs = { git = "https://github.com/gvtret/spodes-rs", branch = "main" }
# или path dependency для локальной разработки:
# spodes-rs = { path = "../spodes-rs" }
```

### Минимальный пример (клиент)

```rust
use spodes_rs::obis::ObisCode;
use spodes_rs::session::ClientSession;
use spodes_rs::transport::wrapper::Wrapper;
use spodes_rs::transport::{NetworkTransport, PhysicalTransport};
use std::net::TcpStream;
use std::io;

struct TcpTransport(TcpStream);

impl NetworkTransport for TcpTransport {}

impl PhysicalTransport for TcpTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        self.0.write_all(data)
    }
    fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.0.read(buf)
    }
}

fn main() -> io::Result<()> {
    let stream = TcpStream::connect("192.168.1.100:4059")?;
    let transport = TcpTransport(stream);
    let link = Wrapper::new(transport, 1000, 4059);
    let mut session = ClientSession::new(link);

    // Чтение серийного номера (OBIS 0.0.96.1.0.255, атрибут 2)
    let serial = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    match session.get(1, serial, 2) {
        Ok(response) => println!("Ответ: {response:?}"),
        Err(e) => eprintln!("Ошибка: {e}"),
    }
    Ok(())
}
```

## Конфигурация транспорта

### TCP (IEC 62056-47 wrapper)

Стандартный транспорт для DLMS/COSEM по TCP. Использует wrapper-подуровень с 8-байтным заголовком.

```text
Порт: 4059 (стандартный DLMS TCP порт)
Заголовок wrapper:
  version (2) + source_wPort (2) + dest_wPort (2) + length (2)
```

### HDLC (IEC 62056-46)

Фрейминг HDLC для последовательных линий или TCP. Работает поверх любого `PhysicalTransport`.

```text
Адреса: client (1), server (1)
Контрольная сумма: CRC-16 CCITT
Формат фрэйма: flag + address + control + information + fcs + flag
```

### UDP (IEC 62056-47 wrapper)

Для без соединения передачи. Использует тот же wrapper-заголовок, что и TCP.

```text
Порт: 4065 (стандартный DLMS UDP порт)
Ограничение: один запрос → один ответ на дейтаграмму
```

## Конфигурация безопасности

### Security Suite 0 (AES-GCM-128)

Базовый набор без PKI. Шифрование AES-128-GCM, аутентификация через GMAC.

```rust
use spodes_rs::security::{SecuritySuite, SecurityPolicy, AuthMechanism};

let suite = SecuritySuite::Suite0;
let policy = SecurityPolicy::AuthenticatedEncryption;
let mechanism = AuthMechanism::HlsGmac; // mechanism 5
```

### Security Suite 1 (ECDH-ECDSA-P256)

С PKI. Согласование ключей ECDH на кривой P-256, подписи ECDSA.

```rust
let suite = SecuritySuite::Suite1;
let policy = SecurityPolicy::AuthenticatedEncryption;
let mechanism = AuthMechanism::HlsEcdsa; // mechanism 7
```

### GOST Suite (Р 1323565.1)

Российский профиль. Кузнечик-CMAC (mechanism 8) или ГОСТ 34.10 (mechanism 10).

```rust
let suite = SecuritySuite::Gost; // набор 9
let policy = SecurityPolicy::AuthenticatedEncryption;
let mechanism = AuthMechanism::HlsGostCmac; // mechanism 8
```

## Настройка сервера

### RequestDispatcher

Диспетчер запросов — серверная сторона, обрабатывающая GET/SET/ACTION запросы.

```rust
use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::types::CosemDataType;

let mut server = RequestDispatcher::new();

// Регистрация объектов
let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF); // активная энергия
server.add(Box::new(Data::new(obis, CosemDataType::DoubleLongUnsigned(123_456))));

// Обработка запроса
let response = server.dispatch(&request_bytes)?;
```

### Association LN

Настройка ассоциации для управления доступом.

```rust
use spodes_rs::classes::association_ln::{
    AssociationLn, AssociationLnConfig, AuthenticationMechanism
};

let assoc = AssociationLn::new(AssociationLnConfig {
    logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
    version: AssociationLnVersion::Version1,
    authentication_mechanism: AuthenticationMechanism::HlsSha256,
    // ...
});
```

## Интеграция с СПОДУС (ИВКЭ)

Для работы концентратора ИВКЭ используйте модуль `spodus`:

```rust
use spodes_rs::spodus::node::Concentrator;
use spodes_rs::spodus::catalog;

// Создание каталога объектов ИВКЭ
let clock = catalog::clock();
let sap = catalog::sap_assignment(sap_list);
let sec = catalog::security_setup(obis, 0, client_st, server_st);
```

## Тестирование

```bash
# Все тесты
cargo test

# Только unit тесты
cargo test --lib

# Интеграционные тесты
cargo test --test spodus_integration

# Документационные тесты
cargo test --doc

# Clippy
cargo clippy --all-targets -- -D warnings

# Проверка форматирования
cargo fmt --check

# Генерация документации
cargo doc --no-deps
```

## Мониторинг

### Логирование

Библиотека не использует фреймворки логирования. Для отладки рекомендуется:

1. Включить `RUST_LOG=debug` для вывода трассировки
2. Использовать `env_logger` или `tracing` в приложении

### Метрики

Для мониторинга производительности:

- Количество обработанных запросов (GET/SET/ACTION)
- Время ответа на запрос
- Количество ошибок аутентификации
- Состояние ассоциаций

## Безопасность

### Рекомендации

1. **Используйте Security Suite 1 или 2** дляProduction окружений
2. **Включайте аутентификацию** (mechanism 5..10) для всех соединений
3. **Регулярно обновляйте ключи** шифрования и аутентификации
4. **Мониторьте invocation counter** — его рост должен быть монотонным
5. **Используйте GOST профиль** для соответствия Р 1323565.1

### Известные ограничения

- Библиотека не реализует физический транспорт (нужно свой `PhysicalTransport`)
- Ассоциации SN (class 12) не реализованы (только LN)
- Некоторые legacy классы (Register table, Compact data) отсутствуют

## Примеры

См. директорию `examples/`:

- `client_session` — клиент через in-memory транспорт
- `server_dispatch` — сервер с диспетчером запросов
- `tcp_client` / `tcp_server` — TCP примеры
- `udp_client` — UDP пример
- `hls_handshake` — HLS рукопожатие
- `spodus_concentrator` — ИВКЭ концентратор
- `data_usage` / `register_usage` / `clock_usage` — примеры классов
