---
title: KeenProxy
hide:
  - navigation
  - toc
---

<div class="kp-landing" markdown>

<section class="kp-hero" markdown>
<div class="kp-hero__text" markdown>

![Логотип KeenProxy](../assets/logo.png){ .kp-hero__logo width="72" }

# Ваша сеть — ваши маршруты

Выборочная маршрутизация трафика для роутеров Keenetic и Netcraze с Entware. Выбирайте, какие устройства, домены, адреса и страны идут через туннель, напрямую или блокируются, — в браузерном интерфейсе.

<div class="kp-actions" markdown>
[Начать работу](getting-started.md){ .md-button .md-button--primary }
</div>

</div>


</section>

<section class="kp-section" markdown>

## Возможности

<div class="kp-grid" markdown>

<div class="kp-card" markdown>
:material-devices:{ .kp-card__icon }

### Политики для устройств и сетей

Раздельная маршрутизация, полный туннель или прямой доступ для сети и отдельные правила для устройств по MAC-адресу.
</div>

<div class="kp-card" markdown>
:material-earth:{ .kp-card__icon }

### Группы доменов, IP и стран

Маршрутизация по домену, CIDR или стране — в том числе с исключениями вроде «всё, кроме России».
</div>

<div class="kp-card" markdown>
:material-vpn:{ .kp-card__icon }

### Разные типы соединений

WireGuard, ссылки подключения sing-box, outbound-объекты sing-box и необязательный клиент TrustTunnel.
</div>

<div class="kp-card" markdown>
:material-shield-sync:{ .kp-card__icon }

### Резервирование

Переход на другое соединение при отказе и возврат после восстановления.
</div>

<div class="kp-card" markdown>
:material-dns:{ .kp-card__icon }

### DNS

Локальный DNS-фронтенд с резолверами DoH/DoT и выбором маршрута для DNS.
</div>

<div class="kp-card" markdown>
:material-file-document-check-outline:{ .kp-card__icon }

### Проверка перед применением

Все изменения попадают в общий черновик. Примените его, когда готовы, или отмените; журналы объясняют результат.
</div>

</div>

</section>

<section class="kp-section" markdown>

## Как это работает

<div class="kp-steps" markdown>

<div class="kp-step" markdown>
### Добавьте соединение

Импортируйте файл WireGuard или ссылку подключения либо воспользуйтесь мастером.
</div>

<div class="kp-step" markdown>
### Создайте группы

Соберите домены, адреса или страны и выберите, куда их направить.
</div>

<div class="kp-step" markdown>
### Выберите устройства и примените

Укажите, какие сети и клиенты следуют правилам, и примените черновик.
</div>

</div>

KeenProxy также следит за своими правилами перехвата. На совместимых прошивках Keenetic/Netcraze хук netfilter запускает проверку после изменений firewall; периодический сторож работает везде, включая экспериментальные установки OpenWrt. [Как устроено восстановление правил](network-flow.md#how-firewall-rules-recover-after-a-firmware-change).

</section>

<section class="kp-cta" markdown>

## Подробнее

<div class="kp-actions" markdown>
[Читать обзор](overview.md){ .md-button .md-button--primary }
</div>

<p class="kp-note">KeenProxy — экспериментальный проект. Совместимость зависит от архитектуры роутера, прошивки, возможностей ядра и состава сборки.</p>

</section>

</div>
